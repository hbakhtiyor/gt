package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"

	aesgcm "github.com/hbakhtiyor/openssl_gcm"
)

const (
	ChunkSize = 8192
	SpoolSize = 16 * 1024 * 1024
)

// https://github.com/euphoria-io/heim/blob/097b7da2e0b23e9c5828c0e4831a3de660bb5302/proto/security/aesgcm.go
// https://github.com/mozilla/send/blob/93072c0c1e252efc17c9a52b900a52f0c35489d0/docs/encryption.md
// TODO https://send.firefox.com/api/info
type Version struct {
	Version string
	Commit  string
	Source  string
}

type Token struct {
	OwnerToken  string `json:"owner_token,omitempty"`
	DeleteToken string `json:"delete_token,omitempty"`
	Auth        string `json:"auth,omitempty"`
	DLimit      int    `json:"dlimit,omitempty"`
}

type MetaData struct {
	IV   string `json:"iv"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type SendReseponse struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Owner  string `json:"owner"`
	Delete string `json:"delete"`
}

type SecretFile struct {
	SecretUrl  string
	FileID     string
	FileNonce  []byte
	OwnerToken string
}

// DefaultClient is the default Client and is used by Put, and Options.
// var DefaultClient = &http.Client{}

// Splits a Send url into key, urlid and 'prefix' for the Send server
// Should handle any hostname, but will brake on key & id length changes
// e.g. https://send.firefox.com/download/c8ab3218f9/#39EL7SuqwWNYe4ISl2M06g
// service == "https://send.firefox.com/"
// urlid == "c8ab3218f9"
// key == "39EL7SuqwWNYe4ISl2M06g"
func SplitKeyURL(rawURL string) (service string, URLID string, key string) {
	l := len(rawURL)
	key = rawURL[l-22:]
	URLID = rawURL[l-34 : l-24]
	service = rawURL[:l-43]
	return
}

func CheckServerVersion(service string, ignoreVersion bool) (bool, error) {
	if ignoreVersion {
		return true, nil
	}

	response, err := http.Get(service + "__version__")

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("checkServerVersion: Error occurs while processing POST request: %s %s\n", service, responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("checkServerVersion: Received body while processing POST request: %s %s\n", service, responseDump)
	}

	result := &Version{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return false, err
	}

	if result.Version == "v2.5.3" && result.Commit == "cda38f9" {
		return true, nil
	}

	return false, nil
}

// Decode url-safe base64 string, with or without padding, to bytes
func UnPaddedURLSafe64Decode(s string) ([]byte, error) {
	// repeat = (4 - len(s) % 4) with URLEncoding?
	return base64.StdEncoding.DecodeString(s)
}

// delete.go
// Delete a file already uploaded to Send
func ApiDelete(service, fileID, ownerToken string) (bool, error) {
	service += "api/delete/%s"
	j := &Token{OwnerToken: ownerToken, DeleteToken: ownerToken}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return false, err
	}

	if Debug {
		log.Printf("ApiDelete: Generated json data: %s\n", b.String())
	}

	response, err := http.Post(
		fmt.Sprintf(service, fileID),
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiDelete: Error occurs while processing POST request: %s\n", responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiDelete: Received body while processing POST request: %s\n", responseDump)
	}

	// result := &map[string]interface{}{}
	// if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
	// 	return false, err
	// }

	result, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	if string(result) == "OK" {
		return true, nil
	}

	return false, nil
}

// password.go
// changes the authKey required to download a file hosted on a send server
func ApiPassword(service, fileID, ownerToken string, newAuthKey []byte) (bool, error) {
	service += "api/password/%s"
	auth := base64.RawURLEncoding.EncodeToString(newAuthKey)
	j := &Token{OwnerToken: ownerToken, Auth: auth}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return false, err
	}

	if Debug {
		log.Printf("ApiPassword: Generated json data: %s\n", b.String())
	}

	response, err := http.Post(
		fmt.Sprintf(service, fileID),
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiPassword: Error occurs while processing POST request: %s\n", responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiPassword: Received body while processing POST request: %s\n", responseDump)
	}

	result, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	if string(result) == "OK" {
		return true, nil
	}

	return false, nil
}

// set or change the password required to download a file hosted on a send server.
func SetPassword(url, ownerToken, password string) (bool, error) {
	service, fileID, key := SplitKeyURL(url)
	rawKey, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return false, err
	}
	mKey, err := NewManagedKey(rawKey, password, url)
	if err != nil {
		return false, err
	}

	return ApiPassword(service, fileID, ownerToken, mKey.NewAuthKey)
}

// params.go

// Change the download limit for a file hosted on a Send Server
func ApiParams(service, fileID, ownerToken string, downloadLimit int) (bool, error) {
	service += "api/params/%s"
	j := &Token{OwnerToken: ownerToken, DLimit: downloadLimit}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return false, err
	}

	if Debug {
		log.Printf("ApiParams: Generated json data: %s\n", b.String())
	}

	response, err := http.Post(
		fmt.Sprintf(service, fileID),
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiParams: Error occurs while processing POST request: %s\n", responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiParams: Received body while processing POST request: %s\n", responseDump)
	}

	result, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	if string(result) == "OK" {
		return true, nil
	}

	return false, nil
}

// Encrypt file metadata with the same method as the Send browser/js client
func EncryptMetadata(key *ManagedKey, fileName, fileType string) ([]byte, error) {
	metadata := &MetaData{
		base64.RawURLEncoding.EncodeToString(key.EncryptIV),
		fileName,
		fileType,
	}

	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(metadata); err != nil {
		return nil, err
	}

	if Debug {
		log.Printf("EncryptMetadata: Generated json data: %s\n", b.String())
	}

	block, err := aes.NewCipher(key.MetaKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// WebcryptoAPI expects the gcm tag at the end of the ciphertext, return them concatenated
	return aesgcm.Seal(nil, key.MetaIV, b.Bytes(), nil), nil
}

// sign the server nonce from the WWW-Authenticate header with an authKey
func SignNonce(key, nonce []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	return mac.Sum(nil)
}

// Uploads data to Send.
func ApiUpload(service string, file *os.File, encMeta []byte, key *ManagedKey, fileName string) (*SecretFile, error) {
	service += "api/upload"

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	fileWriter, err := bodyWriter.CreateFormFile("file", fileName)
	if err != nil {
		fmt.Println("error writing to buffer")
		return nil, err
	}

	// reader := bufio.NewReader(file)
	r, err := aesgcm.NewGcmEncryptReader(file, key.EncryptKey, key.EncryptIV, nil)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(fileWriter, r)
	if err != nil {
		return nil, err
	}

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	req, err := http.NewRequest(http.MethodPost, service, bodyBuf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-File-Metadata", base64.RawURLEncoding.EncodeToString(encMeta))
	req.Header.Set("Authorization", "send-v1 "+base64.RawURLEncoding.EncodeToString(key.AuthKey))
	// binary/octet-stream,  "application/octet-stream"
	req.Header.Set("Content-Type", contentType)
	response, err := DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiUpload: Error occurs while processing POST request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiUpload: Received body while processing POST request: %s\n", responseDump)
	}

	result := &SendReseponse{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	secretFile := &SecretFile{}
	secretFile.SecretUrl = result.URL + "#" + base64.RawURLEncoding.EncodeToString(key.SecretKey)
	secretFile.FileID = result.ID
	fileNonce := strings.Replace(response.Header.Get("WWW-Authenticate"), "send-v1 ", "", 1)
	secretFile.FileNonce, err = UnPaddedURLSafe64Decode(fileNonce)
	if err != nil {
		return nil, err
	}
	secretFile.OwnerToken = result.Owner
	if secretFile.OwnerToken == "" {
		secretFile.OwnerToken = result.Delete
	}

	return secretFile, nil
}

// Encrypt & Upload a file to send and return the download URL
func SendFile(service string, file *os.File, fileName, password string, ignoreVersion bool) (*SecretFile, error) {
	if status, err := CheckServerVersion(service, ignoreVersion); err != nil {
		return nil, err
	} else if !status {
		fmt.Println("\033[1;41m!!! Potentially incompatible server version !!!\033[0m")
	}

	if fileName == "" {
		fileName = filepath.Base(file.Name())
	}

	fmt.Printf("Encrypting data from \"%s\"\n", fileName)
	key, err := NewManagedKey(nil, "", "")
	if err != nil {
		return nil, err
	}

	encMeta, err := EncryptMetadata(key, fileName, "application/octet-stream")
	if err != nil {
		return nil, err
	}

	fmt.Printf("Uploading \"%s\"\n", fileName)
	r, err := ApiUpload(service, file, encMeta, key, fileName)
	if err != nil {
		return nil, err
	}

	if password != "" {
		fmt.Println("Setting password")
		status, err := SetPassword(r.SecretUrl, r.OwnerToken, password)
		if err != nil {
			return nil, err
		}
		fmt.Println(status)
	}

	return r, nil
}

// Decrypt file metadata with the same method as the Send browser/js client
func DecryptMetadata(encMeta []byte, key *ManagedKey) ([]byte, error) {
	block, err := aes.NewCipher(key.MetaKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, key.MetaIV, encMeta, nil)
}

func ApiMetadata(service, fileID string, authKey []byte) (*map[string]interface{}, error) {
	service += "api/metadata/%s"

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(service, fileID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "send-v1 "+base64.RawURLEncoding.EncodeToString(authKey))
	response, err := DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiMetadata: Error occurs while processing POST request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiMetadata: Received body while processing POST request: %s\n", responseDump)
	}

	// newNonce, err := UnPaddedURLSafe64Decode(strings.Replace(response.Header.Get("WWW-Authenticate"), "send-v1 ", "", 1))
	// if err != nil {
	// 	return nil, err
	// }

	result := &map[string]interface{}{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
