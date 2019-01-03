package main

import (
	"bufio"
	"bytes"
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

// https://github.com/euphoria-io/heim/blob/097b7da2e0b23e9c5828c0e4831a3de660bb5302/proto/security/aesgcm.go
// https://github.com/mozilla/send/blob/93072c0c1e252efc17c9a52b900a52f0c35489d0/docs/encryption.md

// Content-Disposition: form-data; name="data"; filename="blob"
// Content-Type: application/octet-stream
// {"url":"https://send.firefox.com/download/3a068d79ae/","owner":"b2c2c2235e42dae2bc43","id":"3a068d79ae"}

// TODO https://send.firefox.com/api/info/fileId
// {"dlimit":1,"dtotal":0,"ttl":86398000}

type Version struct {
	Version string
	Commit  string
	Source  string
}

type Token struct {
	OwnerToken string `json:"owner_token,omitempty"`
	Auth       string `json:"auth,omitempty"`
	DLimit     int    `json:"dlimit,omitempty"`
}

type Meta struct {
	MetaData      string `json:"metadata"`
	FinalDownload bool   `json:"finalDownload"`
	Size          int64  `json:"size,string"`
	TTL           int64  `json:"ttl"`
}

type FileInfo struct {
	PasswordRequired bool `json:"password"`
}

type File struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Owner string `json:"owner"`
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
			log.Printf("CheckServerVersion: Error occurs while processing POST request: %s %s\n", service, responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("CheckServerVersion: Received body while processing POST request: %s %s\n", service, responseDump)
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

// delete.go
// Delete a file already uploaded to Send
func ApiDelete(service, fileID, ownerToken string) (bool, error) {
	service += "api/delete/%s"
	j := &Token{OwnerToken: ownerToken}
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
	mKey := NewManagedKey(rawKey, password, url)
	if mKey.Err() != nil {
		return false, mKey.Err()
	}

	return ApiPassword(service, fileID, ownerToken, mKey.AuthKey)
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

// Uploads data to Send.
func ApiUpload(service string, file *os.File, encMeta []byte, key *ManagedKey, fileName string) (*File, error) {
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

	result := &File{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	result.URL += "#" + base64.RawURLEncoding.EncodeToString(key.SecretKey)

	return result, nil
}

// Encrypt & Upload a file to send and return the download URL
func SendFile(service string, file *os.File, fileName, password string, ignoreVersion bool) (*File, error) {
	if status, err := CheckServerVersion(service, ignoreVersion); err != nil {
		return nil, err
	} else if !status {
		fmt.Println("\033[1;41m!!! Potentially incompatible server version !!!\033[0m")
	}

	if fileName == "" {
		fileName = filepath.Base(file.Name())
	}

	fmt.Printf("Encrypting data from \"%s\"\n", fileName)
	key := NewManagedKey(nil, "", "")
	if key.Err() != nil {
		return nil, key.Err()
	}

	metadata := &MetaData{
		Name: fileName,
		Type: "application/octet-stream",
	}

	encMeta, err := metadata.Encrypt(key)
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
		status, err := SetPassword(r.URL, r.Owner, password)
		if err != nil {
			return nil, err
		}
		fmt.Println(status)
	}

	return r, nil
}

func ApiMetadata(service, fileID string, authKey []byte) (*Meta, []byte, error) {
	service += "api/metadata/%s"

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(service, fileID), nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Authorization", "send-v1 "+base64.RawURLEncoding.EncodeToString(authKey))
	response, err := DefaultClient.Do(req)

	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiMetadata: Error occurs while processing POST request: %s\n", responseDump)
		}
		return nil, nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiMetadata: Received body while processing POST request: %s\n", responseDump)
	}

	newNonce, err := base64.StdEncoding.DecodeString(strings.Replace(response.Header.Get("WWW-Authenticate"), "send-v1 ", "", 1))
	if err != nil {
		return nil, nil, err
	}

	result := &Meta{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, nil, err
	}

	return result, newNonce, nil
}

func ApiExists(service, fileID string) (*FileInfo, error) {
	service += "api/exists/%s"

	response, err := http.Get(fmt.Sprintf(service, fileID))

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiExists: Error occurs while processing GET request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiExists: Received body while processing GET request: %s\n", responseDump)
	}

	result := &FileInfo{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// Given a Send url, download and return the encrypted data and metadata
func ApiDownload(service, fileID, fileName string, fileSize int64, authKey []byte, key *ManagedKey) error {
	service += "api/download/%s"

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(service, fileID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "send-v1 "+base64.RawURLEncoding.EncodeToString(authKey))
	response, err := DefaultClient.Do(req)

	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiDownload: Error occurs while processing POST request: %s\n", responseDump)
		}
		return errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiDownload: Received body while processing POST request: %s\n", responseDump)
	}

	reader := bufio.NewReader(response.Body)
	// https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations
	r, err := aesgcm.NewGcmDecryptReader(reader, key.EncryptKey, key.EncryptIV, nil, fileSize)
	if err != nil {
		return err
	}

	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = io.Copy(file, r); err != nil {
		return err
	}

	return nil
}

func DownloadFile(rawURL, password string, ignoreVersion bool) error {
	service, fileID, key := SplitKeyURL(rawURL)
	if status, err := CheckServerVersion(service, ignoreVersion); err != nil {
		return err
	} else if !status {
		return errors.New("Potentially incompatible server version, use --ignore-version to disable version checks")
	}

	fmt.Println("Checking if file exists...")
	info, err := ApiExists(service, fileID)
	if err != nil {
		return err
	}

	if info.PasswordRequired && password == "" {
		fmt.Scanln("A password is required, please enter it now", password)
	} else if !info.PasswordRequired && password != "" {
		fmt.Println("A password was provided but none is required, ignoring...")
	}

	rawKey, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return err
	}

	mKey := NewManagedKey(rawKey, password, rawURL)
	if mKey.Err() != nil {
		return mKey.Err()
	}

	nonce, err := GetNonce(service + "download/" + fileID + "/")
	if err != nil {
		return err
	}

	authorisation := mKey.SignNonce(nonce)
	fmt.Println("Fetching metadata...")
	meta, nonce, err := ApiMetadata(service, fileID, authorisation)
	if err != nil {
		return err
	}

	encMeta, err := base64.RawURLEncoding.DecodeString(meta.MetaData)
	if err != nil {
		return err
	}

	metadata, err := DecryptMetadata(encMeta, mKey)
	if err != nil {
		return err
	}

	mKey.EncryptIV, err = base64.RawURLEncoding.DecodeString(metadata.IV)
	if err != nil {
		return err
	}

	fmt.Printf("The file wishes to be called '%s' and is %d bytes in size\n", metadata.Name, meta.Size-16)

	fmt.Println("Downloading " + rawURL)
	authorisation = mKey.SignNonce(nonce)
	err = ApiDownload(service, fileID, metadata.Name, meta.Size, authorisation, mKey)
	if err != nil {
		return err
	}

	return nil
}

func GetNonce(url string) ([]byte, error) {
	response, err := http.Get(url)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("GetNonce: Error occurs while processing POST request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("GetNonce: Received body while processing POST request: %s\n", responseDump)
	}

	fileNonce := strings.Replace(response.Header.Get("WWW-Authenticate"), "send-v1 ", "", 1)
	return base64.StdEncoding.DecodeString(fileNonce)
}
