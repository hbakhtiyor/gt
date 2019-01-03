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

type Version struct {
	Version string
	Commit  string
	Source  string
}

type Token struct {
	OwnerToken    string `json:"owner_token,omitempty"`
	Auth          string `json:"auth,omitempty"`
	DownloadLimit int    `json:"dlimit,omitempty"`
}

type Meta struct {
	MetaData      string `json:"metadata"`
	FinalDownload bool   `json:"finalDownload"`
	Size          int64  `json:"size,string"`
	TTL           int64  `json:"ttl"`
	Nonce         []byte
}

type FileInfo struct {
	PasswordRequired bool  `json:"password,omitempty"`
	DownloadLimit    int   `json:"dlimit,omitempty"`
	DownloadTotal    int   `json:"dtotal,omitempty"`
	TTL              int64 `json:"ttl,omitempty"`
}

type File struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Owner string `json:"owner"`
}

type Config struct {
	BaseURL   string
	FileID    string
	SecretKey []byte
	RawURL    string
}

type Options struct {
	Password      string
	IgnoreVersion bool
}

// DefaultClient is the default Client and is used by Put, and Options.
// var DefaultClient = &http.Client{}

// Splits a Send url into key, fileid and 'prefix' for the Send server
// Should handle any hostname, but will brake on key & id length changes
// e.g. https://send.firefox.com/download/c8ab3218f9/#39EL7SuqwWNYe4ISl2M06g
// baseURL == "https://send.firefox.com/"
// fileID == "c8ab3218f9"
// secretKey == "39EL7SuqwWNYe4ISl2M06g"
func NewConfigFromURL(url string) (*Config, error) {
	// TODO Validate with regex
	l := len(url)

	key := url[l-22:]
	rawKey, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode a key: %v", err)
	}

	c := &Config{
		BaseURL:   url[:l-43],
		FileID:    url[l-34 : l-24],
		SecretKey: rawKey,
		RawURL:    url,
	}

	return c, nil
}

func CheckServerVersion(config *Config, option *Options) (bool, error) {
	if option.IgnoreVersion {
		return true, nil
	}

	response, err := http.Get(config.BaseURL + "__version__")

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("CheckServerVersion: Error occurs while processing POST request: %s %s\n", config.BaseURL, responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("CheckServerVersion: Received body while processing POST request: %s %s\n", config.BaseURL, responseDump)
	}

	result := &Version{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return false, err
	}

	if result.Version == "v2.6.1" && result.Commit == "7013f5c" {
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
	config, err := NewConfigFromURL(url)
	if err != nil {
		return false, err
	}

	mKey := NewManagedKey(config.SecretKey, password, url)
	if mKey.Err() != nil {
		return false, mKey.Err()
	}

	return ApiPassword(config.BaseURL, config.FileID, ownerToken, mKey.AuthKey)
}

// params.go

// Change the download limit for a file hosted on a Send Server
func ApiParams(service, fileID, ownerToken string, downloadLimit int) (bool, error) {
	service += "api/params/%s"
	j := &Token{OwnerToken: ownerToken, DownloadLimit: downloadLimit}
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

	// TODO Stream upload
	// https://github.com/cloudfoundry-incubator/cflocal/blob/49495238fad2959061bef7a23c6b28da8734f838/remote/droplet.go#L21-L58
	// https://stackoverflow.com/questions/39761910/how-can-you-upload-files-as-a-stream-in-go
	// https://blog.depado.eu/post/bufferless-multipart-post-in-go

	// Content-Disposition: form-data; name="data"; filename="blob"
	// Content-Type: application/octet-stream

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

	result.URL += "#" + key.RawSecretKey()

	return result, nil
}

// Encrypt & Upload a file to send and return the download URL
func SendFile(file *os.File, config *Config, options *Options) (*File, error) {
	if config == nil {
		config = &Config{BaseURL: "https://send.firefox.com/"}
	}
	if options == nil {
		options = &Options{}
	}

	if status, err := CheckServerVersion(config, options); err != nil {
		return nil, err
	} else if !status {
		fmt.Println("\033[1;41m!!! Potentially incompatible server version !!!\033[0m")
	}

	fileName := filepath.Base(file.Name())

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
	r, err := ApiUpload(config.BaseURL, file, encMeta, key, fileName)
	if err != nil {
		return nil, err
	}

	if options.Password != "" {
		fmt.Println("Setting password")
		status, err := SetPassword(r.URL, r.Owner, options.Password)
		if err != nil {
			return nil, err
		}
		fmt.Println(status)
	}

	return r, nil
}

func ApiMetadata(service, fileID string, authKey []byte) (*Meta, error) {
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

	newNonce, err := base64.StdEncoding.DecodeString(strings.Replace(response.Header.Get("WWW-Authenticate"), "send-v1 ", "", 1))
	if err != nil {
		return nil, err
	}

	result := &Meta{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	result.Nonce = newNonce
	return result, nil
}

func ApiExists(config *Config) (*FileInfo, error) {
	response, err := http.Get(fmt.Sprintf(config.BaseURL+"api/exists/%s", config.FileID))

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

func ApiInfo(config *Config) (*FileInfo, error) {
	response, err := http.Get(fmt.Sprintf(config.BaseURL+"api/info/%s", config.FileID))

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiInfo: Error occurs while processing GET request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiInfo: Received body while processing GET request: %s\n", responseDump)
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

func DownloadFile(url string, options *Options) error {
	config, err := NewConfigFromURL(url)
	if err != nil {
		return err
	}
	if options == nil {
		options = &Options{}
	}

	if status, err := CheckServerVersion(config, options); err != nil {
		return err
	} else if !status {
		return errors.New("Potentially incompatible server version, use --ignore-version to disable version checks")
	}

	fmt.Println("Checking if file exists...")
	info, err := ApiExists(config)
	if err != nil {
		return err
	}

	if info.PasswordRequired && options.Password == "" {
		fmt.Scanln("A password is required, please enter it now", options.Password)
	} else if !info.PasswordRequired && options.Password != "" {
		fmt.Println("A password was provided but none is required, ignoring...")
	}

	mKey := NewManagedKey(config.SecretKey, options.Password, config.RawURL)
	if mKey.Err() != nil {
		return mKey.Err()
	}

	nonce, err := GetNonce(config)
	if err != nil {
		return err
	}

	authorisation := mKey.SignNonce(nonce)
	fmt.Println("Fetching metadata...")
	meta, err := ApiMetadata(config.BaseURL, config.FileID, authorisation)
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

	fmt.Println("Downloading " + config.RawURL)
	authorisation = mKey.SignNonce(meta.Nonce)
	err = ApiDownload(config.BaseURL, config.FileID, metadata.Name, meta.Size, authorisation, mKey)
	if err != nil {
		return err
	}

	return nil
}

func GetNonce(config *Config) ([]byte, error) {
	response, err := http.Head(fmt.Sprintf(config.BaseURL+"download/%s", config.FileID))

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

	nonce := strings.Replace(response.Header.Get("WWW-Authenticate"), "send-v1 ", "", 1)
	return base64.StdEncoding.DecodeString(nonce)
}
