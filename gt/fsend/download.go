package fsend

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	aesgcm "github.com/hbakhtiyor/openssl_gcm"
)

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
