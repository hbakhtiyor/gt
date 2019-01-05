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

	aesgcm "github.com/hbakhtiyor/openssl_gcm"
)

// Given a Send url, download and return the encrypted data and metadata
func Download(meta *Meta, key *ManagedKey) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(config.BaseURL+"api/download/%s", config.FileID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "send-v1 "+base64.RawURLEncoding.EncodeToString(key.SignNonce(meta.Nonce)))
	response, err := DefaultClient.Do(req)

	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("Download: Error occurs while processing POST request: %s\n", responseDump)
		}
		return errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("Download: Received body while processing POST request: %s\n", responseDump)
	}

	reader := bufio.NewReader(response.Body)
	// https://www.w3.org/TR/WebCryptoAPI/#aes-gcm-operations
	r, err := aesgcm.NewGcmDecryptReader(reader, key.EncryptKey, key.EncryptIV, nil, meta.Size)
	if err != nil {
		return err
	}

	file, err := os.Create(meta.MetaData.Name)
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
	cfg, err := NewConfigFromURL(url)
	if err != nil {
		return err
	}
	config = cfg
	if options == nil {
		options = &Options{}
	}

	if status, err := CheckVersion(options.IgnoreVersion); err != nil {
		return err
	} else if !status {
		return errors.New("Potentially incompatible server version, use --ignore-version to disable version checks")
	}

	fmt.Println("Checking if file exists...")

	if info, err := Exists(); err != nil {
		return err
	} else if info.PasswordRequired && options.Password == "" {
		fmt.Scanln("A password is required, please enter it now", &options.Password)
	} else if !info.PasswordRequired && options.Password != "" {
		fmt.Println("A password was provided but none is required, ignoring...")
	}

	mKey := NewManagedKey(config.SecretKey, options.Password, config.RawURL)
	if mKey.Err() != nil {
		return mKey.Err()
	}

	nonce, err := GetNonce()
	if err != nil {
		return err
	}

	fmt.Println("Fetching metadata...")
	meta, err := GetMetadata(nonce, mKey)
	if err != nil {
		return err
	}

	mKey.EncryptIV, err = base64.RawURLEncoding.DecodeString(meta.MetaData.IV)
	if err != nil {
		return err
	}

	fmt.Printf("The file wishes to be called '%s' and is %d bytes in size\n", meta.MetaData.Name, meta.Size-16)

	fmt.Println("Downloading " + config.RawURL)
	err = Download(meta, mKey)
	if err != nil {
		return err
	}

	return nil
}

func GetNonce() ([]byte, error) {
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

	return ParseNonce(response.Header.Get("WWW-Authenticate"))
}
