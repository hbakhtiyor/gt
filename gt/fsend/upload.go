package fsend

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"

	aesgcm "github.com/hbakhtiyor/openssl_gcm"
)

type File struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Owner string `json:"owner"`
}

// Uploads data to Send.
func ApiUpload(service string, file *os.File, encMeta []byte, key *ManagedKey, fileName string) (*File, error) {
	service += "api/upload"

	readBody, writeBody := io.Pipe()
	defer readBody.Close()

	form := multipart.NewWriter(writeBody)

	errChan := make(chan error, 1)
	go func() {
		defer writeBody.Close()

		part, err := form.CreateFormFile("file", fileName)
		if err != nil {
			errChan <- fmt.Errorf("Failed to create form file: %v", err)
			return
		}

		// reader := bufio.NewReader(file)
		r, err := aesgcm.NewGcmEncryptReader(file, key.EncryptKey, key.EncryptIV, nil)
		if err != nil {
			errChan <- err
			return
		}

		if _, err = io.Copy(part, r); err != nil {
			errChan <- err
			return
		}
		errChan <- form.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, service, readBody)
	if err != nil {
		<-errChan
		return nil, err
	}
	req.Header.Set("X-File-Metadata", base64.RawURLEncoding.EncodeToString(encMeta))
	req.Header.Set("Authorization", "send-v1 "+base64.RawURLEncoding.EncodeToString(key.AuthKey))
	req.Header.Set("Content-Type", form.FormDataContentType())
	response, err := DefaultClient.Do(req)

	if err != nil {
		<-errChan
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("ApiUpload: Error occurs while processing POST request: %s\n", responseDump)
		}
		<-errChan
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiUpload: Received body while processing POST request: %s\n", responseDump)
	}

	result := &File{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		<-errChan
		return nil, err
	}

	result.URL += "#" + key.RawSecretKey()

	return result, <-errChan
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
