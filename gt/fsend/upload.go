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
func Upload(file *os.File, key *ManagedKey) (*File, error) {
	fileName := filepath.Base(file.Name())

	metadata := &MetaData{
		Name: fileName,
		Type: "application/octet-stream",
	}

	encMeta, err := metadata.Encrypt(key)
	if err != nil {
		return nil, err
	}

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
		// TODO
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

	req, err := http.NewRequest(http.MethodPost, config.BaseURL+"api/upload", readBody)
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
			log.Printf("Upload: Error occurs while processing POST request: %s\n", responseDump)
		}
		<-errChan
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("Upload: Received body while processing POST request: %s\n", responseDump)
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
func UploadFile(filePath string, cfg *Config, options *Options) (*File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	if cfg != nil {
		config = cfg
	}
	if options == nil {
		options = &Options{}
	}

	if status, err := CheckVersion(options.IgnoreVersion); err != nil {
		return nil, err
	} else if !status {
		fmt.Println("\033[1;41m!!! Potentially incompatible server version !!!\033[0m")
	}

	fileName := filepath.Base(file.Name())

	key := NewManagedKey(nil, "", "")
	if key.Err() != nil {
		return nil, key.Err()
	}

	fmt.Printf("Uploading \"%s\"\n", fileName)
	r, err := Upload(file, key)
	if err != nil {
		return nil, err
	}

	if options.Password != "" {
		fmt.Println("Setting password")
		if status, err := SetPassword(r.URL, r.Owner, options.Password); err != nil {
			return nil, err
		} else if status {
			fmt.Println("Successfully to set password")
		} else {
			fmt.Println("Failed to set password")
		}
	}

	if options.DownloadLimit != 0 {
		fmt.Println("Setting params")
		if status, err := SetParams(r.Owner, options.DownloadLimit); err != nil {
			return nil, err
		} else if status {
			fmt.Println("Successfully to set params")
		} else {
			fmt.Println("Failed to set params")
		}
	}

	return r, nil
}
