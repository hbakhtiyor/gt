package fsend

import (
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

// Upload and encrypt data to Send.
func Upload(file *os.File, fileInfo *FileInfo) (*File, error) {
	metadata := &MetaData{
		Name: fileInfo.Name,
		Type: "application/octet-stream",
	}

	readBody, writeBody := io.Pipe()
	defer readBody.Close()

	form := multipart.NewWriter(writeBody)

	errChan := make(chan error, 1)
	go func() {
		defer writeBody.Close()

		part, err := form.CreateFormFile("file", fileInfo.Name)
		if err != nil {
			errChan <- fmt.Errorf("Failed to create form file: %v", err)
			return
		}
		// TODO
		// reader := bufio.NewReader(file)
		r, err := aesgcm.NewGcmEncryptReader(file, fileInfo.Key.EncryptKey, fileInfo.Key.EncryptIV, nil)
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

	req, err := http.NewRequest(http.MethodPost, fileInfo.BaseURL+"api/upload", readBody)
	if err != nil {
		<-errChan
		return nil, err
	}

	encMeta, err := metadata.EncryptToString(fileInfo.Key)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-File-Metadata", encMeta)
	req.Header.Set("Authorization", fileInfo.Key.AuthHeader())
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

	result.URL += "#" + fileInfo.Key.RawSecretKey()

	fileInfo.Owner = result.Owner
	if err := fileInfo.ParseURLAndUpdateKey(result.URL); err != nil {
		<-errChan
		return nil, err
	}

	return result, <-errChan
}

// UploadFile uploads a file to send and return the download URL
func UploadFile(filePath string, fileInfo *FileInfo, ignoreVersion bool) (*File, error) {
	if fileInfo == nil {
		fileInfo = &FileInfo{BaseURL: DefaultBaseURL}
	} else if fileInfo.BaseURL == "" {
		fileInfo.BaseURL = DefaultBaseURL
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	fileInfo.Size = stat.Size()
	if err := fileInfo.CheckRequirements(); err != nil {
		return nil, err
	}

	if status, err := CheckVersion(fileInfo, ignoreVersion); err != nil {
		return nil, err
	} else if !status {
		fmt.Println("\033[1;41m!!! Potentially incompatible server version !!!\033[0m")
	}

	key, err := NewManagedKey(fileInfo)
	if err != nil {
		return nil, err
	}
	fileInfo.Key = key

	fileInfo.Name = filepath.Base(file.Name())
	fmt.Printf("Uploading \"%s\"\n", fileInfo.Name)
	r, err := Upload(file, fileInfo)
	if err != nil {
		return nil, err
	}

	if fileInfo.Password != "" {
		fmt.Println("Setting password")
		if status, err := SetPassword(fileInfo); err != nil {
			return nil, err
		} else if status {
			fmt.Println("Successfully to set password")
		} else {
			fmt.Println("Failed to set password")
		}
	}

	if fileInfo.DownloadLimit != 0 {
		fmt.Println("Setting params")
		if status, err := SetParams(fileInfo); err != nil {
			return nil, err
		} else if status {
			fmt.Println("Successfully to set params")
		} else {
			fmt.Println("Failed to set params")
		}
	}

	return r, nil
}
