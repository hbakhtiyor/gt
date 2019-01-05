package fsend

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	aesgcm "github.com/hbakhtiyor/openssl_gcm"
	"golang.org/x/crypto/ssh/terminal"
)

// Download given a Send url, and decrypt the encrypted data.
func Download(fileInfo *FileInfo) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(fileInfo.BaseURL+"api/download/%s", fileInfo.FileID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fileInfo.Key.AuthHeader())
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
	r, err := aesgcm.NewGcmDecryptReader(reader, fileInfo.Key.EncryptKey, fileInfo.Key.EncryptIV, nil, fileInfo.Size)
	if err != nil {
		return err
	}

	file, err := os.Create(fileInfo.Name)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = io.Copy(file, r); err != nil {
		return err
	}

	return nil
}

func DownloadFile(url, password string, ignoreVersion bool) error {
	fileInfo, err := NewFileInfo(url, password)
	if err != nil {
		return err
	}

	if status, err := CheckVersion(fileInfo, ignoreVersion); err != nil {
		return err
	} else if !status {
		return errors.New("Potentially incompatible server version, use --ignore-version to disable version checks")
	}

	fmt.Println("Checking if file exists...")
	if info, err := Exists(fileInfo); err != nil {
		return err
	} else if info.PasswordRequired && fileInfo.Password == "" {
		fmt.Print("A password is required, please enter it now: ")
		password, err := terminal.ReadPassword(0)
		if err != nil {
			return err
		}
		fmt.Println()
		if err := fileInfo.SetPassword(string(password)); err != nil {
			return err
		}
	} else if !info.PasswordRequired && fileInfo.Password != "" {
		fmt.Println("A password was provided but none is required, ignoring...")
	}

	fmt.Println("Fetching metadata...")
	_, err = GetMetadata(fileInfo)
	if err != nil {
		return err
	}

	fmt.Printf("The file wishes to be called '%s' and is %d bytes in size\n", fileInfo.Name, fileInfo.Size-16)
	fmt.Println("Downloading " + fileInfo.RawURL)
	err = Download(fileInfo)
	if err != nil {
		return err
	}

	return nil
}
