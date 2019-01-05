package fsend

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

func GetInfo(fileInfo *FileInfo) (*FileInfo, error) {
	response, err := http.Get(fmt.Sprintf(fileInfo.BaseURL+"api/info/%s", fileInfo.FileID))

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("GetInfo: Error occurs while processing GET request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("GetInfo: Received body while processing GET request: %s\n", responseDump)
	}

	result := &FileInfo{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func Exists(fileInfo *FileInfo, key *ManagedKey) (*FileInfo, error) {
	response, err := http.Get(fmt.Sprintf(fileInfo.BaseURL+"api/exists/%s", fileInfo.FileID))

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("Exists: Error occurs while processing GET request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("Exists: Received body while processing GET request: %s\n", responseDump)
	}

	result := &FileInfo{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}
	nonce, err := ParseNonce(response.Header.Get("WWW-Authenticate"))
	if err != nil {
		return nil, err
	}
	key.Nonce = nonce

	return result, nil
}
