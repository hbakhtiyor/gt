package fsend

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

type FileInfo struct {
	PasswordRequired bool  `json:"password,omitempty"`
	DownloadLimit    int   `json:"dlimit,omitempty"`
	DownloadTotal    int   `json:"dtotal,omitempty"`
	TTL              int64 `json:"ttl,omitempty"`
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
