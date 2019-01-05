package fsend

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

type Meta struct {
	Data          string `json:"metadata"`
	FinalDownload bool   `json:"finalDownload"`
	Size          int64  `json:"size,string"`
	TTL           int64  `json:"ttl"`
	MetaData      *MetaData
}

func GetMetadata(fileInfo *FileInfo) (*Meta, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(fileInfo.BaseURL+"api/metadata/%s", fileInfo.FileID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fileInfo.Key.AuthHeader())
	response, err := DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("GetMetadata: Error occurs while processing POST request: %s\n", responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("GetMetadata: Received body while processing POST request: %s\n", responseDump)
	}

	result := &Meta{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	nonce, err := ParseNonce(response.Header.Get("WWW-Authenticate"))
	if err != nil {
		return nil, err
	}
	fileInfo.Key.Nonce = nonce

	encMeta, err := base64.RawURLEncoding.DecodeString(result.Data)
	if err != nil {
		return nil, err
	}

	metadata, err := DecryptMetadata(encMeta, fileInfo.Key)
	if err != nil {
		return nil, err
	}
	result.MetaData = metadata
	fileInfo.Name = metadata.Name
	fileInfo.Size = result.Size

	fileInfo.Key.EncryptIV, err = base64.RawURLEncoding.DecodeString(metadata.IV)
	if err != nil {
		return nil, err
	}

	return result, nil
}
