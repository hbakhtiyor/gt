package fsend

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

type Meta struct {
	MetaData      string `json:"metadata"`
	FinalDownload bool   `json:"finalDownload"`
	Size          int64  `json:"size,string"`
	TTL           int64  `json:"ttl"`
	Nonce         []byte
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
