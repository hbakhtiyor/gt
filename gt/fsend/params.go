package fsend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
)

// Change the download limit for a file hosted on a Send Server
func SetParams(ownerToken string, downloadLimit int) (bool, error) {
	j := &Token{OwnerToken: ownerToken, DownloadLimit: downloadLimit}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return false, err
	}

	if Debug {
		log.Printf("SetParams: Generated json data: %s\n", b.String())
	}

	response, err := http.Post(
		fmt.Sprintf(config.BaseURL+"api/params/%s", config.FileID),
		"application/json; charset=utf-8",
		b,
	)

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("SetParams: Error occurs while processing POST request: %s\n", responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("SetParams: Received body while processing POST request: %s\n", responseDump)
	}

	result, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	if string(result) == "OK" {
		return true, nil
	}

	return false, nil
}
