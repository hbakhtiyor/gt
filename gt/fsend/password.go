package fsend

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
)

// changes the authKey required to download a file hosted on a send server
func ApiPassword(service, fileID, ownerToken string, newAuthKey []byte) (bool, error) {
	service += "api/password/%s"
	auth := base64.RawURLEncoding.EncodeToString(newAuthKey)
	j := &Token{OwnerToken: ownerToken, Auth: auth}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return false, err
	}

	if Debug {
		log.Printf("ApiPassword: Generated json data: %s\n", b.String())
	}

	response, err := http.Post(
		fmt.Sprintf(service, fileID),
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
			log.Printf("ApiPassword: Error occurs while processing POST request: %s\n", responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("ApiPassword: Received body while processing POST request: %s\n", responseDump)
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

// set or change the password required to download a file hosted on a send server.
func SetPassword(url, ownerToken, password string) (bool, error) {
	config, err := NewConfigFromURL(url)
	if err != nil {
		return false, err
	}

	mKey := NewManagedKey(config.SecretKey, password, url)
	if mKey.Err() != nil {
		return false, mKey.Err()
	}

	return ApiPassword(config.BaseURL, config.FileID, ownerToken, mKey.AuthKey)
}
