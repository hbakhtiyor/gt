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

// set or change the password required to download a file hosted on a send server.
func SetPassword(fileInfo *FileInfo) (bool, error) {
	mKey := NewManagedKey(fileInfo)
	if mKey.Err() != nil {
		return false, mKey.Err()
	}

	auth := base64.RawURLEncoding.EncodeToString(mKey.AuthKey)
	j := &Token{OwnerToken: fileInfo.Owner, Auth: auth}
	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(j); err != nil {
		return false, err
	}

	if Debug {
		log.Printf("SetPassword: Generated json data: %s\n", b.String())
	}

	response, err := http.Post(
		fmt.Sprintf(fileInfo.BaseURL+"api/password/%s", fileInfo.FileID),
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
			log.Printf("SetPassword: Error occurs while processing POST request: %s\n", responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("SetPassword: Received body while processing POST request: %s\n", responseDump)
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
