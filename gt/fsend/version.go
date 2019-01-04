package fsend

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
)

type Version struct {
	Version string
	Commit  string
	Source  string
}

var currentVersion = &Version{
	Version: "v2.6.1",
	Commit:  "7013f5c",
}

func GetVersion() (*Version, error) {
	response, err := http.Get(config.BaseURL + "__version__")

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("GetVersion: Error occurs while processing POST request: %s %s\n", config.BaseURL, responseDump)
		}
		return nil, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("GetVersion: Received body while processing POST request: %s %s\n", config.BaseURL, responseDump)
	}

	result := &Version{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func CheckVersion(ignoreVersion bool) (bool, error) {
	if ignoreVersion {
		return true, nil
	}

	if version, err := GetVersion(); err != nil {
		return false, err
	} else if version.Version == currentVersion.Version && version.Commit == currentVersion.Commit {
		return true, nil
	}

	return false, nil
}
