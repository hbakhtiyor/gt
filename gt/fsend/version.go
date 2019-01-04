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

func CheckServerVersion(config *Config, option *Options) (bool, error) {
	if option.IgnoreVersion {
		return true, nil
	}

	response, err := http.Get(config.BaseURL + "__version__")

	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if Debug {
			responseDump, _ := httputil.DumpResponse(response, true)
			log.Printf("CheckServerVersion: Error occurs while processing POST request: %s %s\n", config.BaseURL, responseDump)
		}
		return false, errors.New(response.Status)
	}

	if Debug {
		responseDump, _ := httputil.DumpResponse(response, true)
		log.Printf("CheckServerVersion: Received body while processing POST request: %s %s\n", config.BaseURL, responseDump)
	}

	result := &Version{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return false, err
	}

	if result.Version == "v2.6.1" && result.Commit == "7013f5c" {
		return true, nil
	}

	return false, nil
}
