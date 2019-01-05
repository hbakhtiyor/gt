package fsend

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

const (
	Debug = false
)

type Token struct {
	OwnerToken    string `json:"owner_token,omitempty"`
	Auth          string `json:"auth,omitempty"`
	DownloadLimit int    `json:"dlimit,omitempty"`
}

type FileInfo struct {
	BaseURL          string
	FileID           string
	SecretKey        []byte
	RawURL           string
	Password         string
	Name             string
	Size             int64
	Owner            string
	PasswordRequired bool  `json:"password,omitempty"`
	DownloadLimit    int   `json:"dlimit,omitempty"`
	DownloadTotal    int   `json:"dtotal,omitempty"`
	TTL              int64 `json:"ttl,omitempty"`
}

// DefaultClient is the default Client and is used by Put, and Options.
var DefaultClient = &http.Client{}
var DefaultBaseURL = "https://send.firefox.com/"

// ParseURL parses a Send url into key, fileid and 'prefix' for the Send server
// Should handle any hostname, but will brake on key & id length changes
// e.g. https://send.firefox.com/download/c8ab3218f9/#39EL7SuqwWNYe4ISl2M06g
// baseURL == "https://send.firefox.com/"
// fileID == "c8ab3218f9"
// secretKey == "39EL7SuqwWNYe4ISl2M06g"
func (fi *FileInfo) ParseURL(url string) error {
	// TODO Validate with regex
	l := len(url)

	key := url[l-22:]
	rawKey, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("Failed to decode a key: %v", err)
	}

	fi.BaseURL = url[:l-43]
	fi.FileID = url[l-34 : l-24]
	fi.SecretKey = rawKey
	fi.RawURL = url

	return nil
}

func (fi *FileInfo) CheckRequirements() error {
	if fi.DownloadLimit > 20 || fi.DownloadLimit < 0 {
		return fmt.Errorf("Wrong range of download limit: %d, must be 1-20", fi.DownloadLimit)
	}
	// TODO plus 16 bytes mac tag
	if fi.Size > 1024*1024*1024 {
		return fmt.Errorf("Exceed file size: %d, must be max 1gb", fi.Size)
	}
	if len(fi.Password) > 32 {
		return fmt.Errorf("Maximum length of password is 32: %d", len(fi.Password))
	}
	return nil
}

func ParseNonce(header string) ([]byte, error) {
	r := strings.Fields(header)
	if len(r) < 2 {
		return nil, fmt.Errorf("Failed to parse a nonce: %v", header)
	}
	nonce, err := base64.StdEncoding.DecodeString(r[1])
	if err != nil {
		return nil, fmt.Errorf("Failed to decode a nonce: %v", err)
	}
	return nonce, nil
}
