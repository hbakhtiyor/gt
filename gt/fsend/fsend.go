package fsend

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

const (
	Debug = false
)

type Token struct {
	OwnerToken    string `json:"owner_token,omitempty"`
	Auth          string `json:"auth,omitempty"`
	DownloadLimit int    `json:"dlimit,omitempty"`
}

type Config struct {
	BaseURL   string
	FileID    string
	SecretKey []byte
	RawURL    string
}

type Options struct {
	Password      string
	IgnoreVersion bool
	DownloadLimit int
}

// DefaultClient is the default Client and is used by Put, and Options.
var DefaultClient = &http.Client{}
var config = BuildDefaultConfig()

// Splits a Send url into key, fileid and 'prefix' for the Send server
// Should handle any hostname, but will brake on key & id length changes
// e.g. https://send.firefox.com/download/c8ab3218f9/#39EL7SuqwWNYe4ISl2M06g
// baseURL == "https://send.firefox.com/"
// fileID == "c8ab3218f9"
// secretKey == "39EL7SuqwWNYe4ISl2M06g"
func NewConfigFromURL(url string) (*Config, error) {
	// TODO Validate with regex
	l := len(url)

	key := url[l-22:]
	rawKey, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode a key: %v", err)
	}

	c := &Config{
		BaseURL:   url[:l-43],
		FileID:    url[l-34 : l-24],
		SecretKey: rawKey,
		RawURL:    url,
	}

	return c, nil
}

func BuildDefaultConfig() *Config {
	return &Config{BaseURL: "https://send.firefox.com/"}
}
