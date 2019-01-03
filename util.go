package main

import "net/url"

// IsValidURL checks if URL is valid or not.
func IsValidURL(rawURL string) bool {
	if r, err := url.ParseRequestURI(rawURL); err != nil || r.Host == "" {
		return false
	}
	return true
}
