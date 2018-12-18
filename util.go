package main

import "net/url"

// IsValidURL checks if URL is valid or not.
func IsValidURL(rawURL string) bool {
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return false
	}
	return true
}
