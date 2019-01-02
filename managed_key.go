package main

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type ManagedKey struct {
	SecretKey  []byte
	EncryptKey []byte
	EncryptIV  []byte
	AuthKey    []byte
	MetaKey    []byte
	Password   string
	RawURL     string
	NewAuthKey []byte
	MetaIV     []byte
}

func NewManagedKey(secretKey []byte, password string, rawURL string) (*ManagedKey, error) {
	key := &ManagedKey{
		SecretKey: secretKey,
		Password:  password,
		RawURL:    rawURL,
	}

	if key.SecretKey == nil {
		key.SecretKey, _ = key.RandomSecretKey()
	}

	key.EncryptKey, _ = key.DeriveEncryptKey()
	key.EncryptIV, _ = key.RandomEncryptIV()
	key.AuthKey, _ = key.DeriveAuthKey()
	key.MetaKey, _ = key.DeriveMetaKey()
	key.MetaIV = make([]byte, 12) // Send uses a 12 byte all-zero IV when encrypting metadata
	if password != "" && rawURL != "" {
		key.DeriveNewAuthKey(password, rawURL)
	}

	return key, nil
}

func (s *ManagedKey) RandomSecretKey() ([]byte, error) {
	b := make([]byte, 16)
	n, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b[:n], nil
}

func (s *ManagedKey) RandomEncryptIV() ([]byte, error) {
	b := make([]byte, 12)
	n, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b[:n], nil
}

func (s *ManagedKey) DeriveEncryptKey() ([]byte, error) {
	hkdf := hkdf.New(sha256.New, s.SecretKey, nil, []byte("encryption"))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *ManagedKey) DeriveAuthKey() ([]byte, error) {
	hkdf := hkdf.New(sha256.New, s.SecretKey, nil, []byte("authentication"))
	key := make([]byte, 64)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *ManagedKey) DeriveMetaKey() ([]byte, error) {
	hkdf := hkdf.New(sha256.New, s.SecretKey, nil, []byte("metadata"))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}
func (s *ManagedKey) DeriveNewAuthKey(password string, rawURL string) []byte {
	s.Password = password
	s.RawURL = rawURL
	s.NewAuthKey = pbkdf2.Key([]byte(password), []byte(rawURL), 100, 64, sha256.New)
	return s.NewAuthKey
}
