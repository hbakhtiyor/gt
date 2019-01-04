package fsend

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	MetaIV     []byte
	err        error
}

func NewManagedKey(secretKey []byte, password string, rawURL string) *ManagedKey {
	key := &ManagedKey{SecretKey: secretKey}
	key.MetaIV = make([]byte, 12) // Send uses a 12 byte all-zero IV when encrypting metadata

	return key.
		RandomSecretKey().
		DeriveEncryptKey().
		RandomEncryptIV().
		DeriveAuthKey(password, rawURL).
		DeriveMetaKey()
}

func (key *ManagedKey) RawSecretKey() string {
	return base64.RawURLEncoding.EncodeToString(key.SecretKey)
}

func (key *ManagedKey) RandomSecretKey() *ManagedKey {
	if key.err != nil {
		return key
	}

	if key.SecretKey == nil {
		b := make([]byte, 16)
		n, err := rand.Read(b)
		if err != nil {
			key.err = err
			return key
		}

		key.SecretKey = b[:n]
	}

	return key
}

func (key *ManagedKey) RandomEncryptIV() *ManagedKey {
	if key.err != nil {
		return key
	}

	b := make([]byte, 12)
	n, err := rand.Read(b)
	if err != nil {
		key.err = err
		return key
	}

	key.EncryptIV = b[:n]

	return key
}

func (key *ManagedKey) DeriveEncryptKey() *ManagedKey {
	if key.err != nil {
		return key
	}

	hkdf := hkdf.New(sha256.New, key.SecretKey, nil, []byte("encryption"))
	rawKey := make([]byte, 16)
	n, err := io.ReadFull(hkdf, rawKey)
	if err != nil {
		key.err = err
		return key
	}

	key.EncryptKey = rawKey[:n]

	return key
}

func (key *ManagedKey) DeriveAuthKey(password string, rawURL string) *ManagedKey {
	if key.err != nil {
		return key
	}

	if password != "" && rawURL != "" {
		key.AuthKey = pbkdf2.Key([]byte(password), []byte(rawURL), 100, 64, sha256.New)
	} else {
		hkdf := hkdf.New(sha256.New, key.SecretKey, nil, []byte("authentication"))
		rawKey := make([]byte, 64)
		n, err := io.ReadFull(hkdf, rawKey)
		if err != nil {
			key.err = err
			return key
		}

		key.AuthKey = rawKey[:n]
	}

	return key
}

func (key *ManagedKey) DeriveMetaKey() *ManagedKey {
	if key.err != nil {
		return key
	}

	hkdf := hkdf.New(sha256.New, key.SecretKey, nil, []byte("metadata"))
	rawKey := make([]byte, 16)
	n, err := io.ReadFull(hkdf, rawKey)
	if err != nil {
		key.err = err
		return key
	}

	key.MetaKey = rawKey[:n]

	return key
}

// Sign the server nonce from the WWW-Authenticate header with an authKey
func (key *ManagedKey) SignNonce(nonce []byte) []byte {
	mac := hmac.New(sha256.New, key.AuthKey)
	mac.Write(nonce)
	return mac.Sum(nil)
}

func (key *ManagedKey) Err() error {
	return key.err
}
