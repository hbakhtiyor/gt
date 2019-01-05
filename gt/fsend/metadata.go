package fsend

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"log"
)

type MetaData struct {
	IV   string `json:"iv"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func (md *MetaData) EncryptToString(key *ManagedKey) (string, error) {
	data, err := md.Encrypt(key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Encrypt file metadata with the same method as the Send browser/js client
func (md *MetaData) Encrypt(key *ManagedKey) ([]byte, error) {
	md.IV = base64.RawURLEncoding.EncodeToString(key.EncryptIV)

	b := bytes.NewBuffer(nil)
	if err := json.NewEncoder(b).Encode(md); err != nil {
		return nil, err
	}

	if Debug {
		log.Printf("EncryptMetadata: Generated json data: %s\n", b.String())
	}

	block, err := aes.NewCipher(key.MetaKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// WebcryptoAPI expects the gcm tag at the end of the ciphertext, return them concatenated
	return aesgcm.Seal(nil, key.MetaIV, b.Bytes(), nil), nil
}

// DecryptMetadata decrypts file metadata with the same method as the Send browser/js client
func DecryptMetadata(encMeta []byte, key *ManagedKey) (*MetaData, error) {
	block, err := aes.NewCipher(key.MetaKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	metadataBytes, err := aesgcm.Open(nil, key.MetaIV, encMeta, nil)
	if err != nil {
		return nil, err
	}

	metadata := &MetaData{}

	if err := json.Unmarshal(metadataBytes, metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}
