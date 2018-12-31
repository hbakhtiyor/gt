package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestSplitKeyURL(t *testing.T) {
	rawURL := "https://send.firefox.com/download/c8ab3218f9/#39EL7SuqwWNYe4ISl2M06g"
	service, URLID, key := SplitKeyURL(rawURL)
	expectedService := "https://send.firefox.com/"
	expectedURLID := "c8ab3218f9"
	expectedKey := "39EL7SuqwWNYe4ISl2M06g"

	if service != expectedService || URLID != expectedURLID || key != expectedKey {
		t.Fatalf("SplitKeyURL() = %v, %v, %v, want %v, %v, %v", service, URLID, key, expectedService, expectedURLID, expectedKey)
	}
}

func TestUnPaddedURLSafe64Encode(t *testing.T) {
	key := []byte("\xdf\xd1\x0b\xed+\xaa\xc1cX{\x82\x12\x97c4\xea")
	expected := "39EL7SuqwWNYe4ISl2M06g"
	if observed := UnPaddedURLSafe64Encode(key); observed != expected {
		t.Fatalf("UnPaddedURLSafe64Encode(%v) = %v, want %v", key, observed, expected)
	}
}

func TestUnpaddedURLSafe64Decode(t *testing.T) {
	jwk := "39EL7SuqwWNYe4ISl2M06g"
	expected := []byte("\xdf\xd1\x0b\xed+\xaa\xc1cX{\x82\x12\x97c4\xea")
	observed, err := UnPaddedURLSafe64Decode(jwk)

	if err != nil {
		t.Fatalf("Unexpected error from UnPaddedURLSafe64Decode: %v", err)
	}

	if !bytes.Equal(expected, observed) {
		t.Fatalf("UnPaddedURLSafe64Decode(%v) = %v, want %v", jwk, observed, expected)
	}
}

func TestSecretKeysKnownGoodKeys(t *testing.T) {
	// test data was obtained by adding debug messages to {"commit":"188b28f","source":"https://github.com/mozilla/send/","version":"v1.2.4"}
	expected := &SecretKeys{
		SecretKey:  []byte("q\xd94B\xa1&\x03\xa5<8\xddk\xee.\xea&"),
		EncryptKey: []byte("\xc4\x979\xaa\r\n\xeb\xc7\xa16\xa4%\xfd\xa6\x91\t"),
		AuthKey:    []byte("5\xa0@\xef\xd0}f\xc7o{S\x05\xe4,\xe1\xe4\xc2\x8cE\xa1\xfat\xc1\x11\x94e[L\x89%\xf5\x8b\xfc\xb5\x9b\x87\x9a\xf2\xc3\x0eKt\xdeL\xab\xa4\xa6%t\xa6\"4\r\x07\xb3\xf5\xf6\xb9\xec\xcc\x08\x80}\xea"),
		MetaKey:    []byte("\xd5\x9dF\x05\x86\x1a\xfdi\xaeK+\xe7\x8e\x7f\xf2\xfd"),
		Password:   "drowssap",
		URL:        "http://192.168.254.87:1443/download/fa4cd959de/#cdk0QqEmA6U8ON1r7i7qJg",
		NewAuthKey: []byte("U\x02F\x19\x1b\xc1W\x03q\x86q\xbc\xe7\x84WB\xa7(\x0f\x8a\x0f\x17\\\xb9y\xfaZT\xc1\xbf\xb2\xd48\x82\xa7\t\x9a\xb1\x1e{cg\n\xc6\x995+\x0f\xd3\xf4\xb3kd\x93D\xca\xf9\xa1(\xdf\xcb_^\xa3"),
	}

	// generate all keys
	observed, err := NewSecretKeys(expected.SecretKey, expected.Password, expected.URL)

	if err != nil {
		t.Fatalf("Unexpected error from NewSecretKeys: %v", err)
	}

	if !bytes.Equal(expected.SecretKey, observed.SecretKey) {
		t.Fatalf("SecretKey = %v, want %v", observed.SecretKey, expected.SecretKey)
	}
	if !bytes.Equal(expected.EncryptKey, observed.EncryptKey) {
		t.Fatalf("EncryptKey = %v, want %v", observed.EncryptKey, expected.EncryptKey)
	}
	if !bytes.Equal(expected.AuthKey, observed.AuthKey) {
		t.Fatalf("AuthKey = %v, want %v", observed.AuthKey, expected.AuthKey)
	}
	if !bytes.Equal(expected.MetaKey, observed.MetaKey) {
		t.Fatalf("MetaKey = %v, want %v", observed.MetaKey, expected.MetaKey)
	}
	if expected.Password != observed.Password {
		t.Fatalf("Password = %v, want %v", observed.Password, expected.Password)
	}
	if expected.URL != observed.URL {
		t.Fatalf("URL = %v, want %v", observed.URL, expected.URL)
	}
	if !bytes.Equal(expected.NewAuthKey, observed.NewAuthKey) {
		t.Fatalf("NewAuthKey = %v, want %v", observed.NewAuthKey, expected.NewAuthKey)
	}

}

func TestSecretKeysRandomKeyLengths(t *testing.T) {
	// test key generation without providing the master secretKey
	observed, err := NewSecretKeys(nil, "", "")

	if err != nil {
		t.Fatalf("Unexpected error from NewSecretKeys: %v", err)
	}

	if len(observed.SecretKey) != 16 {
		t.Fatalf("SecretKey = %v, want %v", len(observed.SecretKey), 16)
	}
	if len(observed.EncryptKey) != 16 {
		t.Fatalf("EncryptKey = %v, want %v", len(observed.EncryptKey), 16)
	}
	if len(observed.EncryptIV) != 12 {
		t.Fatalf("EncryptIV = %v, want %v", len(observed.EncryptIV), 12)
	}
	if len(observed.AuthKey) != 64 {
		t.Fatalf("AuthKey = %v, want %v", len(observed.AuthKey), 64)
	}
	if len(observed.MetaKey) != 16 {
		t.Fatalf("MetaKey = %v, want %v", len(observed.MetaKey), 16)
	}
	if len(observed.DeriveNewAuthKey("drowssap", "https://send.server/download/aFileID/#someSecretKey")) != 64 {
		t.Fatalf("NewAuthKey = %v, want %v", len(observed.NewAuthKey), 64)
	}
}

func TestEncryptMetadata(t *testing.T) {

	keys := &SecretKeys{
		MetaKey:   []byte("\x92\x0b*JH+i>\x1f\x0ey\x90 l\x99\xdb"),
		MetaIV:    []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		EncryptIV: []byte("\xa9\x1b\x80\x7fzY\xb4\xb9\x94\xaas\xc0"),
	}

	observed, err := EncryptMetadata(keys, "testfile", "")

	expected := []byte("V\xad`(\xf8\xb3\x84Y\xfb@ \xb9\xb7\xd8)\x8b\xb51y\xed\xb1\xc2\xc0\x9b\xb6:\t\xda\x84\xc5\x12\xa4\xf3b\x00\x83\x07\xae\x81\xf1%\xc3CM\x04\xbd\xae\x9d\xaf\xc2\xd4VF5\xdb\xe7\xf0l\xa1\xe6IN\xeb\xf3:\xbe\xc3j6F&\x8b\xd75\x00\xce{\xfb\xc1)\x8f\xe4\x8c\xac\xd0\xc2\xd5_\xd7\xa9\xe8]\x13B\x00\xdd\x89!")

	if err != nil {
		t.Fatalf("Unexpected error from EncryptMetadata: %v", err)
	}

	if !bytes.Equal(expected, observed) {
		t.Fatalf("EncryptMetadata() = %v, want %v", observed, expected)
	}
}

func TestSignNonce(t *testing.T) {
	key := []byte("\x1d\x9d\x82^V\xf45C\xc0B\x81\xcbq\x1e>\x1a\x02*\x954`ot\x01\x8b0\xcaw\x81M\xceS*\xa5\xf8\x80h\xb4\xde7\xbe\x88\x83ll\xf8\x11~J\xd5*\x05\xe1a\x9e\x95Kn/\x82H\xd4B\xfa")
	nonce := []byte("\xb3\x16\xc4\x7fP\xf3\xc9\xaa\x17H\x8eY\xb8{\xf3&")
	// test for expected output
	expected := []byte("A\xde6*\x1c\x05\x04\x94\xa8U+\x97\xcd\xf62\xa0\x89;\xee\x00E\x05\xed\x84^\xfdB\x82\x85lM\xf8")

	if observed := SignNonce(key, nonce); !bytes.Equal(expected, observed) {
		t.Fatalf("SignNonce() = %v, want %v", observed, expected)
	}
}

func TestEncryptFile(t *testing.T) {

	keys := &SecretKeys{
		EncryptKey: []byte("\x81\xbe^\t\xc1\x11Wa\x03\xa8PvX\xd4x\x91"),
		EncryptIV:  []byte("\x81\xbe^\t\xc1\x11Wa\x03\xa8Pv"),
	}

	file, err := os.Open("testdata")
	if err != nil {
		t.Fatalf("Unexpected error from Open: %v", err)
	}

	encFile, err := EncryptFile(file, keys)
	if err != nil {
		t.Fatalf("Unexpected error from EncryptFile: %v", err)
	}

	fmt.Println(encFile.Name())
	// check the aes-gcm tag
	encFile.Seek(-16, 2)
	b := make([]byte, 16)
	n, err := encFile.Read(b)
	expected := []byte("L\x1f\xf6\xe3\r\x94L\xd0 \x9b\\\xd1\xaf\xe3>K")
	if !bytes.Equal(b[:n], expected) {
		t.Fatalf("EncryptFile() = %v, want %v", b, expected)
	}

	encFile.Seek(0, 0)
	c := make([]byte, 1024*1024)
	n, err = encFile.Read(c)
	sum := sha256.Sum256(c[:n])
	expected1 := "cd55109593e01d4aec4a81ddcaf81d246dc9a17b7776c72cc1f8eead4d5457c0"
	if observed := hex.EncodeToString(sum[:32]); observed != expected1 {
		t.Fatalf("%v, want %v", observed, expected1)
	}
}

// Creates and returns the path to the 1MB test file
func TestData1M(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "temp")
	if err != nil {
		t.Fatalf(err.Error())
	}

	defer os.Remove(tempFile.Name()) // clean up

	data := make([]byte, 1024*1024)
	for i := 0; i < 1024*1024; i++ {
		data[i] = 174
	}

	sum := sha256.Sum256(data)
	expected := "c957c34dad5b9b74e8a7ef2c4867b3a6163f2b2020ceb87cd78fa54fce1037de"
	if observed := hex.EncodeToString(sum[:32]); observed != expected {
		t.Fatalf("%v, want %v", observed, expected)
	}

	tempFile.Write(data)

	if err := tempFile.Close(); err != nil {
		t.Fatalf(err.Error())
	}
}
