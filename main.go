package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"net/url"
	"os"
	s "strings"
)

func main() {
	args := os.Args[1:]

	secret := args[0]
	salt := args[1]
	cookie := args[2]

	key := DeriveKey(secret, salt)
	data, iv, err := CookieData(cookie)
	if err != nil {
		fmt.Println("failed to extract cookie")
		return
	}

	msg, err := Decrypt(key, data, iv)
	if err != nil {
		fmt.Println("failed to decrypt")
		return
	}

	fmt.Println(string(msg))

	auth, _ := Authenticated(msg)
	fmt.Println(auth)
}

func CookieData(cookie string) ([]byte, []byte, error) {
	rawCookie, err := url.QueryUnescape(cookie)
	if err != nil {
		return nil, nil, err
	}

	cookieParts := s.Split(rawCookie, "--")
	if len(cookieParts) != 2 {
		return nil, nil, err
	}

	encryptedBlob, err := b64.StdEncoding.DecodeString(cookieParts[0])
	if err != nil {
		return nil, nil, err
	}

	encryptedParts := s.Split(string(encryptedBlob), "--")
	if len(encryptedParts) != 2 {
		return nil, nil, err
	}

	data, err := b64.StdEncoding.DecodeString(encryptedParts[0])
	if err != nil {
		return nil, nil, err
	}

	iv, err := b64.StdEncoding.DecodeString(encryptedParts[1])
	if err != nil {
		return nil, nil, err
	}

	return []byte(data), []byte(iv), nil
}

func DeriveKey(secret string, salt string) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), 1000, 32, sha1.New)
}

func Decrypt(key []byte, data []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	msg := make([]byte, len([]byte(data)))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(msg, data)

	length := len(msg)
	unpadding := int(msg[length-1])

	return msg[:(length - unpadding)], nil
}

func Authenticated(b []byte) (bool, error) {
	var f interface{}
	err := json.Unmarshal(b, &f)
	if err != nil {
		return false, err
	}

	for k, _ := range f.(map[string]interface{}) {
		if k == "warden.user.user.key" {
			return true, nil
		}
	}

	return false, nil
}
