package main

import (
	"crypto/rand"
	"encoding/base64"
)

func RandomString(s int) (string, error) {
	buf := make([]byte, s)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(buf), nil
}
