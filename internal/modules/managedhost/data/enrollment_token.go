package data

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

type EnrollmentTokens struct{}

func (EnrollmentTokens) New() (string, string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(value)
	for index := range value {
		value[index] = 0
	}
	return raw, hashEnrollmentToken(raw), nil
}

func (EnrollmentTokens) Hash(raw string) string {
	return hashEnrollmentToken(raw)
}

func hashEnrollmentToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
