package data

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type BuildTriggerTokens struct{}

func (BuildTriggerTokens) New() (string, string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", "", fmt.Errorf("generate build trigger token: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(value)
	return raw, (BuildTriggerTokens{}).Hash(raw), nil
}

func (BuildTriggerTokens) Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
