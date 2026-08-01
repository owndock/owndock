package data

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const ticketEntropyBytes = 32

type TicketTokens struct{}

func (TicketTokens) New() (string, string, error) {
	buffer := make([]byte, ticketEntropyBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", "", fmt.Errorf("generate terminal ticket: %w", err)
	}
	ticket := base64.RawURLEncoding.EncodeToString(buffer)
	return ticket, TicketTokens{}.Hash(ticket), nil
}

func (TicketTokens) Hash(ticket string) string {
	digest := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(digest[:])
}
