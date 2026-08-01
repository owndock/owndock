package data

import "testing"

func TestTicketTokensAreRandomAndHashable(t *testing.T) {
	t.Parallel()
	tokens := TicketTokens{}
	first, firstHash, err := tokens.New()
	if err != nil {
		t.Fatalf("new first ticket: %v", err)
	}
	second, secondHash, err := tokens.New()
	if err != nil {
		t.Fatalf("new second ticket: %v", err)
	}
	if first == second || firstHash == secondHash {
		t.Fatal("tickets must be unique")
	}
	if tokens.Hash(first) != firstHash || len(firstHash) != 64 {
		t.Fatal("ticket hash is not stable SHA-256 hex")
	}
}
