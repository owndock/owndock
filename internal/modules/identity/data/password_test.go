package data

import "testing"

func TestPasswordHasher(t *testing.T) {
	hasher, err := NewPasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hasher.Hash("a-valid-password")
	if err != nil {
		t.Fatal(err)
	}
	if !hasher.Verify("a-valid-password", encoded) {
		t.Fatal("valid password was rejected")
	}
	if hasher.Verify("wrong-password", encoded) {
		t.Fatal("wrong password was accepted")
	}
	if hasher.Verify("a-valid-password", "$argon2id$invalid") {
		t.Fatal("invalid encoded hash was accepted")
	}
}

func TestSessionTokens(t *testing.T) {
	raw, hash, err := (SessionTokens{}).New()
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || hash == "" || hash != (SessionTokens{}).Hash(raw) || raw == hash {
		t.Fatalf("invalid token pair raw=%q hash=%q", raw, hash)
	}
}
