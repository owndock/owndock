package data

import "testing"

func TestEnrollmentTokensStoreOnlyOneWayHash(t *testing.T) {
	raw, hash, err := (EnrollmentTokens{}).New()
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || hash == "" || raw == hash ||
		(EnrollmentTokens{}).Hash(raw) != hash {
		t.Fatalf("raw/hash contract was not preserved")
	}
	second, _, err := (EnrollmentTokens{}).New()
	if err != nil {
		t.Fatal(err)
	}
	if second == raw {
		t.Fatal("enrollment token was reused")
	}
}
