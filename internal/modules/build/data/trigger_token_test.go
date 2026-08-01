package data

import "testing"

func TestBuildTriggerTokens(t *testing.T) {
	raw, hash, err := (BuildTriggerTokens{}).New()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 43 || len(hash) != 64 || hash != (BuildTriggerTokens{}).Hash(raw) || raw == hash {
		t.Fatalf("unexpected token lengths or hash: raw=%q hash=%q", raw, hash)
	}
}
