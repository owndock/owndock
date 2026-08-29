package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnrollmentTokenFileRequiresPrivateRegularFile(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	value := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGH_12345678\n")
	if err := os.WriteFile(tokenPath, value, 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := readEnrollmentTokenFile(tokenPath)
	if err != nil || string(token) != string(value) {
		t.Fatalf("token = %q, err = %v", token, err)
	}
	clearEnrollmentSecret(token)
	if err := os.Chmod(tokenPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnrollmentTokenFile(tokenPath); err == nil {
		t.Fatal("group-readable enrollment token was accepted")
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "token-link")
	if err := os.Symlink(tokenPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnrollmentTokenFile(linkPath); err == nil {
		t.Fatal("symbolic-link enrollment token was accepted")
	}
}

func TestReadEnrollmentTokenFileRejectsRelativeAndOversizedFiles(t *testing.T) {
	if _, err := readEnrollmentTokenFile("token"); err == nil {
		t.Fatal("relative enrollment token path was accepted")
	}
	path := filepath.Join(t.TempDir(), "token")
	value := make([]byte, maximumEnrollmentTokenFileBytes+1)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnrollmentTokenFile(path); err == nil {
		t.Fatal("oversized enrollment token was accepted")
	}
}
