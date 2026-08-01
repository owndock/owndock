package biz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const testSSHFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestRepositoryCredentialValidation(t *testing.T) {
	now := time.Unix(100, 0)
	ssh, err := NewRepositoryCredential(
		"credential-1", "project-1", "Deploy key", CredentialTypeSSHDeployKey,
		"", "secret://git-deploy-key", testSSHFingerprint, "user-1", now,
	)
	if err != nil || !ssh.Summary().SecretConfigured || ssh.Version != 1 {
		t.Fatalf("SSH credential = %+v, %v", ssh, err)
	}
	https, err := NewRepositoryCredential(
		"credential-2", "project-1", "Access token", CredentialTypeHTTPSAccessToken,
		"build-user", "secret://git-access-token", "", "user-1", now,
	)
	if err != nil || https.Username != "build-user" {
		t.Fatalf("HTTPS credential = %+v, %v", https, err)
	}
	invalid := []struct {
		credentialType CredentialType
		username       string
		secretRef      string
		fingerprint    string
	}{
		{CredentialTypeSSHDeployKey, "git", "secret://key", testSSHFingerprint},
		{CredentialTypeSSHDeployKey, "", "secret://key", "SHA256:short"},
		{CredentialTypeHTTPSAccessToken, "", "plain-token", ""},
		{CredentialTypeHTTPSAccessToken, "", "secret://token", testSSHFingerprint},
		{"password", "", "secret://password", ""},
	}
	for _, item := range invalid {
		if _, err := NewRepositoryCredential(
			"credential-3", "project-1", "Invalid", item.credentialType,
			item.username, item.secretRef, item.fingerprint, "user-1", now,
		); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("invalid credential %+v error = %v", item, err)
		}
	}
}

func TestSourceRepositoryAcceptsOnlyCredentialFreeHTTPSAndPinnedSSH(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name        string
		url         string
		fingerprint string
		protocol    RepositoryProtocol
	}{
		{"https", "https://git.example.com/team/api.git", "", RepositoryProtocolHTTPS},
		{"ssh URL", "ssh://git@git.example.com:2222/team/api.git", testSSHFingerprint, RepositoryProtocolSSH},
		{"scp-like", "git@git.example.com:team/api.git", testSSHFingerprint, RepositoryProtocolSSH},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := NewSourceRepository(
				"source-1", "project-1", "API", test.url, "main", "",
				test.fingerprint, "user-1", now,
			)
			if err != nil || source.Protocol != test.protocol || source.Status != SourceRepositoryStatusPending {
				t.Fatalf("source = %+v, %v", source, err)
			}
		})
	}
	for _, repositoryURL := range []string{
		"http://git.example.com/team/api.git",
		"https://token@git.example.com/team/api.git",
		"https://git.example.com/team/api.git?token=secret",
		"ssh://git:password@git.example.com/team/api.git",
		"git://git.example.com/team/api.git",
		"file:///tmp/repository",
		"/tmp/repository",
		"ext::command repository",
		"https://git.example.com/%2e%2e/private.git",
	} {
		if _, err := NewSourceRepository(
			"source-1", "project-1", "API", repositoryURL, "main", "",
			"", "user-1", now,
		); !errors.Is(err, ErrInvalidSourceRepository) {
			t.Errorf("repository URL %q error = %v", repositoryURL, err)
		}
	}
	if _, err := NewSourceRepository(
		"source-1", "project-1", "API", "git@git.example.com:team/api.git",
		"main", "", "", "user-1", now,
	); !errors.Is(err, ErrInvalidSourceRepository) {
		t.Fatalf("unpinned SSH error = %v", err)
	}
}

func TestSourceRepositoryRejectsUnsafeBranches(t *testing.T) {
	for _, branch := range []string{
		"", "../main", "refs/heads/main", "team/.hidden", "team/release.lock",
		"feature lock.lock", "main~1", strings.Repeat("a", 256),
	} {
		if _, err := NewSourceRepository(
			"source-1", "project-1", "API", "https://git.example.com/team/api.git",
			branch, "", "", "user-1", time.Unix(100, 0),
		); !errors.Is(err, ErrInvalidSourceRepository) {
			t.Errorf("branch %q error = %v", branch, err)
		}
	}
}

func TestCredentialProtocolCompatibility(t *testing.T) {
	ssh := RepositoryCredential{Type: CredentialTypeSSHDeployKey}
	https := RepositoryCredential{Type: CredentialTypeHTTPSAccessToken}
	if !CredentialSupportsProtocol(ssh, RepositoryProtocolSSH) ||
		CredentialSupportsProtocol(ssh, RepositoryProtocolHTTPS) ||
		!CredentialSupportsProtocol(https, RepositoryProtocolHTTPS) ||
		CredentialSupportsProtocol(https, RepositoryProtocolSSH) {
		t.Fatal("credential protocol compatibility is incorrect")
	}
}
