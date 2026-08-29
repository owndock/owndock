package data

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type signingEnvironmentProbe struct {
	values map[string][]byte
	err    error
}

func (p *signingEnvironmentProbe) ResolveSigningEnvironment(context.Context, string, string,
	biz.SigningKeyProvider) (map[string][]byte, error) {
	return p.values, p.err
}

func TestCosignSignerUsesKMSReferenceAndOnlyExplicitProviderEnvironment(t *testing.T) {
	directory := t.TempDir()
	capture := filepath.Join(directory, "capture")
	executable := filepath.Join(directory, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + capture + ".args'\n" +
		"previous=''\nfor argument in \"$@\"; do if [ \"$previous\" = '--signing-config' ]; then cp \"$argument\" '" + capture + ".signing-config'; fi; previous=\"$argument\"; done\n" +
		"printf '%s' \"$VAULT_ADDR|$VAULT_TOKEN|$UNRELATED_SECRET\" > '" + capture + ".env'\n" +
		"cp \"$DOCKER_CONFIG/config.json\" '" + capture + ".docker'\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	environment := &signingEnvironmentProbe{values: map[string][]byte{
		"VAULT_ADDR": []byte("https://vault.example.com"), "VAULT_TOKEN": []byte("vault-secret-sentinel")}}
	credentials := &credentialCaptureProvider{username: "signer", password: "registry-secret-sentinel"}
	signer, err := NewCosignSigner(CosignSignerOptions{Executable: executable,
		ExpectedVersion: "3.0.6", Credentials: credentials, SigningEnvironment: environment,
		TemporaryRoot: directory})
	if err != nil {
		t.Fatal(err)
	}
	request := biz.SignatureSigningRequest{ProjectID: "project-1", ProfileID: "profile-1",
		RegistryCredentialID: "registry-1", RegistryRepository: "registry.example.com/team/api",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), KeyReference: "hashivault://release-signing-key"}
	result, err := signer.SignSignature(t.Context(), request)
	if err != nil || result.Provider != biz.SigningKeyVault || !strings.HasPrefix(result.KeyReferenceFingerprint, "sha256:") {
		t.Fatalf("SignSignature() = %+v, %v", result, err)
	}
	arguments, _ := os.ReadFile(capture + ".args")
	for _, expected := range []string{"sign", "--yes", "--new-bundle-format=true", "--signing-config", "--key",
		request.KeyReference, request.CanonicalSubject()} {
		if !strings.Contains(string(arguments), expected) {
			t.Fatalf("missing argument %q: %s", expected, arguments)
		}
	}
	if strings.Contains(string(arguments), "sentinel") || !credentials.cleared() || len(environment.values) != 0 {
		t.Fatal("signing or Registry credential leaked in arguments or remained in mutable buffers")
	}
	signingConfig, err := os.ReadFile(capture + ".signing-config")
	if err != nil || string(signingConfig) != offlineCosignSigningConfig || strings.Contains(string(arguments), "--tlog-upload") {
		t.Fatalf("offline signing config = %q, err=%v, args=%s", signingConfig, err, arguments)
	}
	environmentCapture, _ := os.ReadFile(capture + ".env")
	if string(environmentCapture) != "https://vault.example.com|vault-secret-sentinel|" {
		t.Fatalf("provider environment = %q", environmentCapture)
	}
}

func TestCosignSignerRejectsFileKeysAndUnexpectedEnvironment(t *testing.T) {
	for _, keyReference := range []string{"/keys/cosign.key", "env://PRIVATE_KEY", "https://kms.example/key"} {
		if _, err := biz.ParseSigningKeyReference(keyReference); !errors.Is(err, biz.ErrInvalidSigningKey) {
			t.Fatalf("key reference %q error = %v", keyReference, err)
		}
	}
	directory := t.TempDir()
	executable := filepath.Join(directory, "cosign")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	signer, err := NewCosignSigner(CosignSignerOptions{Executable: executable, ExpectedVersion: "3.0.6",
		Credentials:        &credentialCaptureProvider{username: "signer", password: "password"},
		SigningEnvironment: &signingEnvironmentProbe{values: map[string][]byte{"UNRELATED_SECRET": []byte("secret")}},
		TemporaryRoot:      directory})
	if err != nil {
		t.Fatal(err)
	}
	_, err = signer.SignSignature(t.Context(), biz.SignatureSigningRequest{ProjectID: "project-1",
		ProfileID: "profile-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		KeyReference: "hashivault://release-signing-key"})
	if !errors.Is(err, biz.ErrSignatureSigning) {
		t.Fatalf("unexpected environment error = %v", err)
	}
}

func TestCosignSignerPropagatesOperationDeadline(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "cosign")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	environment := &signingEnvironmentProbe{values: map[string][]byte{
		"VAULT_ADDR": []byte("https://vault.example.com"), "VAULT_TOKEN": []byte("timeout-token"),
	}}
	credentials := &credentialCaptureProvider{username: "signer", password: "password"}
	signer, err := NewCosignSigner(CosignSignerOptions{Executable: executable, ExpectedVersion: "3.0.6",
		Credentials: credentials, SigningEnvironment: environment, TemporaryRoot: directory})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = signer.SignSignature(ctx, biz.SignatureSigningRequest{ProjectID: "project-1", ProfileID: "profile-1",
		RegistryCredentialID: "registry-1", RegistryRepository: "registry.example.com/team/api",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), KeyReference: "hashivault://release-signing-key"})
	if !errors.Is(err, context.DeadlineExceeded) || len(environment.values) != 0 || !credentials.cleared() {
		t.Fatalf("deadline result = %v environment=%v credentials_cleared=%t", err, environment.values, credentials.cleared())
	}
}

func TestCosignSignerAllowsPlainHTTPOnlyForLoopbackIntegrationRegistry(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "cosign")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	signer, err := NewCosignSigner(CosignSignerOptions{Executable: executable, ExpectedVersion: "3.0.6",
		Credentials:        &credentialCaptureProvider{username: "signer", password: "password"},
		SigningEnvironment: &signingEnvironmentProbe{values: map[string][]byte{}},
		TemporaryRoot:      directory, AllowPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = signer.SignSignature(t.Context(), biz.SignatureSigningRequest{ProjectID: "project-1",
		ProfileID: "profile-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		KeyReference: "hashivault://release-signing-key"})
	if !errors.Is(err, biz.ErrInvalidSigningKey) {
		t.Fatalf("remote plain HTTP Registry error = %v", err)
	}
}
