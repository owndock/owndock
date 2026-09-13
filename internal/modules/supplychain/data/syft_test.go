package data

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
)

type syftCredentialProviderStub struct {
	credential biz.RegistryCredential
	err        error
}

func (s syftCredentialProviderStub) ResolveRegistryCredential(
	context.Context, string, string, string,
) (biz.RegistryCredential, error) {
	return biz.RegistryCredential{
		AuthenticationMode: s.credential.AuthenticationMode,
		Username:           s.credential.Username,
		Password:           append([]byte(nil), s.credential.Password...),
	}, s.err
}

func validSyftCredentialProvider() biz.RegistryCredentialProvider {
	return syftCredentialProviderStub{credential: biz.RegistryCredential{
		AuthenticationMode: registryauth.ModeBasic,
		Username:           "publisher", Password: []byte("registry-password"),
	}}
}

func writeFakeSyft(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "syft")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func syftRequest() biz.SBOMRequest {
	return biz.SBOMRequest{
		ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		FormatVersion:      biz.CycloneDXVersion16,
	}
}

func TestSyftGeneratorVerifiesPinnedVersionAndExactInvocation(t *testing.T) {
	executable := writeFakeSyft(t, `
if [ "$1" = "version" ]; then
  [ "$2" = "-o" ] && [ "$3" = "json" ]
  printf '%s' '{"version":"1.50.0"}'
  exit 0
fi
[ "$1" = "scan" ]
[ "$2" = "registry:registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]
[ "$3" = "-o" ] && [ "$4" = "cyclonedx-json@1.6" ]
[ "$HOME" = "/tmp" ] && [ "$SYFT_CHECK_FOR_APP_UPDATE" = "false" ]
[ "$SYFT_REGISTRY_AUTH_AUTHORITY" = "registry.example.com" ]
[ "$SYFT_REGISTRY_AUTH_USERNAME" = "publisher" ]
[ "$SYFT_REGISTRY_AUTH_PASSWORD" = "registry-password" ]
[ "$SYFT_SOURCE_IMAGE_MAX_LAYER_SIZE" = "268435456" ]
[ "$SYFT_CACHE_DIR" = "/tmp/syft-cache" ] && [ "$SYFT_CACHE_TTL" = "0" ]
[ "$HTTPS_PROXY" = "http://proxy.internal:3128" ] && [ "$https_proxy" = "$HTTPS_PROXY" ]
[ "$HTTP_PROXY" = "$HTTPS_PROXY" ] && [ "$http_proxy" = "$HTTPS_PROXY" ]
[ -z "$NO_PROXY" ] && [ -z "$no_proxy" ]
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"demo"}]}'
`)
	generator, err := NewSyftGenerator(SyftOptions{
		Executable: executable, ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 4096,
		MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider(),
		RegistryHTTPSProxy: "http://proxy.internal:3128",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := generator.Verify(t.Context()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	document, err := generator.GenerateSBOM(t.Context(), syftRequest())
	if err != nil || document.FormatVersion != "1.6" || generator.String() != "syft/1.50.0" {
		t.Fatalf("GenerateSBOM() = %+v/%v (%s)", document, err, generator)
	}
}

func TestSyftGeneratorOmitsAuthenticationForAnonymousRegistry(t *testing.T) {
	executable := writeFakeSyft(t, `
if [ "$1" = "version" ]; then
  printf '%s' '{"version":"1.50.0"}'
  exit 0
fi
[ -z "${SYFT_REGISTRY_AUTH_AUTHORITY:-}" ]
[ -z "${SYFT_REGISTRY_AUTH_USERNAME:-}" ]
[ -z "${SYFT_REGISTRY_AUTH_PASSWORD:-}" ]
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}'
`)
	generator, err := NewSyftGenerator(SyftOptions{
		Executable: executable, ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 4096,
		MaxLayerBytes: 256 * 1024 * 1024,
		Credentials: syftCredentialProviderStub{credential: biz.RegistryCredential{
			AuthenticationMode: registryauth.ModeAnonymous,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generator.GenerateSBOM(t.Context(), syftRequest()); err != nil {
		t.Fatalf("anonymous GenerateSBOM() error = %v", err)
	}
}

func TestSyftGeneratorFailsClosedForVersionExecutionAndOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		script string
		verify bool
		want   error
	}{
		{name: "wrong version", script: `printf '%s' '{"version":"1.49.0"}'`, verify: true, want: biz.ErrGeneratorVersion},
		{name: "invalid version output", script: `printf '%s' 'not-json'`, verify: true, want: biz.ErrGeneratorVersion},
		{name: "command failure", script: `exit 19`, want: biz.ErrSBOMGeneration},
		{name: "invalid document", script: `printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}'`, want: biz.ErrInvalidSBOM},
		{name: "oversized", script: `i=0; while [ "$i" -lt 2000 ]; do printf x; i=$((i + 1)); done`, want: biz.ErrSBOMTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			generator, err := NewSyftGenerator(SyftOptions{
				Executable: writeFakeSyft(t, test.script), ExpectedVersion: PinnedSyftVersion,
				MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024,
				Credentials: validSyftCredentialProvider(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.verify {
				err = generator.Verify(t.Context())
			} else {
				_, err = generator.GenerateSBOM(t.Context(), syftRequest())
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewSyftGeneratorRejectsFloatingOrUnsafeConfiguration(t *testing.T) {
	for _, options := range []SyftOptions{
		{Executable: "syft", ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/usr/bin/syft", ExpectedVersion: "latest", MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/usr/bin/syft", ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 1, MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/usr/bin/syft", ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 65 * 1024 * 1024, MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/usr/bin/syft", ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 1024, MaxLayerBytes: 1, Credentials: validSyftCredentialProvider()},
		{Executable: "/usr/bin/syft", ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024},
		{Executable: "/usr/bin/syft", ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider(), RegistryHTTPSProxy: "http://user:secret@proxy.internal:3128"},
	} {
		if _, err := NewSyftGenerator(options); !errors.Is(err, biz.ErrGeneratorVersion) {
			t.Fatalf("NewSyftGenerator(%+v) error = %v", options, err)
		}
	}
	invalid := syftRequest()
	invalid.SubjectDigest = "latest"
	generator, _ := NewSyftGenerator(SyftOptions{
		Executable: writeFakeSyft(t, "exit 0"), ExpectedVersion: PinnedSyftVersion, MaxOutputBytes: 1024,
		MaxLayerBytes: 256 * 1024 * 1024, Credentials: validSyftCredentialProvider(),
	})
	if _, err := generator.GenerateSBOM(t.Context(), invalid); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid request error = %v", err)
	}
}

func TestSyftGeneratorFailsClosedWhenRegistryCredentialIsUnavailable(t *testing.T) {
	secretSentinel := "must-not-appear"
	generator, err := NewSyftGenerator(SyftOptions{
		Executable: writeFakeSyft(t, "exit 0"), ExpectedVersion: PinnedSyftVersion,
		MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024,
		Credentials: syftCredentialProviderStub{
			credential: biz.RegistryCredential{AuthenticationMode: registryauth.ModeBasic, Username: "publisher", Password: []byte(secretSentinel)},
			err:        errors.New("upstream secret lookup failed"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = generator.GenerateSBOM(t.Context(), syftRequest())
	if !errors.Is(err, biz.ErrRegistryAuthentication) || strings.Contains(err.Error(), secretSentinel) {
		t.Fatalf("credential failure = %v", err)
	}
}

func TestSyftGeneratorBoundsOutputDiscardsStderrAndClearsCredential(t *testing.T) {
	secretSentinel := "syft-secret-sentinel"
	executable := writeFakeSyft(t, `
i=0
while [ "$i" -lt 2048 ]; do printf x; i=$((i + 1)); done
printf '%s' "$SYFT_REGISTRY_AUTH_PASSWORD" >&2
`)
	credentials := &credentialCaptureProvider{username: "publisher", password: secretSentinel}
	generator, err := NewSyftGenerator(SyftOptions{
		Executable: executable, ExpectedVersion: PinnedSyftVersion,
		MaxOutputBytes: 1024, MaxLayerBytes: 256 * 1024 * 1024, Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = generator.GenerateSBOM(t.Context(), syftRequest())
	if !errors.Is(err, biz.ErrSBOMTooLarge) || strings.Contains(err.Error(), secretSentinel) {
		t.Fatalf("oversized secret-bearing output error = %v", err)
	}
	if !credentials.cleared() {
		t.Fatal("Syft generator did not clear its mutable Registry password")
	}
}
