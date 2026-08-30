package data

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func mustNewOCIArtifactProber(t testing.TB, options OCIArtifactProberOptions) *OCIArtifactProber {
	t.Helper()
	prober, err := NewOCIArtifactProber(options)
	if err != nil {
		t.Fatalf("NewOCIArtifactProber() error = %v", err)
	}
	return prober
}

func TestOCIArtifactProberReadsAndHashesExactDigest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"` + mediaTypeOCIManifest + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":2},"layers":[]}`)
	manifestDigest := digest.FromBytes(manifest).String()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/team/api/manifests/"+manifestDigest {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", mediaTypeOCIManifest)
		response.Header().Set("Docker-Content-Digest", manifestDigest)
		response.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		response.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			_, _ = response.Write(manifest)
		}
	}))
	t.Cleanup(server.Close)
	repository := strings.TrimPrefix(server.URL, "http://") + "/team/api"
	prober := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{
		AllowPlainHTTP: true,
		Credentials: registryCredentialProviderProbe{credential: biz.RegistryCredential{
			AuthenticationMode: registryauth.ModeAnonymous,
		}},
	})
	if err := prober.ProbeArtifact(t.Context(), "project-1", "registry-1", repository,
		manifestDigest); err != nil {
		t.Fatalf("ProbeArtifact() error = %v", err)
	}
}

func TestOCIArtifactProberUsesExplicitRegistryCA(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"` + mediaTypeOCIManifest + `","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":2},"layers":[]}`)
	manifestDigest := digest.FromBytes(manifest).String()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v2/team/api/manifests/"+manifestDigest {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", mediaTypeOCIManifest)
		response.Header().Set("Docker-Content-Digest", manifestDigest)
		response.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		if request.Method != http.MethodHead {
			_, _ = response.Write(manifest)
		}
	}))
	t.Cleanup(server.Close)
	repository := strings.TrimPrefix(server.URL, "https://") + "/team/api"
	credentials := registryCredentialProviderProbe{credential: biz.RegistryCredential{
		AuthenticationMode: registryauth.ModeAnonymous,
	}}
	untrusted := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{Credentials: credentials})
	if err := untrusted.ProbeArtifact(t.Context(), "project-1", "registry-1", repository,
		manifestDigest); !errors.Is(err, buildbiz.ErrArtifactRegistryUnavailable) {
		t.Fatalf("untrusted self-signed Registry error = %v", err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	trusted := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{
		Credentials: credentials, RegistryCABundle: certificate,
	})
	if err := trusted.ProbeArtifact(t.Context(), "project-1", "registry-1", repository,
		manifestDigest); err != nil {
		t.Fatalf("ProbeArtifact(explicit CA) error = %v", err)
	}
}

func TestOCIArtifactProberRejectsTamperedManifest(t *testing.T) {
	original := []byte(`{"schemaVersion":2,"mediaType":"` + mediaTypeOCIManifest + `"}`)
	requestedDigest := digest.FromBytes(original).String()
	tampered := []byte(`{"schemaVersion":2,"mediaType":"` + mediaTypeOCIIndex + `"}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", mediaTypeOCIManifest)
		response.Header().Set("Docker-Content-Digest", requestedDigest)
		response.Header().Set("Content-Length", strconv.Itoa(len(tampered)))
		_, _ = response.Write(tampered)
	}))
	t.Cleanup(server.Close)
	repository := strings.TrimPrefix(server.URL, "http://") + "/team/api"
	prober := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{AllowPlainHTTP: true})
	if err := prober.ProbeArtifact(t.Context(), "project-1", "registry-1", repository,
		requestedDigest); !errors.Is(err, buildbiz.ErrArtifactRegistryIntegrity) {
		t.Fatalf("ProbeArtifact() error = %v", err)
	}
}

func TestOCIArtifactProberRejectsOversizedManifest(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"` + mediaTypeOCIManifest + `","padding":"` +
		strings.Repeat("x", int(maximumArtifactManifestBytes)) + `"}`)
	manifestDigest := digest.FromBytes(manifest).String()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", mediaTypeOCIManifest)
		response.Header().Set("Docker-Content-Digest", manifestDigest)
		response.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		response.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			_, _ = response.Write(manifest)
		}
	}))
	t.Cleanup(server.Close)
	prober := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{AllowPlainHTTP: true})
	if err := prober.ProbeArtifact(t.Context(), "project-1", "registry-1",
		strings.TrimPrefix(server.URL, "http://")+"/team/api", manifestDigest,
	); !errors.Is(err, buildbiz.ErrArtifactRegistryIntegrity) {
		t.Fatalf("oversized manifest error = %v", err)
	}
}

func TestOCIArtifactProberRejectsCrossOriginRedirectBeforeCredentialCanLeaveRegistry(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+request.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	credentials := &credentialCaptureProvider{username: "robot", password: "redirect-secret-sentinel"}
	prober := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{
		AllowPlainHTTP: true, Credentials: credentials,
	})
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	if err := prober.ProbeArtifact(t.Context(), "project-1", "registry-1",
		strings.TrimPrefix(source.URL, "http://")+"/team/api", manifestDigest,
	); !errors.Is(err, buildbiz.ErrArtifactRegistryUnavailable) {
		t.Fatalf("cross-origin redirect error = %v", err)
	}
	if redirected.Load() {
		t.Fatal("cross-origin Registry redirect reached the target host")
	}
	if !credentials.cleared() {
		t.Fatal("Registry credential was not cleared after rejected redirect")
	}
}

func TestOCIArtifactProberRejectsMutableReferenceAndNonLoopbackPlainHTTP(t *testing.T) {
	prober := mustNewOCIArtifactProber(t, OCIArtifactProberOptions{AllowPlainHTTP: true})
	for _, testCase := range []struct {
		repository string
		digest     string
	}{
		{"registry.example.com/team/api", "latest"},
		{"registry.example.com/team/api:latest", "sha256:" + strings.Repeat("a", 64)},
	} {
		if err := prober.ProbeArtifact(context.Background(), "project-1", "registry-1",
			testCase.repository, testCase.digest); !errors.Is(err, buildbiz.ErrInvalidArtifact) {
			t.Fatalf("ProbeArtifact(%q, %q) error = %v", testCase.repository, testCase.digest, err)
		}
	}
}

func TestArtifactRegistryErrorIsStable(t *testing.T) {
	if err := artifactRegistryError(&errcode.ErrorResponse{StatusCode: http.StatusUnauthorized}); !errors.Is(err, buildbiz.ErrArtifactRegistryAuthentication) {
		t.Fatalf("authentication error = %v", err)
	}
	if err := artifactRegistryError(errors.New("dial failed: secret detail")); !errors.Is(err, buildbiz.ErrArtifactRegistryUnavailable) || strings.Contains(err.Error(), "secret detail") {
		t.Fatalf("unavailable error = %v", err)
	}
}
