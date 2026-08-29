package data

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func TestOCIReferrerClientProbesBoundedOCIIndex(t *testing.T) {
	subject := "sha256:" + strings.Repeat("a", 64)
	descriptor := "sha256:" + strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/team/api/referrers/"+subject ||
			r.Header.Get("Accept") != ociImageIndexMediaType {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", ociImageIndexMediaType)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.cyclonedx+json","digest":"` + descriptor + `","size":512}]}`))
	}))
	defer server.Close()
	client, err := NewOCIReferrerClient(OCIReferrerClientOptions{AllowPlainHTTP: true})
	if err != nil {
		t.Fatalf("NewOCIReferrerClient() error = %v", err)
	}
	repository := strings.TrimPrefix(server.URL, "http://") + "/team/api"
	capability, err := client.Probe(t.Context(), repository, subject)
	if err != nil || !capability.Supported || capability.Count != 1 || capability.Mode != ReferrerDiscoveryNative {
		t.Fatalf("Probe() = %+v, %v", capability, err)
	}
}

func TestOCIReferrerClientUsesStandardTagFallback(t *testing.T) {
	subject := "sha256:" + strings.Repeat("a", 64)
	descriptor := "sha256:" + strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/referrers/") {
			http.NotFound(w, r)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/manifests/sha256-"+strings.Repeat("a", 64)) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ociImageIndexMediaType)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + descriptor + `","size":10}]}`))
	}))
	defer server.Close()
	client, _ := NewOCIReferrerClient(OCIReferrerClientOptions{AllowPlainHTTP: true})
	capability, err := client.Probe(t.Context(), strings.TrimPrefix(server.URL, "http://")+"/team/api", subject)
	if err != nil || capability.Mode != ReferrerDiscoveryTagSchema || capability.Count != 1 {
		t.Fatalf("fallback Probe() = %+v, %v", capability, err)
	}
}

func TestOCIReferrerClientFailsClosed(t *testing.T) {
	subject := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{name: "unsupported", status: http.StatusNotFound, want: biz.ErrReferrersUnsupported},
		{name: "unauthorized", status: http.StatusUnauthorized, want: biz.ErrRegistryAuthentication},
		{name: "invalid index", status: http.StatusOK, body: `{"schemaVersion":1}`, want: biz.ErrInvalidRegistryResponse},
		{name: "invalid descriptor", status: http.StatusOK, body: `{"schemaVersion":2,"manifests":[{"mediaType":"application/json","digest":"bad","size":1}]}`, want: biz.ErrInvalidRegistryResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", ociImageIndexMediaType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client, _ := NewOCIReferrerClient(OCIReferrerClientOptions{AllowPlainHTTP: true})
			_, err := client.Probe(t.Context(), strings.TrimPrefix(server.URL, "http://")+"/team/api", subject)
			if !errors.Is(err, test.want) {
				t.Fatalf("Probe() error = %v, want %v", err, test.want)
			}
		})
	}
	client, _ := NewOCIReferrerClient(OCIReferrerClientOptions{AllowPlainHTTP: true})
	if _, err := client.Probe(t.Context(), "registry.example.com/team/api", subject); !errors.Is(err, biz.ErrInvalidEvidence) {
		t.Fatalf("plain non-loopback error = %v", err)
	}
	if _, err := NewOCIReferrerClient(OCIReferrerClientOptions{MaxResponseBytes: 1}); !errors.Is(err, biz.ErrInvalidEvidence) {
		t.Fatalf("invalid response limit error = %v", err)
	}
}

func TestOCIReferrerClientRejectsOversizedResponseAndRedirect(t *testing.T) {
	subject := "sha256:" + strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("redirected") {
			w.Header().Set("Content-Type", ociImageIndexMediaType)
			_, _ = w.Write([]byte(`{"schemaVersion":2,"manifests":[]}`))
			return
		}
		http.Redirect(w, r, r.URL.Path+"?redirected=1", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, _ := NewOCIReferrerClient(OCIReferrerClientOptions{AllowPlainHTTP: true, MaxResponseBytes: 1024})
	_, err := client.Probe(t.Context(), strings.TrimPrefix(server.URL, "http://")+"/team/api", subject)
	if !errors.Is(err, biz.ErrUnavailable) {
		t.Fatalf("redirect error = %v", err)
	}

	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ociImageIndexMediaType)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"padding":"` + strings.Repeat("x", 2048) + `","manifests":[]}`))
	}))
	defer large.Close()
	_, err = client.Probe(t.Context(), strings.TrimPrefix(large.URL, "http://")+"/team/api", subject)
	if !errors.Is(err, biz.ErrInvalidRegistryResponse) {
		t.Fatalf("oversized response error = %v", err)
	}
}
