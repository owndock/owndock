package data

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/owndock/owndock/internal/shared/tlstrust"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const maximumRegistryCABundleBytes = int64(1024 * 1024)

var (
	errUnsafeRegistryRedirect = errors.New("unsafe Registry redirect")
	errInvalidRegistryTrust   = errors.New("Registry TLS trust configuration is invalid")
)

// LoadRegistryCABundle validates and snapshots the optional installation-wide
// Registry CA bundle. Empty input keeps the host system roots only.
func LoadRegistryCABundle(path string) ([]byte, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		if path != "" {
			return nil, errInvalidRegistryTrust
		}
		return nil, nil
	}
	if trimmed != path || !filepath.IsAbs(path) {
		return nil, errInvalidRegistryTrust
	}
	bundle, err := tlstrust.ReadBundle(path, maximumRegistryCABundleBytes)
	if err != nil {
		return nil, errInvalidRegistryTrust
	}
	return bundle, nil
}

// SnapshotRegistryCABundle writes already validated CA bytes into a private,
// process-owned directory for pinned subprocess tools that honor SSL_CERT_FILE.
// It prevents those tools from reopening a mutable operator-supplied path.
func SnapshotRegistryCABundle(root string, bundle []byte) (string, func(), error) {
	cleanup := func() {}
	if len(bundle) == 0 {
		return "", cleanup, nil
	}
	if !filepath.IsAbs(root) || !tlstrust.ValidBundle(bundle) {
		return "", cleanup, errInvalidRegistryTrust
	}
	directory, err := os.MkdirTemp(root, ".owndock-registry-ca-")
	if err != nil {
		return "", cleanup, errInvalidRegistryTrust
	}
	cleanup = func() { _ = os.RemoveAll(directory) }
	if err := os.Chmod(directory, 0o700); err != nil {
		cleanup()
		return "", func() {}, errInvalidRegistryTrust
	}
	path := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(path, append([]byte(nil), bundle...), 0o600); err != nil {
		cleanup()
		return "", func() {}, errInvalidRegistryTrust
	}
	return path, cleanup, nil
}

func newRegistryHTTPClient(allowPlainHTTP bool, caBundle []byte) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Registry traffic must use the explicitly supported direct route. In
	// particular, worker processes must not inherit ambient proxy variables.
	transport.Proxy = nil
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if len(caBundle) > 0 {
		if !tlstrust.ValidBundle(caBundle) {
			return nil, errInvalidRegistryTrust
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(append([]byte(nil), caBundle...)) {
			return nil, errInvalidRegistryTrust
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport:     retry.NewTransport(transport),
		CheckRedirect: registryRedirectPolicy(allowPlainHTTP),
	}, nil
}

func registryRedirectPolicy(allowPlainHTTP bool) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if len(via) >= 3 || request.URL.User != nil ||
			!strings.EqualFold(request.URL.Scheme, via[0].URL.Scheme) ||
			!strings.EqualFold(request.URL.Host, via[0].URL.Host) {
			return errUnsafeRegistryRedirect
		}
		switch strings.ToLower(request.URL.Scheme) {
		case "https":
			return nil
		case "http":
			if allowPlainHTTP && loopbackRegistry(request.URL.Host) &&
				loopbackRegistry(via[0].URL.Host) {
				return nil
			}
		}
		return errUnsafeRegistryRedirect
	}
}
