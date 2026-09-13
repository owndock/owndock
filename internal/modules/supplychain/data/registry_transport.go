package data

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/owndock/owndock/internal/shared/tlstrust"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const maximumRegistryCABundleBytes = int64(1024 * 1024)

var (
	errUnsafeRegistryRedirect = errors.New("unsafe Registry redirect")
	errInvalidRegistryTrust   = errors.New("Registry TLS trust configuration is invalid")
	errInvalidRegistryProxy   = errors.New("Registry proxy configuration is invalid")
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

func newRegistryHTTPClient(allowPlainHTTP bool, caBundle []byte, proxyAddress string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxyURL, err := parseRegistryHTTPSProxy(proxyAddress)
	if err != nil {
		return nil, err
	}
	// Registry traffic uses only this explicit route and never inherits ambient
	// proxy variables from the Server or Worker process.
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	} else {
		transport.Proxy = nil
	}
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

func parseRegistryHTTPSProxy(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	if strings.TrimSpace(value) != value {
		return nil, errInvalidRegistryProxy
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		strings.HasSuffix(parsed.Hostname(), ".") || parsed.Host != strings.ToLower(parsed.Host) {
		return nil, errInvalidRegistryProxy
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number < 1 || number > 65535 {
			return nil, errInvalidRegistryProxy
		}
	}
	if parsed.String() != value {
		return nil, errInvalidRegistryProxy
	}
	return parsed, nil
}

func registryProxyEnvironment(environment []string, proxyAddress string) []string {
	if proxyAddress == "" {
		return environment
	}
	return append(environment,
		"HTTP_PROXY="+proxyAddress,
		"HTTPS_PROXY="+proxyAddress,
		"http_proxy="+proxyAddress,
		"https_proxy="+proxyAddress,
		"NO_PROXY=",
		"no_proxy=",
	)
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
