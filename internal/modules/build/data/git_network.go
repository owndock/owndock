package data

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/transport"
)

const maximumGitCABundleBytes = int64(1024 * 1024)

// GitNetworkOptions is installation-scoped trust configuration shared by the
// API probe and Build Worker checkout paths. It deliberately carries no proxy
// credentials; authenticated proxies must inject credentials outside normal
// configuration in a future secret-provider adapter.
type GitNetworkOptions struct {
	CACertFile    string
	HTTPSProxyURL string
}

type gitNetworkPolicy struct {
	caCertFile string
	caBundle   []byte
	proxy      transport.ProxyOptions
}

func newGitNetworkPolicy(options GitNetworkOptions) (gitNetworkPolicy, error) {
	policy := gitNetworkPolicy{}
	caFile := strings.TrimSpace(options.CACertFile)
	if caFile != "" {
		if caFile != options.CACertFile || !filepath.IsAbs(caFile) {
			return gitNetworkPolicy{}, ErrInvalidGitNetwork
		}
		bundle, err := readGitCABundle(caFile)
		if err != nil {
			return gitNetworkPolicy{}, err
		}
		policy.caCertFile, policy.caBundle = caFile, bundle
	}
	proxyURL := strings.TrimSpace(options.HTTPSProxyURL)
	if proxyURL != "" {
		if proxyURL != options.HTTPSProxyURL || !validGitHTTPSProxyURL(proxyURL) {
			return gitNetworkPolicy{}, ErrInvalidGitNetwork
		}
		policy.proxy = transport.ProxyOptions{URL: proxyURL}
	}
	return policy, nil
}

func readGitCABundle(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumGitCABundleBytes {
		return nil, ErrInvalidGitNetwork
	}
	bundle, err := os.ReadFile(path)
	if err != nil || int64(len(bundle)) > maximumGitCABundleBytes || !validCertificateBundle(bundle) {
		return nil, ErrInvalidGitNetwork
	}
	return bundle, nil
}

func validCertificateBundle(bundle []byte) bool {
	remaining, certificates := bundle, 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		certificates++
		remaining = rest
	}
	return certificates > 0
}

func validGitHTTPSProxyURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}
	if strings.HasSuffix(parsed.Hostname(), ".") || parsed.Host != strings.ToLower(parsed.Host) {
		return false
	}
	return parsed.String() == value
}

func (p gitNetworkPolicy) proxyFor(repositoryURL string) transport.ProxyOptions {
	if strings.HasPrefix(repositoryURL, "https://") {
		return p.proxy
	}
	return transport.ProxyOptions{}
}

var ErrInvalidGitNetwork = errors.New("Git network trust configuration is invalid")
