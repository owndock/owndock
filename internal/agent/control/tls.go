package agentcontrol

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maximumTLSMaterialBytes = 1024 * 1024

type TLSFiles struct {
	CACertificateFile     string
	ClientCertificateFile string
	ClientPrivateKeyFile  string
}

func NewHTTPClient(
	files TLSFiles,
	handshakeTimeout time.Duration,
) (*http.Client, error) {
	if handshakeTimeout <= 0 {
		return nil, ErrConfigurationInvalid
	}
	caPath, err := regularAbsoluteFile(files.CACertificateFile, false)
	if err != nil {
		return nil, err
	}
	certificatePath, err := regularAbsoluteFile(
		files.ClientCertificateFile,
		false,
	)
	if err != nil {
		return nil, err
	}
	privateKeyPath, err := regularAbsoluteFile(
		files.ClientPrivateKeyFile,
		true,
	)
	if err != nil {
		return nil, err
	}
	caCertificate, err := readBoundedTLSFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read Agent CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertificate) {
		return nil, fmt.Errorf(
			"%w: parse Agent CA certificate",
			ErrConfigurationInvalid,
		)
	}
	certificatePEM, err := readBoundedTLSFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("read Agent client certificate: %w", err)
	}
	privateKeyPEM, err := readBoundedTLSFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read Agent client private key: %w", err)
	}
	defer func() {
		for index := range privateKeyPEM {
			privateKeyPEM[index] = 0
		}
	}()
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: parse Agent client certificate",
			ErrConfigurationInvalid,
		)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || time.Now().Before(leaf.NotBefore) ||
		!time.Now().Before(leaf.NotAfter) ||
		!allowsClientAuthentication(leaf) {
		return nil, fmt.Errorf(
			"%w: Agent client certificate is not currently valid for client authentication",
			ErrConfigurationInvalid,
		)
	}
	certificate.Leaf = leaf
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   handshakeTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxConnsPerHost:       1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: handshakeTimeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots,
			Certificates: []tls.Certificate{certificate},
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Agent control redirects are not allowed")
		},
	}, nil
}

func readBoundedTLSFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	value, err := io.ReadAll(
		io.LimitReader(file, maximumTLSMaterialBytes+1),
	)
	if err != nil {
		return nil, err
	}
	if len(value) > maximumTLSMaterialBytes {
		return nil, ErrConfigurationInvalid
	}
	return value, nil
}

func allowsClientAuthentication(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth ||
			usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func regularAbsoluteFile(value string, private bool) (string, error) {
	path := filepath.Clean(strings.TrimSpace(value))
	if !filepath.IsAbs(path) {
		return "", ErrConfigurationInvalid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Agent TLS material: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrConfigurationInvalid
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf(
			"%w: Agent private key permissions must not allow group or other access",
			ErrConfigurationInvalid,
		)
	}
	return path, nil
}
