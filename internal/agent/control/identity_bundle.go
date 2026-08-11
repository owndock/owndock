package agentcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertificateRotationRequest struct {
	CSRPEM        []byte
	PrivateKeyPEM []byte
}

// NewCertificateRotationRequest creates a fresh local key and a signed CSR.
// The CSR intentionally carries no caller-controlled identity; the Server
// derives Organization, Host, Agent Identity and instance from the currently
// authenticated certificate.
func NewCertificateRotationRequest(identity Identity) (CertificateRotationRequest, error) {
	if !validBundleIdentity(identity) {
		return CertificateRotationRequest{}, ErrConfigurationInvalid
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CertificateRotationRequest{}, fmt.Errorf("generate Agent rotation key: %w", err)
	}
	requestDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "owndock-agent-rotation"},
		},
		privateKey,
	)
	if err != nil {
		return CertificateRotationRequest{}, fmt.Errorf("create Agent rotation CSR: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return CertificateRotationRequest{}, fmt.Errorf("encode Agent rotation key: %w", err)
	}
	request := CertificateRotationRequest{
		CSRPEM: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: requestDER,
		}),
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: privateKeyDER,
		}),
	}
	if request.CSRPEM == nil || request.PrivateKeyPEM == nil ||
		!bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		clearTLSBytes(request.PrivateKeyPEM)
		return CertificateRotationRequest{}, ErrConfigurationInvalid
	}
	return request, nil
}

// InstallClientIdentityBundle validates and atomically installs a client
// certificate and private key into one 0600 PEM file. Using one file avoids a
// crash window where only one half of a rotated identity has been replaced.
func InstallClientIdentityBundle(
	path string,
	certificatePEM, privateKeyPEM, caCertificatePEM []byte,
	identity Identity,
	now time.Time,
) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || !validBundleIdentity(identity) ||
		len(certificatePEM) == 0 || len(privateKeyPEM) == 0 ||
		len(caCertificatePEM) == 0 ||
		len(certificatePEM) > maximumTLSMaterialBytes ||
		len(privateKeyPEM) > maximumTLSMaterialBytes ||
		len(caCertificatePEM) > maximumTLSMaterialBytes {
		return ErrConfigurationInvalid
	}
	if err := validateBundleTarget(path); err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("%w: parse rotated Agent identity", ErrConfigurationInvalid)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		!allowsClientAuthentication(leaf) || !certificateMatchesIdentity(leaf, identity) {
		return fmt.Errorf("%w: rotated Agent certificate identity", ErrConfigurationInvalid)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertificatePEM) {
		return fmt.Errorf("%w: rotated Agent CA", ErrConfigurationInvalid)
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return fmt.Errorf("%w: rotated Agent certificate chain", ErrConfigurationInvalid)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("%w: verify rotated Agent certificate", ErrConfigurationInvalid)
	}
	bundle := make([]byte, 0, len(certificatePEM)+len(privateKeyPEM)+2)
	bundle = append(bundle, certificatePEM...)
	if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
		bundle = append(bundle, '\n')
	}
	bundle = append(bundle, privateKeyPEM...)
	defer clearTLSBytes(bundle)
	return replaceIdentityBundle(path, bundle)
}

func validateBundleTarget(path string) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrConfigurationInvalid
	}
	info, err = os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("inspect Agent identity bundle: %w", err)
	case !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0:
		return ErrConfigurationInvalid
	default:
		return nil
	}
}

func replaceIdentityBundle(path string, bundle []byte) (result error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".owndock-agent-identity-*")
	if err != nil {
		return fmt.Errorf("create Agent identity bundle: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if result != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect Agent identity bundle: %w", err)
	}
	if _, err := temporary.Write(bundle); err != nil {
		return fmt.Errorf("write Agent identity bundle: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync Agent identity bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Agent identity bundle: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace Agent identity bundle: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open Agent identity directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync Agent identity directory: %w", err)
	}
	return nil
}

func certificateMatchesIdentity(certificate *x509.Certificate, identity Identity) bool {
	if certificate == nil || len(certificate.URIs) != 1 {
		return false
	}
	expected := &url.URL{
		Scheme: "spiffe", Host: "owndock",
		Path: "/organizations/" + identity.OrganizationID +
			"/managed-hosts/" + identity.ManagedHostID +
			"/agents/" + identity.IdentityID +
			"/instances/" + identity.InstanceID,
	}
	return bytes.Equal([]byte(certificate.URIs[0].String()), []byte(expected.String()))
}

func validBundleIdentity(identity Identity) bool {
	for _, value := range []string{
		identity.OrganizationID,
		identity.ManagedHostID,
		identity.IdentityID,
		identity.InstanceID,
	} {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "/?#") {
			return false
		}
	}
	return true
}
