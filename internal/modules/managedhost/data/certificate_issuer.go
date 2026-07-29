package data

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"path"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
)

var (
	ErrInvalidAgentCA  = errors.New("agent certificate authority is invalid")
	ErrInvalidAgentCSR = errors.New("agent certificate request is invalid")
)

type CertificateIssuer struct {
	caCertificate *x509.Certificate
	caPrivateKey  crypto.Signer
	caPEM         []byte
	ttl           time.Duration
}

func NewCertificateIssuer(
	caCertificatePEM, caPrivateKeyPEM []byte,
	ttl time.Duration,
) (*CertificateIssuer, error) {
	if ttl <= 0 {
		return nil, ErrInvalidAgentCA
	}
	certificateBlock, certificateRest := pem.Decode(caCertificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" ||
		len(bytes.TrimSpace(certificateRest)) != 0 {
		return nil, ErrInvalidAgentCA
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !certificate.IsCA ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrInvalidAgentCA
	}
	privateKey, err := parseSigner(caPrivateKeyPEM)
	if err != nil {
		return nil, ErrInvalidAgentCA
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, ErrInvalidAgentCA
	}
	signerPublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil || !bytes.Equal(certificatePublicKey, signerPublicKey) {
		return nil, ErrInvalidAgentCA
	}
	return &CertificateIssuer{
		caCertificate: certificate,
		caPrivateKey:  privateKey,
		caPEM:         append([]byte(nil), caCertificatePEM...),
		ttl:           ttl,
	}, nil
}

func (i *CertificateIssuer) Issue(
	ctx context.Context,
	claim biz.AgentCertificateClaim,
	csrPEM []byte,
	now time.Time,
) (biz.IssuedCertificate, error) {
	if err := ctx.Err(); err != nil {
		return biz.IssuedCertificate{}, err
	}
	if !validCertificateIdentity(claim.OrganizationID) ||
		!validCertificateIdentity(claim.ManagedHostID) ||
		!validCertificateIdentity(claim.IdentityID) ||
		!validCertificateIdentity(claim.InstanceID) {
		return biz.IssuedCertificate{}, ErrInvalidAgentCSR
	}
	requestBlock, requestRest := pem.Decode(csrPEM)
	if requestBlock == nil || requestBlock.Type != "CERTIFICATE REQUEST" ||
		len(bytes.TrimSpace(requestRest)) != 0 {
		return biz.IssuedCertificate{}, ErrInvalidAgentCSR
	}
	request, err := x509.ParseCertificateRequest(requestBlock.Bytes)
	if err != nil || request.CheckSignature() != nil ||
		!supportedAgentPublicKey(request.PublicKey) {
		return biz.IssuedCertificate{}, ErrInvalidAgentCSR
	}
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return biz.IssuedCertificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	for index := range serialBytes {
		serialBytes[index] = 0
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	now = now.UTC()
	if now.Before(i.caCertificate.NotBefore) {
		return biz.IssuedCertificate{}, ErrInvalidAgentCA
	}
	expiresAt := now.Add(i.ttl)
	if expiresAt.After(i.caCertificate.NotAfter) {
		expiresAt = i.caCertificate.NotAfter.UTC()
	}
	if !expiresAt.After(now) {
		return biz.IssuedCertificate{}, ErrInvalidAgentCA
	}
	identityURI := &url.URL{
		Scheme: "spiffe",
		Host:   "owndock",
		Path: path.Join(
			"/organizations", claim.OrganizationID,
			"managed-hosts", claim.ManagedHostID,
			"agents", claim.IdentityID,
			"instances", claim.InstanceID,
		),
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "owndock-agent:" + claim.IdentityID,
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{identityURI},
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		i.caCertificate,
		request.PublicKey,
		i.caPrivateKey,
	)
	if err != nil {
		return biz.IssuedCertificate{}, fmt.Errorf("sign agent certificate: %w", err)
	}
	fingerprint := sha256.Sum256(der)
	return biz.IssuedCertificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: der,
		}),
		CACertificatePEM: append([]byte(nil), i.caPEM...),
		Serial:           serial.Text(16),
		SHA256:           hex.EncodeToString(fingerprint[:]),
		ExpiresAt:        expiresAt,
	}, nil
}

func parseSigner(value []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(value)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidAgentCA
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, ErrInvalidAgentCA
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidAgentCA
	}
	return signer, nil
}

func supportedAgentPublicKey(publicKey any) bool {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize >= 256
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

func validCertificateIdentity(value string) bool {
	if value == "" || len(value) > 128 || value[0] == '.' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
