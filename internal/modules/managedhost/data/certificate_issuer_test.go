package data

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
)

func TestCertificateIssuerBindsAgentIdentityToClientCertificate(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	caCertificate, caPrivateKey := testCertificateAuthority(t, now)
	issuer, err := NewCertificateIssuer(
		caCertificate, caPrivateKey, 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-client-value"}},
		agentKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(
		t.Context(),
		biz.AgentCertificateClaim{
			OrganizationID: "organization-1",
			ManagedHostID:  "host-1",
			IdentityID:     "identity-1",
			InstanceID:     "instance-1",
		},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.CommonName != "owndock-agent:identity-1" ||
		len(certificate.URIs) != 1 ||
		!strings.Contains(certificate.URIs[0].String(), "/managed-hosts/host-1/") ||
		!strings.Contains(certificate.URIs[0].String(), "/instances/instance-1") ||
		len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		issued.Serial == "" || issued.SHA256 == "" {
		t.Fatalf("certificate = %+v, issued = %+v", certificate, issued)
	}
}

func TestCertificateIssuerRejectsInvalidCSR(t *testing.T) {
	now := time.Now().UTC()
	caCertificate, caPrivateKey := testCertificateAuthority(t, now)
	issuer, err := NewCertificateIssuer(caCertificate, caPrivateKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(
		t.Context(),
		biz.AgentCertificateClaim{
			OrganizationID: "organization",
			ManagedHostID:  "host",
			IdentityID:     "identity",
			InstanceID:     "instance",
		},
		[]byte("not-a-csr"),
		now,
	); err != ErrInvalidAgentCSR {
		t.Fatalf("error = %v", err)
	}
}

func TestCertificateIssuerRejectsCANotYetValid(t *testing.T) {
	now := time.Now().UTC()
	caCertificate, caPrivateKey := testCertificateAuthority(t, now.Add(2*time.Hour))
	issuer, err := NewCertificateIssuer(caCertificate, caPrivateKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader, &x509.CertificateRequest{}, agentKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(
		t.Context(),
		biz.AgentCertificateClaim{
			OrganizationID: "organization",
			ManagedHostID:  "host",
			IdentityID:     "identity",
			InstanceID:     "instance",
		},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		now,
	); err != ErrInvalidAgentCA {
		t.Fatalf("error = %v", err)
	}
}

func testCertificateAuthority(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OwnDock Test Agent CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, privateKey.Public(), privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
