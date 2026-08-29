package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	agentconfig "github.com/owndock/owndock/internal/agent/config"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestMaterialsAndConfigCreateStrictRunnableInputs(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "materials")
	if err := runMaterials([]string{"--output", directory}); err != nil {
		t.Fatal(err)
	}
	paths, err := pathsFor(directory)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string]os.FileMode{
		paths.ca:           0o644,
		paths.caKey:        0o600,
		paths.serverBundle: 0o600,
		paths.clientCert:   0o644,
		paths.clientKey:    0o600,
		paths.clientBundle: 0o600,
		paths.bootID:       0o600,
		paths.state:        0o700,
	} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s: %v", path, statErr)
		}
		if info.Mode().Perm() != expected {
			t.Fatalf("%s mode = %#o, want %#o", path, info.Mode().Perm(), expected)
		}
	}
	serverPEM, err := os.ReadFile(paths.serverBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(serverPEM, serverPEM); err != nil {
		t.Fatalf("server bundle: %v", err)
	}
	clientCertificatePEM, err := os.ReadFile(paths.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	clientPrivateKeyPEM, err := os.ReadFile(paths.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(clientCertificatePEM, clientPrivateKeyPEM)
	if err != nil {
		t.Fatalf("client pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(clientPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() !=
		"spiffe://owndock/organizations/conformance-organization/managed-hosts/"+
			"conformance-host/agents/conformance-identity/instances/conformance-instance" {
		t.Fatalf("client identity = %+v", leaf)
	}

	endpoint := "https://127.0.0.1:18443/api/v1/agent/connect"
	if err := runConfig([]string{"--output", directory, "--endpoint", endpoint}); err != nil {
		t.Fatal(err)
	}
	config, err := agentconfig.Load(paths.config)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.Endpoint != endpoint ||
		config.Control.OrganizationID != organizationID ||
		config.Control.ManagedHostID != hostID ||
		config.Control.IdentityID != identityID ||
		config.Control.InstanceID != instanceID ||
		len(config.Control.Capabilities) != 1 ||
		config.Control.Capabilities[0] != agentprotocol.CapabilityRuntimeProbe ||
		config.CertificateRotation.Enabled {
		t.Fatalf("generated config = %+v", config)
	}
}

func TestConformanceInputsFailClosed(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "materials")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runMaterials([]string{"--output", directory}); err == nil {
		t.Fatal("non-empty material directory unexpectedly succeeded")
	}
	if err := runConfig([]string{
		"--output", directory,
		"--endpoint", "https://example.com/api/v1/agent/connect",
	}); err == nil {
		t.Fatal("non-loopback conformance endpoint unexpectedly succeeded")
	}
	if _, err := pathsFor("relative"); err == nil {
		t.Fatal("relative conformance directory unexpectedly succeeded")
	}
}

func TestRotationConfigUsesOnePrivateIdentityBundle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "materials")
	if err := runMaterials([]string{"--output", directory}); err != nil {
		t.Fatal(err)
	}
	paths, err := pathsFor(directory)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://127.0.0.1:18444/api/v1/agent/connect"
	if err := runConfig([]string{
		"--output", directory, "--endpoint", endpoint, "--enable-rotation",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := agentconfig.Load(paths.config)
	if err != nil {
		t.Fatal(err)
	}
	if !config.CertificateRotation.Enabled ||
		config.Control.ClientCertificateFile != paths.clientBundle ||
		config.Control.ClientPrivateKeyFile != paths.clientBundle {
		t.Fatalf("rotation config = %+v", config)
	}
	info, err := os.Lstat(paths.clientBundle)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("rotation identity mode = %v", info.Mode())
	}
	bundle, err := os.ReadFile(paths.clientBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(bundle, bundle); err != nil {
		t.Fatalf("rotation identity bundle: %v", err)
	}
}

func TestAdditionalHostIdentityUsesSharedAuthority(t *testing.T) {
	root := t.TempDir()
	authority := filepath.Join(root, "authority")
	additional := filepath.Join(root, "additional")
	if err := runMaterials([]string{
		"--output", authority, "--host-id", "conformance-host-a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runIdentity([]string{
		"--authority", authority, "--output", additional,
		"--host-id", "conformance-host-b",
	}); err != nil {
		t.Fatal(err)
	}
	authorityPaths, _ := pathsFor(authority)
	additionalPaths, _ := pathsFor(additional)
	authorityCA, err := os.ReadFile(authorityPaths.ca)
	if err != nil {
		t.Fatal(err)
	}
	additionalCA, err := os.ReadFile(additionalPaths.ca)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authorityCA, additionalCA) {
		t.Fatal("additional Host did not reuse the shared control authority")
	}
	certificatePEM, err := os.ReadFile(additionalPaths.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(additionalPaths.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.String() != "5" || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() !=
			"spiffe://owndock/organizations/conformance-organization/managed-hosts/"+
				"conformance-host-b/agents/conformance-identity/instances/conformance-instance" {
		t.Fatalf("additional Host certificate = %+v", leaf)
	}
	endpoint := "https://127.0.0.1:18445/api/v1/agent/connect"
	if err := runConfig([]string{
		"--output", additional, "--endpoint", endpoint,
		"--host-id", "conformance-host-b",
	}); err != nil {
		t.Fatal(err)
	}
	config, err := agentconfig.Load(additionalPaths.config)
	if err != nil {
		t.Fatal(err)
	}
	if config.Control.ManagedHostID != "conformance-host-b" {
		t.Fatalf("additional Host config = %+v", config.Control)
	}
}
