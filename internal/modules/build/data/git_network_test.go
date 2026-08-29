package data

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

type repositorySecretResolverFunc func(context.Context, biz.RepositoryCredential) ([]byte, error)

func (f repositorySecretResolverFunc) ResolveRepositoryCredential(
	ctx context.Context,
	credential biz.RepositoryCredential,
) ([]byte, error) {
	return f(ctx, credential)
}

func TestGitNetworkPolicyRejectsUnsafeTrustConfiguration(t *testing.T) {
	certificate := testCertificatePEM(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := newGitNetworkPolicy(GitNetworkOptions{
		CACertFile: caFile, HTTPSProxyURL: "http://proxy.internal:3128",
	})
	if err != nil || policy.caCertFile != caFile || len(policy.caBundle) == 0 ||
		policy.proxy.URL != "http://proxy.internal:3128" {
		t.Fatalf("valid policy = %+v, %v", policy, err)
	}

	invalidPEM := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalidPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "ca-link.pem")
	if err := os.Symlink(caFile, symlink); err != nil {
		t.Fatal(err)
	}
	for _, options := range []GitNetworkOptions{
		{CACertFile: "relative.pem"},
		{CACertFile: invalidPEM},
		{CACertFile: symlink},
		{HTTPSProxyURL: "http://user:secret@proxy.internal:3128"},
		{HTTPSProxyURL: "http://proxy.internal:3128/path"},
		{HTTPSProxyURL: "socks5://proxy.internal:1080"},
		{HTTPSProxyURL: "http://proxy.internal:65536"},
	} {
		if _, err := newGitNetworkPolicy(options); !errors.Is(err, ErrInvalidGitNetwork) {
			t.Errorf("options %+v error = %v", options, err)
		}
	}
}

func TestGitCheckoutDoesNotInheritAmbientTrustOrProxy(t *testing.T) {
	gateway := &GitCheckoutGateway{
		lookupEnv: func(name string) (string, bool) {
			return map[string]string{
				"PATH": "/usr/bin", "SSL_CERT_FILE": "/tmp/ambient-ca.pem",
				"GIT_SSL_CAINFO": "/tmp/ambient-git-ca.pem",
				"HTTPS_PROXY":    "http://user:secret@ambient-proxy:3128",
			}[name], true
		},
	}
	environment := strings.Join(gateway.baseEnvironment(t.TempDir()), "\n")
	if !strings.Contains(environment, "PATH=/usr/bin") ||
		strings.Contains(environment, "ambient-ca") || strings.Contains(environment, "ambient-proxy") ||
		strings.Contains(environment, "secret") {
		t.Fatalf("base environment = %q", environment)
	}
}

func TestGitHTTPSProbeAndCheckoutUseExplicitCAAndProxy(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git CLI is unavailable")
	}
	projectRoot := t.TempDir()
	_, commitSHA := createHTTPGitFixture(t, gitPath, projectRoot)
	const username, token = "builder", "fixture-access-token"
	backend := gitHTTPBackend(t, gitPath, projectRoot)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+token))
		if request.Header.Get("Authorization") != expected {
			response.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(response, "authentication required", http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(response, request)
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "git-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy, proxyConnections := startCONNECTProxy(t)
	defer proxy.Close()
	network := GitNetworkOptions{CACertFile: caFile, HTTPSProxyURL: proxy.URL}
	resolver := repositorySecretResolverFunc(func(context.Context, biz.RepositoryCredential) ([]byte, error) {
		return []byte(token), nil
	})
	credential := biz.RepositoryCredential{
		ID: "credential-1", ProjectID: "project-1", Type: biz.CredentialTypeHTTPSAccessToken,
		Username: username, SecretRef: "secret://git-token",
	}
	source := biz.SourceRepository{
		ID: "source-1", ProjectID: "project-1", DefaultBranch: "main",
		RepositoryURL: server.URL + "/repository.git", Protocol: biz.RepositoryProtocolHTTPS,
		CredentialID: credential.ID,
	}
	prober, err := NewGitSourceProberWithNetwork(resolver, network)
	if err != nil {
		t.Fatal(err)
	}
	if status, probeErr := prober.ProbeSource(t.Context(), source, &credential); probeErr != nil || status != biz.SourceRepositoryStatusReady {
		t.Fatalf("ProbeSource(real HTTPS) = %s, %v", status, probeErr)
	}
	revision, err := prober.ResolveSourceRevision(
		t.Context(), source, &credential, "refs/heads/main", commitSHA,
	)
	if err != nil || revision.CommitSHA != commitSHA {
		t.Fatalf("ResolveSourceRevision(real HTTPS) = %+v, %v", revision, err)
	}
	version := strings.TrimPrefix(strings.TrimSpace(runFixtureGit(t, gitPath, "", "--version")), "git version ")
	checkout, err := NewGitCheckoutGateway(resolver, GitCheckoutOptions{
		Executable: gitPath, ExpectedVersion: version, Timeout: time.Minute,
		MaxWorkspaceBytes: 10 * 1024 * 1024, MaxWorkspaceFiles: 1000, Network: network,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "checkout")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkout.Checkout(t.Context(), biz.CheckoutRequest{
		Source: source, Credential: &credential, Revision: revision, Destination: destination,
	}); err != nil {
		t.Fatalf("Checkout(real HTTPS through proxy) = %v", err)
	}
	if proxyConnections.Load() < 3 {
		t.Fatalf("proxy CONNECT count = %d, want probe, resolve, and checkout", proxyConnections.Load())
	}

	untrusted := NewGitSourceProber(resolver)
	if status, probeErr := untrusted.ProbeSource(t.Context(), source, &credential); probeErr != nil || status != biz.SourceRepositoryStatusUnreachable {
		t.Fatalf("probe without explicit CA = %s, %v", status, probeErr)
	}
	badResolver := repositorySecretResolverFunc(func(context.Context, biz.RepositoryCredential) ([]byte, error) {
		return []byte("wrong-token"), nil
	})
	badAuth, err := NewGitSourceProberWithNetwork(badResolver, network)
	if err != nil {
		t.Fatal(err)
	}
	if status, probeErr := badAuth.ProbeSource(t.Context(), source, &credential); probeErr != nil || status != biz.SourceRepositoryStatusAuthenticationError {
		t.Fatalf("probe with wrong token = %s, %v", status, probeErr)
	}
	unavailableProxy, err := NewGitSourceProberWithNetwork(resolver, GitNetworkOptions{
		CACertFile: caFile, HTTPSProxyURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if status, probeErr := unavailableProxy.ProbeSource(t.Context(), source, &credential); probeErr != nil || status != biz.SourceRepositoryStatusUnreachable {
		t.Fatalf("probe with unavailable proxy = %s, %v", status, probeErr)
	}
}

func TestGitSSHProberUsesPinnedHostAndDeployKeyAgainstRealService(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git CLI is unavailable")
	}
	projectRoot := t.TempDir()
	bareRepository, commitSHA := createHTTPGitFixture(t, gitPath, projectRoot)
	deployPrivateKey, deployPublicKey := testOpenSSHMaterials(t)
	hostPrivateKey, hostPublicKey := testSSHMaterials(t)
	hostSigner, err := ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	address := startGitSSHFixture(t, gitPath, bareRepository, hostSigner, deployPublicKey)
	resolver := repositorySecretResolverFunc(func(context.Context, biz.RepositoryCredential) ([]byte, error) {
		return append([]byte(nil), deployPrivateKey...), nil
	})
	credential := biz.RepositoryCredential{
		ID: "credential-1", ProjectID: "project-1", Type: biz.CredentialTypeSSHDeployKey,
		SecretRef: "secret://deploy-key", PublicKeyFingerprint: ssh.FingerprintSHA256(deployPublicKey),
	}
	source := biz.SourceRepository{
		ID: "source-1", ProjectID: "project-1", DefaultBranch: "main",
		RepositoryURL: "ssh://git@" + address + "/repository.git", Protocol: biz.RepositoryProtocolSSH,
		CredentialID: credential.ID, SSHHostKeyFingerprint: ssh.FingerprintSHA256(hostPublicKey),
	}
	prober := NewGitSourceProber(resolver)
	if status, probeErr := prober.ProbeSource(t.Context(), source, &credential); probeErr != nil || status != biz.SourceRepositoryStatusReady {
		t.Fatalf("ProbeSource(real SSH) = %s, %v", status, probeErr)
	}
	revision, err := prober.ResolveSourceRevision(
		t.Context(), source, &credential, "refs/heads/main", commitSHA,
	)
	if err != nil || revision.CommitSHA != commitSHA {
		t.Fatalf("ResolveSourceRevision(real SSH) = %+v, %v", revision, err)
	}
	changed := source
	changed.SSHHostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if status, probeErr := prober.ProbeSource(t.Context(), changed, &credential); probeErr != nil || status != biz.SourceRepositoryStatusHostKeyMismatch {
		t.Fatalf("changed Host Key = %s, %v", status, probeErr)
	}
}

func startCONNECTProxy(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	connections := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(response, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.DialTimeout("tcp", request.Host, 5*time.Second)
		if err != nil {
			http.Error(response, "upstream unavailable", http.StatusBadGateway)
			return
		}
		hijacker, ok := response.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			http.Error(response, "tunnel unsupported", http.StatusInternalServerError)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		connections.Add(1)
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		go tunnelConnections(client, upstream)
	}))
	return server, connections
}

func tunnelConnections(left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	<-done
}

func testCertificatePEM(t *testing.T) []byte {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}
