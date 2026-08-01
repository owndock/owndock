package data

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

func TestGitCheckoutRequiresPinnedVersion(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf '%s\\n' 'git version 2.55.0'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGitCheckoutGateway(nil, GitCheckoutOptions{Executable: executable}); err != nil {
		t.Fatalf("pinned Git was rejected: %v", err)
	}
	if _, err := NewGitCheckoutGateway(nil, GitCheckoutOptions{
		Executable: executable, ExpectedVersion: "2.54.0",
	}); err != ErrGitVersionMismatch {
		t.Fatalf("version mismatch error = %v", err)
	}
}

func TestGitCheckoutHTTPSKeepsSecretOutOfArgumentsAndEnvironment(t *testing.T) {
	secret := []byte("customer-token-do-not-leak")
	resolver := repositorySecretResolverStub{secret: secret}
	gateway := &GitCheckoutGateway{
		timeout: time.Minute, maxBytes: 1024 * 1024, maxFiles: 100,
		resolver: resolver, lookupEnv: func(string) (string, bool) { return "", false },
	}
	gateway.run = func(_ context.Context, _ string, environment []string, arguments ...string) ([]byte, error) {
		joined := strings.Join(append(append([]string(nil), environment...), arguments...), "\n")
		if strings.Contains(joined, "customer-token-do-not-leak") {
			t.Fatal("credential appeared in Git arguments or environment")
		}
		if containsArgument(arguments, "fetch") {
			tokenFile := environmentNamed(environment, "OWNDOCK_GIT_TOKEN_FILE")
			value, err := os.ReadFile(tokenFile)
			if err != nil || string(value) != "customer-token-do-not-leak" {
				t.Fatalf("temporary token file = %q/%v", value, err)
			}
		}
		if containsArgument(arguments, "rev-parse") {
			return []byte("a975c10d68a2d7461634f13b15c52a2efba72d16\n"), nil
		}
		return nil, nil
	}
	destination := filepath.Join(t.TempDir(), "checkout")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	credential := biz.RepositoryCredential{
		ID: "credential-1", ProjectID: "project-1", Type: biz.CredentialTypeHTTPSAccessToken,
		Username: "builder", SecretRef: "secret://git-token",
	}
	err := gateway.Checkout(t.Context(), biz.CheckoutRequest{
		Source: biz.SourceRepository{
			ID: "source-1", ProjectID: "project-1", RepositoryURL: "https://git.example.com/team/api.git",
			Protocol: biz.RepositoryProtocolHTTPS, CredentialID: credential.ID,
		},
		Credential:  &credential,
		Revision:    biz.SourceRevision{SourceRepositoryID: "source-1", Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16"},
		Destination: destination,
	})
	if err != nil {
		t.Fatalf("Checkout() error = %v", err)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatalf("resolved secret was not cleared: %v", secret)
		}
	}
}

func TestGitCheckoutStopsFetchWhenWorkspaceLimitIsExceeded(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "checkout")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := &GitCheckoutGateway{
		timeout: time.Minute, maxBytes: 32, maxFiles: 100,
		lookupEnv: func(string) (string, bool) { return "", false },
	}
	var fetchCanceled bool
	gateway.run = func(ctx context.Context, _ string, _ []string, arguments ...string) ([]byte, error) {
		if !containsArgument(arguments, "fetch") {
			return nil, nil
		}
		if err := os.WriteFile(filepath.Join(destination, "oversized-pack"), make([]byte, 33), 0o600); err != nil {
			return nil, err
		}
		<-ctx.Done()
		fetchCanceled = true
		return nil, ctx.Err()
	}
	err := gateway.Checkout(t.Context(), biz.CheckoutRequest{
		Source: biz.SourceRepository{
			ID: "source-1", ProjectID: "project-1", RepositoryURL: "https://git.example.com/team/api.git",
			Protocol: biz.RepositoryProtocolHTTPS,
		},
		Revision:    biz.SourceRevision{SourceRepositoryID: "source-1", Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16"},
		Destination: destination,
	})
	if err != biz.ErrCheckoutResourceLimit || !fetchCanceled {
		t.Fatalf("Checkout() = %v, fetch canceled = %t", err, fetchCanceled)
	}
}

func TestGitCheckoutPreservesCallerCancellation(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "checkout")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := &GitCheckoutGateway{
		timeout: time.Minute, maxBytes: 1024, maxFiles: 100,
		lookupEnv: func(string) (string, bool) { return "", false },
	}
	gateway.run = func(ctx context.Context, _ string, _ []string, arguments ...string) ([]byte, error) {
		if containsArgument(arguments, "fetch") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := gateway.Checkout(ctx, biz.CheckoutRequest{
		Source: biz.SourceRepository{
			ID: "source-1", ProjectID: "project-1", RepositoryURL: "https://git.example.com/team/api.git",
			Protocol: biz.RepositoryProtocolHTTPS,
		},
		Revision:    biz.SourceRevision{SourceRepositoryID: "source-1", Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16"},
		Destination: destination,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Checkout() = %v, want caller cancellation", err)
	}
}

func TestGitCheckoutWithRealHTTPSRemoteVerifiesCommitAndCleansConfig(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git CLI is unavailable")
	}
	projectRoot := t.TempDir()
	bareRepository, commitSHA := createHTTPGitFixture(t, gitPath, projectRoot)
	server := httptest.NewTLSServer(gitHTTPBackend(t, gitPath, projectRoot))
	defer server.Close()
	certificateFile := filepath.Join(t.TempDir(), "git-test-ca.pem")
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test TLS server certificate is missing")
	}
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "checkout")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := &GitCheckoutGateway{
		executable: gitPath, timeout: time.Minute, maxBytes: 10 * 1024 * 1024, maxFiles: 1000,
		lookupEnv: func(name string) (string, bool) {
			if name == "SSL_CERT_FILE" || name == "GIT_SSL_CAINFO" {
				return certificateFile, true
			}
			if name == "PATH" {
				return os.Getenv("PATH"), true
			}
			return "", false
		},
	}
	gateway.run = func(ctx context.Context, directory string, environment []string, arguments ...string) ([]byte, error) {
		return runGitCommand(ctx, gitPath, directory, environment, arguments...)
	}
	repositoryURL := server.URL + "/" + filepath.Base(bareRepository)
	request := biz.CheckoutRequest{
		Source:      biz.SourceRepository{ID: "source-1", ProjectID: "project-1", RepositoryURL: repositoryURL, Protocol: biz.RepositoryProtocolHTTPS},
		Revision:    biz.SourceRevision{SourceRepositoryID: "source-1", Ref: "refs/heads/main", CommitSHA: commitSHA},
		Destination: destination,
	}
	if err := gateway.Checkout(t.Context(), request); err != nil {
		t.Fatalf("Checkout(real HTTPS) error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "README.md"))
	if err != nil || string(content) != "exact revision\n" {
		t.Fatalf("checked out content = %q/%v", content, err)
	}
	wrong := request
	wrong.Revision.CommitSHA = strings.Repeat("b", 40)
	wrong.Destination = filepath.Join(t.TempDir(), "wrong")
	if err := os.Mkdir(wrong.Destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Checkout(t.Context(), wrong); err != biz.ErrCheckoutRevision {
		t.Fatalf("wrong Commit error = %v", err)
	}
}

func TestGitCheckoutWithRealSSHRemotePinsHostAndDeployKeys(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git CLI is unavailable")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client is unavailable")
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
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	credential := biz.RepositoryCredential{
		ID: "credential-1", ProjectID: "project-1", Type: biz.CredentialTypeSSHDeployKey,
		SecretRef: "secret://deploy-key", PublicKeyFingerprint: ssh.FingerprintSHA256(deployPublicKey),
	}
	secret := append([]byte(nil), deployPrivateKey...)
	gateway := &GitCheckoutGateway{
		executable: gitPath, timeout: time.Minute, maxBytes: 10 * 1024 * 1024, maxFiles: 1000,
		resolver: repositorySecretResolverStub{secret: secret},
		lookupEnv: func(name string) (string, bool) {
			if name == "PATH" {
				return os.Getenv("PATH"), true
			}
			return "", false
		},
	}
	gateway.run = func(ctx context.Context, directory string, environment []string, arguments ...string) ([]byte, error) {
		return runGitCommand(ctx, gitPath, directory, environment, arguments...)
	}
	destination := filepath.Join(t.TempDir(), "checkout")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	request := biz.CheckoutRequest{
		Source: biz.SourceRepository{
			ID: "source-1", ProjectID: "project-1",
			RepositoryURL: "ssh://git@" + net.JoinHostPort(host, port) + "/repository.git",
			Protocol:      biz.RepositoryProtocolSSH, CredentialID: credential.ID,
			SSHHostKeyFingerprint: ssh.FingerprintSHA256(hostPublicKey),
		},
		Credential:  &credential,
		Revision:    biz.SourceRevision{SourceRepositoryID: "source-1", Ref: "refs/heads/main", CommitSHA: commitSHA},
		Destination: destination,
	}
	if err := gateway.Checkout(t.Context(), request); err != nil {
		t.Fatalf("Checkout(real SSH) error = %v", err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "README.md"))
	if err != nil || string(content) != "exact revision\n" {
		t.Fatalf("checked out SSH content = %q/%v", content, err)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatal("SSH private key was not cleared")
		}
	}

	badHost := request
	badHost.Destination = filepath.Join(t.TempDir(), "bad-host")
	badHost.Source.SSHHostKeyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := os.Mkdir(badHost.Destination, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway.resolver = repositorySecretResolverStub{secret: append([]byte(nil), deployPrivateKey...)}
	if err := gateway.Checkout(t.Context(), badHost); err != biz.ErrCheckoutAuthentication {
		t.Fatalf("changed SSH Host Key error = %v", err)
	}
}

func startGitSSHFixture(t *testing.T, gitPath, repository string, hostSigner ssh.Signer, authorized ssh.PublicKey) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	configuration := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return nil, fmt.Errorf("unauthorized key")
			}
			return nil, nil
		},
	}
	configuration.AddHostKey(hostSigner)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveGitSSHConnection(gitPath, repository, configuration, connection)
		}
	}()
	return listener.Addr().String()
}

func testOpenSSHMaterials(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), publicKey
}

func serveGitSSHConnection(gitPath, repository string, configuration *ssh.ServerConfig, connection net.Conn) {
	server, channels, requests, err := ssh.NewServerConn(connection, configuration)
	if err != nil {
		_ = connection.Close()
		return
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for candidate := range channels {
		if candidate.ChannelType() != "session" {
			_ = candidate.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, channelRequests, err := candidate.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range channelRequests {
				if request.Type != "exec" {
					_ = request.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if err := ssh.Unmarshal(request.Payload, &payload); err != nil ||
					!strings.HasPrefix(payload.Command, "git-upload-pack ") {
					_ = request.Reply(false, nil)
					continue
				}
				command := exec.Command(gitPath, "upload-pack", repository)
				command.Stdin, command.Stdout, command.Stderr = channel, channel, channel.Stderr()
				if err := command.Start(); err != nil {
					_ = request.Reply(false, nil)
					return
				}
				_ = request.Reply(true, nil)
				status := uint32(0)
				if err := command.Wait(); err != nil {
					status = 1
				}
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				return
			}
		}()
	}
}

func createHTTPGitFixture(t *testing.T, gitPath, projectRoot string) (string, string) {
	t.Helper()
	work := filepath.Join(t.TempDir(), "source")
	runFixtureGit(t, gitPath, "", "init", "--quiet", "--initial-branch=main", work)
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("exact revision\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, gitPath, work, "-c", "user.name=OwnDock Test", "-c", "user.email=test@owndock.net", "add", "README.md")
	runFixtureGit(t, gitPath, work, "-c", "user.name=OwnDock Test", "-c", "user.email=test@owndock.net", "commit", "--quiet", "-m", "fixture")
	commit := strings.TrimSpace(runFixtureGit(t, gitPath, work, "rev-parse", "HEAD"))
	bare := filepath.Join(projectRoot, "repository.git")
	runFixtureGit(t, gitPath, "", "clone", "--quiet", "--bare", work, bare)
	return bare, commit
}

func gitHTTPBackend(t *testing.T, gitPath, projectRoot string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		command := exec.Command(gitPath, "http-backend")
		command.Env = append(os.Environ(),
			"GIT_PROJECT_ROOT="+projectRoot,
			"GIT_HTTP_EXPORT_ALL=1",
			"PATH_INFO="+request.URL.Path,
			"QUERY_STRING="+request.URL.RawQuery,
			"REQUEST_METHOD="+request.Method,
			"CONTENT_TYPE="+request.Header.Get("Content-Type"),
			"CONTENT_LENGTH="+strconv.FormatInt(request.ContentLength, 10),
		)
		command.Stdin = request.Body
		output, err := command.Output()
		if err != nil {
			http.Error(response, "Git backend unavailable", http.StatusBadGateway)
			return
		}
		reader := bufio.NewReader(bytes.NewReader(output))
		status := http.StatusOK
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				http.Error(response, "Git backend response invalid", http.StatusBadGateway)
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			name, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			value = strings.TrimSpace(value)
			if strings.EqualFold(name, "Status") {
				fields := strings.Fields(value)
				if len(fields) > 0 {
					status, _ = strconv.Atoi(fields[0])
				}
				continue
			}
			response.Header().Add(name, value)
		}
		response.WriteHeader(status)
		_, _ = io.Copy(response, reader)
	})
}

func runFixtureGit(t *testing.T, gitPath, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command(gitPath, arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture Git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}

func containsArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}

func environmentNamed(environment []string, name string) string {
	prefix := name + "="
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix)
		}
	}
	return ""
}
