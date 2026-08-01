package data

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	httptransport "github.com/go-git/go-git/v5/plumbing/transport/http"
	sshtransport "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

type repositorySecretResolverStub struct {
	secret []byte
	err    error
}

func (s repositorySecretResolverStub) ResolveRepositoryCredential(
	context.Context,
	biz.RepositoryCredential,
) ([]byte, error) {
	return s.secret, s.err
}

func TestGitSourceProberListsHTTPSBranchAndClearsResolvedSecret(t *testing.T) {
	secret := []byte("customer-token")
	prober := NewGitSourceProber(repositorySecretResolverStub{secret: secret})
	prober.list = func(
		_ context.Context,
		repositoryURL string,
		auth transport.AuthMethod,
		_ time.Duration,
	) ([]*plumbing.Reference, error) {
		if repositoryURL != "https://git.example.com/team/api.git" {
			t.Fatalf("repository URL = %q", repositoryURL)
		}
		basic, ok := auth.(*httptransport.BasicAuth)
		if !ok || basic.Username != "builder" || basic.Password != "customer-token" {
			t.Fatalf("auth = %#v", auth)
		}
		return []*plumbing.Reference{
			plumbing.NewHashReference(plumbing.NewBranchReferenceName("main"), plumbing.ZeroHash),
		}, nil
	}
	status, err := prober.ProbeSource(
		context.Background(),
		biz.SourceRepository{
			RepositoryURL: "https://git.example.com/team/api.git",
			Protocol:      biz.RepositoryProtocolHTTPS, DefaultBranch: "main",
		},
		&biz.RepositoryCredential{
			Type: biz.CredentialTypeHTTPSAccessToken, Username: "builder",
		},
	)
	if err != nil || status != biz.SourceRepositoryStatusReady {
		t.Fatalf("ProbeSource() = %s, %v", status, err)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatalf("resolved secret was not cleared: %v", secret)
		}
	}
}

func TestGitSourceProberReportsMissingDefaultBranch(t *testing.T) {
	prober := NewGitSourceProber(nil)
	prober.list = func(
		context.Context,
		string,
		transport.AuthMethod,
		time.Duration,
	) ([]*plumbing.Reference, error) {
		return []*plumbing.Reference{
			plumbing.NewHashReference(plumbing.NewBranchReferenceName("develop"), plumbing.ZeroHash),
		}, nil
	}
	status, err := prober.ProbeSource(context.Background(), biz.SourceRepository{
		RepositoryURL: "https://git.example.com/team/api.git",
		Protocol:      biz.RepositoryProtocolHTTPS, DefaultBranch: "main",
	}, nil)
	if err != nil || status != biz.SourceRepositoryStatusReferenceNotFound {
		t.Fatalf("ProbeSource() = %s, %v", status, err)
	}
}

func TestGitSourceProberPinsSSHHostKey(t *testing.T) {
	privateKeyPEM, deployKey := testSSHMaterials(t)
	_, serverKey := testSSHMaterials(t)
	pinnedFingerprint := ssh.FingerprintSHA256(serverKey)
	prober := NewGitSourceProber(repositorySecretResolverStub{secret: privateKeyPEM})
	prober.list = func(
		_ context.Context,
		_ string,
		auth transport.AuthMethod,
		_ time.Duration,
	) ([]*plumbing.Reference, error) {
		keys, ok := auth.(*sshtransport.PublicKeys)
		if !ok || keys.User != "deploy" {
			t.Fatalf("auth = %#v", auth)
		}
		if err := keys.HostKeyCallback("git.example.com:22", &net.TCPAddr{}, serverKey); err != nil {
			return nil, err
		}
		return []*plumbing.Reference{
			plumbing.NewHashReference(plumbing.NewBranchReferenceName("main"), plumbing.ZeroHash),
		}, nil
	}
	status, err := prober.ProbeSource(context.Background(), biz.SourceRepository{
		RepositoryURL: "deploy@git.example.com:team/api.git",
		Protocol:      biz.RepositoryProtocolSSH, DefaultBranch: "main",
		SSHHostKeyFingerprint: pinnedFingerprint,
	}, &biz.RepositoryCredential{
		Type:                 biz.CredentialTypeSSHDeployKey,
		PublicKeyFingerprint: ssh.FingerprintSHA256(deployKey),
	})
	if err != nil || status != biz.SourceRepositoryStatusReady {
		t.Fatalf("ProbeSource() = %s, %v", status, err)
	}
}

func TestGitSourceProberRejectsChangedSSHHostKey(t *testing.T) {
	privateKeyPEM, deployKey := testSSHMaterials(t)
	_, unexpectedServerKey := testSSHMaterials(t)
	prober := NewGitSourceProber(repositorySecretResolverStub{secret: privateKeyPEM})
	prober.list = func(
		_ context.Context,
		_ string,
		auth transport.AuthMethod,
		_ time.Duration,
	) ([]*plumbing.Reference, error) {
		keys := auth.(*sshtransport.PublicKeys)
		return nil, keys.HostKeyCallback("git.example.com:22", &net.TCPAddr{}, unexpectedServerKey)
	}
	status, err := prober.ProbeSource(context.Background(), biz.SourceRepository{
		RepositoryURL: "git@git.example.com:team/api.git",
		Protocol:      biz.RepositoryProtocolSSH, DefaultBranch: "main",
		SSHHostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}, &biz.RepositoryCredential{
		Type:                 biz.CredentialTypeSSHDeployKey,
		PublicKeyFingerprint: ssh.FingerprintSHA256(deployKey),
	})
	if err != nil || status != biz.SourceRepositoryStatusHostKeyMismatch {
		t.Fatalf("ProbeSource() = %s, %v", status, err)
	}
}

func TestGitSourceProberRejectsDeployKeyFingerprintMismatch(t *testing.T) {
	privateKeyPEM, _ := testSSHMaterials(t)
	called := false
	prober := NewGitSourceProber(repositorySecretResolverStub{secret: privateKeyPEM})
	prober.list = func(
		context.Context,
		string,
		transport.AuthMethod,
		time.Duration,
	) ([]*plumbing.Reference, error) {
		called = true
		return nil, nil
	}
	status, err := prober.ProbeSource(context.Background(), biz.SourceRepository{
		RepositoryURL: "git@git.example.com:team/api.git",
		Protocol:      biz.RepositoryProtocolSSH, DefaultBranch: "main",
		SSHHostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}, &biz.RepositoryCredential{
		Type:                 biz.CredentialTypeSSHDeployKey,
		PublicKeyFingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	})
	if err != nil || status != biz.SourceRepositoryStatusAuthenticationError || called {
		t.Fatalf("ProbeSource() = %s, %v, transport called = %t", status, err, called)
	}
}

func TestGitSourceProberReturnsSafeFailureCategories(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status biz.SourceRepositoryStatus
	}{
		{name: "authentication", err: transport.ErrAuthenticationRequired, status: biz.SourceRepositoryStatusAuthenticationError},
		{name: "not found", err: transport.ErrRepositoryNotFound, status: biz.SourceRepositoryStatusAuthenticationError},
		{name: "network", err: errors.New("dial failed with sensitive details"), status: biz.SourceRepositoryStatusUnreachable},
	} {
		t.Run(test.name, func(t *testing.T) {
			prober := NewGitSourceProber(nil)
			prober.list = func(context.Context, string, transport.AuthMethod, time.Duration) ([]*plumbing.Reference, error) {
				return nil, test.err
			}
			status, err := prober.ProbeSource(context.Background(), biz.SourceRepository{
				RepositoryURL: "https://git.example.com/team/api.git",
				Protocol:      biz.RepositoryProtocolHTTPS, DefaultBranch: "main",
			}, nil)
			if err != nil || status != test.status {
				t.Fatalf("ProbeSource() = %s, %v", status, err)
			}
		})
	}
}

func TestGitSourceProberHonorsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	status, err := NewGitSourceProber(nil).ProbeSource(ctx, biz.SourceRepository{}, nil)
	if status != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("ProbeSource() = %s, %v", status, err)
	}
}

func testSSHMaterials(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), sshPublicKey
}
