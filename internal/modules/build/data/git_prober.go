package data

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	httptransport "github.com/go-git/go-git/v5/plumbing/transport/http"
	sshtransport "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/crypto/ssh"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

const defaultSourceProbeTimeout = 10 * time.Second

var errSSHHostKeyMismatch = errors.New("SSH host key does not match pinned fingerprint")

type listRemoteFunc func(
	context.Context,
	string,
	transport.AuthMethod,
	time.Duration,
) ([]*plumbing.Reference, error)

type GitSourceProber struct {
	resolver RepositorySecretResolver
	timeout  time.Duration
	list     listRemoteFunc
}

func NewGitSourceProber(resolver RepositorySecretResolver) *GitSourceProber {
	return &GitSourceProber{
		resolver: resolver,
		timeout:  defaultSourceProbeTimeout,
		list:     listRemote,
	}
}

func (p *GitSourceProber) WithTimeout(timeout time.Duration) *GitSourceProber {
	if timeout > 0 {
		p.timeout = timeout
	}
	return p
}

func (p *GitSourceProber) ProbeSource(
	ctx context.Context,
	source biz.SourceRepository,
	credential *biz.RepositoryCredential,
) (biz.SourceRepositoryStatus, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	probeContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	auth, secret, status := p.authentication(probeContext, source, credential)
	if secret != nil {
		defer clearBytes(secret)
	}
	if status != "" {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return status, nil
	}
	references, err := p.list(probeContext, source.RepositoryURL, auth, p.timeout)
	if err != nil {
		if contextErr := probeContext.Err(); contextErr != nil {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return biz.SourceRepositoryStatusUnreachable, nil
		}
		return classifyProbeError(err), nil
	}
	wanted := plumbing.NewBranchReferenceName(source.DefaultBranch)
	for _, reference := range references {
		if reference != nil && reference.Name() == wanted {
			return biz.SourceRepositoryStatusReady, nil
		}
	}
	return biz.SourceRepositoryStatusReferenceNotFound, nil
}

func (p *GitSourceProber) authentication(
	ctx context.Context,
	source biz.SourceRepository,
	credential *biz.RepositoryCredential,
) (transport.AuthMethod, []byte, biz.SourceRepositoryStatus) {
	if credential == nil {
		if source.Protocol == biz.RepositoryProtocolSSH {
			return nil, nil, biz.SourceRepositoryStatusAuthenticationError
		}
		return nil, nil, ""
	}
	if p.resolver == nil || !biz.CredentialSupportsProtocol(*credential, source.Protocol) {
		return nil, nil, biz.SourceRepositoryStatusAuthenticationError
	}
	secret, err := p.resolver.ResolveRepositoryCredential(ctx, *credential)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, biz.SourceRepositoryStatusUnreachable
		}
		return nil, nil, biz.SourceRepositoryStatusAuthenticationError
	}
	switch source.Protocol {
	case biz.RepositoryProtocolHTTPS:
		username := strings.TrimSpace(credential.Username)
		if username == "" {
			username = "git"
		}
		return &httptransport.BasicAuth{Username: username, Password: string(secret)}, secret, ""
	case biz.RepositoryProtocolSSH:
		publicKeys, err := sshtransport.NewPublicKeys(sshUsername(source.RepositoryURL), secret, "")
		if err != nil {
			clearBytes(secret)
			return nil, nil, biz.SourceRepositoryStatusAuthenticationError
		}
		if ssh.FingerprintSHA256(publicKeys.Signer.PublicKey()) != credential.PublicKeyFingerprint {
			clearBytes(secret)
			return nil, nil, biz.SourceRepositoryStatusAuthenticationError
		}
		pinnedFingerprint := source.SSHHostKeyFingerprint
		publicKeys.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != pinnedFingerprint {
				return errSSHHostKeyMismatch
			}
			return nil
		}
		return publicKeys, secret, ""
	default:
		clearBytes(secret)
		return nil, nil, biz.SourceRepositoryStatusUnreachable
	}
}

func listRemote(
	ctx context.Context,
	repositoryURL string,
	auth transport.AuthMethod,
	timeout time.Duration,
) ([]*plumbing.Reference, error) {
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin", URLs: []string{repositoryURL},
	})
	seconds := int(timeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return remote.ListContext(ctx, &git.ListOptions{
		Auth: auth, InsecureSkipTLS: false,
		PeelingOption: git.IgnorePeeled, Timeout: seconds,
	})
}

func classifyProbeError(err error) biz.SourceRepositoryStatus {
	switch {
	case errors.Is(err, errSSHHostKeyMismatch):
		return biz.SourceRepositoryStatusHostKeyMismatch
	case errors.Is(err, transport.ErrAuthenticationRequired),
		errors.Is(err, transport.ErrAuthorizationFailed),
		errors.Is(err, transport.ErrRepositoryNotFound),
		errors.Is(err, transport.ErrInvalidAuthMethod):
		return biz.SourceRepositoryStatusAuthenticationError
	default:
		return biz.SourceRepositoryStatusUnreachable
	}
}

func sshUsername(repositoryURL string) string {
	if parsed, err := url.Parse(repositoryURL); err == nil && parsed.User != nil {
		if username := parsed.User.Username(); username != "" {
			return username
		}
	}
	if at := strings.IndexByte(repositoryURL, '@'); at > 0 {
		return repositoryURL[:at]
	}
	return "git"
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ biz.SourceProber = (*GitSourceProber)(nil)
