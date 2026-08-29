package data

import (
	"context"
	"errors"
	"net"
	"net/http"
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
	network  gitNetworkPolicy
	list     listRemoteFunc
	resolve  listRemoteFunc
}

func NewGitSourceProber(resolver RepositorySecretResolver) *GitSourceProber {
	prober, _ := NewGitSourceProberWithNetwork(resolver, GitNetworkOptions{})
	return prober

}

func NewGitSourceProberWithNetwork(
	resolver RepositorySecretResolver,
	options GitNetworkOptions,
) (*GitSourceProber, error) {
	network, err := newGitNetworkPolicy(options)
	if err != nil {
		return nil, err
	}
	prober := &GitSourceProber{resolver: resolver, timeout: defaultSourceProbeTimeout, network: network}
	prober.list = func(ctx context.Context, repositoryURL string, auth transport.AuthMethod,
		timeout time.Duration) ([]*plumbing.Reference, error) {
		return listRemote(ctx, repositoryURL, auth, timeout, network)
	}
	prober.resolve = func(ctx context.Context, repositoryURL string, auth transport.AuthMethod,
		timeout time.Duration) ([]*plumbing.Reference, error) {
		return listRemotePeeled(ctx, repositoryURL, auth, timeout, network)
	}
	return prober, nil
}

func (p *GitSourceProber) ResolveSourceRevision(
	ctx context.Context,
	source biz.SourceRepository,
	credential *biz.RepositoryCredential,
	ref, expectedCommitSHA string,
) (biz.SourceRevision, error) {
	if err := ctx.Err(); err != nil {
		return biz.SourceRevision{}, err
	}
	resolveContext, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	auth, secret, status := p.authentication(resolveContext, source, credential)
	if secret != nil {
		defer clearBytes(secret)
	}
	if status != "" {
		if err := ctx.Err(); err != nil {
			return biz.SourceRevision{}, err
		}
		return biz.SourceRevision{}, biz.ErrRevisionResolveUnavailable
	}
	references, err := p.resolve(resolveContext, source.RepositoryURL, auth, p.timeout)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return biz.SourceRevision{}, err
		}
		return biz.SourceRevision{}, biz.ErrRevisionResolveUnavailable
	}
	wanted := plumbing.ReferenceName(ref)
	peeled := plumbing.ReferenceName(ref + "^{}")
	var commit plumbing.Hash
	for _, reference := range references {
		if reference != nil && reference.Name() == wanted {
			commit = reference.Hash()
		}
	}
	for _, reference := range references {
		if reference != nil && reference.Name() == peeled {
			commit = reference.Hash()
			break
		}
	}
	if commit.IsZero() {
		return biz.SourceRevision{}, biz.ErrRevisionNotFound
	}
	commitSHA := commit.String()
	if expectedCommitSHA != "" && !strings.EqualFold(expectedCommitSHA, commitSHA) {
		return biz.SourceRevision{}, biz.ErrRevisionMismatch
	}
	return biz.NewSourceRevision(source.ID, ref, commitSHA)
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
	network gitNetworkPolicy,
) ([]*plumbing.Reference, error) {
	if strings.HasPrefix(repositoryURL, "https://") {
		return listHTTPSRemote(ctx, repositoryURL, auth, network, git.IgnorePeeled)
	}
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin", URLs: []string{repositoryURL},
	})
	seconds := int(timeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return remote.ListContext(ctx, &git.ListOptions{
		Auth: auth, InsecureSkipTLS: false,
		CABundle: network.caBundle, ProxyOptions: network.proxyFor(repositoryURL),
		PeelingOption: git.IgnorePeeled, Timeout: seconds,
	})
}

func listRemotePeeled(
	ctx context.Context,
	repositoryURL string,
	auth transport.AuthMethod,
	timeout time.Duration,
	network gitNetworkPolicy,
) ([]*plumbing.Reference, error) {
	if strings.HasPrefix(repositoryURL, "https://") {
		return listHTTPSRemote(ctx, repositoryURL, auth, network, git.AppendPeeled)
	}
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin", URLs: []string{repositoryURL},
	})
	seconds := int(timeout.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return remote.ListContext(ctx, &git.ListOptions{
		Auth: auth, InsecureSkipTLS: false,
		CABundle: network.caBundle, ProxyOptions: network.proxyFor(repositoryURL),
		PeelingOption: git.AppendPeeled, Timeout: seconds,
	})
}

func listHTTPSRemote(ctx context.Context, repositoryURL string, auth transport.AuthMethod,
	network gitNetworkPolicy, peeling git.PeelingOption) ([]*plumbing.Reference, error) {
	endpoint, err := transport.NewEndpoint(repositoryURL)
	if err != nil {
		return nil, err
	}
	endpoint.CaBundle = network.caBundle
	endpoint.Proxy = network.proxy
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, biz.ErrRevisionResolveUnavailable
	}
	directTransport := base.Clone()
	directTransport.Proxy = nil
	client := httptransport.NewClient(&http.Client{Transport: directTransport})
	session, err := client.NewUploadPackSession(endpoint, auth)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	advertised, err := session.AdvertisedReferencesContext(ctx)
	if err != nil {
		return nil, err
	}
	all, err := advertised.AllReferences()
	if err != nil {
		return nil, err
	}
	iterator, err := all.IterReferences()
	if err != nil {
		return nil, err
	}
	defer iterator.Close()
	result := make([]*plumbing.Reference, 0, 32)
	if peeling == git.AppendPeeled || peeling == git.IgnorePeeled {
		if err := iterator.ForEach(func(reference *plumbing.Reference) error {
			result = append(result, reference)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if peeling == git.AppendPeeled || peeling == git.OnlyPeeled {
		for name, hash := range advertised.Peeled {
			result = append(result, plumbing.NewReferenceFromStrings(name+"^{}", hash.String()))
		}
	}
	return result, nil
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
var _ biz.SourceRevisionResolver = (*GitSourceProber)(nil)
