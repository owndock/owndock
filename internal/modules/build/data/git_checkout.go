package data

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

const (
	PinnedGitVersion        = "2.55.0"
	defaultCheckoutTimeout  = 10 * time.Minute
	defaultCheckoutMaxBytes = int64(5 * 1024 * 1024 * 1024)
	defaultCheckoutMaxFiles = int64(250000)
	maximumGitCommandOutput = 64 * 1024
)

var (
	ErrGitVersionMismatch = errors.New("Git CLI version does not match the pinned version")
	ErrInvalidGitCheckout = errors.New("Git checkout configuration is invalid")
)

type GitCheckoutOptions struct {
	Executable        string
	ExpectedVersion   string
	Timeout           time.Duration
	MaxWorkspaceBytes int64
	MaxWorkspaceFiles int64
}

type gitCommandRunner func(context.Context, string, []string, ...string) ([]byte, error)

type GitCheckoutGateway struct {
	executable string
	timeout    time.Duration
	maxBytes   int64
	maxFiles   int64
	resolver   RepositorySecretResolver
	run        gitCommandRunner
	lookupEnv  func(string) (string, bool)
}

func NewGitCheckoutGateway(resolver RepositorySecretResolver, options GitCheckoutOptions) (*GitCheckoutGateway, error) {
	executable := strings.TrimSpace(options.Executable)
	if executable == "" {
		executable = "git"
	}
	resolved, err := exec.LookPath(executable)
	if err != nil {
		return nil, ErrInvalidGitCheckout
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, ErrInvalidGitCheckout
	}
	expected := strings.TrimSpace(options.ExpectedVersion)
	if expected == "" {
		expected = PinnedGitVersion
	}
	if options.Timeout == 0 {
		options.Timeout = defaultCheckoutTimeout
	}
	if options.MaxWorkspaceBytes == 0 {
		options.MaxWorkspaceBytes = defaultCheckoutMaxBytes
	}
	if options.MaxWorkspaceFiles == 0 {
		options.MaxWorkspaceFiles = defaultCheckoutMaxFiles
	}
	if options.Timeout <= 0 || options.MaxWorkspaceBytes <= 0 || options.MaxWorkspaceFiles <= 0 {
		return nil, ErrInvalidGitCheckout
	}
	gateway := &GitCheckoutGateway{
		executable: resolved, timeout: options.Timeout,
		maxBytes: options.MaxWorkspaceBytes, maxFiles: options.MaxWorkspaceFiles,
		resolver: resolver, lookupEnv: os.LookupEnv,
	}
	gateway.run = func(ctx context.Context, directory string, environment []string, arguments ...string) ([]byte, error) {
		return runGitCommand(ctx, resolved, directory, environment, arguments...)
	}
	versionContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := gateway.run(versionContext, "", gateway.baseEnvironment(""), "--version")
	if err != nil || strings.TrimSpace(string(output)) != "git version "+expected {
		return nil, ErrGitVersionMismatch
	}
	return gateway, nil
}

func (g *GitCheckoutGateway) Checkout(ctx context.Context, request biz.CheckoutRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	checkoutContext, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	authDirectory, err := os.MkdirTemp("", "owndock-git-auth-")
	if err != nil {
		return biz.ErrCheckoutResourceLimit
	}
	defer func() { _ = os.RemoveAll(authDirectory) }()
	if err := os.Chmod(authDirectory, 0o700); err != nil {
		return biz.ErrCheckoutResourceLimit
	}
	environment := g.baseEnvironment(authDirectory)
	environment, secret, err := g.authentication(checkoutContext, request, authDirectory, environment)
	if secret != nil {
		defer clearBytes(secret)
	}
	if err != nil {
		return err
	}
	commands := [][]string{
		g.gitArguments("init", "--quiet", request.Destination),
		g.gitArguments("-C", request.Destination, "remote", "add", "origin", request.Source.RepositoryURL),
	}
	for _, arguments := range commands {
		if _, commandErr := g.run(checkoutContext, request.Destination, environment, arguments...); commandErr != nil {
			return classifyCheckoutResult(ctx, checkoutContext, commandErr)
		}
	}
	if err := g.runBounded(ctx, checkoutContext, request.Destination, environment,
		g.gitArguments("-C", request.Destination, "fetch", "--quiet", "--force", "--no-tags", "--no-recurse-submodules", "--depth=1", "origin", request.Revision.Ref)...); err != nil {
		return err
	}
	resolved, err := g.run(checkoutContext, request.Destination, environment,
		g.gitArguments("-C", request.Destination, "rev-parse", "--verify", "FETCH_HEAD^{commit}")...)
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(resolved)), request.Revision.CommitSHA) {
		return biz.ErrCheckoutRevision
	}
	if _, err := g.run(checkoutContext, request.Destination, environment,
		g.gitArguments("-C", request.Destination, "checkout", "--quiet", "--detach", "--force", request.Revision.CommitSHA, "--")...); err != nil {
		return classifyCheckoutResult(ctx, checkoutContext, err)
	}
	if err := enforceWorkspaceLimit(request.Destination, g.maxBytes, g.maxFiles); err != nil {
		return err
	}
	return nil
}

func (g *GitCheckoutGateway) runBounded(parentContext, operationContext context.Context, destination string,
	environment []string, arguments ...string) error {
	commandContext, cancel := context.WithCancel(operationContext)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := g.run(commandContext, destination, environment, arguments...)
		result <- err
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-result:
			if limitErr := enforceWorkspaceLimit(destination, g.maxBytes, g.maxFiles); limitErr != nil {
				return limitErr
			}
			if err != nil {
				return classifyCheckoutResult(parentContext, operationContext, err)
			}
			return nil
		case <-ticker.C:
			if err := enforceWorkspaceLimit(destination, g.maxBytes, g.maxFiles); err != nil {
				cancel()
				<-result
				return err
			}
		case <-operationContext.Done():
			cancel()
			<-result
			return classifyCheckoutResult(parentContext, operationContext, operationContext.Err())
		}
	}
}

func (g *GitCheckoutGateway) gitArguments(arguments ...string) []string {
	base := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
		"-c", "http.followRedirects=false",
		"-c", "submodule.recurse=false",
	}
	return append(base, arguments...)
}

func (g *GitCheckoutGateway) baseEnvironment(home string) []string {
	environment := []string{
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never",
		"GIT_OPTIONAL_LOCKS=0", "LC_ALL=C", "LANG=C",
	}
	if home != "" {
		environment = append(environment, "HOME="+home, "XDG_CONFIG_HOME="+home)
	}
	for _, name := range []string{"PATH", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "HTTPS_PROXY", "NO_PROXY"} {
		if value, found := g.lookupEnv(name); found && value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func (g *GitCheckoutGateway) authentication(ctx context.Context, request biz.CheckoutRequest,
	directory string, environment []string) ([]string, []byte, error) {
	if request.Credential == nil {
		return environment, nil, nil
	}
	if g.resolver == nil {
		return nil, nil, biz.ErrCheckoutAuthentication
	}
	secret, err := g.resolver.ResolveRepositoryCredential(ctx, *request.Credential)
	if err != nil {
		return nil, nil, biz.ErrCheckoutAuthentication
	}
	switch request.Source.Protocol {
	case biz.RepositoryProtocolHTTPS:
		environment, err = writeHTTPSCheckoutAuth(directory, request.Credential.Username, secret, environment)
	case biz.RepositoryProtocolSSH:
		environment, err = g.writeSSHCheckoutAuth(ctx, directory, request.Source, *request.Credential, secret, environment)
	default:
		err = biz.ErrCheckoutUnreachable
	}
	if err != nil {
		clearBytes(secret)
		return nil, nil, err
	}
	return environment, secret, nil
}

func writeHTTPSCheckoutAuth(directory, username string, token []byte, environment []string) ([]string, error) {
	if username == "" {
		username = "git"
	}
	tokenFile := filepath.Join(directory, "token")
	askPass := filepath.Join(directory, "askpass")
	if err := os.WriteFile(tokenFile, token, 0o600); err != nil {
		return nil, biz.ErrCheckoutResourceLimit
	}
	const script = `#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' "$OWNDOCK_GIT_USERNAME" ;;
  *) exec /bin/cat "$OWNDOCK_GIT_TOKEN_FILE" ;;
esac
`
	if err := os.WriteFile(askPass, []byte(script), 0o700); err != nil {
		return nil, biz.ErrCheckoutResourceLimit
	}
	return append(environment,
		"GIT_ASKPASS="+askPass,
		"OWNDOCK_GIT_USERNAME="+username,
		"OWNDOCK_GIT_TOKEN_FILE="+tokenFile,
	), nil
}

func (g *GitCheckoutGateway) writeSSHCheckoutAuth(ctx context.Context, directory string,
	source biz.SourceRepository, credential biz.RepositoryCredential, privateKey []byte,
	environment []string) ([]string, error) {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != credential.PublicKeyFingerprint {
		return nil, biz.ErrCheckoutAuthentication
	}
	host, port, _, err := parseSSHCheckoutURL(source.RepositoryURL)
	if err != nil {
		return nil, biz.ErrCheckoutUnreachable
	}
	serverKey, err := capturePinnedSSHHostKey(ctx, host, port, source.SSHHostKeyFingerprint)
	if err != nil {
		if errors.Is(err, errSSHHostKeyMismatch) {
			return nil, biz.ErrCheckoutAuthentication
		}
		return nil, biz.ErrCheckoutUnreachable
	}
	keyFile := filepath.Join(directory, "deploy-key")
	knownHostsFile := filepath.Join(directory, "known-hosts")
	wrapper := filepath.Join(directory, "ssh-wrapper")
	if err := os.WriteFile(keyFile, privateKey, 0o600); err != nil {
		return nil, biz.ErrCheckoutResourceLimit
	}
	hostPattern := knownhosts.Normalize(net.JoinHostPort(host, port))
	if err := os.WriteFile(knownHostsFile, []byte(knownhosts.Line([]string{hostPattern}, serverKey)+"\n"), 0o600); err != nil {
		return nil, biz.ErrCheckoutResourceLimit
	}
	sshExecutable, err := exec.LookPath("ssh")
	if err != nil {
		return nil, biz.ErrCheckoutUnreachable
	}
	script := "#!/bin/sh\nexec " + shellQuote(sshExecutable) +
		" -F /dev/null -i " + shellQuote(keyFile) +
		" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes" +
		" -o UserKnownHostsFile=" + shellQuote(knownHostsFile) +
		" -o GlobalKnownHostsFile=/dev/null \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		return nil, biz.ErrCheckoutResourceLimit
	}
	return append(environment, "GIT_SSH="+wrapper, "GIT_SSH_VARIANT=ssh"), nil
}

func capturePinnedSSHHostKey(ctx context.Context, host, port, fingerprint string) (ssh.PublicKey, error) {
	connection, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	var captured ssh.PublicKey
	configuration := &ssh.ClientConfig{
		User: "git", Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != fingerprint {
				return errSSHHostKeyMismatch
			}
			captured = key
			return nil
		},
		Timeout: 10 * time.Second,
	}
	client, channels, requests, handshakeErr := ssh.NewClientConn(connection, net.JoinHostPort(host, port), configuration)
	if handshakeErr == nil {
		ssh.NewClient(client, channels, requests).Close()
	}
	if captured == nil {
		return nil, handshakeErr
	}
	return captured, nil
}

func parseSSHCheckoutURL(value string) (host, port, username string, err error) {
	if strings.HasPrefix(value, "ssh://") {
		parsed, parseErr := url.Parse(value)
		if parseErr != nil || parsed.Hostname() == "" || parsed.User == nil || parsed.User.Username() == "" {
			return "", "", "", ErrInvalidGitCheckout
		}
		port = parsed.Port()
		if port == "" {
			port = "22"
		}
		return parsed.Hostname(), port, parsed.User.Username(), nil
	}
	at := strings.IndexByte(value, '@')
	colon := strings.IndexByte(value, ':')
	if at <= 0 || colon <= at+1 {
		return "", "", "", ErrInvalidGitCheckout
	}
	return value[at+1 : colon], "22", value[:at], nil
}

func enforceWorkspaceLimit(root string, maximumBytes, maximumFiles int64) error {
	var bytesUsed, files int64
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		files++
		if files > maximumFiles {
			return biz.ErrCheckoutResourceLimit
		}
		if entry.Type().IsRegular() {
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			bytesUsed += info.Size()
			if bytesUsed > maximumBytes {
				return biz.ErrCheckoutResourceLimit
			}
		}
		return nil
	})
	if err != nil {
		return biz.ErrCheckoutResourceLimit
	}
	return nil
}

func classifyCheckoutCommand(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return biz.ErrCheckoutUnreachable
	}
	var commandError *gitCommandError
	if errors.As(err, &commandError) {
		message := strings.ToLower(string(commandError.output))
		if strings.Contains(message, "authentication") || strings.Contains(message, "permission denied") ||
			strings.Contains(message, "could not read username") || strings.Contains(message, "repository not found") {
			return biz.ErrCheckoutAuthentication
		}
		if strings.Contains(message, "couldn't find remote ref") || strings.Contains(message, "not our ref") {
			return biz.ErrCheckoutRevision
		}
	}
	return biz.ErrCheckoutUnreachable
}

func classifyCheckoutResult(parentContext, operationContext context.Context, err error) error {
	if parentErr := parentContext.Err(); parentErr != nil {
		return parentErr
	}
	return classifyCheckoutCommand(operationContext, err)
}

type gitCommandError struct{ output []byte }

func (e *gitCommandError) Error() string { return "Git command failed" }

func runGitCommand(ctx context.Context, executable, directory string, environment []string, arguments ...string) ([]byte, error) {
	if len(arguments) == 0 {
		return nil, ErrInvalidGitCheckout
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	if directory != "" {
		command.Dir = directory
	}
	command.Env = environment
	var output limitedBuffer
	output.limit = maximumGitCommandOutput
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return nil, &gitCommandError{output: append([]byte(nil), output.Bytes()...)}
	}
	return append([]byte(nil), output.Bytes()...), nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if remaining := b.limit - b.Len(); remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.Buffer.Write(value)
	}
	return original, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

var _ biz.CheckoutGateway = (*GitCheckoutGateway)(nil)
