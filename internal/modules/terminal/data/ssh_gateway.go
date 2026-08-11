package data

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/secretref"
)

const (
	directSSHHandshakeTimeout = 10 * time.Second
	directSSHCloseGrace       = 5 * time.Second
)

var (
	ErrInvalidDirectSSHGateway  = errors.New("direct SSH terminal gateway is invalid")
	ErrSSHCredentialUnavailable = errors.New("SSH credential is unavailable")
)

type SSHPrivateKeyResolver interface {
	ResolveSSHPrivateKey(context.Context, string) ([]byte, error)
}

type EnvironmentSSHPrivateKeyResolver struct {
	lookup func(string) (string, bool)
}

func NewEnvironmentSSHPrivateKeyResolver() *EnvironmentSSHPrivateKeyResolver {
	return &EnvironmentSSHPrivateKeyResolver{lookup: os.LookupEnv}
}

func (r *EnvironmentSSHPrivateKeyResolver) ResolveSSHPrivateKey(
	ctx context.Context,
	reference string,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	alias, err := secretref.Alias(reference)
	if err != nil {
		return nil, ErrSSHCredentialUnavailable
	}
	name := "OWNDOCK_MANAGED_HOST_SSH_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_")) +
		"_PRIVATE_KEY_PEM"
	value, ok := r.lookup(name)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%w: %s is not configured", ErrSSHCredentialUnavailable, name)
	}
	return []byte(value), nil
}

type sshDialContext func(context.Context, string, string) (net.Conn, error)

type DirectSSHGateway struct {
	secrets          SSHPrivateKeyResolver
	dial             sshDialContext
	handshakeTimeout time.Duration
	closeGrace       time.Duration
}

func NewDirectSSHGateway(secrets SSHPrivateKeyResolver) (*DirectSSHGateway, error) {
	if secrets == nil {
		return nil, ErrInvalidDirectSSHGateway
	}
	dialer := &net.Dialer{}
	return &DirectSSHGateway{
		secrets:          secrets,
		dial:             dialer.DialContext,
		handshakeTimeout: directSSHHandshakeTimeout,
		closeGrace:       directSSHCloseGrace,
	}, nil
}

func (g *DirectSSHGateway) OpenHost(
	ctx context.Context,
	sessionID string,
	target terminalbiz.Target,
	size terminalbiz.TerminalSize,
) (terminalbiz.TerminalStream, error) {
	if target.Kind != terminalbiz.KindHost ||
		target.ConnectionMode != runtimeaccess.ModeDirectDocker ||
		sessionID == "" || target.OrganizationID == "" || target.ManagedHostID == "" ||
		target.SSHAddress == "" || target.SSHUser == "" ||
		target.SSHHostKeySHA256 == "" || target.SSHCredentialRef == "" ||
		size.Validate() != nil {
		return nil, terminalbiz.ErrTargetUnavailable
	}
	privateKey, err := g.secrets.ResolveSSHPrivateKey(ctx, target.SSHCredentialRef)
	if err != nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	defer clearBytes(privateKey)
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	config := &ssh.ClientConfig{
		User:            target.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: pinnedSSHHostKey(target.SSHHostKeySHA256),
	}
	handshakeContext, cancel := context.WithTimeout(ctx, g.handshakeTimeout)
	defer cancel()
	connection, err := g.dial(handshakeContext, "tcp", target.SSHAddress)
	if err != nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	closeConnection := true
	defer func() {
		if closeConnection {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(g.handshakeTimeout)
	if contextDeadline, ok := handshakeContext.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	clientConnection, channels, requests, err := ssh.NewClientConn(
		connection,
		target.SSHAddress,
		config,
	)
	if err != nil {
		return nil, terminalbiz.ErrStreamUnavailable
	}
	_ = connection.SetDeadline(time.Time{})
	client := ssh.NewClient(clientConnection, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, terminalbiz.ErrStreamUnavailable
	}
	input, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, terminalbiz.ErrStreamUnavailable
	}
	outputReader, outputWriter := io.Pipe()
	session.Stdout, session.Stderr = outputWriter, outputWriter
	if err := session.RequestPty(
		"xterm-256color",
		int(size.Rows),
		int(size.Columns),
		ssh.TerminalModes{ssh.ECHO: 1},
	); err != nil {
		_ = outputReader.Close()
		_ = outputWriter.Close()
		_ = session.Close()
		_ = client.Close()
		return nil, terminalbiz.ErrStreamUnavailable
	}
	if err := session.Shell(); err != nil {
		_ = outputReader.Close()
		_ = outputWriter.Close()
		_ = session.Close()
		_ = client.Close()
		return nil, terminalbiz.ErrStreamUnavailable
	}
	stream := &directSSHStream{
		reader: outputReader, writer: input,
		session: session, client: client, connection: connection,
		output: outputWriter, closeGrace: g.closeGrace,
		exited: make(chan struct{}),
	}
	closeConnection = false
	go stream.wait()
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-stream.exited:
		}
	}()
	return stream, nil
}

func pinnedSSHHostKey(expected string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actual := ssh.FingerprintSHA256(key)
		if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
			return ErrSSHCredentialUnavailable
		}
		return nil
	}
}

type directSSHStream struct {
	reader     *io.PipeReader
	writer     io.WriteCloser
	session    *ssh.Session
	client     *ssh.Client
	connection net.Conn
	output     *io.PipeWriter
	closeGrace time.Duration
	exited     chan struct{}
	closeOnce  sync.Once
}

func (s *directSSHStream) wait() {
	err := s.session.Wait()
	if err == nil {
		err = io.EOF
	}
	_ = s.output.CloseWithError(err)
	close(s.exited)
}

func (s *directSSHStream) Read(payload []byte) (int, error) {
	return s.reader.Read(payload)
}

func (s *directSSHStream) Write(payload []byte) (int, error) {
	return s.writer.Write(payload)
}

func (s *directSSHStream) Resize(
	ctx context.Context,
	size terminalbiz.TerminalSize,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := size.Validate(); err != nil {
		return err
	}
	select {
	case <-s.exited:
		return terminalbiz.ErrStreamUnavailable
	default:
	}
	if err := s.session.WindowChange(int(size.Rows), int(size.Columns)); err != nil {
		return terminalbiz.ErrStreamUnavailable
	}
	return nil
}

func (s *directSSHStream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.session.Signal(ssh.SIGTERM)
		timer := time.NewTimer(s.closeGrace)
		select {
		case <-s.exited:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
		_ = s.writer.Close()
		_ = s.session.Close()
		_ = s.client.Close()
		_ = s.connection.Close()
		_ = s.reader.Close()
	})
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ terminalbiz.HostGateway = (*DirectSSHGateway)(nil)
var _ terminalbiz.TerminalStream = (*directSSHStream)(nil)
