package data

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type sshKeyResolverStub struct{ key []byte }

func (r *sshKeyResolverStub) ResolveSSHPrivateKey(
	context.Context,
	string,
) ([]byte, error) {
	return r.key, nil
}

func TestEnvironmentSSHPrivateKeyResolverUsesConstrainedAlias(t *testing.T) {
	resolver := &EnvironmentSSHPrivateKeyResolver{lookup: func(name string) (string, bool) {
		if name != "OWNDOCK_MANAGED_HOST_SSH_PRODUCTION_HOST_PRIVATE_KEY_PEM" {
			t.Fatalf("environment name = %q", name)
		}
		return "private-key", true
	}}
	value, err := resolver.ResolveSSHPrivateKey(t.Context(), "secret://production-host")
	if err != nil || string(value) != "private-key" {
		t.Fatalf("resolved key = %q, error = %v", value, err)
	}
	if _, err := resolver.ResolveSSHPrivateKey(
		t.Context(), "secret://../process-env",
	); !errors.Is(err, ErrSSHCredentialUnavailable) {
		t.Fatalf("invalid reference error = %v", err)
	}
}

func TestPinnedSSHHostKeyRejectsMismatch(t *testing.T) {
	first := newSSHSigner(t)
	second := newSSHSigner(t)
	callback := pinnedSSHHostKey(ssh.FingerprintSHA256(first.PublicKey()))
	if err := callback("host.example.com:22", nil, first.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := callback("host.example.com:22", nil, second.PublicKey()); !errors.Is(err, ErrSSHCredentialUnavailable) {
		t.Fatalf("host-key mismatch error = %v", err)
	}
}

func TestDirectSSHGatewayOpensPinnedFixedUserPTYAndClearsKey(t *testing.T) {
	hostSigner := newSSHSigner(t)
	clientKey := newSSHPrivateKeyPEM(t)
	clientSigner, err := ssh.ParsePrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &sshKeyResolverStub{key: clientKey}
	gateway, err := NewDirectSSHGateway(resolver)
	if err != nil {
		t.Fatal(err)
	}
	gateway.closeGrace = 100 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		serverConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serveTestSSH(
			serverConnection,
			hostSigner,
			"owndock",
			clientSigner.PublicKey(),
			serverDone,
		)
	}()
	stream, err := gateway.OpenHost(
		t.Context(),
		"terminal-session-1",
		terminalbiz.Target{
			Kind: terminalbiz.KindHost, OrganizationID: "organization-1",
			ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeDirectDocker,
			SSHAddress: listener.Addr().String(), SSHUser: "owndock",
			SSHHostKeySHA256: ssh.FingerprintSHA256(hostSigner.PublicKey()),
			SSHCredentialRef: "secret://production-host",
		},
		terminalbiz.TerminalSize{Columns: 100, Rows: 40},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !allZero(clientKey) {
		t.Fatal("resolved SSH private key was not cleared after handshake")
	}
	if err := stream.Resize(
		t.Context(), terminalbiz.TerminalSize{Columns: 132, Rows: 43},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("host-ssh-ok\n")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	read, err := stream.Read(buffer)
	if err != nil || !bytes.Contains(buffer[:read], []byte("host-ssh-ok")) {
		t.Fatalf("SSH PTY output = %q, error = %v", buffer[:read], err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil && err != io.EOF {
			t.Fatalf("SSH server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH server did not stop")
	}
}

func serveTestSSH(
	connection net.Conn,
	hostSigner ssh.Signer,
	expectedUser string,
	expectedClientKey ssh.PublicKey,
	done chan<- error,
) {
	defer connection.Close()
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(
			metadata ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			if metadata.User() != expectedUser || key.Type() != expectedClientKey.Type() ||
				!bytes.Equal(key.Marshal(), expectedClientKey.Marshal()) {
				return nil, errors.New("unexpected SSH client identity")
			}
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)
	_, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		done <- err
		return
	}
	go ssh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		channel, requests, acceptErr := channelRequest.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		for request := range requests {
			switch request.Type {
			case "pty-req", "window-change":
				_ = request.Reply(true, nil)
			case "shell":
				_ = request.Reply(true, nil)
				go func() { _, _ = io.Copy(channel, channel) }()
			case "signal":
				_ = request.Reply(true, nil)
				_ = channel.Close()
			}
		}
	}
	done <- nil
}

func newSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newSSHPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}
