package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
)

type AgentServer struct {
	server   *http.Server
	registry interface{ Close() }

	mu       sync.Mutex
	listener net.Listener
}

func NewAgentServer(
	cfg platformconfig.Agent,
	handler http.Handler,
	clientCAPEM, serverCertificatePEM, serverPrivateKeyPEM []byte,
	registry interface{ Close() },
) (*AgentServer, error) {
	if handler == nil || registry == nil {
		return nil, fmt.Errorf("Agent server handler and connection registry are required")
	}
	handshakeTimeout, err := cfg.HandshakeTimeoutDuration()
	if err != nil {
		return nil, err
	}
	serverCertificate, err := tls.X509KeyPair(
		serverCertificatePEM, serverPrivateKeyPEM,
	)
	if err != nil {
		return nil, fmt.Errorf("load Agent server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse Agent server certificate: %w", err)
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) ||
		!allowsServerAuthentication(leaf) {
		return nil, fmt.Errorf("Agent server certificate is not valid for server authentication")
	}
	serverCertificate.Leaf = leaf
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("Agent client certificate authority is invalid")
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/agent/connect", handler)
	return &AgentServer{
		server: &http.Server{
			Addr: cfg.Address, Handler: mux,
			ReadHeaderTimeout: handshakeTimeout,
			IdleTimeout:       2 * handshakeTimeout,
			MaxHeaderBytes:    16 * 1024,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{serverCertificate},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    clientCAs,
				NextProtos:   []string{"h2", "http/1.1"},
			},
		},
		registry: registry,
	}, nil
}

func (s *AgentServer) Start(context.Context) error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("listen for Agent connections: %w", err)
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	err = s.server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *AgentServer) Stop(ctx context.Context) error {
	s.registry.Close()
	return s.server.Shutdown(ctx)
}

func (s *AgentServer) Endpoint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func allowsServerAuthentication(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth ||
			usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
