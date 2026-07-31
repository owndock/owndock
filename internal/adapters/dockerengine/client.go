// Package dockerengine constructs narrowly configured Moby API clients for
// direct Runtime Target connections.
package dockerengine

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

// TLSCredential is intentionally short lived. Callers own the byte slices and
// must clear them after NewTLS returns and the resulting client is closed.
type TLSCredential struct {
	CACertificate     []byte
	ClientCertificate []byte
	ClientKey         []byte
}

// NewTLS creates a TLS 1.2+ client without Docker API version negotiation.
// OwnDock uses the Moby client's supported API directly and does not enable
// automatic API-version negotiation.
func NewTLS(
	connection runtimeaccess.Connection,
	credential TLSCredential,
) (*mobyclient.Client, error) {
	if err := connection.Validate(); err != nil ||
		connection.Mode != runtimeaccess.ModeDirectDocker ||
		connection.DirectDocker == nil {
		return nil, runtimeaccess.ErrInvalidConnection
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(credential.CACertificate) {
		return nil, errors.New("runtime CA certificate is invalid")
	}
	certificate, err := tls.X509KeyPair(
		credential.ClientCertificate,
		credential.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("runtime client certificate is invalid: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   connection.DirectDocker.TLSServerName,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}}
	httpClient := &http.Client{
		Transport: transport, CheckRedirect: mobyclient.CheckRedirect,
	}
	client, err := mobyclient.New(
		mobyclient.WithHTTPClient(httpClient),
		mobyclient.WithHost(connection.DirectDocker.Endpoint),
		mobyclient.WithScheme("https"),
	)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return client, nil
}
