package data

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"

	"github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/secretref"
)

type runtimeTargetEngine interface {
	Ping(context.Context, client.PingOptions) (client.PingResult, error)
	Close() error
}

type runtimeTargetEngineFactory func(
	biz.RuntimeTarget,
	[]byte,
	[]byte,
	[]byte,
) (runtimeTargetEngine, error)

type DockerRuntimeTargetProber struct {
	lookup    func(string) (string, bool)
	newEngine runtimeTargetEngineFactory
}

func NewDockerRuntimeTargetProber() *DockerRuntimeTargetProber {
	return &DockerRuntimeTargetProber{
		lookup: os.LookupEnv, newEngine: newRuntimeTargetEngine,
	}
}

func (p *DockerRuntimeTargetProber) ProbeRuntimeTarget(
	ctx context.Context,
	target biz.RuntimeTarget,
) (biz.RuntimeTargetStatus, error) {
	alias, err := secretref.Alias(target.CredentialRef)
	if err != nil {
		return biz.RuntimeTargetStatusCredentialError, nil
	}
	prefix := "OWNDOCK_RUNTIME_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_"))
	values := make([][]byte, 3)
	defer func() {
		for _, value := range values {
			for i := range value {
				value[i] = 0
			}
		}
	}()
	for index, suffix := range []string{"_CA_PEM", "_CERT_PEM", "_KEY_PEM"} {
		value, ok := p.lookup(prefix + suffix)
		if !ok || strings.TrimSpace(value) == "" {
			return biz.RuntimeTargetStatusCredentialError, nil
		}
		values[index] = []byte(value)
	}
	engine, err := p.newEngine(target, values[0], values[1], values[2])
	if err != nil {
		return biz.RuntimeTargetStatusCredentialError, nil
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.Ping(ctx, client.PingOptions{}); err != nil {
		return biz.RuntimeTargetStatusUnreachable, nil
	}
	return biz.RuntimeTargetStatusReady, nil
}

func newRuntimeTargetEngine(
	target biz.RuntimeTarget,
	caCertificate, clientCertificate, clientKey []byte,
) (runtimeTargetEngine, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertificate) {
		return nil, errInvalidRuntimeTargetCA
	}
	certificate, err := tls.X509KeyPair(clientCertificate, clientKey)
	if err != nil {
		return nil, errInvalidRuntimeTargetCertificate
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: target.TLSServerName,
		RootCAs: roots, Certificates: []tls.Certificate{certificate},
	}}
	return client.New(
		client.WithHTTPClient(&http.Client{
			Transport: transport, CheckRedirect: client.CheckRedirect,
		}),
		client.WithHost(target.Endpoint),
		client.WithScheme("https"),
	)
}

type probeConfigurationError string

func (e probeConfigurationError) Error() string { return string(e) }

const (
	errInvalidRuntimeTargetCA          probeConfigurationError = "runtime target CA is invalid"
	errInvalidRuntimeTargetCertificate probeConfigurationError = "runtime target client certificate is invalid"
)
