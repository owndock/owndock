package agentruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const (
	DefaultCaddyAdminSocket = "/run/owndock-ingress/admin.sock"
	caddyHTTPPort           = 8080
	caddyHTTPSPort          = 8443
	caddyPublicHTTPPort     = 80
	caddyPublicHTTPSPort    = 443
	caddyProbeHeader        = "X-OwnDock-Route-Probe"
	maximumCaddyResponse    = 4 * 1024
	maximumCaddyConfig      = 256 * 1024
)

type CaddyGatewayConfig struct {
	AdminSocket    string
	RequestTimeout time.Duration
}

// CaddyGateway submits only generated complete JSON documents to a local Unix
// socket. The desired digest is represented as a Caddy metadata ID, allowing an
// exact replay to verify a resumed config without needlessly reloading it.
type CaddyGateway struct {
	adminSocket string
	client      *http.Client
	probeClient *http.Client
	timeout     time.Duration
}

func NewCaddyGateway(config CaddyGatewayConfig) (*CaddyGateway, error) {
	socket := strings.TrimSpace(config.AdminSocket)
	if !validCaddyAdminSocket(socket) || config.RequestTimeout < time.Second ||
		config.RequestTimeout > time.Minute {
		return nil, ErrIngressConfiguration
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			info, err := os.Lstat(socket)
			if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
				return nil, ErrIngressGatewayUnavailable
			}
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	probeTransport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil || port != "80" && port != "443" {
				return nil, ErrIngressConfiguration
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		},
	}
	return &CaddyGateway{adminSocket: socket,
		client: &http.Client{Transport: transport},
		probeClient: &http.Client{Transport: probeTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: config.RequestTimeout}, nil
}

func (g *CaddyGateway) Apply(ctx context.Context, command agentprotocol.IngressCommand) (string, error) {
	if command.Validate() != nil {
		return "", ErrIngressConfiguration
	}
	config, configID, err := buildCaddyConfig(g.adminSocket, command)
	if err != nil {
		return "", err
	}
	requestContext, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	current, err := g.isCurrent(requestContext, configID)
	if err != nil {
		return "", err
	}
	if current {
		return command.ConfigDigest, nil
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost,
		"http://unix/load", bytes.NewReader(config))
	if err != nil {
		return "", ErrIngressConfiguration
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := g.client.Do(request)
	if err != nil {
		return "", classifyCaddyTransportError(requestContext, err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumCaddyResponse+1))
	if readErr != nil || len(body) > maximumCaddyResponse {
		return "", ErrIngressGatewayUnavailable
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return command.ConfigDigest, nil
	}
	if response.StatusCode >= 500 {
		return "", ErrIngressGatewayUnavailable
	}
	if caddyPortConflict(body) {
		return "", ErrIngressPortConflict
	}
	return "", ErrIngressConfiguration
}

func (g *CaddyGateway) Clear(ctx context.Context) error {
	digest, err := agentprotocol.IngressConfigDigest(1, nil)
	if err != nil {
		return ErrIngressConfiguration
	}
	_, err = g.Apply(ctx, agentprotocol.IngressCommand{
		HostRevision: 1,
		ConfigDigest: digest,
		Routes:       []agentprotocol.IngressRoute{},
	})
	return err
}

func (g *CaddyGateway) Probe(ctx context.Context, command agentprotocol.IngressCommand) error {
	if command.Validate() != nil {
		return ErrIngressConfiguration
	}
	if len(command.ProbeRouteIDs) == 0 {
		return nil
	}
	routes := make(map[string]agentprotocol.IngressRoute, len(command.Routes))
	for _, route := range command.Routes {
		routes[route.RouteID] = route
	}
	probeContext, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	for _, routeID := range command.ProbeRouteIDs {
		route := routes[routeID]
		scheme, port := "http", caddyPublicHTTPPort
		if route.TLSMode == agentprotocol.IngressTLSAutomatic {
			scheme, port = "https", caddyPublicHTTPSPort
		}
		token := caddyProbeToken(command.ConfigDigest, route.RouteID)
		for {
			request, err := http.NewRequestWithContext(probeContext, http.MethodGet,
				fmt.Sprintf("%s://%s:%d/", scheme, route.Hostname, port), nil)
			if err != nil {
				return ErrIngressConfiguration
			}
			request.Header.Set(caddyProbeHeader, token)
			response, err := g.probeClient.Do(request)
			if err != nil {
				return classifyCaddyProbeError(probeContext, route, err)
			}
			readBytes, readErr := io.Copy(io.Discard,
				io.LimitReader(response.Body, maximumCaddyResponse+1))
			closeErr := response.Body.Close()
			if readErr == nil && closeErr == nil && readBytes <= maximumCaddyResponse &&
				response.Header.Get(caddyProbeHeader) == token {
				break
			}
			select {
			case <-ctx.Done():
				return ErrIngressGatewayUnavailable
			case <-probeContext.Done():
				return ErrIngressBackendUnhealthy
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil
}

func classifyCaddyProbeError(
	ctx context.Context,
	route agentprotocol.IngressRoute,
	err error,
) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return ErrIngressGatewayUnavailable
	}
	var networkError *net.OpError
	hasNetworkError := errors.As(err, &networkError)
	var certificateError *tls.CertificateVerificationError
	certificateFailure := errors.As(err, &certificateError) ||
		hasNetworkError && networkError.Op == "remote error"
	// Certificate verification failures and TLS alerts occur only after the
	// local HTTPS listener accepted the connection. Backend failures happen
	// after TLS and return an unmarked HTTP response instead. Other transport
	// failures stay gateway-unavailable rather than being guessed as ACME.
	if route.TLSMode == agentprotocol.IngressTLSAutomatic && certificateFailure {
		return ErrIngressCertificateUnavailable
	}
	return ErrIngressGatewayUnavailable
}

func (g *CaddyGateway) isCurrent(ctx context.Context, configID string) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://unix/id/"+url.PathEscape(configID), nil)
	if err != nil {
		return false, ErrIngressConfiguration
	}
	response, err := g.client.Do(request)
	if err != nil {
		return false, classifyCaddyTransportError(ctx, err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, maximumCaddyResponse+1)); err != nil {
		return false, ErrIngressGatewayUnavailable
	}
	switch response.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, ErrIngressGatewayUnavailable
	}
}

func classifyCaddyTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return ErrIngressGatewayUnavailable
	}
	return ErrIngressGatewayUnavailable
}

func caddyPortConflict(body []byte) bool {
	message := strings.ToLower(string(body))
	return strings.Contains(message, "address already in use") ||
		strings.Contains(message, "bind: permission denied")
}

func validCaddyAdminSocket(value string) bool {
	return value != "" && len(value) <= 96 && filepath.IsAbs(value) &&
		filepath.Clean(value) == value && strings.HasSuffix(value, ".sock") &&
		!strings.ContainsAny(value, "|\x00\r\n")
}

func buildCaddyConfig(adminSocket string, command agentprotocol.IngressCommand) ([]byte, string, error) {
	if !validCaddyAdminSocket(adminSocket) || command.Validate() != nil {
		return nil, "", ErrIngressConfiguration
	}
	configID := "owndock-config-" + strings.TrimPrefix(command.ConfigDigest, "sha256:")
	routes := make([]caddyRoute, 0, len(command.Routes)+1)
	skipped := make([]string, 0, len(command.Routes))
	hasAutomaticTLS := false
	for _, route := range command.Routes {
		probeToken := caddyProbeToken(command.ConfigDigest, route.RouteID)
		routes = append(routes, caddyRoute{
			Match: []caddyMatcher{{Host: []string{route.Hostname},
				Header: map[string][]string{caddyProbeHeader: {probeToken}}}},
			Handle: []caddyHandler{{Handler: "reverse_proxy",
				Upstreams: []caddyUpstream{{Dial: net.JoinHostPort(route.BackendAlias,
					fmt.Sprintf("%d", route.BackendPort))}}, StreamCloseDelay: "5m",
				Headers: &caddyHeaders{Response: &caddyResponseHeaders{
					Set: map[string][]string{caddyProbeHeader: {probeToken}},
				}}}},
			Terminal: true,
		})
		routes = append(routes, caddyRoute{
			Match: []caddyMatcher{{Host: []string{route.Hostname}}},
			Handle: []caddyHandler{{Handler: "reverse_proxy",
				Upstreams: []caddyUpstream{{Dial: net.JoinHostPort(route.BackendAlias,
					fmt.Sprintf("%d", route.BackendPort))}}, StreamCloseDelay: "5m"}},
			Terminal: true,
		})
		if route.TLSMode == agentprotocol.IngressTLSDisabled {
			skipped = append(skipped, route.Hostname)
		} else {
			hasAutomaticTLS = true
		}
	}
	routes = append(routes, caddyRoute{Handle: []caddyHandler{{Handler: "static_response",
		StatusCode: http.StatusNotFound}}, Terminal: true})
	sort.Strings(skipped)
	listen := []string{fmt.Sprintf(":%d", caddyHTTPPort)}
	if hasAutomaticTLS {
		listen = append(listen, fmt.Sprintf(":%d", caddyHTTPSPort))
	}
	strictSNI := hasAutomaticTLS
	server := caddyServer{Listen: listen, Routes: routes,
		ReadHeaderTimeout: "10s", IdleTimeout: "5m", MaxHeaderBytes: 32 * 1024,
		Protocols: []string{"h1", "h2"}}
	if hasAutomaticTLS {
		server.AutomaticHTTPS = &caddyAutomaticHTTPS{Skip: skipped}
		server.StrictSNIHost = &strictSNI
	}
	persist := true
	httpsPort := 0
	if hasAutomaticTLS {
		httpsPort = caddyHTTPSPort
	}
	document := caddyConfig{ID: configID,
		Admin: caddyAdmin{Listen: "unix/" + adminSocket + "|0660",
			Config: caddyAdminConfig{Persist: &persist}},
		Storage: caddyStorage{Module: "file_system", Root: "/data/caddy"},
		Apps: caddyApps{HTTP: caddyHTTPApp{HTTPPort: caddyHTTPPort,
			HTTPSPort: httpsPort, GracePeriod: "30s",
			Servers: map[string]caddyServer{"managed": server}}},
	}
	value, err := json.Marshal(document)
	if err != nil || len(value) > maximumCaddyConfig {
		return nil, "", ErrIngressConfiguration
	}
	return value, configID, nil
}

func caddyProbeToken(configDigest, routeID string) string {
	digest := sha256.Sum256([]byte(configDigest + "\x00" + routeID))
	return hex.EncodeToString(digest[:16])
}

type caddyConfig struct {
	ID      string       `json:"@id"`
	Admin   caddyAdmin   `json:"admin"`
	Storage caddyStorage `json:"storage"`
	Apps    caddyApps    `json:"apps"`
}

type caddyAdmin struct {
	Listen string           `json:"listen"`
	Config caddyAdminConfig `json:"config"`
}

type caddyAdminConfig struct {
	Persist *bool `json:"persist"`
}

type caddyStorage struct {
	Module string `json:"module"`
	Root   string `json:"root"`
}

type caddyApps struct {
	HTTP caddyHTTPApp `json:"http"`
}

type caddyHTTPApp struct {
	HTTPPort    int                    `json:"http_port"`
	HTTPSPort   int                    `json:"https_port,omitempty"`
	GracePeriod string                 `json:"grace_period"`
	Servers     map[string]caddyServer `json:"servers"`
}

type caddyServer struct {
	Listen            []string             `json:"listen"`
	Routes            []caddyRoute         `json:"routes"`
	ReadHeaderTimeout string               `json:"read_header_timeout"`
	IdleTimeout       string               `json:"idle_timeout"`
	MaxHeaderBytes    int                  `json:"max_header_bytes"`
	Protocols         []string             `json:"protocols"`
	AutomaticHTTPS    *caddyAutomaticHTTPS `json:"automatic_https,omitempty"`
	StrictSNIHost     *bool                `json:"strict_sni_host,omitempty"`
}

type caddyAutomaticHTTPS struct {
	Skip []string `json:"skip,omitempty"`
}

type caddyRoute struct {
	Match    []caddyMatcher `json:"match,omitempty"`
	Handle   []caddyHandler `json:"handle"`
	Terminal bool           `json:"terminal"`
}

type caddyMatcher struct {
	Host   []string            `json:"host"`
	Header map[string][]string `json:"header,omitempty"`
}

type caddyHandler struct {
	Handler          string          `json:"handler"`
	Upstreams        []caddyUpstream `json:"upstreams,omitempty"`
	StreamCloseDelay string          `json:"stream_close_delay,omitempty"`
	StatusCode       int             `json:"status_code,omitempty"`
	Headers          *caddyHeaders   `json:"headers,omitempty"`
}

type caddyHeaders struct {
	Response *caddyResponseHeaders `json:"response,omitempty"`
}

type caddyResponseHeaders struct {
	Set map[string][]string `json:"set,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

var _ IngressGateway = (*CaddyGateway)(nil)
