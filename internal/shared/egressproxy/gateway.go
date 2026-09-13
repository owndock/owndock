package egressproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidConfiguration = errors.New("egress gateway configuration is invalid")

type Destination struct {
	Authority    string
	AllowPrivate bool
}

type Options struct {
	Destinations       []Destination
	DialTimeout        time.Duration
	IdleTimeout        time.Duration
	MaximumConnections int
}

type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Gateway struct {
	allowed  map[string]Destination
	resolver resolver
	dialer   dialer
	idle     time.Duration
	permits  chan struct{}
}

func New(options Options) (*Gateway, error) {
	return newGateway(options, net.DefaultResolver, &net.Dialer{Timeout: options.DialTimeout})
}

func newGateway(options Options, resolver resolver, dialer dialer) (*Gateway, error) {
	if resolver == nil || dialer == nil || options.DialTimeout < time.Second || options.DialTimeout > time.Minute ||
		options.IdleTimeout < 10*time.Second || options.IdleTimeout > 30*time.Minute ||
		options.MaximumConnections < 1 || options.MaximumConnections > 4096 ||
		len(options.Destinations) < 1 || len(options.Destinations) > 256 {
		return nil, ErrInvalidConfiguration
	}
	allowed := make(map[string]Destination, len(options.Destinations))
	for _, destination := range options.Destinations {
		authority, err := canonicalAuthority(destination.Authority, "")
		if err != nil || authority != destination.Authority {
			return nil, ErrInvalidConfiguration
		}
		host, _, _ := net.SplitHostPort(authority)
		if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil &&
			prohibitedAddress(address, destination.AllowPrivate) {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := allowed[authority]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		allowed[authority] = destination
	}
	return &Gateway{
		allowed: allowed, resolver: resolver, dialer: dialer, idle: options.IdleTimeout,
		permits: make(chan struct{}, options.MaximumConnections),
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.acquire() {
		writeProxyError(w, http.StatusServiceUnavailable)
		return
	}
	defer g.release()
	if r.Method == http.MethodConnect {
		g.connect(w, r)
		return
	}
	g.forwardHTTP(w, r)
}

func (g *Gateway) acquire() bool {
	select {
	case g.permits <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *Gateway) release() { <-g.permits }

func (g *Gateway) connect(w http.ResponseWriter, r *http.Request) {
	authority, err := canonicalAuthority(r.Host, "")
	if err != nil {
		writeProxyError(w, http.StatusForbidden)
		return
	}
	upstream, err := g.dialApproved(r.Context(), authority)
	if err != nil {
		writeProxyError(w, proxyStatus(err))
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		writeProxyError(w, http.StatusInternalServerError)
		return
	}
	downstream, buffer, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffer.Flush() != nil {
		_ = downstream.Close()
		_ = upstream.Close()
		return
	}
	g.tunnel(downstream, upstream, buffer)
}

func (g *Gateway) tunnel(downstream net.Conn, upstream net.Conn, buffered *bufio.ReadWriter) {
	downstream = &deadlineConn{Conn: downstream, idle: g.idle}
	upstream = &deadlineConn{Conn: upstream, idle: g.idle}
	defer downstream.Close()
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, buffered)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(downstream, upstream)
		done <- struct{}{}
	}()
	// A CONNECT tunnel is no longer reusable once either peer closes its
	// direction. Close both sockets immediately so the opposite copy unblocks
	// and, importantly, the gateway connection permit is released promptly.
	<-done
	_ = downstream.Close()
	_ = upstream.Close()
	<-done
}

func (g *Gateway) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) ||
		!r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
		writeProxyError(w, http.StatusForbidden)
		return
	}
	authority, err := canonicalAuthority(r.URL.Host, "80")
	if err != nil {
		writeProxyError(w, http.StatusForbidden)
		return
	}
	requestAuthority, err := canonicalAuthority(r.Host, "80")
	if err != nil || requestAuthority != authority {
		writeProxyError(w, http.StatusForbidden)
		return
	}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			candidate, err := canonicalAuthority(address, "80")
			if err != nil || candidate != authority {
				return nil, errDestinationDenied
			}
			return g.dialApproved(ctx, authority)
		},
	}
	defer transport.CloseIdleConnections()
	outbound := r.Clone(r.Context())
	outbound.RequestURI = ""
	outbound.URL = cloneURL(r.URL)
	outbound.Host = r.URL.Host
	removeHopHeaders(outbound.Header)
	response, err := transport.RoundTrip(outbound)
	if err != nil {
		writeProxyError(w, proxyStatus(err))
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

var errDestinationDenied = errors.New("destination denied")

func (g *Gateway) dialApproved(ctx context.Context, authority string) (net.Conn, error) {
	destination, ok := g.allowed[authority]
	if !ok {
		return nil, errDestinationDenied
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, errDestinationDenied
	}
	host = strings.Trim(host, "[]")
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if prohibitedAddress(address, destination.AllowPrivate) {
			return nil, errDestinationDenied
		}
		return g.dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port))
	}
	addresses, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("destination resolution failed")
	}
	var lastErr error
	for _, address := range addresses {
		if prohibitedAddress(address.Unmap(), destination.AllowPrivate) {
			continue
		}
		connection, dialErr := g.dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, errors.New("destination connection failed")
	}
	return nil, errDestinationDenied
}

func prohibitedAddress(address netip.Addr, allowPrivate bool) bool {
	return !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() ||
		address.IsLinkLocalUnicast() || (!allowPrivate && address.IsPrivate())
}

func canonicalAuthority(value, defaultPort string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) ||
		strings.ContainsAny(value, "/?#@") {
		return "", ErrInvalidConfiguration
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil && defaultPort != "" && !strings.Contains(value, ":") {
		host, port, err = value, defaultPort, nil
	}
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 || !validHost(host) ||
		strings.HasSuffix(host, ".") {
		return "", ErrInvalidConfiguration
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
}

func validHost(host string) bool {
	host = strings.Trim(host, "[]")
	if address, err := netip.ParseAddr(host); err == nil {
		return address.IsValid()
	}
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func proxyStatus(err error) int {
	if errors.Is(err, errDestinationDenied) || errors.Is(err, ErrInvalidConfiguration) {
		// 451 is an internal transport marker that survives common command output
		// without reflecting the denied destination. Callers may map it to a stable
		// network-policy failure category; it is not a public API status.
		return http.StatusUnavailableForLegalReasons
	}
	return http.StatusBadGateway
}

func writeProxyError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, http.StatusText(status)+"\n")
}

func cloneURL(value *url.URL) *url.URL {
	cloned := *value
	return &cloned
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func copyHeaders(destination, source http.Header) {
	for name, values := range source {
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

type deadlineConn struct {
	net.Conn
	idle time.Duration
}

func (c *deadlineConn) Read(buffer []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(buffer)
}

func (c *deadlineConn) Write(buffer []byte) (int, error) {
	_ = c.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(buffer)
}

// Handler is intentionally the only exposed behavior: the gateway has no
// administrative HTTP routes and never reports destination or request data.
var _ http.Handler = (*Gateway)(nil)
