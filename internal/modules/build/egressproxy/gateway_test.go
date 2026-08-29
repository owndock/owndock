package egressproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayAllowsOnlyConfiguredHTTPDestination(t *testing.T) {
	var allowedHits atomic.Int32
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedHits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Fatal("proxy authorization header reached destination")
		}
		_, _ = io.WriteString(w, "approved dependency")
	}))
	defer allowed.Close()
	var deniedHits atomic.Int32
	denied := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		deniedHits.Add(1)
	}))
	defer denied.Close()
	allowedAuthority := "allowed.internal:" + portFromURL(t, allowed.URL)
	deniedAuthority := "denied.internal:" + portFromURL(t, denied.URL)
	gateway := newTestGateway(t, map[string]string{allowedAuthority: authorityFromURL(t, allowed.URL)})
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+allowedAuthority+"/module", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Proxy-Authorization", "Basic must-not-forward")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "approved dependency" || allowedHits.Load() != 1 {
		t.Fatalf("allowed response = %d %q hits=%d", response.StatusCode, body, allowedHits.Load())
	}
	response, err = client.Get("http://" + deniedAuthority + "/token=must-not-reflect")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnavailableForLegalReasons || deniedHits.Load() != 0 ||
		strings.Contains(string(body), "must-not-reflect") || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("denied response = %d %q headers=%v hits=%d", response.StatusCode, body, response.Header, deniedHits.Load())
	}
}

func TestGatewayAllowsConfiguredConnectAndRejectsOtherTLSAuthority(t *testing.T) {
	allowed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls dependency")
	}))
	defer allowed.Close()
	var deniedHits atomic.Int32
	denied := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		deniedHits.Add(1)
	}))
	defer denied.Close()
	allowedAuthority := "allowed.internal:" + portFromURL(t, allowed.URL)
	deniedAuthority := "denied.internal:" + portFromURL(t, denied.URL)
	gateway := newTestGateway(t, map[string]string{allowedAuthority: authorityFromURL(t, allowed.URL)})
	proxy := httptest.NewServer(gateway)
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test fixture only
	}, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + allowedAuthority)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "tls dependency" {
		t.Fatalf("allowed TLS response = %d %q", response.StatusCode, body)
	}
	if _, err := client.Get("https://" + deniedAuthority + "/secret-query"); err == nil || deniedHits.Load() != 0 {
		t.Fatalf("denied CONNECT error=%v hits=%d", err, deniedHits.Load())
	}
}

func TestTunnelReleasesBothSidesWhenEitherPeerCloses(t *testing.T) {
	gateway := &Gateway{idle: 10 * time.Second}
	downstreamGateway, downstreamClient := net.Pipe()
	upstreamGateway, upstreamServer := net.Pipe()
	done := make(chan struct{})
	go func() {
		gateway.tunnel(downstreamGateway, upstreamGateway,
			bufio.NewReadWriter(bufio.NewReader(downstreamGateway), bufio.NewWriter(downstreamGateway)))
		close(done)
	}()
	if err := downstreamClient.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("tunnel retained the opposite peer after downstream closed")
	}
	buffer := make([]byte, 1)
	if _, err := upstreamServer.Read(buffer); err == nil {
		t.Fatal("upstream peer remained open after downstream closed")
	}
	_ = upstreamServer.Close()
}

func TestGatewayRejectsDNSRebindingToPrivateAddress(t *testing.T) {
	resolver := staticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	dialer := &recordingDialer{}
	gateway, err := newGateway(Options{
		Destinations: []Destination{{Authority: "packages.example:443"}},
		DialTimeout:  time.Second, IdleTimeout: 10 * time.Second, MaximumConnections: 1,
	}, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.dialApproved(t.Context(), "packages.example:443"); err == nil || dialer.called.Load() {
		t.Fatalf("private DNS result reached dialer: err=%v called=%t", err, dialer.called.Load())
	}
}

func TestGatewayRejectsUnsafeConfiguration(t *testing.T) {
	valid := Options{
		Destinations: []Destination{{Authority: "packages.example:443"}},
		DialTimeout:  time.Second, IdleTimeout: 10 * time.Second, MaximumConnections: 1,
	}
	for name, mutate := range map[string]func(*Options){
		"no destinations": func(options *Options) { options.Destinations = nil },
		"duplicate": func(options *Options) {
			options.Destinations = append(options.Destinations, options.Destinations[0])
		},
		"credentials": func(options *Options) {
			options.Destinations = []Destination{{Authority: "user@packages.example:443"}}
		},
		"loopback": func(options *Options) {
			options.Destinations = []Destination{{Authority: "127.0.0.1:443", AllowPrivate: true}}
		},
		"private without opt in": func(options *Options) {
			options.Destinations = []Destination{{Authority: "10.0.0.1:443"}}
		},
		"bad timeout":     func(options *Options) { options.DialTimeout = 0 },
		"bad concurrency": func(options *Options) { options.MaximumConnections = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if _, err := New(options); err == nil {
				t.Fatal("unsafe gateway configuration accepted")
			}
		})
	}
}

func newTestGateway(t *testing.T, targets map[string]string) *Gateway {
	t.Helper()
	destinations := make([]Destination, 0, len(targets))
	dialTargets := make(map[string]string, len(targets))
	for authority, target := range targets {
		destinations = append(destinations, Destination{Authority: authority, AllowPrivate: true})
		_, port, err := net.SplitHostPort(authority)
		if err != nil {
			t.Fatal(err)
		}
		dialTargets[net.JoinHostPort("10.0.0.1", port)] = target
	}
	gateway, err := newGateway(Options{
		Destinations: destinations, DialTimeout: time.Second,
		IdleTimeout: 10 * time.Second, MaximumConnections: 8,
	}, staticResolver{addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}, mappingDialer{targets: dialTargets})
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func portFromURL(t *testing.T, value string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(authorityFromURL(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func authorityFromURL(t *testing.T, value string) string {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

type staticResolver struct{ addresses []netip.Addr }

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, nil
}

type recordingDialer struct{ called atomic.Bool }

func (d *recordingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.called.Store(true)
	return nil, context.DeadlineExceeded
}

type mappingDialer struct{ targets map[string]string }

func (d mappingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target, ok := d.targets[address]
	if !ok {
		return nil, context.DeadlineExceeded
	}
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, target)
}
