package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClientIPResolverIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	address, err := resolver.Resolve(request)
	if err != nil || address.String() != "192.0.2.10" {
		t.Fatalf("Resolve() = %s, %v", address, err)
	}
}

func TestLimiterPublishesTrustedClientIPToProtectedHandler(t *testing.T) {
	resolver, err := NewClientIPResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewLimiter(
		allowingGuard{}, resolver, 10, 20, time.Minute, func() time.Time { return time.Unix(1, 0) },
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.RemoteAddr = "192.0.2.20:1234"
	response := httptest.NewRecorder()
	limiter.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := ClientIPFromContext(r.Context())
		if !ok || address.String() != "192.0.2.20" {
			t.Fatalf("client address = %s, %v", address, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}

type allowingGuard struct{}

func (allowingGuard) Reserve(_ context.Context, _ string, now time.Time, _ int, window time.Duration) (bool, time.Time, error) {
	return true, now.Add(window), nil
}

func TestClientIPResolverWalksTrustedProxyChainFromRight(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.RemoteAddr = "10.0.0.3:4321"
	request.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.20, 10.0.0.2")
	address, err := resolver.Resolve(request)
	if err != nil || address.String() != "198.51.100.20" {
		t.Fatalf("Resolve() = %s, %v", address, err)
	}
}

func TestClientIPResolverRejectsMalformedTrustedHeader(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.RemoteAddr = "10.0.0.3:4321"
	request.Header.Set("X-Forwarded-For", "not-an-ip")
	if _, err := resolver.Resolve(request); !errors.Is(err, ErrInvalidClientAddress) {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestClientIPResolverRejectsTrustingEveryPeer(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := NewClientIPResolver([]string{cidr}); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("NewClientIPResolver(%q) error = %v", cidr, err)
		}
	}
}

type memoryGuard struct {
	counts map[string]int
	err    error
}

func (g *memoryGuard) Reserve(
	_ context.Context, key string, now time.Time, limit int, window time.Duration,
) (bool, time.Time, error) {
	if g.err != nil {
		return false, time.Time{}, g.err
	}
	if g.counts == nil {
		g.counts = make(map[string]int)
	}
	if g.counts[key] >= limit {
		return false, now.Add(window), nil
	}
	g.counts[key]++
	return true, time.Time{}, nil
}

func newTestLimiter(t *testing.T, guard Guard, source, global int) *Limiter {
	t.Helper()
	resolver, err := NewClientIPResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewLimiter(guard, resolver, source, global, time.Minute,
		func() time.Time { return time.Unix(100, 0) })
	if err != nil {
		t.Fatal(err)
	}
	return limiter
}

func TestLimiterEnforcesSourceAndDoesNotPersistRawIPKey(t *testing.T) {
	guard := &memoryGuard{}
	handler := newTestLimiter(t, guard, 2, 10).Protect(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
	))
	for attempt, want := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		request.RemoteAddr = "192.0.2.10:1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", attempt+1, response.Code, want)
		}
		if want == http.StatusTooManyRequests && response.Header().Get("Retry-After") == "" {
			t.Fatal("rate-limited response has no Retry-After")
		}
	}
	for key := range guard.counts {
		if len(key) != 64 || strings.Contains(key, "192.0.2.10") {
			t.Fatalf("stored admission key = %q", key)
		}
	}
}

func TestLimiterEnforcesInstallationGlobalLimit(t *testing.T) {
	handler := newTestLimiter(t, &memoryGuard{}, 2, 2).Protect(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
	))
	for index, want := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
		request.RemoteAddr = "192.0.2." + strconv.Itoa(index+1) + ":1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("request %d status = %d, want %d", index+1, response.Code, want)
		}
	}
}

func TestLimiterFailsClosedWhenSharedGuardIsUnavailable(t *testing.T) {
	handler := newTestLimiter(t, &memoryGuard{err: errors.New("database unavailable")}, 10, 100).
		Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("protected handler called")
		}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("status = %d, headers = %v", response.Code, response.Header())
	}
}
