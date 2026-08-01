package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/platform/httpx"
)

var (
	ErrInvalidClientAddress = errors.New("client address is invalid")
	ErrInvalidPolicy        = errors.New("ingress rate policy is invalid")
)

const (
	maximumForwardedForBytes   = 2048
	maximumForwardedForEntries = 20
)

type Guard interface {
	Reserve(context.Context, string, time.Time, int, time.Duration) (bool, time.Time, error)
}

type clientIPContextKey struct{}

// ClientIPFromContext returns the address resolved at the trusted ingress
// boundary. Security-sensitive handlers must not reinterpret forwarding
// headers on their own.
func ClientIPFromContext(ctx context.Context) (netip.Addr, bool) {
	address, ok := ctx.Value(clientIPContextKey{}).(netip.Addr)
	return address, ok && address.IsValid() && !address.IsUnspecified()
}

// WithResolvedClientIP is for trusted ingress adapters and tests. Callers must
// resolve proxy headers before storing the address.
func WithResolvedClientIP(ctx context.Context, address netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, address)
}

type ClientIPResolver struct {
	trusted []netip.Prefix
}

func NewClientIPResolver(trustedProxyCIDRs []string) (*ClientIPResolver, error) {
	if len(trustedProxyCIDRs) > 64 {
		return nil, ErrInvalidPolicy
	}
	resolver := &ClientIPResolver{trusted: make([]netip.Prefix, 0, len(trustedProxyCIDRs))}
	seen := make(map[netip.Prefix]struct{}, len(trustedProxyCIDRs))
	for _, raw := range trustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return nil, ErrInvalidPolicy
		}
		if _, exists := seen[prefix]; exists {
			return nil, ErrInvalidPolicy
		}
		seen[prefix] = struct{}{}
		resolver.trusted = append(resolver.trusted, prefix)
	}
	return resolver, nil
}

func (r *ClientIPResolver) Resolve(request *http.Request) (netip.Addr, error) {
	peer, err := parseRemoteAddress(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, ErrInvalidClientAddress
	}
	if r == nil || !r.isTrusted(peer) {
		return peer, nil
	}
	forwarded := strings.Join(request.Header.Values("X-Forwarded-For"), ",")
	if forwarded == "" {
		return peer, nil
	}
	if len(forwarded) > maximumForwardedForBytes {
		return netip.Addr{}, ErrInvalidClientAddress
	}
	parts := strings.Split(forwarded, ",")
	if len(parts) > maximumForwardedForEntries {
		return netip.Addr{}, ErrInvalidClientAddress
	}
	current := peer
	for index := len(parts) - 1; index >= 0; index-- {
		if !r.isTrusted(current) {
			break
		}
		candidate, parseErr := netip.ParseAddr(strings.TrimSpace(parts[index]))
		if parseErr != nil || !candidate.IsValid() || candidate.IsUnspecified() {
			return netip.Addr{}, ErrInvalidClientAddress
		}
		current = candidate.Unmap()
	}
	return current, nil
}

func (r *ClientIPResolver) isTrusted(address netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRemoteAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.Addr().Unmap(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.IsUnspecified() {
		return netip.Addr{}, ErrInvalidClientAddress
	}
	return address.Unmap(), nil
}

type Limiter struct {
	guard       Guard
	clients     *ClientIPResolver
	sourceLimit int
	globalLimit int
	window      time.Duration
	now         func() time.Time
}

func NewLimiter(
	guard Guard,
	clients *ClientIPResolver,
	sourceLimit, globalLimit int,
	window time.Duration,
	now func() time.Time,
) (*Limiter, error) {
	if guard == nil || clients == nil || sourceLimit < 1 || globalLimit < sourceLimit ||
		window < time.Second || window > time.Hour || now == nil {
		return nil, ErrInvalidPolicy
	}
	return &Limiter{
		guard: guard, clients: clients, sourceLimit: sourceLimit,
		globalLimit: globalLimit, window: window, now: now,
	}, nil
}

func (l *Limiter) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, err := l.clients.Resolve(r)
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_client_address")
			return
		}
		now := l.now().UTC()
		allowed, retryAt, err := l.guard.Reserve(
			r.Context(), admissionKey("source:"+clientIP.String()), now, l.sourceLimit, l.window,
		)
		if err != nil {
			protectionUnavailable(w, r)
			return
		}
		if !allowed {
			rateLimited(w, r, now, retryAt)
			return
		}
		allowed, retryAt, err = l.guard.Reserve(
			r.Context(), admissionKey("global"), now, l.globalLimit, l.window,
		)
		if err != nil {
			protectionUnavailable(w, r)
			return
		}
		if !allowed {
			rateLimited(w, r, now, retryAt)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithResolvedClientIP(r.Context(), clientIP)))
	})
}

func admissionKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func rateLimited(w http.ResponseWriter, r *http.Request, now, retryAt time.Time) {
	retryAfter := retryAt.Sub(now)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	seconds := int64((retryAfter + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.FormatInt(max(seconds, 1), 10))
	w.Header().Set("Cache-Control", "no-store")
	httpx.ErrorRequest(w, r, http.StatusTooManyRequests, "rate_limited")
}

func protectionUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Cache-Control", "no-store")
	httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "ingress_protection_unavailable")
}
