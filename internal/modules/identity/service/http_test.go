package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/identity/biz"
	identitydata "github.com/owndock/owndock/internal/modules/identity/data"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

func TestIdentityHTTPBootstrapAuthenticationAndLogout(t *testing.T) {
	passwords, err := identitydata.NewPasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryIdentityRepository{}
	tokens := &testTokens{}
	ids := 0
	useCase := biz.NewUseCase(
		repository,
		transaction.Passthrough{},
		discardAudit{},
		passwords,
		tokens,
		func() (string, error) {
			ids++
			return fmt.Sprintf("id-%d", ids), nil
		},
		func() time.Time { return time.Unix(100, 0) },
		time.Hour,
	).WithLoginProtection(
		allowedLoginGuard{},
		5,
		15*time.Minute,
	).WithSessionPolicy(10)
	handler := NewHTTP(useCase, func() (string, error) { return "bootstrap-secret", nil })

	denied := request(handler, http.MethodPost, "/api/v1/auth/bootstrap",
		`{"organization_name":"Example","email":"owner@example.com","password":"long-enough-password"}`, "")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("bootstrap without token status = %d", denied.Code)
	}

	bootstrapRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/bootstrap",
		strings.NewReader(`{"organization_name":"Example","email":"owner@example.com","password":"long-enough-password"}`),
	)
	bootstrapRequest.Header.Set("Content-Type", "application/json")
	bootstrapRequest.Header.Set(bootstrapTokenHeader, "bootstrap-secret")
	bootstrap := httptest.NewRecorder()
	handler.ServeHTTP(bootstrap, bootstrapRequest)
	if bootstrap.Code != http.StatusCreated || !strings.Contains(bootstrap.Body.String(), `"access_token"`) {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}

	login := request(handler, http.MethodPost, "/api/v1/auth/login",
		`{"email":"owner@example.com","password":"long-enough-password"}`, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	rawToken := tokens.lastRaw
	if rawToken == "" {
		t.Fatal("test repository did not capture raw token")
	}
	sessionList := request(
		handler,
		http.MethodGet,
		"/api/v1/auth/sessions",
		"",
		rawToken,
	)
	if sessionList.Code != http.StatusOK ||
		!strings.Contains(sessionList.Body.String(), `"current":true`) {
		t.Fatalf(
			"session list status=%d body=%s",
			sessionList.Code,
			sessionList.Body.String(),
		)
	}
	var bootstrapSessionID string
	for _, session := range repository.sessions {
		if session.TokenHash != tokens.Hash(rawToken) {
			bootstrapSessionID = session.ID
			break
		}
	}
	revoke := request(
		handler,
		http.MethodDelete,
		"/api/v1/auth/sessions/"+bootstrapSessionID,
		"",
		rawToken,
	)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf(
			"session revoke status=%d body=%s",
			revoke.Code,
			revoke.Body.String(),
		)
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meRequest.Header.Set("Authorization", "Bearer "+rawToken)
	me := httptest.NewRecorder()
	handler.ServeHTTP(me, meRequest)
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"role":"owner"`) {
		t.Fatalf("me status=%d body=%s", me.Code, me.Body.String())
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutRequest.Header.Set("Authorization", "Bearer "+rawToken)
	logout := httptest.NewRecorder()
	handler.ServeHTTP(logout, logoutRequest)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logout.Code, logout.Body.String())
	}
	meAfterLogout := httptest.NewRecorder()
	handler.ServeHTTP(meAfterLogout, meRequest)
	if meAfterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout status=%d", meAfterLogout.Code)
	}
}

func TestIdentityHTTPReturnsRetryAfterWhenLoginIsLimited(t *testing.T) {
	passwords, err := identitydata.NewPasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	useCase := biz.NewUseCase(
		&memoryIdentityRepository{},
		transaction.Passthrough{},
		discardAudit{},
		passwords,
		&testTokens{},
		func() (string, error) { return "id-1", nil },
		func() time.Time { return time.Unix(100, 0) },
		time.Hour,
	).WithLoginProtection(
		deniedLoginGuard{retryAt: time.Unix(190, 0)},
		5,
		15*time.Minute,
	).WithSessionPolicy(10)
	handler := NewHTTP(
		useCase,
		func() (string, error) { return "bootstrap-secret", nil },
	)
	response := request(
		handler,
		http.MethodPost,
		"/api/v1/auth/login",
		`{"email":"owner@example.com","password":"wrong-password"}`,
		"",
	)
	if response.Code != http.StatusTooManyRequests ||
		response.Header().Get("Retry-After") != "90" ||
		!strings.Contains(
			response.Body.String(),
			`"code":"login_rate_limited"`,
		) {
		t.Fatalf(
			"limited login status=%d retry=%q body=%s",
			response.Code,
			response.Header().Get("Retry-After"),
			response.Body.String(),
		)
	}
}

func request(handler http.Handler, method, path, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

type memoryIdentityRepository struct {
	organization biz.Organization
	user         biz.User
	sessions     map[string]biz.Session
}

func (r *memoryIdentityRepository) HasUsers(context.Context) (bool, error) {
	return r.user.ID != "", nil
}

func (r *memoryIdentityRepository) CreateBootstrap(
	_ context.Context,
	organization biz.Organization,
	user biz.User,
	session biz.Session,
) error {
	r.organization = organization
	r.user = user
	r.sessions = map[string]biz.Session{session.TokenHash: session}
	return nil
}

func (r *memoryIdentityRepository) FindUserByEmail(_ context.Context, email string) (biz.User, error) {
	if r.user.EmailNormalized != email {
		return biz.User{}, biz.ErrNotFound
	}
	return r.user, nil
}

func (r *memoryIdentityRepository) CreateSession(
	_ context.Context,
	session biz.Session,
	_ time.Time,
	_ int,
) error {
	r.sessions[session.TokenHash] = session
	return nil
}

func (r *memoryIdentityRepository) FindSession(_ context.Context, tokenHash string, now time.Time) (biz.Session, biz.User, error) {
	session, ok := r.sessions[tokenHash]
	if !ok || !session.ExpiresAt.After(now) {
		return biz.Session{}, biz.User{}, biz.ErrNotFound
	}
	return session, r.user, nil
}

func (r *memoryIdentityRepository) ListSessions(
	_ context.Context,
	userID string,
	now time.Time,
) ([]biz.Session, error) {
	var result []biz.Session
	for _, session := range r.sessions {
		if session.UserID == userID && session.ExpiresAt.After(now) {
			result = append(result, session)
		}
	}
	return result, nil
}

func (r *memoryIdentityRepository) DeleteSession(_ context.Context, sessionID, userID string) error {
	for hash, session := range r.sessions {
		if session.ID == sessionID && session.UserID == userID {
			delete(r.sessions, hash)
			return nil
		}
	}
	return biz.ErrNotFound
}

type discardAudit struct{}

func (discardAudit) Record(context.Context, sharedaudit.Event) error { return nil }

type testTokens struct {
	count   int
	lastRaw string
}

type deniedLoginGuard struct {
	retryAt time.Time
}

type allowedLoginGuard struct{}

func (allowedLoginGuard) ReserveLoginAttempt(
	context.Context,
	string,
	time.Time,
	int,
	time.Duration,
) (bool, time.Time, error) {
	return true, time.Time{}, nil
}

func (allowedLoginGuard) ResetLoginAttempts(
	context.Context,
	string,
) error {
	return nil
}

func (g deniedLoginGuard) ReserveLoginAttempt(
	context.Context,
	string,
	time.Time,
	int,
	time.Duration,
) (bool, time.Time, error) {
	return false, g.retryAt, nil
}

func (deniedLoginGuard) ResetLoginAttempts(
	context.Context,
	string,
) error {
	return nil
}

func (t *testTokens) New() (string, string, error) {
	t.count++
	t.lastRaw = fmt.Sprintf("token-%d", t.count)
	return t.lastRaw, t.Hash(t.lastRaw), nil
}

func (*testTokens) Hash(value string) string {
	return "hash:" + value
}
