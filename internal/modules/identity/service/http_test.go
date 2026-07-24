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
	)
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

func (r *memoryIdentityRepository) CreateSession(_ context.Context, session biz.Session) error {
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

func (t *testTokens) New() (string, string, error) {
	t.count++
	t.lastRaw = fmt.Sprintf("token-%d", t.count)
	return t.lastRaw, t.Hash(t.lastRaw), nil
}

func (*testTokens) Hash(value string) string {
	return "hash:" + value
}
