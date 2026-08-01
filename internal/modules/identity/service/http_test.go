package service

import (
	"context"
	"encoding/json"
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
	if bootstrap.Code != http.StatusCreated || !strings.Contains(bootstrap.Body.String(), `"access_token"`) ||
		bootstrap.Header().Get("Cache-Control") != "no-store" || bootstrap.Header().Get("Set-Cookie") != "" {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}

	login := request(handler, http.MethodPost, "/api/v1/auth/login",
		`{"email":"owner@example.com","password":"long-enough-password"}`, "")
	if login.Code != http.StatusOK || login.Header().Get("Cache-Control") != "no-store" ||
		login.Header().Get("Set-Cookie") != "" {
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

func TestIdentityHTTPInvitationIsOneTimeAndSecretSafe(t *testing.T) {
	passwords, err := identitydata.NewPasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryIdentityRepository{}
	tokens := &testTokens{}
	sequence := 0
	useCase := biz.NewUseCase(repository, transaction.Passthrough{}, discardAudit{}, passwords, tokens,
		func() (string, error) { sequence++; return fmt.Sprintf("id-%d", sequence), nil },
		func() time.Time { return time.Unix(100, 0) }, time.Hour).
		WithLoginProtection(allowedLoginGuard{}, 5, time.Minute).
		WithSessionPolicy(10).
		WithInvitationPolicy(repository, 24*time.Hour).
		WithAdministrativeSessions(repository)
	handler := NewHTTP(useCase, func() (string, error) { return "bootstrap-secret", nil })
	bootstrapRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap",
		strings.NewReader(`{"organization_name":"Example","email":"owner@example.com","password":"owner-long-password"}`))
	bootstrapRequest.Header.Set("Content-Type", "application/json")
	bootstrapRequest.Header.Set(bootstrapTokenHeader, "bootstrap-secret")
	bootstrap := httptest.NewRecorder()
	handler.ServeHTTP(bootstrap, bootstrapRequest)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status/body = %d/%s", bootstrap.Code, bootstrap.Body.String())
	}
	ownerToken := tokens.lastRaw
	created := request(handler, http.MethodPost, "/api/v1/auth/invitations",
		`{"email":"member@example.com"}`, ownerToken)
	if created.Code != http.StatusCreated || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create invitation status/body = %d/%s", created.Code, created.Body.String())
	}
	var invitation struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &invitation); err != nil || invitation.ID == "" || len(invitation.Token) < 32 {
		t.Fatalf("invitation response = %+v/%v", invitation, err)
	}
	listed := request(handler, http.MethodGet, "/api/v1/auth/invitations", "", ownerToken)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), invitation.Token) ||
		strings.Contains(listed.Body.String(), "token_hash") {
		t.Fatalf("list invitations status/body = %d/%s", listed.Code, listed.Body.String())
	}
	accepted := request(handler, http.MethodPost, "/api/v1/auth/invitations:accept",
		fmt.Sprintf(`{"token":%q,"password":"member-long-password"}`, invitation.Token), "")
	if accepted.Code != http.StatusCreated || !strings.Contains(accepted.Body.String(), `"role":"viewer"`) ||
		accepted.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("accept invitation status/body = %d/%s", accepted.Code, accepted.Body.String())
	}
	memberToken := tokens.lastRaw
	member := repository.users["member@example.com"]
	adminSessions := request(handler, http.MethodGet,
		"/api/v1/auth/users/"+member.ID+"/sessions", "", ownerToken)
	if adminSessions.Code != http.StatusOK || adminSessions.Header().Get("Cache-Control") != "no-store" ||
		strings.Contains(adminSessions.Body.String(), "token_hash") {
		t.Fatalf("admin session list status/body = %d/%s", adminSessions.Code, adminSessions.Body.String())
	}
	revokeAll := request(handler, http.MethodDelete,
		"/api/v1/auth/users/"+member.ID+"/sessions", "", ownerToken)
	if revokeAll.Code != http.StatusOK || !strings.Contains(revokeAll.Body.String(), `"revoked_sessions":1`) {
		t.Fatalf("admin revoke all status/body = %d/%s", revokeAll.Code, revokeAll.Body.String())
	}
	memberAfterRevoke := request(handler, http.MethodGet, "/api/v1/auth/me", "", memberToken)
	if memberAfterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("member after admin revoke status/body = %d/%s", memberAfterRevoke.Code, memberAfterRevoke.Body.String())
	}
	replayed := request(handler, http.MethodPost, "/api/v1/auth/invitations:accept",
		fmt.Sprintf(`{"token":%q,"password":"member-long-password"}`, invitation.Token), "")
	if replayed.Code != http.StatusUnauthorized || !strings.Contains(replayed.Body.String(), `"code":"invalid_invitation"`) {
		t.Fatalf("replay invitation status/body = %d/%s", replayed.Code, replayed.Body.String())
	}
	users := request(handler, http.MethodGet, "/api/v1/auth/users", "", ownerToken)
	if users.Code != http.StatusOK || !strings.Contains(users.Body.String(), "member@example.com") ||
		strings.Contains(users.Body.String(), "password_hash") {
		t.Fatalf("list users status/body = %d/%s", users.Code, users.Body.String())
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
	users        map[string]biz.User
	usersByID    map[string]biz.User
	invitations  map[string]biz.Invitation
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
	r.users = map[string]biz.User{user.EmailNormalized: user}
	r.usersByID = map[string]biz.User{user.ID: user}
	r.invitations = make(map[string]biz.Invitation)
	r.sessions = map[string]biz.Session{session.TokenHash: session}
	return nil
}

func (r *memoryIdentityRepository) FindUserByEmail(_ context.Context, email string) (biz.User, error) {
	if user, ok := r.users[email]; ok {
		return user, nil
	}
	if r.user.EmailNormalized != email {
		return biz.User{}, biz.ErrNotFound
	}
	return r.user, nil
}

func (r *memoryIdentityRepository) ListUsers(_ context.Context, organizationID string) ([]biz.User, error) {
	var result []biz.User
	for _, user := range r.users {
		if user.OrganizationID == organizationID {
			user.PasswordHash = ""
			result = append(result, user)
		}
	}
	return result, nil
}

func (r *memoryIdentityRepository) GetOrganizationUser(
	_ context.Context, organizationID, userID string,
) (biz.User, error) {
	user, ok := r.usersByID[userID]
	if !ok || user.OrganizationID != organizationID {
		return biz.User{}, biz.ErrNotFound
	}
	user.PasswordHash = ""
	return user, nil
}

func (r *memoryIdentityRepository) CreateInvitation(_ context.Context, item biz.Invitation) (biz.Invitation, error) {
	r.invitations[item.ID] = item
	return item, nil
}

func (r *memoryIdentityRepository) ListInvitations(_ context.Context, organizationID string) ([]biz.Invitation, error) {
	var result []biz.Invitation
	for _, item := range r.invitations {
		if item.OrganizationID == organizationID {
			result = append(result, item.Safe())
		}
	}
	return result, nil
}

func (r *memoryIdentityRepository) GetInvitation(_ context.Context, organizationID, invitationID string) (biz.Invitation, error) {
	item, ok := r.invitations[invitationID]
	if !ok || item.OrganizationID != organizationID {
		return biz.Invitation{}, biz.ErrNotFound
	}
	return item, nil
}

func (r *memoryIdentityRepository) FindInvitationByTokenHash(_ context.Context, tokenHash string, now time.Time) (biz.Invitation, error) {
	for _, item := range r.invitations {
		if item.TokenHash == tokenHash && item.Status == biz.InvitationStatusActive && item.ExpiresAt.After(now) {
			return item, nil
		}
	}
	return biz.Invitation{}, biz.ErrInvalidInvitation
}

func (r *memoryIdentityRepository) AcceptInvitation(_ context.Context, accepted biz.Invitation,
	expectedVersion uint64, user biz.User, session biz.Session) error {
	current, ok := r.invitations[accepted.ID]
	if !ok || current.Version != expectedVersion || current.Status != biz.InvitationStatusActive {
		return biz.ErrInvalidInvitation
	}
	if _, exists := r.users[user.EmailNormalized]; exists {
		return biz.ErrUserAlreadyExists
	}
	r.invitations[accepted.ID] = accepted
	r.users[user.EmailNormalized], r.usersByID[user.ID] = user, user
	r.sessions[session.TokenHash] = session
	return nil
}

func (r *memoryIdentityRepository) RevokeInvitation(_ context.Context, revoked biz.Invitation,
	expectedVersion uint64) (biz.Invitation, error) {
	current, ok := r.invitations[revoked.ID]
	if !ok || current.Version != expectedVersion || current.Status != biz.InvitationStatusActive {
		return biz.Invitation{}, biz.ErrInvalidInvitation
	}
	r.invitations[revoked.ID] = revoked
	return revoked, nil
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
	user, ok := r.usersByID[session.UserID]
	if !ok {
		return biz.Session{}, biz.User{}, biz.ErrNotFound
	}
	return session, user, nil
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

func (r *memoryIdentityRepository) DeleteUserSessions(_ context.Context, userID string) (int64, error) {
	var deleted int64
	for hash, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, hash)
			deleted++
		}
	}
	return deleted, nil
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
	t.lastRaw = fmt.Sprintf("token-%d-012345678901234567890123456789", t.count)
	return t.lastRaw, t.Hash(t.lastRaw), nil
}

func (*testTokens) Hash(value string) string {
	return "hash:" + value
}
