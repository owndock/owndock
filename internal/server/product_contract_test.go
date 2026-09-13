package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/log"

	applicationbiz "github.com/owndock/owndock/internal/modules/application/biz"
	applicationdata "github.com/owndock/owndock/internal/modules/application/data"
	applicationservice "github.com/owndock/owndock/internal/modules/application/service"
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	buildservice "github.com/owndock/owndock/internal/modules/build/service"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	controlplanedata "github.com/owndock/owndock/internal/modules/controlplane/data"
	controlplaneservice "github.com/owndock/owndock/internal/modules/controlplane/service"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	deploymentdata "github.com/owndock/owndock/internal/modules/deployment/data"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
	environmentdata "github.com/owndock/owndock/internal/modules/environment/data"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	identitybiz "github.com/owndock/owndock/internal/modules/identity/biz"
	identityservice "github.com/owndock/owndock/internal/modules/identity/service"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostservice "github.com/owndock/owndock/internal/modules/managedhost/service"
	"github.com/owndock/owndock/internal/modules/meta"
	runtimeinventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	runtimeinventoryservice "github.com/owndock/owndock/internal/modules/runtimeinventory/service"
	supplychainbiz "github.com/owndock/owndock/internal/modules/supplychain/biz"
	supplychainservice "github.com/owndock/owndock/internal/modules/supplychain/service"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	terminalservice "github.com/owndock/owndock/internal/modules/terminal/service"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/ingress"
	"github.com/owndock/owndock/internal/platform/observability"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

const contractAccessToken = "test-token-0123456789012345678901234567890123456789"
const contractLoginToken = "login-token-01234567890123456789012345678901234567"
const contractInvitationToken = "invite-token-0123456789012345678901234567890123456"
const contractMemberToken = "member-token-0123456789012345678901234567890123456"

type contractLoginGuard struct{}

type contractAdmissionEvaluator struct{ now func() time.Time }

func (e contractAdmissionEvaluator) EvaluateAdmission(context.Context,
	deploymentbiz.AdmissionRequest) (deploymentbiz.AdmissionSnapshot, error) {
	return (deploymentbiz.AdmissionSnapshot{EvaluatedAt: e.now(), EnvironmentStage: "development",
		Policies: []deploymentbiz.AdmissionPolicySnapshot{}, Evidence: []deploymentbiz.AdmissionEvidenceSnapshot{},
		Verifications: []deploymentbiz.AdmissionVerificationSnapshot{}, Waivers: []deploymentbiz.AdmissionWaiverSnapshot{},
		Violations: []deploymentbiz.AdmissionViolation{}, Decision: deploymentbiz.AdmissionNotConfigured}).Seal()
}

type contractBuildTriggerTokens struct{}

type contractWebhookVerifier struct{}

func (contractWebhookVerifier) VerifyAndParse(context.Context, buildbiz.BuildHook, buildbiz.WebhookEnvelope) (buildbiz.WebhookEvent, error) {
	return buildbiz.WebhookEvent{Supported: true, Ref: "refs/heads/main", CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16"}, nil
}

type contractWebhookRateGuard struct{}

func (contractWebhookRateGuard) ReserveBuildWebhook(_ context.Context, _ string, now time.Time, _ int, _ time.Duration) (bool, time.Time, error) {
	return true, now, nil
}

func (contractBuildTriggerTokens) New() (string, string, error) {
	return "contract-build-trigger-token-01234567890123", strings.Repeat("a", 64), nil
}
func (contractBuildTriggerTokens) Hash(raw string) string {
	if raw == "contract-build-trigger-token-01234567890123" {
		return strings.Repeat("a", 64)
	}
	return strings.Repeat("b", 64)
}

func (contractLoginGuard) ReserveLoginAttempt(
	context.Context,
	string,
	time.Time,
	int,
	time.Duration,
) (bool, time.Time, error) {
	return true, time.Time{}, nil
}

func (contractLoginGuard) ResetLoginAttempts(
	context.Context,
	string,
) error {
	return nil
}

func newProductContractHTTPHandler(t *testing.T) http.Handler {
	t.Helper()
	now := func() time.Time { return time.Unix(100, 0).UTC() }
	newID := func() (string, error) { return "test-id", nil }
	audits := &contractAudit{}

	identityRepository := &contractIdentityRepository{}
	identityUseCase := identitybiz.NewUseCase(
		identityRepository,
		transaction.Passthrough{},
		audits,
		contractPasswords{},
		&contractTokens{},
		newID,
		now,
		time.Hour,
	).WithLoginProtection(
		contractLoginGuard{},
		5,
		15*time.Minute,
	).WithSessionPolicy(10).
		WithInvitationPolicy(identityRepository, 24*time.Hour).
		WithAdministrativeSessions(identityRepository)
	identityHTTP := identityservice.NewHTTP(identityUseCase, func() (string, error) {
		return "bootstrap-secret", nil
	})
	controlStore := &contractControlStore{users: []controlplanebiz.OrganizationUser{{
		ID: "contract-member-id", OrganizationID: "test-id",
		Email: "member@example.com", Role: security.RoleViewer,
	}}}
	managedHostStore := &contractManagedHostStore{}
	runtimeTargetRetirer := &contractRuntimeTargetRetirer{}
	controlUseCase := controlplanebiz.NewUseCaseWithResources(
		controlStore, controlStore, controlStore, controlStore, controlStore, controlStore,
		transaction.Passthrough{}, audits, audits, newID, now,
	).WithManagedHosts(managedHostStore).
		WithProjectMembers(controlStore).
		WithTemplates(controlplanedata.NewBuiltInTemplateCatalog()).
		WithRuntimeTargetProbe(controlStore, contractRuntimeTargetProber{}).
		WithRuntimeTargetRetirement(controlStore, runtimeTargetRetirer)
	controlHTTP := controlplaneservice.NewHTTP(controlUseCase)
	managedHostHTTP := managedhostservice.NewHTTP(managedhostbiz.NewUseCase(
		managedHostStore, transaction.Passthrough{}, audits, newID, now,
	))
	formalDeploymentHTTP := deploymentservice.NewHTTP(
		deploymentbiz.NewUseCase(deploymentdata.NewMemoryRepository(), nil, nil, newID, now).
			WithFormalReferences(deploymentdata.NewFormalReferenceLookup(controlStore)).
			WithFormalSecurity(transaction.Passthrough{}, audits).
			WithAdmissionEvaluator(contractAdmissionEvaluator{now: now}),
	)
	productAPI, err := NewProductAPIWithDeploymentAndManagedHost(
		identityHTTP, controlHTTP, http.HandlerFunc(formalDeploymentHTTP.HandleFormal),
		managedHostHTTP, identityHTTP.Authenticate,
	)
	if err != nil {
		t.Fatalf("NewProductAPI() error = %v", err)
	}
	runtimeInventoryUseCase, err := runtimeinventorybiz.NewViewUseCase(
		contractRuntimeInventory{}, audits, newID, now,
	)
	if err != nil {
		t.Fatalf("NewViewUseCase() error = %v", err)
	}
	if err := productAPI.WithRuntimeInventory(
		runtimeinventoryservice.NewHTTP(runtimeInventoryUseCase),
		identityHTTP.Authenticate,
	); err != nil {
		t.Fatalf("WithRuntimeInventory() error = %v", err)
	}
	buildStore := newContractBuildStore()
	buildUseCase := buildbiz.NewUseCase(
		controlStore,
		buildStore,
		transaction.Passthrough{},
		audits,
		newID,
		now,
	).WithSourceProber(contractSourceProber{}).WithConfigurationReferences(
		contractBuildReferences{}, contractBuildReferences{},
	).WithSourceRevisionResolver(contractSourceProber{}).
		WithWebhookVerifier(contractWebhookVerifier{}).
		WithWebhookAdmission(contractWebhookRateGuard{}, 120, time.Minute).
		WithBuildTriggerAutomation(contractBuildTriggerTokens{}, buildStore, 60, time.Minute).
		WithArtifactReleases(buildStore, contractArtifactReleaseCreator{}).
		WithBuildLogs(buildStore).
		WithExternalArtifactRegistration(contractArtifactEvidenceScheduler{}, contractArtifactProbe{})
	buildHTTP := buildservice.NewHTTP(buildUseCase)
	if err := productAPI.WithBuild(buildHTTP, identityHTTP.Authenticate); err != nil {
		t.Fatalf("WithBuild() error = %v", err)
	}
	contractEvidenceRepository := contractArtifactEvidenceRepository{}
	supplyChainUseCase, err := supplychainbiz.NewUseCase(
		controlStore, contractArtifactEvidenceLookup{}, contractEvidenceRepository,
	)
	if err != nil {
		t.Fatalf("New supply-chain use case: %v", err)
	}
	supplyChainUseCase.WithVerificationRepository(contractEvidenceRepository)
	trustPolicyRepository := &contractSignatureTrustPolicyRepository{items: make(map[string]supplychainbiz.SignatureTrustPolicy)}
	privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	publicDER, keyErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	signingTrustPolicy, keyErr := supplychainbiz.NewSignatureTrustPolicy(supplychainbiz.SignatureTrustPolicyInput{
		ID: "signing-trust-policy", OrganizationID: "test-id", ProjectID: "test-id", Name: "KMS signer",
		Mode:         supplychainbiz.SignatureTrustPublicKey,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		Enabled:      true, Version: 1, CreatedAt: now(), UpdatedAt: now()})
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	trustPolicyRepository.items[signingTrustPolicy.ID] = signingTrustPolicy
	trustPolicyUseCase, err := supplychainbiz.NewSignatureTrustPolicyUseCase(
		controlStore, trustPolicyRepository, newID, now,
	)
	if err != nil {
		t.Fatalf("New signature trust policy use case: %v", err)
	}
	trustPolicyUseCase.WithAudit(transaction.Passthrough{}, audits)
	signingProfileRepository := &contractSigningProfileRepository{items: make(map[string]supplychainbiz.SignatureSigningProfile)}
	signingProfileUseCase, err := supplychainbiz.NewSignatureSigningProfileUseCase(
		controlStore, trustPolicyRepository, signingProfileRepository, newID, now,
	)
	if err != nil {
		t.Fatalf("New signature signing profile use case: %v", err)
	}
	signingProfileUseCase.WithAudit(transaction.Passthrough{}, audits)
	signatureVerificationUseCase, err := supplychainbiz.NewSignatureVerificationUseCase(
		contractArtifactEvidenceLookup{}, trustPolicyRepository, contractEvidenceJobCreator{}, newID, now,
	)
	if err != nil {
		t.Fatalf("New signature verification use case: %v", err)
	}
	signatureVerificationUseCase.WithAudit(transaction.Passthrough{}, audits)
	vulnerabilityWaiverRepository := &contractVulnerabilityWaiverRepository{
		items: make(map[string]supplychainbiz.VulnerabilityWaiver),
	}
	vulnerabilityWaiverUseCase, err := supplychainbiz.NewVulnerabilityWaiverUseCase(
		controlStore, contractArtifactEvidenceLookup{}, vulnerabilityWaiverRepository, newID, now,
	)
	if err != nil {
		t.Fatalf("New vulnerability waiver use case: %v", err)
	}
	vulnerabilityWaiverUseCase.WithAudit(transaction.Passthrough{}, audits)
	deploymentPolicyRepository := &contractDeploymentPolicyRepository{
		items: make(map[string]supplychainbiz.DeploymentPolicy),
	}
	deploymentPolicyUseCase, err := supplychainbiz.NewDeploymentPolicyUseCase(
		controlStore, controlStore, deploymentPolicyRepository, newID, now,
	)
	if err != nil {
		t.Fatalf("New deployment policy use case: %v", err)
	}
	deploymentPolicyUseCase.WithAudit(transaction.Passthrough{}, audits)
	if err := productAPI.WithSupplyChain(
		supplychainservice.NewHTTP(supplyChainUseCase).WithSignatureTrustPolicies(trustPolicyUseCase).
			WithSignatureSigningProfiles(signingProfileUseCase).
			WithSignatureVerifications(signatureVerificationUseCase).
			WithVulnerabilityWaivers(vulnerabilityWaiverUseCase).
			WithDeploymentPolicies(deploymentPolicyUseCase),
		identityHTTP.Authenticate,
	); err != nil {
		t.Fatalf("WithSupplyChain() error = %v", err)
	}
	terminalStore := &contractTerminalStore{
		policies: make(map[string]terminalbiz.AccessPolicy),
		sessions: make(map[string]terminalbiz.TerminalSession),
	}
	terminalUseCase, err := terminalbiz.NewUseCase(
		terminalStore, terminalStore, contractTerminalTargets{}, contractTerminalRoles{},
		transaction.Passthrough{}, audits, contractTerminalTickets{}, newID, now,
	)
	if err != nil {
		t.Fatalf("New terminal use case: %v", err)
	}
	if err := productAPI.WithTerminal(
		terminalservice.NewHTTP(terminalUseCase), identityHTTP.Authenticate,
	); err != nil {
		t.Fatalf("WithTerminal() error = %v", err)
	}
	if err := productAPI.WithIngressProtection(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := ingress.WithResolvedClientIP(r.Context(), netip.MustParseAddr("192.0.2.10"))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}); err != nil {
		t.Fatalf("WithIngressProtection() error = %v", err)
	}

	applications := applicationdata.NewMemoryRepository()
	environments := environmentdata.NewMemoryRepository()
	samples := &EngineeringSamples{
		Application: applicationservice.NewHTTP(applicationbiz.NewUseCase(applications, newID, now)),
		Environment: environmentservice.NewHTTP(environmentbiz.NewUseCase(environments, newID, now)),
		Deployment: deploymentservice.NewHTTP(deploymentbiz.NewUseCase(
			deploymentdata.NewMemoryRepository(),
			deploymentdata.NewApplicationLookup(applications),
			deploymentdata.NewEnvironmentLookup(environments),
			newID,
			now,
		)),
	}
	checker := health.NewChecker()
	checker.SetReady(true)
	tracing, err := observability.NewTracing(context.Background(), platformconfig.Tracing{}, "owndock", "test", "test-instance")
	if err != nil {
		t.Fatalf("NewTracing() error = %v", err)
	}
	srv, err := NewHTTPServer(
		platformconfig.HTTP{Address: "127.0.0.1:0", Timeout: "1s"},
		checker,
		meta.NewService(meta.BuildInfo{Service: "owndock", Version: "test"}),
		samples,
		productAPI,
		observability.NewMetrics(),
		tracing,
		log.NewStdLogger(httptest.NewRecorder()),
	)
	if err != nil {
		t.Fatalf("NewHTTPServer() error = %v", err)
	}
	return srv
}

type contractTerminalStore struct {
	policies map[string]terminalbiz.AccessPolicy
	sessions map[string]terminalbiz.TerminalSession
}

func terminalPolicyKey(scope terminalbiz.PolicyScope, organizationID, projectID string) string {
	return string(scope) + ":" + organizationID + ":" + projectID
}

func (s *contractTerminalStore) GetProjectPolicy(_ context.Context, organizationID, projectID string) (terminalbiz.AccessPolicy, error) {
	item, ok := s.policies[terminalPolicyKey(terminalbiz.PolicyScopeProject, organizationID, projectID)]
	if !ok {
		return terminalbiz.AccessPolicy{}, terminalbiz.ErrPolicyNotFound
	}
	return item, nil
}

func (s *contractTerminalStore) GetOrganizationPolicy(_ context.Context, organizationID string) (terminalbiz.AccessPolicy, error) {
	item, ok := s.policies[terminalPolicyKey(terminalbiz.PolicyScopeOrganization, organizationID, "")]
	if !ok {
		return terminalbiz.AccessPolicy{}, terminalbiz.ErrPolicyNotFound
	}
	return item, nil
}

func (s *contractTerminalStore) SavePolicy(_ context.Context, item terminalbiz.AccessPolicy, _ uint64) (terminalbiz.AccessPolicy, error) {
	s.policies[terminalPolicyKey(item.Scope, item.OrganizationID, item.ProjectID)] = item
	return item, nil
}

func (s *contractTerminalStore) GetSession(_ context.Context, organizationID, sessionID string) (terminalbiz.TerminalSession, error) {
	item, ok := s.sessions[sessionID]
	if !ok || item.OrganizationID != organizationID {
		return terminalbiz.TerminalSession{}, terminalbiz.ErrSessionNotFound
	}
	return item, nil
}

func (s *contractTerminalStore) GetSessionForConnect(
	_ context.Context,
	sessionID string,
) (terminalbiz.TerminalSession, error) {
	item, ok := s.sessions[sessionID]
	if !ok || item.Status != terminalbiz.StatusPending || !item.Active {
		return terminalbiz.TerminalSession{}, terminalbiz.ErrSessionNotFound
	}
	return item, nil
}

func (s *contractTerminalStore) CreateSession(_ context.Context, item terminalbiz.TerminalSession) (terminalbiz.TerminalSession, error) {
	if existing, ok := s.sessions[item.ID]; ok && existing.Active {
		return terminalbiz.TerminalSession{}, terminalbiz.ErrSessionSlotConflict
	}
	s.sessions[item.ID] = item
	return item, nil
}

func (s *contractTerminalStore) SaveSession(_ context.Context, item terminalbiz.TerminalSession, expected uint64) (terminalbiz.TerminalSession, error) {
	current, ok := s.sessions[item.ID]
	if !ok || current.Version != expected {
		return terminalbiz.TerminalSession{}, terminalbiz.ErrSessionConflict
	}
	s.sessions[item.ID] = item
	return item, nil
}

func (s *contractTerminalStore) ConsumeTicket(_ context.Context, organizationID, sessionID, ticketHash string, now time.Time) (terminalbiz.TerminalSession, error) {
	item, ok := s.sessions[sessionID]
	if !ok || item.OrganizationID != organizationID || item.TicketHash != ticketHash {
		return terminalbiz.TerminalSession{}, terminalbiz.ErrInvalidTicket
	}
	connected, err := item.MarkOpen(now)
	if err != nil {
		return terminalbiz.TerminalSession{}, terminalbiz.ErrInvalidTicket
	}
	s.sessions[sessionID] = connected
	return connected, nil
}

type contractTerminalTargets struct{}

func (contractTerminalTargets) ProjectExists(context.Context, string, string) (bool, error) {
	return true, nil
}
func (contractTerminalTargets) ResolveContainer(_ context.Context, organizationID, projectID, deploymentID string) (terminalbiz.Target, error) {
	return terminalbiz.Target{
		Kind: terminalbiz.KindContainer, OrganizationID: organizationID, ProjectID: projectID,
		ManagedHostID: "test-id", RuntimeTargetID: "test-id", DeploymentID: deploymentID,
		RunningInstanceID: deploymentID + ":1", InstanceGeneration: 1,
		EnvironmentStage: "production", ConnectionMode: runtimeaccess.ModeDirectDocker,
	}, nil
}
func (contractTerminalTargets) ResolveHost(_ context.Context, organizationID, hostID string) (terminalbiz.Target, error) {
	return terminalbiz.Target{
		Kind: terminalbiz.KindHost, OrganizationID: organizationID,
		ManagedHostID: hostID, ConnectionMode: runtimeaccess.ModeDirectDocker,
	}, nil
}

type contractTerminalRoles struct{}

func (contractTerminalRoles) ResolveTerminalProjectRole(context.Context, string, string, string) (security.Role, error) {
	return security.RoleOwner, nil
}

type contractTerminalTickets struct{}

func (contractTerminalTickets) New() (string, string, error) {
	return "contract-terminal-ticket-0123456789", strings.Repeat("a", 64), nil
}
func (contractTerminalTickets) Hash(string) string { return strings.Repeat("a", 64) }

type contractRuntimeInventory struct{}

func (contractRuntimeInventory) ListProject(
	context.Context, string, string, runtimeinventorybiz.ViewQuery,
) (runtimeinventorybiz.StatePage, error) {
	return runtimeinventorybiz.StatePage{Items: []runtimeinventorybiz.State{contractInventoryState()}}, nil
}

func (contractRuntimeInventory) ListHost(
	context.Context, string, string, runtimeinventorybiz.ViewQuery,
) (runtimeinventorybiz.StatePage, error) {
	return runtimeinventorybiz.StatePage{Items: []runtimeinventorybiz.State{contractInventoryState()}}, nil
}

func contractInventoryState() runtimeinventorybiz.State {
	now := time.Unix(100, 0).UTC()
	return runtimeinventorybiz.State{
		Resource: runtimeinventorybiz.Resource{
			ObservationID: "observation-1", OrganizationID: "organization-1",
			ManagedHostID: "test-id", RuntimeTargetID: "test-id",
			Kind: runtimeinventorybiz.KindContainer, RuntimeID: "container-1",
			Name: "api", Managed: true, ProjectID: "test-id",
			DeploymentID: "test-id",
			Container:    &runtimeinventorybiz.ContainerSummary{State: "running"},
			Ports:        []runtimeinventorybiz.Port{}, Mounts: []runtimeinventorybiz.Mount{},
			Networks:   []runtimeinventorybiz.NetworkAttachment{},
			ObservedAt: now, SchemaVersion: runtimeinventorybiz.CurrentSchemaVersion,
		},
		Presence:    runtimeinventorybiz.PresencePresent,
		FirstSeenAt: now, LastSeenAt: now, ReconciledAt: now, Generation: 1,
	}
}

type contractIdentityRepository struct {
	user        identitybiz.User
	users       map[string]identitybiz.User
	usersByID   map[string]identitybiz.User
	invitations map[string]identitybiz.Invitation
	sessions    map[string]identitybiz.Session
}

func (r *contractIdentityRepository) HasUsers(context.Context) (bool, error) {
	return r.user.ID != "", nil
}

func (r *contractIdentityRepository) CreateBootstrap(
	_ context.Context,
	_ identitybiz.Organization,
	user identitybiz.User,
	session identitybiz.Session,
) error {
	r.user = user
	r.users = map[string]identitybiz.User{user.EmailNormalized: user}
	r.usersByID = map[string]identitybiz.User{user.ID: user}
	r.invitations = make(map[string]identitybiz.Invitation)
	r.sessions = map[string]identitybiz.Session{session.TokenHash: session}
	return nil
}

func (r *contractIdentityRepository) FindUserByEmail(_ context.Context, email string) (identitybiz.User, error) {
	if user, ok := r.users[email]; ok {
		return user, nil
	}
	if r.user.EmailNormalized != email {
		return identitybiz.User{}, identitybiz.ErrNotFound
	}
	return r.user, nil
}

func (r *contractIdentityRepository) ListUsers(_ context.Context, organizationID string) ([]identitybiz.User, error) {
	var result []identitybiz.User
	for _, user := range r.users {
		if user.OrganizationID == organizationID {
			user.PasswordHash = ""
			result = append(result, user)
		}
	}
	return result, nil
}

func (r *contractIdentityRepository) GetOrganizationUser(
	_ context.Context, organizationID, userID string,
) (identitybiz.User, error) {
	user, ok := r.usersByID[userID]
	if !ok || user.OrganizationID != organizationID {
		return identitybiz.User{}, identitybiz.ErrNotFound
	}
	user.PasswordHash = ""
	return user, nil
}

func (r *contractIdentityRepository) CreateInvitation(_ context.Context, item identitybiz.Invitation) (identitybiz.Invitation, error) {
	r.invitations[item.ID] = item
	return item, nil
}

func (r *contractIdentityRepository) ListInvitations(_ context.Context, organizationID string) ([]identitybiz.Invitation, error) {
	var result []identitybiz.Invitation
	for _, item := range r.invitations {
		if item.OrganizationID == organizationID {
			result = append(result, item.Safe())
		}
	}
	return result, nil
}

func (r *contractIdentityRepository) GetInvitation(_ context.Context, organizationID, invitationID string) (identitybiz.Invitation, error) {
	item, ok := r.invitations[invitationID]
	if !ok || item.OrganizationID != organizationID {
		return identitybiz.Invitation{}, identitybiz.ErrNotFound
	}
	return item, nil
}

func (r *contractIdentityRepository) FindInvitationByTokenHash(_ context.Context, tokenHash string, now time.Time) (identitybiz.Invitation, error) {
	for _, item := range r.invitations {
		if item.TokenHash == tokenHash && item.Status == identitybiz.InvitationStatusActive && item.ExpiresAt.After(now) {
			return item, nil
		}
	}
	return identitybiz.Invitation{}, identitybiz.ErrInvalidInvitation
}

func (r *contractIdentityRepository) AcceptInvitation(_ context.Context, accepted identitybiz.Invitation,
	expectedVersion uint64, user identitybiz.User, session identitybiz.Session) error {
	current, ok := r.invitations[accepted.ID]
	if !ok || current.Version != expectedVersion || current.Status != identitybiz.InvitationStatusActive {
		return identitybiz.ErrInvalidInvitation
	}
	r.invitations[accepted.ID] = accepted
	// Keep the contract member distinct from the bootstrap owner even though the
	// shared deterministic ID generator returns test-id for most product fixtures.
	user.ID = "contract-member-id"
	session.ID = "contract-member-session"
	session.UserID = user.ID
	r.users[user.EmailNormalized] = user
	if _, exists := r.usersByID[user.ID]; !exists {
		r.usersByID[user.ID] = user
	}
	r.sessions[session.TokenHash] = session
	return nil
}

func (r *contractIdentityRepository) RevokeInvitation(_ context.Context, revoked identitybiz.Invitation,
	expectedVersion uint64) (identitybiz.Invitation, error) {
	current, ok := r.invitations[revoked.ID]
	if !ok || current.Version != expectedVersion || current.Status != identitybiz.InvitationStatusActive {
		return identitybiz.Invitation{}, identitybiz.ErrInvalidInvitation
	}
	r.invitations[revoked.ID] = revoked
	return revoked, nil
}

func (r *contractIdentityRepository) CreateSession(
	_ context.Context,
	session identitybiz.Session,
	_ time.Time,
	_ int,
) error {
	r.sessions[session.TokenHash] = session
	return nil
}

func (r *contractIdentityRepository) FindSession(
	_ context.Context,
	tokenHash string,
	now time.Time,
) (identitybiz.Session, identitybiz.User, error) {
	session, ok := r.sessions[tokenHash]
	if !ok || !session.ExpiresAt.After(now) {
		return identitybiz.Session{}, identitybiz.User{}, identitybiz.ErrNotFound
	}
	user, ok := r.usersByID[session.UserID]
	if !ok {
		return identitybiz.Session{}, identitybiz.User{}, identitybiz.ErrNotFound
	}
	return session, user, nil
}

func (r *contractIdentityRepository) ListSessions(
	_ context.Context,
	userID string,
	now time.Time,
) ([]identitybiz.Session, error) {
	var result []identitybiz.Session
	for _, session := range r.sessions {
		if session.UserID == userID && session.ExpiresAt.After(now) {
			result = append(result, session)
		}
	}
	return result, nil
}

func (r *contractIdentityRepository) DeleteSession(_ context.Context, sessionID, userID string) error {
	for hash, session := range r.sessions {
		if session.ID == sessionID && session.UserID == userID {
			delete(r.sessions, hash)
			return nil
		}
	}
	return identitybiz.ErrNotFound
}

func (r *contractIdentityRepository) DeleteUserSessions(_ context.Context, userID string) (int64, error) {
	var deleted int64
	for hash, session := range r.sessions {
		if session.UserID == userID {
			delete(r.sessions, hash)
			deleted++
		}
	}
	return deleted, nil
}

type contractPasswords struct{}

func (contractPasswords) Hash(value string) (string, error) { return "hash:" + value, nil }
func (contractPasswords) Verify(value, encoded string) bool { return encoded == "hash:"+value }
func (contractPasswords) DummyHash() string                 { return "hash:dummy" }

type contractTokens struct{ count int }

func (t *contractTokens) New() (string, string, error) {
	t.count++
	raw := contractAccessToken
	switch t.count {
	case 2:
		raw = contractLoginToken
	case 3:
		raw = contractInvitationToken
	default:
		if t.count > 3 {
			raw = contractMemberToken
		}
	}
	return raw, "hash:" + raw, nil
}
func (*contractTokens) Hash(value string) string { return "hash:" + value }

type contractAudit struct {
	events []sharedaudit.Event
}

func (a *contractAudit) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func (a *contractAudit) List(_ context.Context, organizationID, projectID string, limit int64) ([]sharedaudit.Event, error) {
	var result []sharedaudit.Event
	for _, event := range a.events {
		if event.OrganizationID == organizationID && (projectID == "" || event.ProjectID == projectID) {
			result = append(result, event)
		}
	}
	if int64(len(result)) > limit {
		result = result[:limit]
	}
	return result, nil
}

type contractControlStore struct {
	projects     []controlplanebiz.Project
	users        []controlplanebiz.OrganizationUser
	members      []controlplanebiz.ProjectMember
	applications []controlplanebiz.Application
	releases     []controlplanebiz.Release
	targets      []controlplanebiz.RuntimeTarget
	registries   []controlplanebiz.RegistryCredential
	environments []controlplanebiz.Environment
}

type contractRuntimeTargetProber struct{}

type contractRuntimeTargetRetirer struct{ calls int }

func (r *contractRuntimeTargetRetirer) RetireRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
	security.Principal,
	string,
) error {
	r.calls++
	if r.calls == 1 {
		return controlplanebiz.ErrRuntimeTargetRetirementPending
	}
	return nil
}

type contractManagedHostStore struct {
	items []managedhostbiz.ManagedHost
}

func (s *contractManagedHostStore) List(
	_ context.Context,
	organizationID string,
) ([]managedhostbiz.ManagedHost, error) {
	var result []managedhostbiz.ManagedHost
	for _, item := range s.items {
		if item.OrganizationID == organizationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractManagedHostStore) Get(
	_ context.Context,
	organizationID, hostID string,
) (managedhostbiz.ManagedHost, error) {
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ID == hostID {
			return item, nil
		}
	}
	return managedhostbiz.ManagedHost{}, managedhostbiz.ErrNotFound
}

func (s *contractManagedHostStore) Create(
	_ context.Context,
	item managedhostbiz.ManagedHost,
) (managedhostbiz.ManagedHost, error) {
	s.items = append(s.items, item)
	return item, nil
}

func (s *contractManagedHostStore) Disable(
	_ context.Context,
	organizationID, hostID string,
	now time.Time,
) (managedhostbiz.ManagedHost, error) {
	for index := range s.items {
		if s.items[index].OrganizationID == organizationID &&
			s.items[index].ID == hostID {
			s.items[index].Status = managedhostbiz.StatusDisabled
			s.items[index].AgentBootID = ""
			s.items[index].AgentSessionID = ""
			s.items[index].UpdatedAt = now
			return s.items[index], nil
		}
	}
	return managedhostbiz.ManagedHost{}, managedhostbiz.ErrNotFound
}

func (s *contractManagedHostStore) ConnectionMode(
	ctx context.Context,
	organizationID, hostID string,
) (runtimeaccess.Mode, bool, error) {
	item, err := s.Get(ctx, organizationID, hostID)
	if err == managedhostbiz.ErrNotFound {
		return "", false, nil
	}
	return item.ConnectionMode, err == nil, err
}

func (contractRuntimeTargetProber) ProbeRuntimeTarget(
	context.Context,
	controlplanebiz.RuntimeTarget,
) (controlplanebiz.RuntimeTargetStatus, error) {
	return controlplanebiz.RuntimeTargetStatusReady, nil
}

func (s *contractControlStore) ListProjects(_ context.Context, organizationID string) ([]controlplanebiz.Project, error) {
	var result []controlplanebiz.Project
	for _, item := range s.projects {
		if item.OrganizationID == organizationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateProject(_ context.Context, item controlplanebiz.Project) (controlplanebiz.Project, error) {
	s.projects = append(s.projects, item)
	return item, nil
}

func (s *contractControlStore) ProjectExists(_ context.Context, organizationID, projectID string) (bool, error) {
	for _, item := range s.projects {
		if item.ID == projectID && item.OrganizationID == organizationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) ListProjectIDsForUser(_ context.Context, organizationID, userID string) ([]string, error) {
	var result []string
	for _, member := range s.members {
		if member.OrganizationID == organizationID && member.UserID == userID {
			result = append(result, member.ProjectID)
		}
	}
	return result, nil
}

func (s *contractControlStore) ResolveProjectRole(_ context.Context, organizationID, projectID, userID string) (security.Role, error) {
	for _, member := range s.members {
		if member.OrganizationID == organizationID && member.ProjectID == projectID && member.UserID == userID {
			return member.Role, nil
		}
	}
	return "", controlplanebiz.ErrNotFound
}

func (s *contractControlStore) FindOrganizationUserByEmail(_ context.Context, organizationID, email string) (controlplanebiz.OrganizationUser, error) {
	for _, user := range s.users {
		if user.OrganizationID == organizationID && user.Email == strings.ToLower(strings.TrimSpace(email)) {
			return user, nil
		}
	}
	return controlplanebiz.OrganizationUser{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) ListProjectMembers(_ context.Context, projectID string) ([]controlplanebiz.ProjectMember, error) {
	var result []controlplanebiz.ProjectMember
	for _, member := range s.members {
		if member.ProjectID == projectID {
			result = append(result, member)
		}
	}
	return result, nil
}

func (s *contractControlStore) GetProjectMember(_ context.Context, projectID, userID string) (controlplanebiz.ProjectMember, error) {
	for _, member := range s.members {
		if member.ProjectID == projectID && member.UserID == userID {
			return member, nil
		}
	}
	return controlplanebiz.ProjectMember{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) CreateProjectMember(_ context.Context, item controlplanebiz.ProjectMember) (controlplanebiz.ProjectMember, error) {
	s.members = append(s.members, item)
	return item, nil
}

func (s *contractControlStore) UpdateProjectMember(_ context.Context, item controlplanebiz.ProjectMember, expectedVersion uint64) (controlplanebiz.ProjectMember, error) {
	for index := range s.members {
		if s.members[index].ProjectID == item.ProjectID && s.members[index].UserID == item.UserID {
			if s.members[index].Version != expectedVersion {
				return controlplanebiz.ProjectMember{}, controlplanebiz.ErrProjectMemberConflict
			}
			s.members[index] = item
			return item, nil
		}
	}
	return controlplanebiz.ProjectMember{}, controlplanebiz.ErrProjectMemberConflict
}

func (s *contractControlStore) DeleteProjectMember(_ context.Context, projectID, userID string, expectedVersion uint64) error {
	for index := range s.members {
		if s.members[index].ProjectID == projectID && s.members[index].UserID == userID {
			if s.members[index].Version != expectedVersion {
				return controlplanebiz.ErrProjectMemberConflict
			}
			s.members = append(s.members[:index], s.members[index+1:]...)
			return nil
		}
	}
	return controlplanebiz.ErrProjectMemberConflict
}

func (s *contractControlStore) ListApplications(_ context.Context, projectID string) ([]controlplanebiz.Application, error) {
	var result []controlplanebiz.Application
	for _, item := range s.applications {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateApplication(_ context.Context, item controlplanebiz.Application) (controlplanebiz.Application, error) {
	s.applications = append(s.applications, item)
	return item, nil
}

func (s *contractControlStore) ApplicationExists(_ context.Context, projectID, applicationID string) (bool, error) {
	for _, item := range s.applications {
		if item.ProjectID == projectID && item.ID == applicationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) ListReleases(_ context.Context, projectID, applicationID string) ([]controlplanebiz.Release, error) {
	var result []controlplanebiz.Release
	for _, item := range s.releases {
		if item.ProjectID == projectID && item.ApplicationID == applicationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateRelease(_ context.Context, item controlplanebiz.Release) (controlplanebiz.Release, error) {
	s.releases = append(s.releases, item)
	return item, nil
}

func (s *contractControlStore) ReleaseExists(_ context.Context, projectID, applicationID, releaseID string) (bool, error) {
	for _, item := range s.releases {
		if item.ID == releaseID && item.ProjectID == projectID && item.ApplicationID == applicationID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) ListRuntimeTargets(_ context.Context, projectID string) ([]controlplanebiz.RuntimeTarget, error) {
	var result []controlplanebiz.RuntimeTarget
	for _, item := range s.targets {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateRuntimeTarget(
	_ context.Context,
	item controlplanebiz.RuntimeTarget,
) (controlplanebiz.RuntimeTarget, error) {
	s.targets = append(s.targets, item)
	return item, nil
}

func (s *contractControlStore) RuntimeTargetExists(_ context.Context, projectID, targetID string) (bool, error) {
	for _, item := range s.targets {
		if item.ID == targetID && item.ProjectID == projectID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) RuntimeTargetReady(_ context.Context, projectID, targetID string) (bool, error) {
	for _, item := range s.targets {
		if item.ID == targetID && item.ProjectID == projectID {
			return item.Status == controlplanebiz.RuntimeTargetStatusReady, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) GetRuntimeTarget(
	_ context.Context,
	projectID, targetID string,
) (controlplanebiz.RuntimeTarget, error) {
	for _, item := range s.targets {
		if item.ID == targetID && item.ProjectID == projectID {
			return item, nil
		}
	}
	return controlplanebiz.RuntimeTarget{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) UpdateRuntimeTargetProbe(
	_ context.Context,
	projectID, targetID string,
	status controlplanebiz.RuntimeTargetStatus,
	probedAt time.Time,
) (controlplanebiz.RuntimeTarget, error) {
	for i := range s.targets {
		if s.targets[i].ID == targetID && s.targets[i].ProjectID == projectID {
			s.targets[i].Status = status
			s.targets[i].LastProbedAt = probedAt
			return s.targets[i], nil
		}
	}
	return controlplanebiz.RuntimeTarget{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) BeginRuntimeTargetRetirement(
	_ context.Context,
	projectID, targetID string,
	retirement controlplanebiz.RuntimeTargetRetirement,
) (controlplanebiz.RuntimeTarget, bool, error) {
	for index := range s.targets {
		if s.targets[index].ID == targetID && s.targets[index].ProjectID == projectID {
			changed := s.targets[index].Status != controlplanebiz.RuntimeTargetStatusRetiring
			s.targets[index].Status = controlplanebiz.RuntimeTargetStatusRetiring
			if changed {
				s.targets[index].Retirement = &retirement
			}
			return s.targets[index], changed, nil
		}
	}
	return controlplanebiz.RuntimeTarget{}, false, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) ListRetiringRuntimeTargets(
	_ context.Context,
	limit int64,
) ([]controlplanebiz.RuntimeTarget, error) {
	result := make([]controlplanebiz.RuntimeTarget, 0, limit)
	for _, item := range s.targets {
		if item.Status == controlplanebiz.RuntimeTargetStatusRetiring {
			result = append(result, item)
			if int64(len(result)) == limit {
				break
			}
		}
	}
	return result, nil
}

func (s *contractControlStore) DeleteRetiringRuntimeTarget(
	_ context.Context,
	projectID, targetID string,
) error {
	for index := range s.targets {
		if s.targets[index].ID == targetID && s.targets[index].ProjectID == projectID &&
			s.targets[index].Status == controlplanebiz.RuntimeTargetStatusRetiring {
			s.targets = append(s.targets[:index], s.targets[index+1:]...)
			return nil
		}
	}
	return controlplanebiz.ErrNotFound
}

func (s *contractControlStore) ListRegistryCredentials(
	_ context.Context,
	projectID string,
) ([]controlplanebiz.RegistryCredential, error) {
	var result []controlplanebiz.RegistryCredential
	for _, item := range s.registries {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateRegistryCredential(
	_ context.Context,
	item controlplanebiz.RegistryCredential,
) (controlplanebiz.RegistryCredential, error) {
	s.registries = append(s.registries, item)
	return item, nil
}

func (s *contractControlStore) GetRegistryCredential(
	_ context.Context,
	projectID, credentialID string,
) (controlplanebiz.RegistryCredential, error) {
	for _, item := range s.registries {
		if item.ID == credentialID && item.ProjectID == projectID {
			return item, nil
		}
	}
	return controlplanebiz.RegistryCredential{}, controlplanebiz.ErrNotFound
}

func (s *contractControlStore) ListEnvironments(_ context.Context, projectID string) ([]controlplanebiz.Environment, error) {
	var result []controlplanebiz.Environment
	for _, item := range s.environments {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *contractControlStore) CreateEnvironment(_ context.Context, item controlplanebiz.Environment) (controlplanebiz.Environment, error) {
	s.environments = append(s.environments, item)
	return item, nil
}

func (s *contractControlStore) EnvironmentExists(_ context.Context, projectID, environmentID string) (bool, error) {
	for _, item := range s.environments {
		if item.ID == environmentID && item.ProjectID == projectID {
			return true, nil
		}
	}
	return false, nil
}

func (s *contractControlStore) EnvironmentStage(_ context.Context, projectID, environmentID string) (string, error) {
	for _, item := range s.environments {
		if item.ID == environmentID && item.ProjectID == projectID {
			return item.Stage, nil
		}
	}
	return "", controlplanebiz.ErrNotFound
}

type contractBuildStore struct {
	credentials    map[string]buildbiz.RepositoryCredential
	sources        map[string]buildbiz.SourceRepository
	configurations map[string]buildbiz.BuildConfiguration
	builds         map[string]buildbiz.Build
	triggers       map[string]buildbiz.BuildTrigger
	hooks          map[string]buildbiz.BuildHook
	deliveries     map[string]buildbiz.WebhookDelivery
	artifacts      map[string]buildbiz.Artifact
	logs           map[string][]buildbiz.BuildLogEntry
}

type contractArtifactEvidenceLookup struct{}

func (contractArtifactEvidenceLookup) ResolveArtifact(
	context.Context, string, string, string,
) (supplychainbiz.ArtifactSubject, error) {
	return supplychainbiz.ArtifactSubject{
		ID: "test-id", OrganizationID: "test-id", ProjectID: "test-id",
		SubjectDigest:        "sha256:" + strings.Repeat("a", 64),
		RegistryRepository:   "registry.example.com/team/api",
		RegistryCredentialID: "test-id",
	}, nil
}

type contractArtifactEvidenceRepository struct{}
type contractEvidenceJobCreator struct{}

type contractVulnerabilityWaiverRepository struct {
	items map[string]supplychainbiz.VulnerabilityWaiver
}

type contractDeploymentPolicyRepository struct {
	items map[string]supplychainbiz.DeploymentPolicy
}

func (r *contractDeploymentPolicyRepository) CreateDeploymentPolicy(_ context.Context,
	item supplychainbiz.DeploymentPolicy) (supplychainbiz.DeploymentPolicy, error) {
	for _, current := range r.items {
		if current.OrganizationID == item.OrganizationID && current.ProjectID == item.ProjectID &&
			current.Scope == item.Scope && current.EnvironmentID == item.EnvironmentID {
			return supplychainbiz.DeploymentPolicy{}, supplychainbiz.ErrDeploymentPolicyConflict
		}
	}
	r.items[item.ID] = item
	return item, nil
}

func (r *contractDeploymentPolicyRepository) ListDeploymentPolicies(_ context.Context,
	organizationID, projectID string) ([]supplychainbiz.DeploymentPolicy, error) {
	items := []supplychainbiz.DeploymentPolicy{}
	for _, item := range r.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *contractDeploymentPolicyRepository) GetDeploymentPolicy(_ context.Context,
	organizationID, projectID, policyID string) (supplychainbiz.DeploymentPolicy, error) {
	item, ok := r.items[policyID]
	if !ok || item.OrganizationID != organizationID || item.ProjectID != projectID {
		return supplychainbiz.DeploymentPolicy{}, supplychainbiz.ErrNotFound
	}
	return item, nil
}

func (r *contractDeploymentPolicyRepository) SaveDeploymentPolicy(_ context.Context,
	item supplychainbiz.DeploymentPolicy, expectedVersion uint64) (supplychainbiz.DeploymentPolicy, error) {
	current, ok := r.items[item.ID]
	if !ok || current.Version != expectedVersion {
		return supplychainbiz.DeploymentPolicy{}, supplychainbiz.ErrDeploymentPolicyConflict
	}
	r.items[item.ID] = item
	return item, nil
}

func (r *contractVulnerabilityWaiverRepository) CreateVulnerabilityWaiver(_ context.Context,
	item supplychainbiz.VulnerabilityWaiver) (supplychainbiz.VulnerabilityWaiver, error) {
	r.items[item.ID] = item
	return item, nil
}

func (r *contractVulnerabilityWaiverRepository) ListVulnerabilityWaivers(_ context.Context,
	organizationID, projectID string, query supplychainbiz.VulnerabilityWaiverQuery,
) (supplychainbiz.VulnerabilityWaiverPage, error) {
	page := supplychainbiz.VulnerabilityWaiverPage{Items: []supplychainbiz.VulnerabilityWaiver{}}
	for _, item := range r.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID &&
			(!query.ActiveOnly || item.Status(query.ActiveAt) == supplychainbiz.VulnerabilityWaiverActive) {
			page.Items = append(page.Items, item)
		}
	}
	return page, nil
}

func (r *contractVulnerabilityWaiverRepository) GetVulnerabilityWaiver(_ context.Context,
	organizationID, projectID, waiverID string) (supplychainbiz.VulnerabilityWaiver, error) {
	item, ok := r.items[waiverID]
	if !ok || item.OrganizationID != organizationID || item.ProjectID != projectID {
		return supplychainbiz.VulnerabilityWaiver{}, supplychainbiz.ErrNotFound
	}
	return item, nil
}

func (r *contractVulnerabilityWaiverRepository) SaveVulnerabilityWaiver(_ context.Context,
	item supplychainbiz.VulnerabilityWaiver, expectedVersion uint64,
) (supplychainbiz.VulnerabilityWaiver, error) {
	current, ok := r.items[item.ID]
	if !ok || current.Version != expectedVersion {
		return supplychainbiz.VulnerabilityWaiver{}, supplychainbiz.ErrVulnerabilityWaiverConflict
	}
	r.items[item.ID] = item
	return item, nil
}

func (contractEvidenceJobCreator) CreateEvidenceJob(_ context.Context,
	item supplychainbiz.EvidenceJob) (supplychainbiz.EvidenceJob, error) {
	return item, nil
}

type contractSignatureTrustPolicyRepository struct {
	items map[string]supplychainbiz.SignatureTrustPolicy
}

type contractSigningProfileRepository struct {
	items map[string]supplychainbiz.SignatureSigningProfile
}

func (r *contractSigningProfileRepository) CreateSignatureSigningProfile(_ context.Context,
	item supplychainbiz.SignatureSigningProfile) (supplychainbiz.SignatureSigningProfile, error) {
	r.items[item.ID] = item
	return item, nil
}
func (r *contractSigningProfileRepository) ListSignatureSigningProfiles(_ context.Context,
	projectID string) ([]supplychainbiz.SignatureSigningProfile, error) {
	items := []supplychainbiz.SignatureSigningProfile{}
	for _, item := range r.items {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (r *contractSigningProfileRepository) GetSignatureSigningProfile(_ context.Context,
	projectID, profileID string) (supplychainbiz.SignatureSigningProfile, error) {
	item, ok := r.items[profileID]
	if !ok || item.ProjectID != projectID {
		return supplychainbiz.SignatureSigningProfile{}, supplychainbiz.ErrNotFound
	}
	return item, nil
}
func (r *contractSigningProfileRepository) SaveSignatureSigningProfile(_ context.Context,
	item supplychainbiz.SignatureSigningProfile, expected uint64) (supplychainbiz.SignatureSigningProfile, error) {
	current, ok := r.items[item.ID]
	if !ok {
		return supplychainbiz.SignatureSigningProfile{}, supplychainbiz.ErrNotFound
	}
	if current.Version != expected {
		return supplychainbiz.SignatureSigningProfile{}, supplychainbiz.ErrSigningProfileConflict
	}
	r.items[item.ID] = item
	return item, nil
}

func (r *contractSignatureTrustPolicyRepository) CreateSignatureTrustPolicy(_ context.Context,
	item supplychainbiz.SignatureTrustPolicy) (supplychainbiz.SignatureTrustPolicy, error) {
	r.items[item.ID] = item
	return item, nil
}

func (r *contractSignatureTrustPolicyRepository) ListSignatureTrustPolicies(_ context.Context,
	projectID string) ([]supplychainbiz.SignatureTrustPolicy, error) {
	items := make([]supplychainbiz.SignatureTrustPolicy, 0, len(r.items))
	for _, item := range r.items {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *contractSignatureTrustPolicyRepository) GetSignatureTrustPolicy(_ context.Context,
	projectID, policyID string) (supplychainbiz.SignatureTrustPolicy, error) {
	item, ok := r.items[policyID]
	if !ok || item.ProjectID != projectID {
		return supplychainbiz.SignatureTrustPolicy{}, supplychainbiz.ErrNotFound
	}
	return item, nil
}

func (r *contractSignatureTrustPolicyRepository) SaveSignatureTrustPolicy(_ context.Context,
	item supplychainbiz.SignatureTrustPolicy, expected uint64) (supplychainbiz.SignatureTrustPolicy, error) {
	current, ok := r.items[item.ID]
	if !ok {
		return supplychainbiz.SignatureTrustPolicy{}, supplychainbiz.ErrNotFound
	}
	if current.Version != expected {
		return supplychainbiz.SignatureTrustPolicy{}, supplychainbiz.ErrSignatureTrustPolicyConflict
	}
	r.items[item.ID] = item
	return item, nil
}

func contractArtifactEvidence() supplychainbiz.Evidence {
	item, _ := supplychainbiz.NewEvidence(supplychainbiz.EvidenceInput{
		ID: "test-id", OrganizationID: "test-id", ProjectID: "test-id",
		ArtifactID: "test-id", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Kind: supplychainbiz.EvidenceKindSBOM, MediaType: "application/vnd.cyclonedx+json",
		FormatVersion: "1.6", Producer: "contract-evidence-worker/1.0.0",
		RegistryRepository: "registry.example.com/team/api",
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: supplychainbiz.VerificationVerified,
		CreatedAt:          time.Unix(100, 0).UTC(),
	})
	return item
}

func (contractArtifactEvidenceRepository) ListEvidence(
	context.Context, string, string,
) ([]supplychainbiz.Evidence, error) {
	return []supplychainbiz.Evidence{contractArtifactEvidence()}, nil
}

func (contractArtifactEvidenceRepository) GetEvidence(
	context.Context, string, string, string,
) (supplychainbiz.Evidence, error) {
	return contractArtifactEvidence(), nil
}

func (contractArtifactEvidenceRepository) CreateEvidence(
	_ context.Context, item supplychainbiz.Evidence,
) (supplychainbiz.Evidence, error) {
	return item, nil
}

func (contractArtifactEvidenceRepository) ListEvidenceVerifications(
	context.Context, string, string,
) ([]supplychainbiz.EvidenceVerification, error) {
	return []supplychainbiz.EvidenceVerification{{
		ID: "test-id", OrganizationID: "test-id", ProjectID: "test-id", ArtifactID: "test-id",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), PolicyID: "test-id", PolicyVersion: 1,
		TrustMode: supplychainbiz.SignatureTrustKeyless, TrustRootHash: "sha256:" + strings.Repeat("b", 64),
		SignerIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:     "https://issuer.example.com", BundleSetDigest: "sha256:" + strings.Repeat("c", 64),
		Verifier: "cosign", VerifierVersion: "3.0.6", VerificationStatus: supplychainbiz.VerificationVerified,
		CreatedAt: time.Unix(100, 0).UTC(),
	}}, nil
}

type contractArtifactReleaseCreator struct{}

func (contractArtifactReleaseCreator) CreateArtifactRelease(context.Context, buildbiz.ArtifactReleaseRequest) (string, error) {
	return "release-from-artifact", nil
}

type contractArtifactEvidenceScheduler struct{}

func (contractArtifactEvidenceScheduler) EnsureArtifactEvidence(context.Context, buildbiz.Artifact) error {
	return nil
}

type contractArtifactProbe struct{}

func (contractArtifactProbe) ProbeArtifact(context.Context, string, string, string, string) error {
	return nil
}

func (s *contractBuildStore) ReserveBuildTrigger(context.Context, string, time.Time, int, time.Duration) (bool, time.Time, error) {
	return true, time.Time{}, nil
}

type contractSourceProber struct{}

func (contractSourceProber) ProbeSource(
	context.Context,
	buildbiz.SourceRepository,
	*buildbiz.RepositoryCredential,
) (buildbiz.SourceRepositoryStatus, error) {
	return buildbiz.SourceRepositoryStatusReady, nil
}

func (contractSourceProber) ResolveSourceRevision(
	_ context.Context,
	source buildbiz.SourceRepository,
	_ *buildbiz.RepositoryCredential,
	ref, expectedCommitSHA string,
) (buildbiz.SourceRevision, error) {
	commitSHA := "a975c10d68a2d7461634f13b15c52a2efba72d16"
	if expectedCommitSHA != "" && expectedCommitSHA != commitSHA {
		return buildbiz.SourceRevision{}, buildbiz.ErrRevisionMismatch
	}
	return buildbiz.NewSourceRevision(source.ID, ref, commitSHA)
}

type contractBuildReferences struct{}

func (contractBuildReferences) ApplicationExists(
	context.Context,
	string,
	string,
) (bool, error) {
	return true, nil
}

func (contractBuildReferences) RegistryServer(
	context.Context,
	string,
	string,
) (string, error) {
	return "registry.example.com", nil
}

func newContractBuildStore() *contractBuildStore {
	store := &contractBuildStore{
		credentials:    make(map[string]buildbiz.RepositoryCredential),
		sources:        make(map[string]buildbiz.SourceRepository),
		configurations: make(map[string]buildbiz.BuildConfiguration),
		builds:         make(map[string]buildbiz.Build),
		triggers:       make(map[string]buildbiz.BuildTrigger),
		hooks:          make(map[string]buildbiz.BuildHook),
		deliveries:     make(map[string]buildbiz.WebhookDelivery),
		artifacts:      make(map[string]buildbiz.Artifact),
		logs:           make(map[string][]buildbiz.BuildLogEntry),
	}
	store.triggers["test-id"] = buildbiz.BuildTrigger{
		ID: "test-id", OrganizationID: "test-id", ProjectID: "test-id",
		ApplicationID: "test-id", BuildConfigurationID: "test-id",
		Name: "Contract automation", AllowedRefs: []string{"refs/heads/main"},
		TokenHash: strings.Repeat("a", 64), Status: buildbiz.BuildTriggerStatusActive,
		Version: 1, CreatedBy: "test-id", CreatedAt: time.Unix(100, 0).UTC(),
	}
	store.credentials["test-id"] = buildbiz.RepositoryCredential{
		ID: "test-id", ProjectID: "test-id", Type: buildbiz.CredentialTypeHTTPSAccessToken,
		Name: "Contract credential", SecretRef: "secret://contract", Version: 1,
		CreatedBy: "test-id", CreatedAt: time.Unix(100, 0).UTC(),
	}
	store.sources["test-id"] = buildbiz.SourceRepository{
		ID: "test-id", ProjectID: "test-id", Name: "Contract source",
		RepositoryURL: "https://git.example.com/team/api.git",
		Protocol:      buildbiz.RepositoryProtocolHTTPS, DefaultBranch: "main",
		CredentialID: "test-id", Status: buildbiz.SourceRepositoryStatusReady,
		CreatedBy: "test-id", CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: time.Unix(100, 0).UTC(),
	}
	store.configurations["test-id"] = buildbiz.BuildConfiguration{
		ID: "test-id", ProjectID: "test-id", ApplicationID: "test-id", Name: "Contract build",
		SourceRepositoryID: "test-id", DockerfilePath: "Dockerfile", ContextPath: ".",
		AllowedRefs: []string{"refs/heads/main"}, RegistryCredentialID: "test-id",
		ImageRepository: "registry.example.com/team/api", TargetPlatform: buildbiz.BuildPlatformLinuxAMD64,
		Resources:      buildbiz.BuildResources{CPUMilli: 2000, MemoryBytes: 2147483648, DiskBytes: 10737418240},
		TimeoutSeconds: 1800, MaxConcurrency: 1, Version: 1,
		CreatedBy: "test-id", UpdatedBy: "test-id", CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: time.Unix(100, 0).UTC(),
	}
	store.artifacts["test-id"] = buildbiz.Artifact{
		ID: "test-id", OrganizationID: "test-id", ProjectID: "test-id",
		ApplicationID: "test-id", BuildID: "test-id", BuildConfigurationID: "test-id",
		Origin: buildbiz.ArtifactOriginOwnDockBuild, Producer: "owndock-build-worker",
		ProducerVerification: buildbiz.ArtifactProducerVerified,
		RegistryCredentialID: "test-id", ImageRepository: "registry.example.com/team/api",
		ImageDigest:    "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
		TargetPlatform: buildbiz.BuildPlatformLinuxAMD64,
		ReleaseStatus:  buildbiz.ArtifactReleaseAvailable, Version: 1,
		CreatedAt: time.Unix(100, 0).UTC(),
	}
	store.builds["failed-build"] = buildbiz.Build{
		ID: "failed-build", OrganizationID: "test-id", ProjectID: "test-id",
		ApplicationID: "test-id", BuildConfigurationID: "test-id",
		Revision: buildbiz.SourceRevision{
			SourceRepositoryID: "test-id", Ref: "refs/heads/main",
			CommitSHA: "a975c10d68a2d7461634f13b15c52a2efba72d16",
		},
		Configuration: store.configurations["test-id"].Snapshot(),
		TriggerSource: buildbiz.BuildTriggerSourceManual, IdempotencyKey: "failed-test-1",
		Status: buildbiz.BuildStatusFailed, FailureCategory: buildbiz.BuildFailureBuild,
		Version: 2, TriggeredBy: "test-id", CreatedAt: time.Unix(90, 0).UTC(),
		UpdatedAt: time.Unix(100, 0).UTC(), FinishedAt: time.Unix(100, 0).UTC(),
	}
	return store
}

func (s *contractBuildStore) AppendBuildLog(_ context.Context, item buildbiz.BuildLogAppend) error {
	entries := s.logs[item.BuildID]
	s.logs[item.BuildID] = append(entries, buildbiz.BuildLogEntry{
		Sequence: uint64(len(entries) + 1), Stage: item.Stage,
		Message: item.Message, CreatedAt: item.CreatedAt,
	})
	return nil
}

func (s *contractBuildStore) ReadBuildLogs(_ context.Context, projectID, buildID string,
	query buildbiz.BuildLogQuery) (buildbiz.BuildLogPage, error) {
	if item, found := s.builds[buildID]; !found || item.ProjectID != projectID {
		return buildbiz.BuildLogPage{}, buildbiz.ErrNotFound
	}
	query, err := query.Normalize()
	if err != nil {
		return buildbiz.BuildLogPage{}, err
	}
	entries := make([]buildbiz.BuildLogEntry, 0, query.Limit)
	for _, entry := range s.logs[buildID] {
		if entry.Sequence > query.AfterSequence && len(entries) < query.Limit {
			entries = append(entries, entry)
		}
	}
	next := query.AfterSequence
	if len(entries) > 0 {
		next = entries[len(entries)-1].Sequence
	}
	return buildbiz.BuildLogPage{Entries: entries, NextSequence: next,
		ExpiresAt: time.Unix(100, 0).Add(buildbiz.DefaultBuildLogRetention)}, nil
}

func (s *contractBuildStore) ListBuildHooks(_ context.Context, projectID, applicationID, configurationID string) ([]buildbiz.BuildHookSummary, error) {
	items := make([]buildbiz.BuildHookSummary, 0)
	for _, item := range s.hooks {
		if item.ProjectID == projectID && item.ApplicationID == applicationID && item.BuildConfigurationID == configurationID {
			items = append(items, item.Summary())
		}
	}
	return items, nil
}
func (s *contractBuildStore) CreateBuildHook(_ context.Context, item buildbiz.BuildHook) (buildbiz.BuildHookSummary, error) {
	s.hooks[item.ID] = item
	return item.Summary(), nil
}
func (s *contractBuildStore) GetBuildHook(_ context.Context, id string) (buildbiz.BuildHook, error) {
	item, ok := s.hooks[id]
	if !ok {
		return buildbiz.BuildHook{}, buildbiz.ErrNotFound
	}
	return item, nil
}
func (s *contractBuildStore) RevokeBuildHook(_ context.Context, item buildbiz.BuildHook, expected uint64) (buildbiz.BuildHookSummary, error) {
	current, ok := s.hooks[item.ID]
	if !ok {
		return buildbiz.BuildHookSummary{}, buildbiz.ErrNotFound
	}
	if current.Version != expected {
		return buildbiz.BuildHookSummary{}, buildbiz.ErrVersionConflict
	}
	s.hooks[item.ID] = item
	return item.Summary(), nil
}
func (s *contractBuildStore) CreateWebhookDelivery(_ context.Context, item buildbiz.WebhookDelivery) error {
	key := string(item.Provider) + ":" + item.HookID + ":" + item.DeliveryID
	if _, ok := s.deliveries[key]; ok {
		return buildbiz.ErrDuplicateWebhookDelivery
	}
	s.deliveries[key] = item
	return nil
}
func (s *contractBuildStore) GetWebhookDelivery(_ context.Context, hookID string, provider buildbiz.WebhookProvider, deliveryID string) (buildbiz.WebhookDelivery, error) {
	item, ok := s.deliveries[string(provider)+":"+hookID+":"+deliveryID]
	if !ok {
		return buildbiz.WebhookDelivery{}, buildbiz.ErrNotFound
	}
	return item, nil
}

func (s *contractBuildStore) ListBuildTriggers(_ context.Context, projectID, applicationID, configurationID string) ([]buildbiz.BuildTrigger, error) {
	var items []buildbiz.BuildTrigger
	for _, item := range s.triggers {
		if item.ProjectID == projectID && item.ApplicationID == applicationID && item.BuildConfigurationID == configurationID {
			items = append(items, item)
		}
	}
	return items, nil
}
func (s *contractBuildStore) CreateBuildTrigger(_ context.Context, item buildbiz.BuildTrigger) (buildbiz.BuildTrigger, error) {
	s.triggers[item.ID] = item
	return item, nil
}
func (s *contractBuildStore) GetBuildTrigger(_ context.Context, id string) (buildbiz.BuildTrigger, error) {
	item, ok := s.triggers[id]
	if !ok {
		return buildbiz.BuildTrigger{}, buildbiz.ErrNotFound
	}
	return item, nil
}
func (s *contractBuildStore) RevokeBuildTrigger(_ context.Context, item buildbiz.BuildTrigger, expected uint64) (buildbiz.BuildTrigger, error) {
	current, ok := s.triggers[item.ID]
	if !ok {
		return buildbiz.BuildTrigger{}, buildbiz.ErrNotFound
	}
	if current.Version != expected {
		return buildbiz.BuildTrigger{}, buildbiz.ErrVersionConflict
	}
	s.triggers[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) ListBuilds(
	_ context.Context,
	projectID string,
) ([]buildbiz.Build, error) {
	var items []buildbiz.Build
	for _, item := range s.builds {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *contractBuildStore) ListArtifacts(_ context.Context, projectID string) ([]buildbiz.Artifact, error) {
	var result []buildbiz.Artifact
	for _, item := range s.artifacts {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *contractBuildStore) GetArtifact(_ context.Context, projectID, artifactID string) (buildbiz.Artifact, error) {
	item, found := s.artifacts[artifactID]
	if !found || item.ProjectID != projectID {
		return buildbiz.Artifact{}, buildbiz.ErrNotFound
	}
	return item, nil
}
func (s *contractBuildStore) GetArtifactByBuild(_ context.Context, buildID string) (buildbiz.Artifact, error) {
	for _, item := range s.artifacts {
		if item.BuildID == buildID {
			return item, nil
		}
	}
	return buildbiz.Artifact{}, buildbiz.ErrNotFound
}
func (s *contractBuildStore) GetArtifactByRegistrationKey(_ context.Context,
	projectID, registrationKey string) (buildbiz.Artifact, error) {
	for _, item := range s.artifacts {
		if item.ProjectID == projectID && item.RegistrationKey == registrationKey {
			return item, nil
		}
	}
	return buildbiz.Artifact{}, buildbiz.ErrNotFound
}
func (s *contractBuildStore) CreateArtifact(_ context.Context, item buildbiz.Artifact) (buildbiz.Artifact, error) {
	s.artifacts[item.ID] = item
	return item, nil
}
func (s *contractBuildStore) NextPendingArtifact(context.Context) (buildbiz.Artifact, bool, error) {
	for _, item := range s.artifacts {
		if item.ReleaseStatus == buildbiz.ArtifactReleasePending {
			return item, true, nil
		}
	}
	return buildbiz.Artifact{}, false, nil
}
func (s *contractBuildStore) SaveArtifactRelease(_ context.Context, item buildbiz.Artifact, expected uint64) (buildbiz.Artifact, error) {
	current, found := s.artifacts[item.ID]
	if !found || current.Version != expected {
		return buildbiz.Artifact{}, buildbiz.ErrVersionConflict
	}
	item.Version = expected + 1
	s.artifacts[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) CreateBuild(
	_ context.Context,
	item buildbiz.Build,
) (buildbiz.Build, error) {
	for _, existing := range s.builds {
		if existing.ProjectID == item.ProjectID && existing.IdempotencyKey == item.IdempotencyKey {
			return buildbiz.Build{}, buildbiz.ErrDuplicateIdempotency
		}
	}
	s.builds[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) SaveBuild(_ context.Context, item buildbiz.Build, expected uint64) (buildbiz.Build, error) {
	current, found := s.builds[item.ID]
	if !found || current.ProjectID != item.ProjectID {
		return buildbiz.Build{}, buildbiz.ErrNotFound
	}
	if current.Version != expected {
		return buildbiz.Build{}, buildbiz.ErrVersionConflict
	}
	item.Version = expected + 1
	s.builds[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) GetBuild(
	_ context.Context,
	projectID, buildID string,
) (buildbiz.Build, error) {
	item, found := s.builds[buildID]
	if !found || item.ProjectID != projectID {
		return buildbiz.Build{}, buildbiz.ErrNotFound
	}
	return item, nil
}

func (s *contractBuildStore) GetBuildByIdempotency(
	_ context.Context,
	projectID, idempotencyKey string,
) (buildbiz.Build, error) {
	for _, item := range s.builds {
		if item.ProjectID == projectID && item.IdempotencyKey == idempotencyKey {
			return item, nil
		}
	}
	return buildbiz.Build{}, buildbiz.ErrNotFound
}

func (s *contractBuildStore) ListBuildConfigurations(
	_ context.Context,
	projectID, applicationID string,
) ([]buildbiz.BuildConfiguration, error) {
	var items []buildbiz.BuildConfiguration
	for _, item := range s.configurations {
		if item.ProjectID == projectID && item.ApplicationID == applicationID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *contractBuildStore) CreateBuildConfiguration(
	_ context.Context,
	item buildbiz.BuildConfiguration,
) (buildbiz.BuildConfiguration, error) {
	s.configurations[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) GetBuildConfiguration(
	_ context.Context,
	projectID, applicationID, configurationID string,
) (buildbiz.BuildConfiguration, error) {
	item, found := s.configurations[configurationID]
	if !found || item.ProjectID != projectID || item.ApplicationID != applicationID {
		return buildbiz.BuildConfiguration{}, buildbiz.ErrNotFound
	}
	return item, nil
}

func (s *contractBuildStore) UpdateBuildConfiguration(
	_ context.Context,
	item buildbiz.BuildConfiguration,
	expectedVersion uint64,
) (buildbiz.BuildConfiguration, error) {
	current, found := s.configurations[item.ID]
	if !found {
		return buildbiz.BuildConfiguration{}, buildbiz.ErrNotFound
	}
	if current.Version != expectedVersion {
		return buildbiz.BuildConfiguration{}, buildbiz.ErrVersionConflict
	}
	s.configurations[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) ListCredentials(
	_ context.Context,
	projectID string,
) ([]buildbiz.CredentialSummary, error) {
	items := make([]buildbiz.CredentialSummary, 0, len(s.credentials))
	for _, item := range s.credentials {
		if item.ProjectID == projectID {
			items = append(items, item.Summary())
		}
	}
	return items, nil
}

func (s *contractBuildStore) CreateCredential(
	_ context.Context,
	item buildbiz.RepositoryCredential,
) (buildbiz.CredentialSummary, error) {
	s.credentials[item.ID] = item
	return item.Summary(), nil
}

func (s *contractBuildStore) GetCredential(
	_ context.Context,
	projectID, credentialID string,
) (buildbiz.RepositoryCredential, error) {
	item, found := s.credentials[credentialID]
	if !found || item.ProjectID != projectID {
		return buildbiz.RepositoryCredential{}, buildbiz.ErrNotFound
	}
	return item, nil
}

func (s *contractBuildStore) ListSources(
	_ context.Context,
	projectID string,
) ([]buildbiz.SourceRepository, error) {
	items := make([]buildbiz.SourceRepository, 0, len(s.sources))
	for _, item := range s.sources {
		if item.ProjectID == projectID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *contractBuildStore) CreateSource(
	_ context.Context,
	item buildbiz.SourceRepository,
) (buildbiz.SourceRepository, error) {
	s.sources[item.ID] = item
	return item, nil
}

func (s *contractBuildStore) GetSource(
	_ context.Context,
	projectID, sourceID string,
) (buildbiz.SourceRepository, error) {
	item, found := s.sources[sourceID]
	if !found || item.ProjectID != projectID {
		return buildbiz.SourceRepository{}, buildbiz.ErrNotFound
	}
	return item, nil
}

func (s *contractBuildStore) UpdateSourceProbe(
	_ context.Context,
	projectID, sourceID string,
	status buildbiz.SourceRepositoryStatus,
	probedAt time.Time,
) (buildbiz.SourceRepository, error) {
	item, found := s.sources[sourceID]
	if !found || item.ProjectID != projectID {
		return buildbiz.SourceRepository{}, buildbiz.ErrNotFound
	}
	item.Status = status
	item.LastProbedAt = probedAt
	item.UpdatedAt = probedAt
	s.sources[sourceID] = item
	return item, nil
}
