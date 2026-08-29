package biz

import (
	"context"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type repositoryStub struct {
	items       []ManagedHost
	enrollments []Enrollment
	identities  []AgentIdentity
}

type enrollmentRecoveryRecord struct {
	tokenHash    string
	requestHash  string
	recoverUntil time.Time
	credentials  AgentCredentials
}

type recoverableRepositoryStub struct {
	*repositoryStub
	recovery enrollmentRecoveryRecord
}

func (r *recoverableRepositoryStub) ActivateAgentRecoverable(
	ctx context.Context,
	enrollmentID, tokenHash string,
	now time.Time,
	identity AgentIdentity,
	recovery EnrollmentRecovery,
) error {
	if err := r.ActivateAgent(ctx, enrollmentID, tokenHash, now, identity); err != nil {
		return err
	}
	r.recovery = enrollmentRecoveryRecord{
		tokenHash: tokenHash, requestHash: recovery.RequestSHA256,
		recoverUntil: recovery.RecoverUntil,
		credentials: AgentCredentials{
			Identity:         identity,
			CertificatePEM:   append([]byte(nil), recovery.CertificatePEM...),
			CACertificatePEM: append([]byte(nil), recovery.CACertificatePEM...),
		},
	}
	return nil
}

func (r *recoverableRepositoryStub) RecoverAgentEnrollment(
	_ context.Context,
	tokenHash, requestHash string,
	now time.Time,
) (AgentCredentials, bool, error) {
	if r.recovery.tokenHash == tokenHash && r.recovery.requestHash == requestHash &&
		r.recovery.recoverUntil.After(now) {
		return r.recovery.credentials, true, nil
	}
	return AgentCredentials{}, false, nil
}

func (r *repositoryStub) AuthenticateAgent(
	_ context.Context,
	certificate AgentCertificateIdentity,
	now time.Time,
) (AgentIdentity, error) {
	for _, identity := range r.identities {
		if identity.ID != certificate.IdentityID ||
			identity.OrganizationID != certificate.OrganizationID ||
			identity.ManagedHostID != certificate.ManagedHostID ||
			identity.InstanceID != certificate.InstanceID ||
			!identity.RevokedAt.IsZero() {
			continue
		}
		if identity.CertificateSerial == certificate.CertificateSerial &&
			identity.CertificateSHA256 == certificate.CertificateSHA256 &&
			identity.CertificateExpires.After(now) {
			return identity, nil
		}
		if identity.PreviousCertificateSerial == certificate.CertificateSerial &&
			identity.PreviousCertificateSHA256 == certificate.CertificateSHA256 &&
			identity.PreviousCertificateExpires.After(now) &&
			identity.PreviousCertificateValidUntil.After(now) {
			matched := identity
			matched.CertificateSerial = identity.PreviousCertificateSerial
			matched.CertificateSHA256 = identity.PreviousCertificateSHA256
			matched.CertificateExpires = identity.PreviousCertificateExpires
			return matched, nil
		}
	}
	return AgentIdentity{}, ErrInvalidAgentIdentity
}

func (r *repositoryStub) AuthenticateAgentCertificateRotation(
	ctx context.Context,
	certificate AgentCertificateIdentity,
	rotationID string,
	csrHash string,
	now time.Time,
) (AgentIdentity, error) {
	identity, err := r.AuthenticateAgent(ctx, certificate, now)
	if err == nil {
		return identity, nil
	}
	for _, candidate := range r.identities {
		if candidate.ID == certificate.IdentityID &&
			candidate.OrganizationID == certificate.OrganizationID &&
			candidate.ManagedHostID == certificate.ManagedHostID &&
			candidate.InstanceID == certificate.InstanceID &&
			candidate.PreviousCertificateSerial == certificate.CertificateSerial &&
			candidate.PreviousCertificateSHA256 == certificate.CertificateSHA256 &&
			candidate.PreviousCertificateExpires.After(now) &&
			candidate.PendingRotationID == rotationID &&
			candidate.PendingRotationCSRHash == csrHash && candidate.RevokedAt.IsZero() {
			return candidate, nil
		}
	}
	return AgentIdentity{}, ErrInvalidAgentIdentity
}

func (r *repositoryStub) RotateAgentCertificate(
	_ context.Context,
	rotation AgentCertificateRotation,
	now time.Time,
) (IssuedCertificate, bool, error) {
	for index := range r.identities {
		identity := &r.identities[index]
		if identity.ID != rotation.Presented.IdentityID ||
			identity.OrganizationID != rotation.Presented.OrganizationID ||
			identity.ManagedHostID != rotation.Presented.ManagedHostID ||
			identity.InstanceID != rotation.Presented.InstanceID {
			continue
		}
		if identity.PendingRotationID != "" {
			if identity.PendingRotationID != rotation.ID ||
				identity.PendingRotationCSRHash != rotation.CSRHash {
				return IssuedCertificate{}, false, ErrInvalidAgentIdentity
			}
			return IssuedCertificate{
				CertificatePEM:   append([]byte(nil), identity.PendingCertificatePEM...),
				CACertificatePEM: append([]byte(nil), identity.PendingCACertificatePEM...),
				Serial:           identity.CertificateSerial, SHA256: identity.CertificateSHA256,
				ExpiresAt: identity.CertificateExpires,
			}, false, nil
		}
		if identity.CertificateSerial != rotation.Presented.CertificateSerial ||
			identity.CertificateSHA256 != rotation.Presented.CertificateSHA256 ||
			!identity.CertificateExpires.After(now) {
			return IssuedCertificate{}, false, ErrInvalidAgentIdentity
		}
		identity.PreviousCertificateSerial = identity.CertificateSerial
		identity.PreviousCertificateSHA256 = identity.CertificateSHA256
		identity.PreviousCertificateExpires = identity.CertificateExpires
		identity.PreviousCertificateValidUntil = rotation.PreviousValidUntil
		identity.CertificateSerial = rotation.Certificate.Serial
		identity.CertificateSHA256 = rotation.Certificate.SHA256
		identity.CertificateExpires = rotation.Certificate.ExpiresAt
		identity.PendingRotationID = rotation.ID
		identity.PendingRotationCSRHash = rotation.CSRHash
		identity.PendingCertificatePEM = append([]byte(nil), rotation.Certificate.CertificatePEM...)
		identity.PendingCACertificatePEM = append([]byte(nil), rotation.Certificate.CACertificatePEM...)
		return rotation.Certificate, true, nil
	}
	return IssuedCertificate{}, false, ErrInvalidAgentIdentity
}

func (r *repositoryStub) ConfirmAgentCertificate(
	_ context.Context,
	certificate AgentCertificateIdentity,
	_ time.Time,
) (bool, error) {
	for index := range r.identities {
		identity := &r.identities[index]
		if identity.ID == certificate.IdentityID &&
			identity.CertificateSerial == certificate.CertificateSerial &&
			identity.CertificateSHA256 == certificate.CertificateSHA256 &&
			identity.PendingRotationID != "" {
			identity.PreviousCertificateSerial = ""
			identity.PreviousCertificateSHA256 = ""
			identity.PreviousCertificateExpires = time.Time{}
			identity.PreviousCertificateValidUntil = time.Time{}
			identity.PendingRotationID = ""
			identity.PendingRotationCSRHash = ""
			identity.PendingCertificatePEM = nil
			identity.PendingCACertificatePEM = nil
			return true, nil
		}
	}
	return false, nil
}

func (r *repositoryStub) ConnectAgent(
	_ context.Context,
	session AgentSession,
	now time.Time,
) error {
	for index := range r.items {
		item := &r.items[index]
		if item.ID == session.ManagedHostID &&
			item.OrganizationID == session.OrganizationID &&
			item.AgentIdentityID == session.IdentityID &&
			item.AgentInstanceID == session.InstanceID &&
			item.Status != StatusDisabled {
			item.Status = StatusOnline
			item.AgentSessionID = session.ID
			item.AgentBootID = session.BootID
			item.AgentVersion = session.AgentVersion
			item.ProtocolVersion = session.ProtocolVersion
			item.Capabilities = append([]string(nil), session.Capabilities...)
			item.LastSeenAt = now
			item.UpdatedAt = now
			return nil
		}
	}
	return ErrInvalidAgentIdentity
}

func (r *repositoryStub) HeartbeatAgent(
	_ context.Context,
	session AgentSession,
	now time.Time,
) error {
	for index := range r.items {
		item := &r.items[index]
		if item.ID == session.ManagedHostID &&
			item.AgentSessionID == session.ID &&
			item.Status == StatusOnline {
			item.LastSeenAt = now
			item.UpdatedAt = now
			return nil
		}
	}
	return ErrInvalidAgentIdentity
}

func (r *repositoryStub) DisconnectAgent(
	_ context.Context,
	session AgentSession,
	now time.Time,
) (bool, error) {
	for index := range r.items {
		item := &r.items[index]
		if item.ID == session.ManagedHostID &&
			item.AgentSessionID == session.ID &&
			item.Status == StatusOnline {
			item.Status = StatusOffline
			item.AgentSessionID = ""
			item.AgentBootID = ""
			item.UpdatedAt = now
			return true, nil
		}
	}
	return false, nil
}

func (r *repositoryStub) CreateEnrollment(_ context.Context, item Enrollment) error {
	r.enrollments = append(r.enrollments, item)
	return nil
}

func (r *repositoryStub) FindAvailableEnrollment(
	_ context.Context,
	tokenHash string,
	now time.Time,
) (Enrollment, error) {
	for _, item := range r.enrollments {
		if item.TokenHash == tokenHash && item.ConsumedAt.IsZero() &&
			item.ExpiresAt.After(now) {
			return item, nil
		}
	}
	return Enrollment{}, ErrInvalidEnrollment
}

func (r *repositoryStub) ActivateAgent(
	_ context.Context,
	enrollmentID, tokenHash string,
	now time.Time,
	identity AgentIdentity,
) error {
	for index := range r.enrollments {
		item := &r.enrollments[index]
		if item.ID == enrollmentID && item.TokenHash == tokenHash &&
			item.ConsumedAt.IsZero() && item.ExpiresAt.After(now) {
			item.ConsumedAt = now
			r.identities = append(r.identities, identity)
			for hostIndex := range r.items {
				if r.items[hostIndex].ID == identity.ManagedHostID {
					r.items[hostIndex].AgentIdentityID = identity.ID
					r.items[hostIndex].AgentInstanceID = identity.InstanceID
					r.items[hostIndex].AgentCertificateExpiresAt = identity.CertificateExpires
					r.items[hostIndex].Status = StatusOffline
				}
			}
			return nil
		}
	}
	return ErrInvalidEnrollment
}

type enrollmentTokensStub struct{}

func (enrollmentTokensStub) New() (string, string, error) {
	return "raw-enrollment-token", "hash:raw-enrollment-token", nil
}

func (enrollmentTokensStub) Hash(raw string) string { return "hash:" + raw }

type certificateIssuerStub struct{}

func (certificateIssuerStub) Issue(
	_ context.Context,
	_ AgentCertificateClaim,
	_ []byte,
	now time.Time,
) (IssuedCertificate, error) {
	return IssuedCertificate{
		CertificatePEM:   []byte("certificate"),
		CACertificatePEM: []byte("ca"),
		Serial:           "serial", SHA256: "fingerprint",
		ExpiresAt: now.Add(24 * time.Hour),
	}, nil
}

type countingCertificateIssuerStub struct {
	calls int
}

func (i *countingCertificateIssuerStub) Issue(
	ctx context.Context,
	claim AgentCertificateClaim,
	csr []byte,
	now time.Time,
) (IssuedCertificate, error) {
	i.calls++
	return certificateIssuerStub{}.Issue(ctx, claim, csr, now)
}

func (r *repositoryStub) List(_ context.Context, organizationID string) ([]ManagedHost, error) {
	var result []ManagedHost
	for _, item := range r.items {
		if item.OrganizationID == organizationID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (r *repositoryStub) Get(
	_ context.Context,
	organizationID, hostID string,
) (ManagedHost, error) {
	for _, item := range r.items {
		if item.OrganizationID == organizationID && item.ID == hostID {
			return item, nil
		}
	}
	return ManagedHost{}, ErrNotFound
}

func (r *repositoryStub) Create(_ context.Context, item ManagedHost) (ManagedHost, error) {
	r.items = append(r.items, item)
	return item, nil
}

func (r *repositoryStub) Disable(
	_ context.Context,
	organizationID, hostID string,
	now time.Time,
) (ManagedHost, error) {
	for index := range r.items {
		if r.items[index].OrganizationID == organizationID &&
			r.items[index].ID == hostID {
			r.items[index].Status = StatusDisabled
			r.items[index].AgentBootID = ""
			r.items[index].AgentSessionID = ""
			r.items[index].UpdatedAt = now
			return r.items[index], nil
		}
	}
	return ManagedHost{}, ErrNotFound
}

func (r *repositoryStub) ConnectionMode(
	ctx context.Context,
	organizationID, hostID string,
) (runtimeaccess.Mode, bool, error) {
	item, err := r.Get(ctx, organizationID, hostID)
	if err == ErrNotFound {
		return "", false, nil
	}
	return item.ConnectionMode, err == nil, err
}

type auditStub struct {
	events []sharedaudit.Event
}

func (a *auditStub) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}

type connectionCloserStub struct {
	hostIDs []string
}

func (c *connectionCloserStub) DisconnectHost(hostID string) {
	c.hostIDs = append(c.hostIDs, hostID)
}

func TestCreateManagedHostIsOrganizationScopedAndAudited(t *testing.T) {
	repository := &repositoryStub{}
	audits := &auditStub{}
	ids := []string{"host-1", "audit-1"}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, audits,
		func() (string, error) {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
		func() time.Time { return time.Unix(100, 0) },
	)
	owner := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	item, err := useCase.Create(
		t.Context(), owner, "Production Host", runtimeaccess.ModeDirectDocker,
		DirectSSHConfiguration{}, "request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if item.OrganizationID != owner.OrganizationID ||
		len(audits.events) != 1 ||
		audits.events[0].Action != "managed_host.create" {
		t.Fatalf("item = %+v, audits = %+v", item, audits.events)
	}
}

func TestMaintainerCanReadButCannotCreateManagedHost(t *testing.T) {
	useCase := NewUseCase(
		&repositoryStub{}, transaction.Passthrough{}, &auditStub{},
		func() (string, error) { return "id", nil }, time.Now,
	)
	maintainer := security.Principal{
		UserID: "maintainer", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer,
	}
	if _, err := useCase.List(t.Context(), maintainer); err != nil {
		t.Fatal(err)
	}
	if _, err := useCase.Create(
		t.Context(), maintainer, "Denied Host", runtimeaccess.ModeAgent,
		DirectSSHConfiguration{}, "",
	); err != security.ErrForbidden {
		t.Fatalf("create error = %v", err)
	}
}

func TestDisableManagedHostClosesCurrentAgentConnectionAfterCommit(t *testing.T) {
	repository := &repositoryStub{items: []ManagedHost{{
		ID: "host-1", OrganizationID: "organization-1",
		Status: StatusOnline, ConnectionMode: runtimeaccess.ModeAgent,
	}}}
	closer := &connectionCloserStub{}
	ids := []string{"audit-1"}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, &auditStub{},
		func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
		func() time.Time { return time.Unix(100, 0) },
	).WithAgentControl(repository, closer, []string{"v1"})
	owner := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	if _, err := useCase.Disable(
		t.Context(), owner, "host-1", "request-1",
	); err != nil {
		t.Fatal(err)
	}
	if len(closer.hostIDs) != 1 || closer.hostIDs[0] != "host-1" {
		t.Fatalf("closed hosts = %v", closer.hostIDs)
	}
}

func TestAgentEnrollmentTokenIsOneTimeAndCreatesFixedIdentity(t *testing.T) {
	repository := &repositoryStub{items: []ManagedHost{{
		ID: "host-1", OrganizationID: "organization-1",
		Name: "Private Host", Status: StatusEnrolling,
		ConnectionMode: runtimeaccess.ModeAgent,
	}}}
	audits := &auditStub{}
	ids := []string{"enrollment-1", "audit-1", "identity-1", "audit-2"}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, audits,
		func() (string, error) {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
		func() time.Time { return time.Unix(100, 0).UTC() },
	).WithEnrollment(
		repository, enrollmentTokensStub{}, certificateIssuerStub{}, 15*time.Minute,
	)
	owner := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	enrollment, err := useCase.CreateEnrollment(
		t.Context(), owner, "host-1", "request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Token != "raw-enrollment-token" ||
		repository.enrollments[0].TokenHash == enrollment.Token {
		t.Fatalf("enrollment = %+v, stored = %+v", enrollment, repository.enrollments)
	}
	credentials, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "instance-1", "1.0.0", "v1",
		[]string{"docker"}, []byte("csr"), "request-2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Identity.ManagedHostID != "host-1" ||
		credentials.Identity.InstanceID != "instance-1" ||
		len(repository.identities) != 1 ||
		repository.items[0].AgentIdentityID != credentials.Identity.ID {
		t.Fatalf("credentials = %+v, repository = %+v", credentials, repository)
	}
	if _, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "instance-2", "1.0.0", "v1",
		nil, []byte("csr"), "request-3",
	); err != ErrInvalidEnrollment {
		t.Fatalf("replay error = %v", err)
	}
}

func TestAgentEnrollmentRecoversOnlyTheExactOriginalExchange(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	repository := &recoverableRepositoryStub{repositoryStub: &repositoryStub{
		items: []ManagedHost{{
			ID: "host-1", OrganizationID: "organization-1",
			Name: "Private Host", Status: StatusEnrolling,
			ConnectionMode: runtimeaccess.ModeAgent,
		}},
	}}
	audits := &auditStub{}
	issuer := &countingCertificateIssuerStub{}
	ids := []string{"enrollment-1", "audit-1", "identity-1", "audit-2"}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, audits,
		func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
		func() time.Time { return now },
	).WithEnrollment(repository, enrollmentTokensStub{}, issuer, 15*time.Minute)
	owner := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	enrollment, err := useCase.CreateEnrollment(t.Context(), owner, "host-1", "request-1")
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"runtime.probe", "deployment.prepare"}
	first, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "instance-1", "1.0.0", "v1",
		arguments, []byte("same-csr"), "request-2",
	)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "instance-1", "1.0.0", "v1",
		arguments, []byte("same-csr"), "request-retry",
	)
	if err != nil || recovered.Identity.ID != first.Identity.ID ||
		string(recovered.CertificatePEM) != string(first.CertificatePEM) ||
		issuer.calls != 1 || len(audits.events) != 2 {
		t.Fatalf("first=%+v recovered=%+v err=%v calls=%d audits=%d", first, recovered, err, issuer.calls, len(audits.events))
	}
	if _, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "instance-1", "1.0.0", "v1",
		arguments, []byte("different-csr"), "request-conflict",
	); err != ErrInvalidEnrollment {
		t.Fatalf("conflicting recovery error = %v", err)
	}
	now = now.Add(agentEnrollmentRecoveryWindow + time.Second)
	if _, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "instance-1", "1.0.0", "v1",
		arguments, []byte("same-csr"), "request-expired",
	); err != ErrInvalidEnrollment {
		t.Fatalf("expired recovery error = %v", err)
	}
}

func TestEnrollmentRequestHashUsesUnambiguousOrderedParts(t *testing.T) {
	first := enrollmentRequestHash("instance", "1.0.0", "v1", []string{"ab", "c"}, []byte("csr"))
	if first == "" || first != enrollmentRequestHash(
		"instance", "1.0.0", "v1", []string{"ab", "c"}, []byte("csr"),
	) {
		t.Fatalf("request hash is not stable: %q", first)
	}
	for _, conflict := range []string{
		enrollmentRequestHash("instance", "1.0.0", "v1", []string{"a", "bc"}, []byte("csr")),
		enrollmentRequestHash("instance", "1.0.0", "v1", []string{"c", "ab"}, []byte("csr")),
		enrollmentRequestHash("instance", "1.0.0", "v1", []string{"ab", "c"}, []byte("other")),
	} {
		if conflict == first {
			t.Fatal("distinct enrollment requests shared a fingerprint")
		}
	}
}

func TestInvalidAgentMetadataIsRejectedBeforeCertificateSigning(t *testing.T) {
	repository := &repositoryStub{items: []ManagedHost{{
		ID: "host-1", OrganizationID: "organization-1",
		Name: "Private Host", Status: StatusEnrolling,
		ConnectionMode: runtimeaccess.ModeAgent,
	}}}
	issuer := &countingCertificateIssuerStub{}
	ids := []string{"enrollment-1", "audit-1"}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, &auditStub{},
		func() (string, error) {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
		func() time.Time { return time.Unix(100, 0).UTC() },
	).WithEnrollment(repository, enrollmentTokensStub{}, issuer, 15*time.Minute)
	owner := security.Principal{
		UserID: "owner-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleOwner,
	}
	enrollment, err := useCase.CreateEnrollment(
		t.Context(), owner, "host-1", "request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := useCase.ExchangeEnrollment(
		t.Context(), enrollment.Token, "../instance", "1.0.0", "v1",
		[]string{"docker"}, []byte("csr"), "request-2",
	); err != ErrInvalidAgentIdentity {
		t.Fatalf("exchange error = %v", err)
	}
	if _, err := useCase.ExchangeEnrollment(
		t.Context(),
		enrollment.Token,
		"instance-1",
		"1.0.0",
		"v1",
		[]string{"deployment stage"},
		[]byte("csr"),
		"request-3",
	); err != ErrInvalidAgentIdentity {
		t.Fatalf("capability validation error = %v", err)
	}
	if issuer.calls != 0 {
		t.Fatalf("certificate issuer calls = %d, want 0", issuer.calls)
	}
}

func TestAgentCertificateRotationIsAuthenticatedIdempotentAndKeepsShortFallback(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	repository := &repositoryStub{
		items: []ManagedHost{{
			ID: "host-1", OrganizationID: "organization-1",
			Status: StatusOnline, ConnectionMode: runtimeaccess.ModeAgent,
			AgentIdentityID: "identity-1", AgentInstanceID: "instance-1",
		}},
		identities: []AgentIdentity{{
			ID: "identity-1", OrganizationID: "organization-1",
			ManagedHostID: "host-1", InstanceID: "instance-1",
			CertificateSerial: "old-serial", CertificateSHA256: "old-fingerprint",
			CertificateExpires: now.Add(time.Hour),
			Capabilities:       []string{"runtime.probe"},
		}},
	}
	issuer := &countingCertificateIssuerStub{}
	audits := &auditStub{}
	nextID := 0
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, audits,
		func() (string, error) {
			nextID++
			return "audit-" + time.Unix(int64(nextID), 0).Format("150405"), nil
		},
		func() time.Time { return now },
	).WithEnrollment(
		repository, enrollmentTokensStub{}, issuer, 15*time.Minute,
	).WithAgentControl(repository, nil, []string{"v1"})
	presented := AgentCertificateIdentity{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
		CertificateSerial: "old-serial", CertificateSHA256: "old-fingerprint",
	}
	first, err := useCase.RotateAgentCertificate(
		t.Context(), presented, "rotation-1", []byte("signed-csr"), "request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	identity := repository.identities[0]
	if first.Identity.CertificateSerial != "serial" ||
		identity.CertificateSerial != "serial" ||
		identity.PreviousCertificateSerial != "old-serial" ||
		identity.PendingRotationID != "rotation-1" ||
		!identity.PreviousCertificateValidUntil.Equal(now.Add(agentCertificateRotationGrace)) ||
		len(audits.events) != 1 || audits.events[0].Action != "agent_certificate.rotate" {
		t.Fatalf("credentials=%+v identity=%+v audits=%+v", first, identity, audits.events)
	}
	retried, err := useCase.RotateAgentCertificate(
		t.Context(), presented, "rotation-1", []byte("signed-csr"), "request-2",
	)
	if err != nil || string(retried.CertificatePEM) != "certificate" ||
		len(audits.events) != 1 {
		t.Fatalf("retry=%+v error=%v audits=%+v", retried, err, audits.events)
	}
	if _, err := useCase.RotateAgentCertificate(
		t.Context(), presented, "rotation-2", []byte("another-csr"), "request-3",
	); err != ErrInvalidAgentIdentity {
		t.Fatalf("conflicting retry error = %v", err)
	}
	if _, err := repository.AuthenticateAgent(t.Context(), presented, now.Add(9*time.Minute)); err != nil {
		t.Fatalf("old certificate during grace error = %v", err)
	}
	if _, err := repository.AuthenticateAgent(t.Context(), presented, now.Add(11*time.Minute)); err != ErrInvalidAgentIdentity {
		t.Fatalf("old certificate after grace error = %v", err)
	}
	now = now.Add(11 * time.Minute)
	recovered, err := useCase.RotateAgentCertificate(
		t.Context(), presented, "rotation-1", []byte("signed-csr"), "request-recovery",
	)
	if err != nil || string(recovered.CertificatePEM) != "certificate" || len(audits.events) != 1 {
		t.Fatalf("late recovery=%+v error=%v audits=%+v", recovered, err, audits.events)
	}
	if _, err := useCase.RotateAgentCertificate(
		t.Context(), presented, "rotation-1", []byte("different-csr"), "request-conflict",
	); err != ErrInvalidAgentIdentity {
		t.Fatalf("late conflicting recovery error = %v", err)
	}
	newCertificate := AgentCertificateIdentity{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
		CertificateSerial: "serial", CertificateSHA256: "fingerprint",
	}
	if _, err := useCase.OpenAgentSession(t.Context(), newCertificate, AgentHello{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
		BootID: "boot-rotated", AgentVersion: "1.0.0",
		ProtocolVersion: "v1", Capabilities: []string{"runtime.probe"},
	}, "request-4"); err != nil {
		t.Fatal(err)
	}
	if repository.identities[0].PendingRotationID != "" ||
		repository.identities[0].PreviousCertificateSerial != "" {
		t.Fatalf("confirmed rotation was not cleaned: %+v", repository.identities[0])
	}
	if _, err := repository.AuthenticateAgent(t.Context(), presented, now.Add(time.Minute)); err != ErrInvalidAgentIdentity {
		t.Fatalf("old certificate after confirmation error = %v", err)
	}
}

func TestAgentControlAuthenticatesNegotiatesHeartbeatsAndFencesReconnect(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	identity := AgentIdentity{
		ID: "identity-1", OrganizationID: "organization-1",
		ManagedHostID: "host-1", InstanceID: "instance-1",
		CertificateSerial: "serial-1", CertificateSHA256: "fingerprint-1",
		CertificateExpires: now.Add(time.Hour),
		Capabilities:       []string{"docker"},
	}
	repository := &repositoryStub{
		items: []ManagedHost{{
			ID: "host-1", OrganizationID: "organization-1",
			Status: StatusOffline, ConnectionMode: runtimeaccess.ModeAgent,
			AgentIdentityID: "identity-1", AgentInstanceID: "instance-1",
		}},
		identities: []AgentIdentity{identity},
	}
	audits := &auditStub{}
	ids := []string{
		"session-1", "audit-1", "session-2", "audit-2",
		"audit-stale", "audit-3",
	}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, audits,
		func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
		func() time.Time { return now },
	).WithAgentControl(repository, nil, []string{"v1", "v1.1"})
	certificate := AgentCertificateIdentity{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
		CertificateSerial: "serial-1", CertificateSHA256: "fingerprint-1",
	}
	hello := AgentHello{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
		BootID: "boot-1", AgentVersion: "1.4.0",
		ProtocolVersion: "v1", Capabilities: []string{"docker"},
	}
	first, err := useCase.OpenAgentSession(
		t.Context(), certificate, hello, "request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if repository.items[0].Status != StatusOnline ||
		repository.items[0].AgentSessionID != first.ID {
		t.Fatalf("connected host = %+v", repository.items[0])
	}
	if err := useCase.HeartbeatAgentSession(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	hello.BootID = "boot-2"
	second, err := useCase.OpenAgentSession(
		t.Context(), certificate, hello, "request-2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if repository.items[0].AgentSessionID != second.ID {
		t.Fatalf("reconnected host = %+v", repository.items[0])
	}
	if err := useCase.CloseAgentSession(
		t.Context(), first, "stale-disconnect",
	); err != nil {
		t.Fatal(err)
	}
	if repository.items[0].Status != StatusOnline {
		t.Fatal("stale disconnect took the replacement session offline")
	}
	if err := useCase.CloseAgentSession(
		t.Context(), second, "request-3",
	); err != nil {
		t.Fatal(err)
	}
	if repository.items[0].Status != StatusOffline ||
		len(audits.events) != 3 {
		t.Fatalf("closed host = %+v, audits = %+v", repository.items[0], audits.events)
	}
}

func TestAgentControlRejectsCertificateBindingAndUnsupportedProtocol(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	repository := &repositoryStub{identities: []AgentIdentity{{
		ID: "identity-1", OrganizationID: "organization-1",
		ManagedHostID: "host-1", InstanceID: "instance-1",
		CertificateSerial: "serial-1", CertificateSHA256: "fingerprint-1",
		CertificateExpires: now.Add(time.Hour),
		Capabilities:       []string{"docker"},
	}}}
	useCase := NewUseCase(
		repository, transaction.Passthrough{}, &auditStub{},
		func() (string, error) { return "unused", nil },
		func() time.Time { return now },
	).WithAgentControl(repository, nil, []string{"v1"})
	certificate := AgentCertificateIdentity{
		OrganizationID: "organization-1", ManagedHostID: "host-1",
		IdentityID: "identity-1", InstanceID: "instance-1",
		CertificateSerial: "serial-1", CertificateSHA256: "fingerprint-1",
	}
	hello := AgentHello{
		OrganizationID: "organization-1", ManagedHostID: "host-2",
		IdentityID: "identity-1", InstanceID: "instance-1",
		BootID: "boot-1", AgentVersion: "1.0.0",
		ProtocolVersion: "v1", Capabilities: []string{"docker"},
	}
	if _, err := useCase.OpenAgentSession(
		t.Context(), certificate, hello, "",
	); err != ErrInvalidAgentIdentity {
		t.Fatalf("cross-host error = %v", err)
	}
	hello.ManagedHostID = "host-1"
	hello.ProtocolVersion = "v2"
	if _, err := useCase.OpenAgentSession(
		t.Context(), certificate, hello, "",
	); err != ErrAgentProtocolUnsupported {
		t.Fatalf("protocol error = %v", err)
	}
	repository.identities[0].Capabilities = []string{"runtime.probe"}
	hello.ProtocolVersion = "v1"
	hello.Capabilities = []string{"deployment.stage"}
	if _, err := useCase.OpenAgentSession(
		t.Context(),
		certificate,
		hello,
		"",
	); err != ErrInvalidAgentIdentity {
		t.Fatalf("capability escalation error = %v", err)
	}
}
