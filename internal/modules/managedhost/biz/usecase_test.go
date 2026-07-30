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

func (r *repositoryStub) AuthenticateAgent(
	_ context.Context,
	certificate AgentCertificateIdentity,
	now time.Time,
) (AgentIdentity, error) {
	for _, identity := range r.identities {
		if identity.ID == certificate.IdentityID &&
			identity.OrganizationID == certificate.OrganizationID &&
			identity.ManagedHostID == certificate.ManagedHostID &&
			identity.InstanceID == certificate.InstanceID &&
			identity.CertificateSerial == certificate.CertificateSerial &&
			identity.CertificateSHA256 == certificate.CertificateSHA256 &&
			identity.CertificateExpires.After(now) &&
			identity.RevokedAt.IsZero() {
			return identity, nil
		}
	}
	return AgentIdentity{}, ErrInvalidAgentIdentity
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
		"", "request-1",
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
		t.Context(), maintainer, "Denied Host", runtimeaccess.ModeAgent, "", "",
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
