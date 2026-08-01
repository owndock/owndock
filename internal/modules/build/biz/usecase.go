package biz

import (
	"context"
	"errors"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type IDGenerator func() (string, error)
type Clock func() time.Time

type ProjectLookup interface {
	ProjectExists(context.Context, string, string) (bool, error)
}

type Repository interface {
	ListCredentials(context.Context, string) ([]CredentialSummary, error)
	CreateCredential(context.Context, RepositoryCredential) (CredentialSummary, error)
	GetCredential(context.Context, string, string) (RepositoryCredential, error)
	ListSources(context.Context, string) ([]SourceRepository, error)
	CreateSource(context.Context, SourceRepository) (SourceRepository, error)
	GetSource(context.Context, string, string) (SourceRepository, error)
	UpdateSourceProbe(
		context.Context,
		string,
		string,
		SourceRepositoryStatus,
		time.Time,
	) (SourceRepository, error)
}

type SourceProber interface {
	ProbeSource(
		context.Context,
		SourceRepository,
		*RepositoryCredential,
	) (SourceRepositoryStatus, error)
}

var ErrSourceProbeUnavailable = errors.New("source repository probe is unavailable")

type UseCase struct {
	projects    ProjectLookup
	repository  Repository
	transaction transaction.Manager
	audit       sharedaudit.Recorder
	newID       IDGenerator
	now         Clock
	prober      SourceProber
}

func (u *UseCase) WithSourceProber(prober SourceProber) *UseCase {
	u.prober = prober
	return u
}

func NewUseCase(
	projects ProjectLookup,
	repository Repository,
	transactionManager transaction.Manager,
	audit sharedaudit.Recorder,
	newID IDGenerator,
	now Clock,
) *UseCase {
	return &UseCase{
		projects: projects, repository: repository,
		transaction: transactionManager, audit: audit,
		newID: newID, now: now,
	}
}

func (u *UseCase) ListCredentials(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]CredentialSummary, error) {
	if err := principal.Require(security.PermissionSourceRepositoryRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.repository.ListCredentials(ctx, projectID)
}

func (u *UseCase) CreateCredential(
	ctx context.Context,
	principal security.Principal,
	projectID, name string,
	credentialType CredentialType,
	username, secretReference, publicKeyFingerprint, requestID string,
) (CredentialSummary, error) {
	if err := principal.Require(security.PermissionSourceRepositoryWrite); err != nil {
		return CredentialSummary{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return CredentialSummary{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return CredentialSummary{}, err
	}
	credential, err := NewRepositoryCredential(
		id, projectID, name, credentialType, username, secretReference,
		publicKeyFingerprint, principal.UserID, now,
	)
	if err != nil {
		return CredentialSummary{}, err
	}
	var created CredentialSummary
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var createErr error
		created, createErr = u.repository.CreateCredential(transactionContext, credential)
		if createErr != nil {
			return createErr
		}
		return u.record(
			transactionContext, principal, auditID,
			"repository_credential.create", "repository_credential",
			created.ID, projectID, requestID, now,
		)
	})
	return created, err
}

func (u *UseCase) ListSources(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) ([]SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.repository.ListSources(ctx, projectID)
}

func (u *UseCase) GetSource(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceID string,
) (SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryRead); err != nil {
		return SourceRepository{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SourceRepository{}, err
	}
	return u.repository.GetSource(ctx, projectID, sourceID)
}

func (u *UseCase) CreateSource(
	ctx context.Context,
	principal security.Principal,
	projectID, name, repositoryURL, defaultBranch, credentialID,
	sshHostKeyFingerprint, requestID string,
) (SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryWrite); err != nil {
		return SourceRepository{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SourceRepository{}, err
	}
	id, auditID, now, err := u.identifiers()
	if err != nil {
		return SourceRepository{}, err
	}
	source, err := NewSourceRepository(
		id, projectID, name, repositoryURL, defaultBranch, credentialID,
		sshHostKeyFingerprint, principal.UserID, now,
	)
	if err != nil {
		return SourceRepository{}, err
	}
	if credentialID != "" {
		credential, lookupErr := u.repository.GetCredential(ctx, projectID, credentialID)
		if lookupErr != nil {
			return SourceRepository{}, lookupErr
		}
		if !CredentialSupportsProtocol(credential, source.Protocol) {
			return SourceRepository{}, ErrCredentialProtocolMismatch
		}
	}
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := u.repository.CreateSource(transactionContext, source)
		if createErr != nil {
			return createErr
		}
		source = created
		return u.record(
			transactionContext, principal, auditID,
			"source_repository.create", "source_repository",
			source.ID, projectID, requestID, now,
		)
	})
	return source, err
}

func (u *UseCase) ProbeSource(
	ctx context.Context,
	principal security.Principal,
	projectID, sourceID, requestID string,
) (SourceRepository, error) {
	if err := principal.Require(security.PermissionSourceRepositoryWrite); err != nil {
		return SourceRepository{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SourceRepository{}, err
	}
	if u.prober == nil {
		return SourceRepository{}, ErrSourceProbeUnavailable
	}
	source, err := u.repository.GetSource(ctx, projectID, sourceID)
	if err != nil {
		return SourceRepository{}, err
	}
	var credential *RepositoryCredential
	if source.CredentialID != "" {
		resolved, lookupErr := u.repository.GetCredential(ctx, projectID, source.CredentialID)
		if lookupErr != nil {
			return SourceRepository{}, lookupErr
		}
		if !CredentialSupportsProtocol(resolved, source.Protocol) {
			return SourceRepository{}, ErrCredentialProtocolMismatch
		}
		credential = &resolved
	}
	status, err := u.prober.ProbeSource(ctx, source, credential)
	if err != nil {
		return SourceRepository{}, err
	}
	if !status.ValidProbeResult() {
		return SourceRepository{}, ErrSourceProbeUnavailable
	}
	auditID, err := u.newID()
	if err != nil {
		return SourceRepository{}, err
	}
	now := u.now().UTC()
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		updated, updateErr := u.repository.UpdateSourceProbe(
			transactionContext, projectID, sourceID, status, now,
		)
		if updateErr != nil {
			return updateErr
		}
		source = updated
		return u.record(
			transactionContext, principal, auditID,
			"source_repository.probe", "source_repository",
			source.ID, projectID, requestID, now,
		)
	})
	return source, err
}

func (u *UseCase) requireProject(
	ctx context.Context,
	principal security.Principal,
	projectID string,
) error {
	exists, err := u.projects.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (u *UseCase) identifiers() (string, string, time.Time, error) {
	id, err := u.newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	auditID, err := u.newID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	return id, auditID, u.now().UTC(), nil
}

func (u *UseCase) record(
	ctx context.Context,
	principal security.Principal,
	auditID, action, resourceType, resourceID, projectID, requestID string,
	now time.Time,
) error {
	return u.audit.Record(ctx, sharedaudit.Event{
		ID: auditID, OrganizationID: principal.OrganizationID,
		ProjectID: projectID, ActorID: principal.UserID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID,
		RequestID: requestID, CreatedAt: now,
	})
}
