package data

import (
	"context"
	"errors"
	"testing"
	"time"

	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/modules/deployment/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type emptyRetirementRepository struct{}

func (emptyRetirementRepository) ListForRuntimeTarget(
	context.Context, string, string,
) ([]biz.Deployment, error) {
	return nil, nil
}

func (emptyRetirementRepository) Save(
	context.Context, biz.Deployment, uint64,
) (biz.Deployment, error) {
	return biz.Deployment{}, nil
}

type emptyRetirementCredentials struct{}

func (emptyRetirementCredentials) ResolveCredential(
	context.Context, runtimeaccess.Connection,
) (biz.RuntimeCredential, error) {
	return biz.RuntimeCredential{}, nil
}

type emptyRetirementGateway struct{}

func (emptyRetirementGateway) RemoveRuntime(
	context.Context, biz.ExecutionPlan, biz.RuntimeCredential,
) error {
	return nil
}
func (emptyRetirementGateway) ReleaseCutoverWatermark(
	context.Context, biz.ExecutionPlan,
) error {
	return nil
}

type retirementAudit struct{}

func (retirementAudit) Record(context.Context, sharedaudit.Event) error { return nil }

func TestRuntimeTargetRetirementAdapterMapsConnectionsAndCompletion(t *testing.T) {
	retirement, err := biz.NewRuntimeTargetRetirement(
		emptyRetirementRepository{}, emptyRetirementCredentials{}, emptyRetirementGateway{},
		transaction.Passthrough{}, retirementAudit{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewRuntimeTargetRetirementAdapter(retirement)
	principal := security.Principal{UserID: "owner-1", OrganizationID: "organization-1"}
	for _, target := range []controlplanebiz.RuntimeTarget{
		{ID: "target-agent", ProjectID: "project-1", ManagedHostID: "host-1", ConnectionMode: runtimeaccess.ModeAgent},
		{ID: "target-direct", ProjectID: "project-1", ConnectionMode: runtimeaccess.ModeDirectDocker,
			Endpoint: "tcp://docker.example.com:2376", TLSServerName: "docker.example.com", CredentialRef: "secret://docker"},
	} {
		if err := adapter.RetireRuntimeTarget(
			t.Context(), target, principal, "request-1",
		); err != nil {
			t.Fatalf("target %+v = %v", target, err)
		}
	}
	invalid := controlplanebiz.RuntimeTarget{ID: "target-1", ProjectID: "project-1"}
	if err := adapter.RetireRuntimeTarget(
		t.Context(), invalid, principal, "request-1",
	); !errors.Is(err, controlplanebiz.ErrRuntimeTargetRetirementUnavailable) {
		t.Fatalf("invalid target error = %v", err)
	}
	if err := (*RuntimeTargetRetirementAdapter)(nil).RetireRuntimeTarget(
		t.Context(), invalid, principal, "request-1",
	); !errors.Is(err, controlplanebiz.ErrRuntimeTargetRetirementUnavailable) {
		t.Fatalf("nil adapter error = %v", err)
	}
}

func TestRuntimeTargetRetirementAdapterMapsPending(t *testing.T) {
	repository := NewMemoryRepository()
	if _, err := repository.Create(t.Context(), biz.Deployment{
		ID: "deployment-1", ProjectID: "project-1", ReleaseID: "release-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", Status: biz.StatusQueued, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	retirement, err := biz.NewRuntimeTargetRetirement(
		repository, emptyRetirementCredentials{}, emptyRetirementGateway{},
		transaction.Passthrough{}, retirementAudit{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = NewRuntimeTargetRetirementAdapter(retirement).RetireRuntimeTarget(
		t.Context(),
		controlplanebiz.RuntimeTarget{
			ID: "target-1", ProjectID: "project-1", ManagedHostID: "host-1",
			ConnectionMode: runtimeaccess.ModeAgent,
		},
		security.Principal{UserID: "owner-1", OrganizationID: "organization-1"},
		"request-1",
	)
	if !errors.Is(err, controlplanebiz.ErrRuntimeTargetRetirementPending) {
		t.Fatalf("pending error = %v", err)
	}
}
