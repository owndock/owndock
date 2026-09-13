package biz_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type retirementCredentialResolver struct {
	credential biz.RuntimeCredential
	err        error
}

func (r retirementCredentialResolver) ResolveCredential(
	context.Context,
	runtimeaccess.Connection,
) (biz.RuntimeCredential, error) {
	return r.credential, r.err
}

type retirementGatewayProbe struct {
	removed    []biz.ExecutionPlan
	released   []biz.ExecutionPlan
	current    uint64
	removeErr  error
	releaseErr error
}

func (g *retirementGatewayProbe) RemoveRuntime(
	_ context.Context,
	plan biz.ExecutionPlan,
	_ biz.RuntimeCredential,
) error {
	g.removed = append(g.removed, plan)
	return g.removeErr
}

func (g *retirementGatewayProbe) ReleaseCutoverWatermark(
	_ context.Context,
	plan biz.ExecutionPlan,
) error {
	g.released = append(g.released, plan)
	if g.releaseErr != nil {
		return g.releaseErr
	}
	if plan.CutoverSequence != g.current {
		return biz.ErrCutoverConflict
	}
	return nil
}

func TestRuntimeTargetRetirementValidatesDependenciesAndTarget(t *testing.T) {
	if _, err := biz.NewRuntimeTargetRetirement(
		nil, retirementCredentialResolver{}, &retirementGatewayProbe{},
		transaction.Passthrough{}, &auditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	); !errors.Is(err, biz.ErrRetirementUnavailable) {
		t.Fatalf("constructor error = %v", err)
	}
	retirement, err := biz.NewRuntimeTargetRetirement(
		data.NewMemoryRepository(), retirementCredentialResolver{},
		&retirementGatewayProbe{}, transaction.Passthrough{}, &auditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := retirement.Retire(
		t.Context(), biz.RetirementTarget{}, security.Principal{}, "request-1",
	); !errors.Is(err, biz.ErrRetirementUnavailable) {
		t.Fatalf("invalid target error = %v", err)
	}
}

func TestRuntimeTargetRetirementClearsDirectCredentialAndSkipsWatermark(t *testing.T) {
	repository := data.NewMemoryRepository()
	if _, err := repository.Create(t.Context(), biz.Deployment{
		ID: "deployment-1", ProjectID: "project-1", ReleaseID: "release-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", Status: biz.StatusSucceeded, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	secret := []byte("secret-material")
	credentials := retirementCredentialResolver{credential: biz.RuntimeCredential{
		DirectDocker: &biz.DirectDockerCredential{ClientKey: secret},
	}}
	gateway := &retirementGatewayProbe{}
	retirement, err := biz.NewRuntimeTargetRetirement(
		repository, credentials, gateway, transaction.Passthrough{}, &auditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://docker",
	)
	if err := retirement.Retire(
		t.Context(), biz.RetirementTarget{ID: "target-1", ProjectID: "project-1", Connection: connection},
		security.Principal{UserID: "owner-1", OrganizationID: "organization-1"}, "request-1",
	); err != nil {
		t.Fatal(err)
	}
	if len(gateway.removed) != 1 || len(gateway.released) != 0 {
		t.Fatalf("gateway = %+v", gateway)
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatal("direct credential was not cleared")
		}
	}
}

func TestRuntimeTargetRetirementFailsClosedOnCleanupErrors(t *testing.T) {
	repository := data.NewMemoryRepository()
	if _, err := repository.Create(t.Context(), biz.Deployment{
		ID: "deployment-1", ProjectID: "project-1", ReleaseID: "release-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", Status: biz.StatusSucceeded, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	connection, _ := runtimeaccess.NewAgent("host-1")
	directConnection, _ := runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://docker",
	)
	removeFailure := errors.New("remove failed")
	releaseFailure := errors.New("release failed")
	for _, test := range []struct {
		name        string
		credentials retirementCredentialResolver
		gateway     *retirementGatewayProbe
		connection  runtimeaccess.Connection
		want        error
	}{
		{name: "credential", credentials: retirementCredentialResolver{err: errors.New("secret unavailable")}, gateway: &retirementGatewayProbe{}, connection: directConnection, want: errors.New("execution")},
		{name: "remove", credentials: retirementCredentialResolver{}, gateway: &retirementGatewayProbe{removeErr: removeFailure}, connection: connection, want: removeFailure},
		{name: "release", credentials: retirementCredentialResolver{}, gateway: &retirementGatewayProbe{releaseErr: releaseFailure}, connection: connection, want: releaseFailure},
		{name: "conflict", credentials: retirementCredentialResolver{}, gateway: &retirementGatewayProbe{current: 99}, connection: connection, want: biz.ErrCutoverConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			retirement, err := biz.NewRuntimeTargetRetirement(
				repository, test.credentials, test.gateway,
				transaction.Passthrough{}, &auditProbe{},
				func() (string, error) { return "audit-1", nil }, time.Now,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = retirement.Retire(
				t.Context(), biz.RetirementTarget{ID: "target-1", ProjectID: "project-1", Connection: test.connection},
				security.Principal{UserID: "owner-1", OrganizationID: "organization-1"}, "request-1",
			)
			if test.name == "credential" {
				var executionError *biz.ExecutionError
				if !errors.As(err, &executionError) || executionError.Category != biz.FailureCredential {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRuntimeTargetRetirementCancelsActiveWorkBeforeCleanup(t *testing.T) {
	repository := data.NewMemoryRepository()
	created, err := repository.Create(t.Context(), biz.Deployment{
		ID: "deployment-1", OrganizationID: "organization-1",
		ProjectID: "project-1", ReleaseID: "release-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", Status: biz.StatusDeploying,
		Version: 1, CreatedAt: time.Unix(100, 0), UpdatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	audits := &auditProbe{}
	gateway := &retirementGatewayProbe{}
	sequence := 0
	retirement, err := biz.NewRuntimeTargetRetirement(
		repository, retirementCredentialResolver{}, gateway,
		transaction.Passthrough{}, audits,
		func() (string, error) {
			sequence++
			return fmt.Sprintf("audit-%d", sequence), nil
		},
		func() time.Time { return time.Unix(200, 0) },
	)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	err = retirement.Retire(
		t.Context(),
		biz.RetirementTarget{ID: "target-1", ProjectID: "project-1", Connection: connection},
		security.Principal{UserID: "owner-1", OrganizationID: "organization-1"},
		"request-1",
	)
	if !errors.Is(err, biz.ErrRetirementPending) {
		t.Fatalf("retirement error = %v", err)
	}
	updated, err := repository.Get(t.Context(), "project-1", created.ID)
	if err != nil || updated.Status != biz.StatusCanceling {
		t.Fatalf("deployment = %+v, %v", updated, err)
	}
	if len(gateway.removed) != 0 || len(audits.events) != 1 ||
		audits.events[0].Action != biz.AuditActionRetirementCancel {
		t.Fatalf("gateway/audits = %+v/%+v", gateway, audits.events)
	}
}

func TestRuntimeTargetRetirementRemovesStableThenReleasesExactWatermark(t *testing.T) {
	repository := data.NewMemoryRepository()
	for _, item := range []biz.Deployment{
		{ID: "deployment-stable", OrganizationID: "organization-1", ProjectID: "project-1",
			ReleaseID: "release-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
			RuntimeTargetID: "target-1", Status: biz.StatusSucceeded, Version: 1},
		{ID: "deployment-failed", OrganizationID: "organization-1", ProjectID: "project-1",
			ReleaseID: "release-2", ApplicationID: "application-1", EnvironmentID: "environment-1",
			RuntimeTargetID: "target-1", Status: biz.StatusFailed, Version: 1},
	} {
		if _, err := repository.Create(t.Context(), item); err != nil {
			t.Fatal(err)
		}
	}
	gateway := &retirementGatewayProbe{current: 1}
	retirement, err := biz.NewRuntimeTargetRetirement(
		repository, retirementCredentialResolver{}, gateway,
		transaction.Passthrough{}, &auditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := runtimeaccess.NewAgent("host-1")
	if err := retirement.Retire(
		t.Context(),
		biz.RetirementTarget{ID: "target-1", ProjectID: "project-1", Connection: connection},
		security.Principal{UserID: "owner-1", OrganizationID: "organization-1"},
		"request-1",
	); err != nil {
		t.Fatal(err)
	}
	if len(gateway.removed) != 1 || gateway.removed[0].DeploymentID != "deployment-stable" ||
		len(gateway.released) != 2 || gateway.released[0].CutoverSequence != 2 ||
		gateway.released[1].CutoverSequence != 1 {
		t.Fatalf("cleanup order = removed %+v, released %+v", gateway.removed, gateway.released)
	}
}
