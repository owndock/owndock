package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type executionResolverStub struct {
	plan biz.ExecutionPlan
	err  error
}

type cancellationExecutionResolverStub struct {
	executionResolverStub
	cancellationPlan biz.ExecutionPlan
	called           *bool
}

func (s cancellationExecutionResolverStub) ResolveCancellation(
	context.Context,
	biz.Deployment,
) (biz.ExecutionPlan, error) {
	*s.called = true
	return s.cancellationPlan, nil
}

func (s executionResolverStub) ResolveExecution(context.Context, biz.Deployment) (biz.ExecutionPlan, error) {
	return s.plan, s.err
}

type credentialResolverStub struct {
	credential biz.RuntimeCredential
	err        error
}

func (s credentialResolverStub) ResolveRegistryAuthorization(
	context.Context, string, string, string,
) ([]byte, error) {
	return []byte("registry-auth"), s.err
}

func (s credentialResolverStub) ResolveConfigurationValue(
	_ context.Context, value string,
) (string, error) {
	return "resolved:" + value, s.err
}

func (s credentialResolverStub) ResolveCredential(
	context.Context,
	runtimeaccess.Connection,
) (biz.RuntimeCredential, error) {
	return s.credential, s.err
}

type runtimeGatewayPlanProbe struct {
	runtimeGatewayProbe
	plan              biz.ExecutionPlan
	stagedPlan        biz.ExecutionPlan
	authorizationPlan biz.ExecutionPlan
	registryAuth      string
	staged            bool
	activated         bool
	canceledPrepared  bool
	retired           bool
	stageErr          error
	activateErr       error
	cancelPreparedErr error
	onCancelPrepared  func()
}

func (g *runtimeGatewayPlanProbe) Stage(
	_ context.Context, plan biz.ExecutionPlan, _ biz.RuntimeCredential,
) error {
	g.staged, g.plan, g.stagedPlan = true, plan, plan
	if g.stageErr != nil {
		return g.stageErr
	}
	return g.err
}
func (g *runtimeGatewayPlanProbe) Activate(_ context.Context, plan biz.ExecutionPlan) error {
	g.activated, g.plan = true, plan
	return g.err
}
func (g *runtimeGatewayPlanProbe) ActivatePrepared(
	_ context.Context, authorization biz.ExecutionPlan, execution biz.ExecutionPlan,
) error {
	g.activated, g.authorizationPlan, g.plan = true, authorization, execution
	if g.activateErr != nil {
		return g.activateErr
	}
	return g.err
}
func (g *runtimeGatewayPlanProbe) CancelPrepared(
	_ context.Context, authorization biz.ExecutionPlan, execution biz.ExecutionPlan,
) error {
	g.canceledPrepared, g.authorizationPlan, g.plan = true, authorization, execution
	if g.onCancelPrepared != nil {
		g.onCancelPrepared()
	}
	if g.cancelPreparedErr != nil {
		return g.cancelPreparedErr
	}
	return g.err
}
func (g *runtimeGatewayPlanProbe) Retire(_ context.Context, plan biz.ExecutionPlan) error {
	g.retired, g.plan = true, plan
	return g.err
}

func testDirectConnection(t *testing.T) runtimeaccess.Connection {
	t.Helper()
	connection, err := runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://target",
	)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func testDirectCredential() biz.RuntimeCredential {
	return biz.RuntimeCredential{
		DirectDocker: &biz.DirectDockerCredential{},
	}
}

func (g *runtimeGatewayPlanProbe) Deploy(
	_ context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	g.plan = plan
	g.registryAuth = string(credential.RegistryAuthorization)
	return g.err
}

func TestRuntimeExecutorResolvesRegistryAndEnvironmentCredentials(t *testing.T) {
	gateway := &runtimeGatewayPlanProbe{}
	resolver := credentialResolverStub{credential: testDirectCredential()}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: biz.ExecutionPlan{
			TargetConnection: testDirectConnection(t),
			RegistryServer:   "registry.example.com", RegistryUsername: "robot",
			RegistryPasswordRef: "secret://registry",
			EnvironmentBindings: map[string]string{
				"DATABASE_URL": "secret://database",
			},
		}},
		resolver,
		gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor.WithRegistryCredentials(resolver).WithConfiguration(resolver)
	if err := executor.Deploy(t.Context(), biz.Deployment{}); err != nil {
		t.Fatal(err)
	}
	if gateway.registryAuth != "registry-auth" ||
		len(gateway.plan.Environment) != 1 ||
		gateway.plan.Environment[0] != "DATABASE_URL=resolved:secret://database" {
		t.Fatalf("plan = %+v, registry auth = %q", gateway.plan, gateway.registryAuth)
	}
}

type runtimeGatewayProbe struct {
	prepared bool
	deployed bool
	canceled bool
	err      error
}

func (g *runtimeGatewayProbe) Prepare(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.prepared = true
	return g.err
}
func (g *runtimeGatewayProbe) Deploy(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.deployed = true
	return g.err
}
func (g *runtimeGatewayProbe) Cancel(context.Context, biz.ExecutionPlan, biz.RuntimeCredential) error {
	g.canceled = true
	return g.err
}

func TestRuntimeExecutorResolvesPlanAndCredentialForEveryOperation(t *testing.T) {
	gateway := &runtimeGatewayProbe{}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: biz.ExecutionPlan{
			TargetConnection: testDirectConnection(t),
		}},
		credentialResolverStub{credential: testDirectCredential()},
		gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Prepare(t.Context(), biz.Deployment{}); err != nil {
		t.Fatal(err)
	}
	if err := executor.Deploy(t.Context(), biz.Deployment{}); err != nil {
		t.Fatal(err)
	}
	if err := executor.Cancel(t.Context(), biz.Deployment{}); err != nil {
		t.Fatal(err)
	}
	if !gateway.prepared || !gateway.deployed || !gateway.canceled {
		t.Fatalf("gateway calls = %+v", gateway)
	}
}

func TestRuntimeExecutorCoordinatesManagedIngressPhases(t *testing.T) {
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	plan := biz.ExecutionPlan{DeploymentID: "deployment-1", WorkerID: "worker-1",
		FencingToken: 2, CutoverSequence: 3, ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "container-1",
		TargetConnection: connection,
		RuntimeSpec:      runtimespec.Spec{Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080}}}}
	transaction := applicationroutebiz.CutoverTransaction{
		Request: applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
			ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
			RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
			WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
			CutoverSequence: 3, Ports: map[string]uint16{"http": 8080}},
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1},
	}
	store := &workerCutoverStore{transaction: transaction}
	routeGateway := &workerRouteGateway{}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(store, routeGateway)
	if err != nil {
		t.Fatal(err)
	}
	runtimeGateway := &runtimeGatewayPlanProbe{}
	executor, err := NewRuntimeExecutor(executionResolverStub{plan: plan}, credentialResolverStub{}, runtimeGateway)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}
	observed := make([]string, 0, 9)
	executor.WithManagedIngressObservability(func(phase, result string, duration time.Duration) {
		if duration < 0 {
			t.Fatalf("managed ingress duration = %v", duration)
		}
		observed = append(observed, phase+"/"+result)
	})
	deployment := biz.Deployment{ID: "deployment-1", OrganizationID: "organization-1"}
	if err := executor.Deploy(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	if !runtimeGateway.staged || !runtimeGateway.activated || runtimeGateway.retired ||
		!runtimeGateway.plan.ManagedIngress || routeGateway.prepareCalls != 1 {
		t.Fatalf("deploy phases = runtime %+v route %+v", runtimeGateway, routeGateway)
	}
	if err := executor.MarkControlPlaneCommitted(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	if err := executor.Commit(t.Context(), deployment); err != nil {
		t.Fatal(err)
	}
	if !runtimeGateway.retired || routeGateway.commitCalls != 1 || !store.finished ||
		runtimeGateway.plan.FencingToken != 2 {
		t.Fatalf("commit phases = runtime %+v route %+v store %+v", runtimeGateway, routeGateway, store)
	}
	wantObservations := "required/success,begin/success,runtime_stage/success," +
		"route_prepare/success,runtime_activate/success,control_commit/success," +
		"route_commit/success,runtime_retire/success,cutover_finish/success"
	if strings.Join(observed, ",") != wantObservations {
		t.Fatalf("managed ingress observations = %v", observed)
	}
}

func TestRuntimeExecutorSkipsManagedIngressCommitMarkForDirectTarget(t *testing.T) {
	store := &workerCutoverStore{}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(
		store, &workerRouteGateway{},
	)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: biz.ExecutionPlan{
			TargetConnection: testDirectConnection(t),
		}},
		credentialResolverStub{credential: testDirectCredential()},
		&runtimeGatewayProbe{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}
	if err := executor.MarkControlPlaneCommitted(
		t.Context(), biz.Deployment{ID: "direct-deployment"},
	); err != nil {
		t.Fatal(err)
	}
	if store.transaction.ControlPlaneCommitted {
		t.Fatal("direct target was marked as a managed ingress transaction")
	}
}

func TestRuntimeExecutorReplaysOriginalIngressIdentityAfterLeaseTakeover(t *testing.T) {
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	current := biz.ExecutionPlan{DeploymentID: "deployment-1", WorkerID: "worker-2",
		FencingToken: 9, CutoverSequence: 3, ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "container-1",
		TargetConnection: connection,
		RuntimeSpec:      runtimespec.Spec{Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080}}}}
	original := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
		CutoverSequence: 3, Ports: map[string]uint16{"http": 8080}}
	store := &workerCutoverStore{transaction: applicationroutebiz.CutoverTransaction{
		Request: original,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1},
	}}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(store, &workerRouteGateway{})
	if err != nil {
		t.Fatal(err)
	}
	gateway := &runtimeGatewayPlanProbe{}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: current}, credentialResolverStub{}, gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}
	if err := executor.Deploy(t.Context(), biz.Deployment{
		ID: "deployment-1", OrganizationID: "organization-1",
	}); err != nil {
		t.Fatal(err)
	}
	if gateway.stagedPlan.WorkerID != "worker-1" ||
		gateway.stagedPlan.FencingToken != 2 ||
		gateway.authorizationPlan.WorkerID != "worker-2" ||
		gateway.authorizationPlan.FencingToken != 9 ||
		gateway.plan.WorkerID != "worker-1" || gateway.plan.FencingToken != 2 {
		t.Fatalf("stage = %+v, authorization = %+v, execution = %+v",
			gateway.stagedPlan, gateway.authorizationPlan, gateway.plan)
	}
}

func TestRuntimeExecutorCancelsOriginalManagedIngressIdentityAfterLeaseTakeover(t *testing.T) {
	order := make([]string, 0, 3)
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	current := biz.ExecutionPlan{DeploymentID: "deployment-1", WorkerID: "worker-2",
		FencingToken: 9, CutoverSequence: 3, ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "container-1",
		TargetConnection: connection}
	original := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
		CutoverSequence: 3, Ports: map[string]uint16{"http": 8080}}
	store := &workerCutoverStore{transaction: applicationroutebiz.CutoverTransaction{
		Request: original,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1},
	}, onAbort: func() { order = append(order, "store") }}
	routeGateway := &workerRouteGateway{onAbort: func() { order = append(order, "route") }}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(store, routeGateway)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &runtimeGatewayPlanProbe{onCancelPrepared: func() { order = append(order, "runtime") }}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: current}, credentialResolverStub{}, gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}
	if err := executor.Cancel(t.Context(), biz.Deployment{ID: "deployment-1"}); err != nil {
		t.Fatal(err)
	}
	if !gateway.canceledPrepared || gateway.authorizationPlan.WorkerID != "worker-2" ||
		gateway.plan.WorkerID != "worker-1" || !store.aborted || routeGateway.abortCalls != 1 {
		t.Fatalf("gateway = %+v, store = %+v, route = %+v", gateway, store, routeGateway)
	}
	if len(order) != 3 || order[0] != "route" || order[1] != "runtime" || order[2] != "store" {
		t.Fatalf("rollback order = %v", order)
	}
}

func TestRuntimeExecutorRetainsManagedCutoverAfterAmbiguousStage(t *testing.T) {
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	plan := biz.ExecutionPlan{DeploymentID: "deployment-1", WorkerID: "worker-1",
		FencingToken: 2, CutoverSequence: 3, ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "container-1",
		TargetConnection: connection,
		RuntimeSpec:      runtimespec.Spec{Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080}}}}
	request := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
		CutoverSequence: 3, Ports: map[string]uint16{"http": 8080}}
	store := &workerCutoverStore{transaction: applicationroutebiz.CutoverTransaction{
		Request: request,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1},
	}}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(store, &workerRouteGateway{})
	if err != nil {
		t.Fatal(err)
	}
	gateway := &runtimeGatewayPlanProbe{stageErr: &biz.ExecutionError{
		Category: biz.FailureTargetUnreachable, Cause: errors.New("response lost"),
	}}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: plan}, credentialResolverStub{}, gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}
	err = executor.Deploy(t.Context(), biz.Deployment{
		ID: "deployment-1", OrganizationID: "organization-1",
	})
	if !errors.Is(err, biz.ErrExecutionRetryable) || store.aborted ||
		gateway.canceledPrepared {
		t.Fatalf("error = %v, store = %+v, gateway = %+v", err, store, gateway)
	}
}

func TestRuntimeExecutorCleansCandidateAfterDeterministicRouteFailure(t *testing.T) {
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	plan := biz.ExecutionPlan{DeploymentID: "deployment-1", WorkerID: "worker-1",
		FencingToken: 2, CutoverSequence: 3, ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ContainerName: "container-1",
		TargetConnection: connection,
		RuntimeSpec:      runtimespec.Spec{Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080}}}}
	request := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
		CutoverSequence: 3, Ports: map[string]uint16{"http": 8080}}
	store := &workerCutoverStore{transaction: applicationroutebiz.CutoverTransaction{
		Request: request,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 1},
	}}
	routes := &workerRouteGateway{prepareErr: applicationroutebiz.ErrGatewayBackendUnhealthy}
	coordinator, err := applicationroutebiz.NewCutoverCoordinator(store, routes)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &runtimeGatewayPlanProbe{}
	executor, err := NewRuntimeExecutor(
		executionResolverStub{plan: plan}, credentialResolverStub{}, gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.WithManagedIngress(coordinator, 0); err != nil {
		t.Fatal(err)
	}
	err = executor.Deploy(t.Context(), biz.Deployment{
		ID: "deployment-1", OrganizationID: "organization-1",
	})
	if !errors.Is(err, applicationroutebiz.ErrGatewayBackendUnhealthy) ||
		errors.Is(err, biz.ErrExecutionRetryable) || !gateway.canceledPrepared ||
		!store.aborted || store.failure != applicationroutebiz.FailureBackendUnhealthy ||
		routes.abortCalls != 2 {
		t.Fatalf("error = %v, store = %+v, runtime = %+v, routes = %+v",
			err, store, gateway, routes)
	}
}

func TestManagedIngressFailureCodeUsesOnlySafeExecutionCategories(t *testing.T) {
	tests := []struct {
		err  error
		want applicationroutebiz.FailureCode
	}{
		{err: applicationroutebiz.ErrGatewayCertificateUnavailable,
			want: applicationroutebiz.FailureCertificateUnavailable},
		{err: &biz.ExecutionError{Category: biz.FailureTargetUnreachable,
			Cause: errors.New("private endpoint")}, want: applicationroutebiz.FailureRuntimeUnavailable},
		{err: &biz.ExecutionError{Category: biz.FailureImagePull,
			Cause: errors.New("private registry")}, want: applicationroutebiz.FailureRuntimeUnavailable},
		{err: &biz.ExecutionError{Category: biz.FailureCredential,
			Cause: errors.New("private credential")}, want: applicationroutebiz.FailureConfiguration},
		{err: errors.New("private unknown"), want: applicationroutebiz.FailureUnknown},
	}
	for _, test := range tests {
		if got := managedIngressFailureCode(test.err); got != test.want {
			t.Fatalf("managedIngressFailureCode(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

type workerCutoverStore struct {
	transaction applicationroutebiz.CutoverTransaction
	finished    bool
	aborted     bool
	failure     applicationroutebiz.FailureCode
	onAbort     func()
}

func (*workerCutoverStore) Required(context.Context, applicationroutebiz.CutoverRequest) (bool, error) {
	return true, nil
}
func (s *workerCutoverStore) Begin(context.Context, applicationroutebiz.CutoverRequest) (applicationroutebiz.CutoverTransaction, error) {
	return s.transaction, nil
}
func (*workerCutoverStore) Prepared(context.Context, applicationroutebiz.CutoverTransaction, applicationroutebiz.GatewayObservation) error {
	return nil
}

func (s *workerCutoverStore) MarkControlPlaneCommitted(context.Context, applicationroutebiz.CutoverRequest) error {
	s.transaction.ControlPlaneCommitted = true
	return nil
}
func (s *workerCutoverStore) Get(context.Context, string) (applicationroutebiz.CutoverTransaction, bool, error) {
	return s.transaction, !s.finished && !s.aborted, nil
}
func (*workerCutoverStore) Complete(context.Context, applicationroutebiz.CutoverTransaction, applicationroutebiz.GatewayObservation) error {
	return nil
}
func (s *workerCutoverStore) Finish(context.Context, applicationroutebiz.CutoverTransaction) error {
	s.finished = true
	return nil
}
func (s *workerCutoverStore) Abort(
	_ context.Context,
	_ applicationroutebiz.CutoverTransaction,
	failure applicationroutebiz.FailureCode,
) error {
	s.aborted = true
	s.failure = failure
	if s.onAbort != nil {
		s.onAbort()
	}
	return nil
}

type workerRouteGateway struct {
	prepareCalls int
	commitCalls  int
	abortCalls   int
	prepareErr   error
	onAbort      func()
}

func (g *workerRouteGateway) Prepare(context.Context, applicationroutebiz.HostDesiredConfig) (applicationroutebiz.GatewayObservation, error) {
	g.prepareCalls++
	return applicationroutebiz.GatewayObservation{HostRevision: 1,
		ConfigDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, g.prepareErr
}
func (g *workerRouteGateway) Commit(context.Context, applicationroutebiz.HostDesiredConfig) (applicationroutebiz.GatewayObservation, error) {
	g.commitCalls++
	return applicationroutebiz.GatewayObservation{HostRevision: 1,
		ConfigDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, nil
}
func (g *workerRouteGateway) Abort(context.Context, applicationroutebiz.HostDesiredConfig) (applicationroutebiz.GatewayObservation, error) {
	g.abortCalls++
	if g.onAbort != nil {
		g.onAbort()
	}
	return applicationroutebiz.GatewayObservation{}, nil
}

func TestRuntimeExecutorUsesCancellationResolver(t *testing.T) {
	called := false
	gateway := &runtimeGatewayPlanProbe{}
	resolver := cancellationExecutionResolverStub{
		executionResolverStub: executionResolverStub{err: errors.New("normal resolution must not run")},
		cancellationPlan:      biz.ExecutionPlan{TargetConnection: testDirectConnection(t)},
		called:                &called,
	}
	executor, err := NewRuntimeExecutor(
		resolver,
		credentialResolverStub{credential: testDirectCredential()},
		gateway,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Cancel(t.Context(), biz.Deployment{}); err != nil || !called {
		t.Fatalf("cancel = %v, cancellation resolver called = %t", err, called)
	}
}

func TestRuntimeExecutorCategorizesBoundaryFailures(t *testing.T) {
	for name, test := range map[string]struct {
		executions  executionResolverStub
		credentials credentialResolverStub
		gateway     *runtimeGatewayProbe
		want        biz.FailureCategory
	}{
		"execution": {
			executions: executionResolverStub{err: errors.New("lookup")},
			gateway:    &runtimeGatewayProbe{},
			want:       biz.FailureConfiguration,
		},
		"credential": {
			executions: executionResolverStub{plan: biz.ExecutionPlan{
				TargetConnection: testDirectConnection(t),
			}},
			credentials: credentialResolverStub{err: errors.New("secret")},
			gateway:     &runtimeGatewayProbe{},
			want:        biz.FailureCredential,
		},
		"gateway": {
			executions: executionResolverStub{plan: biz.ExecutionPlan{
				TargetConnection: testDirectConnection(t),
			}},
			credentials: credentialResolverStub{credential: testDirectCredential()},
			gateway: &runtimeGatewayProbe{err: &biz.ExecutionError{
				Category: biz.FailureTargetUnreachable, Cause: errors.New("dial"),
			}},
			want: biz.FailureTargetUnreachable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			executor, err := NewRuntimeExecutor(test.executions, test.credentials, test.gateway)
			if err != nil {
				t.Fatal(err)
			}
			err = executor.Prepare(t.Context(), biz.Deployment{})
			var executionError *biz.ExecutionError
			if !errors.As(err, &executionError) || executionError.Category != test.want {
				t.Fatalf("error = %v, category = %v", err, executionError)
			}
		})
	}
}
