package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type executionResolverStub struct {
	plan biz.ExecutionPlan
	err  error
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
	plan         biz.ExecutionPlan
	registryAuth string
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
