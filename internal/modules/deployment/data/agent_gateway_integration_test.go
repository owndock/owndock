package data

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	managedhostdata "github.com/owndock/owndock/internal/modules/managedhost/data"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type routedAgentCommand struct {
	hostID          string
	runtimeTargetID string
	deploymentID    string
	kind            agentprotocol.AgentCommandKind
}

type multiHostFence struct {
	mu       sync.Mutex
	rejected map[string]struct{}
	calls    map[string]int
}

func (f *multiHostFence) ValidateFence(
	_ context.Context,
	_ string,
	deploymentID string,
	_ string,
	_ uint64,
	_ time.Time,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[deploymentID]++
	if _, rejected := f.rejected[deploymentID]; rejected {
		return biz.ErrStaleExecution
	}
	return nil
}

func TestAgentDockerGatewayRoutesTwoHostsWithoutCrossingTargets(
	t *testing.T,
) {
	registry, err := managedhostdata.NewConnectionRegistry(8, 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)

	routed := make(chan routedAgentCommand, 16)
	agentErrors := make(chan error, 4)
	startAgentCommandResponder(
		registry,
		"host-a",
		"session-a",
		agentprotocol.SupportedCapabilities(),
		routed,
		agentErrors,
	)
	startAgentCommandResponder(
		registry,
		"host-b",
		"session-b",
		agentprotocol.SupportedCapabilities(),
		routed,
		agentErrors,
	)

	fence := &multiHostFence{
		rejected: make(map[string]struct{}),
		calls:    make(map[string]int),
	}
	var identifier atomic.Uint64
	gateway, err := NewAgentDockerGateway(
		registry,
		fence,
		func() (string, error) {
			return "command-" +
				strconv.FormatUint(identifier.Add(1), 10), nil
		},
		time.Now,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := multiHostExecutionPlan(
		t,
		"host-a",
		"target-a",
		"deployment-a",
	)
	second := multiHostExecutionPlan(
		t,
		"host-b",
		"target-b",
		"deployment-b",
	)

	results := make(chan error, 2)
	go func() {
		results <- gateway.Deploy(
			t.Context(),
			first,
			biz.RuntimeCredential{},
		)
	}()
	go func() {
		results <- gateway.Deploy(
			t.Context(),
			second,
			biz.RuntimeCredential{},
		)
	}()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	seen := collectRoutedCommands(t, routed, 4)
	assertHostDeploymentRoute(
		t,
		seen,
		"host-a",
		"target-a",
		"deployment-a",
	)
	assertHostDeploymentRoute(
		t,
		seen,
		"host-b",
		"target-b",
		"deployment-b",
	)
	assertNoAgentErrors(t, agentErrors)

	registry.DisconnectHost("host-a")
	err = gateway.Prepare(
		t.Context(),
		first,
		biz.RuntimeCredential{},
	)
	assertExecutionCategory(
		t,
		err,
		biz.FailureTargetUnreachable,
	)
	if err := gateway.Prepare(
		t.Context(),
		second,
		biz.RuntimeCredential{},
	); err != nil {
		t.Fatalf("connected Host B prepare: %v", err)
	}
	remaining := collectRoutedCommands(t, routed, 1)
	if remaining[0].hostID != "host-b" ||
		remaining[0].runtimeTargetID != "target-b" ||
		remaining[0].deploymentID != "deployment-b" ||
		remaining[0].kind !=
			agentprotocol.AgentCommandDeploymentPrepare {
		t.Fatalf("remaining route = %+v", remaining[0])
	}
	assertNoAgentErrors(t, agentErrors)

	unsupportedCommands := registry.Register(
		"host-c",
		"session-c",
		[]string{agentprotocol.CapabilityRuntimeProbe},
		func() {},
	)
	unsupported := multiHostExecutionPlan(
		t,
		"host-c",
		"target-c",
		"deployment-c",
	)
	err = gateway.Prepare(
		t.Context(),
		unsupported,
		biz.RuntimeCredential{},
	)
	assertExecutionCategory(
		t,
		err,
		biz.FailureUnsupportedTarget,
	)
	select {
	case command := <-unsupportedCommands:
		t.Fatalf("unsupported command was routed: %+v", command)
	default:
	}
}

func TestAgentDockerGatewayKeepsExpiredFenceOnSelectedHost(
	t *testing.T,
) {
	registry, err := managedhostdata.NewConnectionRegistry(4, 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)
	routed := make(chan routedAgentCommand, 4)
	agentErrors := make(chan error, 2)
	startAgentCommandResponder(
		registry,
		"host-a",
		"session-a",
		agentprotocol.SupportedCapabilities(),
		routed,
		agentErrors,
	)
	fence := &multiHostFence{
		rejected: map[string]struct{}{
			"deployment-stale": {},
		},
		calls: make(map[string]int),
	}
	var identifier atomic.Uint64
	gateway, err := NewAgentDockerGateway(
		registry,
		fence,
		func() (string, error) {
			return "stale-command-" +
				strconv.FormatUint(identifier.Add(1), 10), nil
		},
		time.Now,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan := multiHostExecutionPlan(
		t,
		"host-a",
		"target-a",
		"deployment-stale",
	)
	err = gateway.Deploy(
		t.Context(),
		plan,
		biz.RuntimeCredential{},
	)
	if !errors.Is(err, biz.ErrStaleExecution) {
		t.Fatalf("stale deployment error = %v", err)
	}
	seen := collectRoutedCommands(t, routed, 2)
	if seen[0].hostID != "host-a" ||
		seen[0].runtimeTargetID != "target-a" ||
		seen[0].kind != agentprotocol.AgentCommandDeploymentStage ||
		seen[1].hostID != "host-a" ||
		seen[1].runtimeTargetID != "target-a" ||
		seen[1].kind != agentprotocol.AgentCommandDeploymentCancel {
		t.Fatalf("stale command route = %+v", seen)
	}
	assertNoAgentErrors(t, agentErrors)
}

func startAgentCommandResponder(
	registry *managedhostdata.ConnectionRegistry,
	hostID, sessionID string,
	capabilities []string,
	routed chan<- routedAgentCommand,
	errs chan<- error,
) {
	commands := registry.Register(
		hostID,
		sessionID,
		capabilities,
		func() {},
	)
	go func() {
		for command := range commands {
			deployment := command.Deployment
			if deployment == nil {
				errs <- errors.New(
					"deployment responder received non-deployment command",
				)
				continue
			}
			routed <- routedAgentCommand{
				hostID:          hostID,
				runtimeTargetID: deployment.RuntimeTargetID,
				deploymentID:    deployment.DeploymentID,
				kind:            command.Kind,
			}
			if err := registry.Complete(
				hostID,
				sessionID,
				managedhostbiz.AgentCommandResult{
					CommandID: command.ID,
					Status: managedhostbiz.
						AgentCommandSucceeded,
				},
			); err != nil {
				errs <- err
			}
		}
	}()
}

func multiHostExecutionPlan(
	t *testing.T,
	hostID, targetID, deploymentID string,
) biz.ExecutionPlan {
	t.Helper()
	plan := testAgentExecutionPlan(t)
	connection, err := runtimeaccess.NewAgent(hostID)
	if err != nil {
		t.Fatal(err)
	}
	plan.TargetConnection = connection
	plan.RuntimeTargetID = targetID
	plan.DeploymentID = deploymentID
	plan.ContainerName = "owndock-" + targetID
	return plan
}

func collectRoutedCommands(
	t *testing.T,
	commands <-chan routedAgentCommand,
	count int,
) []routedAgentCommand {
	t.Helper()
	result := make([]routedAgentCommand, 0, count)
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for len(result) < count {
		select {
		case command := <-commands:
			result = append(result, command)
		case <-timer.C:
			t.Fatalf(
				"received %d of %d routed commands",
				len(result),
				count,
			)
		}
	}
	return result
}

func assertHostDeploymentRoute(
	t *testing.T,
	commands []routedAgentCommand,
	hostID, targetID, deploymentID string,
) {
	t.Helper()
	kinds := make(map[agentprotocol.AgentCommandKind]int)
	for _, command := range commands {
		if command.hostID != hostID {
			continue
		}
		if command.runtimeTargetID != targetID ||
			command.deploymentID != deploymentID {
			t.Fatalf(
				"Host %s received crossed command %+v",
				hostID,
				command,
			)
		}
		kinds[command.kind]++
	}
	if kinds[agentprotocol.AgentCommandDeploymentStage] != 1 ||
		kinds[agentprotocol.AgentCommandDeploymentActivate] != 1 ||
		len(kinds) != 2 {
		t.Fatalf("Host %s command kinds = %+v", hostID, kinds)
	}
}

func assertExecutionCategory(
	t *testing.T,
	err error,
	category biz.FailureCategory,
) {
	t.Helper()
	var executionError *biz.ExecutionError
	if !errors.As(err, &executionError) ||
		executionError.Category != category {
		t.Fatalf("error = %v, want category %s", err, category)
	}
}

func assertNoAgentErrors(
	t *testing.T,
	errs <-chan error,
) {
	t.Helper()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
}
