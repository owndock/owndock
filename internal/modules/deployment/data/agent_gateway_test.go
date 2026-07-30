package data

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type agentCommandDispatcherStub struct {
	commands []managedhostbiz.AgentCommand
	hosts    []string
	results  []managedhostbiz.AgentCommandResult
	errs     []error
	onCall   func(managedhostbiz.AgentCommand)
}

func (d *agentCommandDispatcherStub) Dispatch(
	_ context.Context,
	hostID string,
	command managedhostbiz.AgentCommand,
) (managedhostbiz.AgentCommandResult, error) {
	d.hosts = append(d.hosts, hostID)
	d.commands = append(d.commands, command)
	if d.onCall != nil {
		d.onCall(command)
	}
	index := len(d.commands) - 1
	if index < len(d.errs) && d.errs[index] != nil {
		return managedhostbiz.AgentCommandResult{}, d.errs[index]
	}
	if index < len(d.results) {
		result := d.results[index]
		if result.CommandID == "" {
			result.CommandID = command.ID
		}
		return result, nil
	}
	return managedhostbiz.AgentCommandResult{
		CommandID: command.ID,
		Status:    managedhostbiz.AgentCommandSucceeded,
	}, nil
}

type agentFenceStub struct {
	err    error
	calls  int
	onCall func()
}

func (f *agentFenceStub) ValidateFence(
	context.Context,
	string,
	string,
	string,
	uint64,
	time.Time,
) error {
	f.calls++
	if f.onCall != nil {
		f.onCall()
	}
	return f.err
}

func TestAgentDockerGatewayBuildsNarrowPrepareCommand(t *testing.T) {
	dispatcher := &agentCommandDispatcherStub{}
	gateway := newAgentGateway(t, dispatcher, &agentFenceStub{})
	plan := testAgentExecutionPlan(t)
	authorization := []byte("encoded-secret")
	if err := gateway.Prepare(
		t.Context(),
		plan,
		biz.RuntimeCredential{
			RegistryAuthorization: authorization,
		},
	); err != nil {
		t.Fatal(err)
	}
	if len(dispatcher.commands) != 1 {
		t.Fatalf("commands = %d", len(dispatcher.commands))
	}
	command := dispatcher.commands[0]
	if dispatcher.hosts[0] != "host-1" ||
		command.Kind != agentprotocol.AgentCommandDeploymentPrepare ||
		command.Deployment == nil ||
		command.Deployment.ImageDigest != plan.ImageDigest ||
		string(command.Deployment.RegistryAuthorization) !=
			string(authorization) ||
		command.Deployment.ProjectID != "" ||
		len(command.Deployment.Environment) != 0 {
		t.Fatalf("command = %+v", command)
	}
}

func TestAgentDockerGatewayStagesFencesThenActivates(t *testing.T) {
	order := make([]string, 0, 3)
	dispatcher := &agentCommandDispatcherStub{
		onCall: func(command managedhostbiz.AgentCommand) {
			order = append(order, string(command.Kind))
		},
	}
	fence := &agentFenceStub{
		onCall: func() {
			order = append(order, "fence")
		},
	}
	gateway := newAgentGateway(t, dispatcher, fence)
	plan := testAgentExecutionPlan(t)
	plan.Environment = []string{"MODE=production"}
	if err := gateway.Deploy(
		t.Context(),
		plan,
		biz.RuntimeCredential{
			RegistryAuthorization: []byte("must-not-be-forwarded"),
		},
	); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") !=
		"deployment.stage,fence,deployment.activate" {
		t.Fatalf("order = %v", order)
	}
	if fence.calls != 1 || len(dispatcher.commands) != 2 {
		t.Fatalf(
			"fence calls = %d, commands = %d",
			fence.calls,
			len(dispatcher.commands),
		)
	}
	stage := dispatcher.commands[0]
	activate := dispatcher.commands[1]
	if stage.Deployment == nil ||
		stage.Deployment.ProjectID != plan.ProjectID ||
		stage.Deployment.Environment[0] != "MODE=production" ||
		len(stage.Deployment.RegistryAuthorization) != 0 {
		t.Fatalf("stage = %+v", stage)
	}
	if activate.Deployment == nil ||
		activate.Deployment.ProjectID != "" ||
		activate.Deployment.ImageDigest != "" ||
		len(activate.Deployment.Environment) != 0 {
		t.Fatalf("activate = %+v", activate)
	}
}

func TestAgentDockerGatewayCancelsCandidateAfterFenceLoss(
	t *testing.T,
) {
	dispatcher := &agentCommandDispatcherStub{}
	fence := &agentFenceStub{err: biz.ErrStaleExecution}
	gateway := newAgentGateway(t, dispatcher, fence)
	err := gateway.Deploy(
		t.Context(),
		testAgentExecutionPlan(t),
		biz.RuntimeCredential{},
	)
	if !errors.Is(err, biz.ErrStaleExecution) ||
		len(dispatcher.commands) != 2 ||
		dispatcher.commands[0].Kind !=
			agentprotocol.AgentCommandDeploymentStage ||
		dispatcher.commands[1].Kind !=
			agentprotocol.AgentCommandDeploymentCancel {
		t.Fatalf(
			"error = %v, commands = %+v",
			err,
			dispatcher.commands,
		)
	}
}

func TestAgentDockerGatewayMapsSafeAgentFailures(t *testing.T) {
	tests := []struct {
		name     string
		result   managedhostbiz.AgentCommandResult
		err      error
		category biz.FailureCategory
	}{
		{
			name: "image pull",
			result: managedhostbiz.AgentCommandResult{
				Status:    managedhostbiz.AgentCommandFailed,
				ErrorCode: "image_pull",
			},
			category: biz.FailureImagePull,
		},
		{
			name:     "offline",
			err:      managedhostbiz.ErrAgentNotConnected,
			category: biz.FailureTargetUnreachable,
		},
		{
			name:     "capability unavailable",
			err:      managedhostbiz.ErrAgentCapabilityUnavailable,
			category: biz.FailureUnsupportedTarget,
		},
		{
			name: "runtime conflict",
			result: managedhostbiz.AgentCommandResult{
				Status:    managedhostbiz.AgentCommandFailed,
				ErrorCode: "runtime_conflict",
			},
			category: biz.FailureRuntime,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := &agentCommandDispatcherStub{
				results: []managedhostbiz.AgentCommandResult{
					test.result,
				},
				errs: []error{test.err},
			}
			gateway := newAgentGateway(
				t,
				dispatcher,
				&agentFenceStub{},
			)
			err := gateway.Prepare(
				t.Context(),
				testAgentExecutionPlan(t),
				biz.RuntimeCredential{},
			)
			var executionError *biz.ExecutionError
			if !errors.As(err, &executionError) ||
				executionError.Category != test.category {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAgentDockerGatewayRejectsDirectConnection(t *testing.T) {
	gateway := newAgentGateway(
		t,
		&agentCommandDispatcherStub{},
		&agentFenceStub{},
	)
	plan := testExecutionPlan()
	err := gateway.Prepare(
		t.Context(),
		plan,
		biz.RuntimeCredential{},
	)
	var executionError *biz.ExecutionError
	if !errors.As(err, &executionError) ||
		executionError.Category != biz.FailureConfiguration {
		t.Fatalf("error = %v", err)
	}
}

func newAgentGateway(
	t *testing.T,
	dispatcher managedhostbiz.AgentCommandDispatcher,
	fence biz.FenceValidator,
) *AgentDockerGateway {
	t.Helper()
	counter := 0
	gateway, err := NewAgentDockerGateway(
		dispatcher,
		fence,
		func() (string, error) {
			counter++
			return "command-" + strconv.Itoa(counter), nil
		},
		time.Now,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func testAgentExecutionPlan(t *testing.T) biz.ExecutionPlan {
	t.Helper()
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	return biz.ExecutionPlan{
		DeploymentID:    "deployment-1",
		WorkerID:        "worker-1",
		FencingToken:    2,
		CutoverSequence: 1,
		ProjectID:       "project-1",
		ApplicationID:   "application-1",
		EnvironmentID:   "environment-1",
		RuntimeTargetID: "target-1",
		ImageDigest: "registry.example/team/api@sha256:" +
			strings.Repeat("a", 64),
		TargetConnection: connection,
		RuntimeSpec: runtimespec.Spec{
			EnvironmentKeys: []string{"MODE"},
			Resources: runtimespec.Resources{
				CPUMilli:    runtimespec.DefaultCPUMilli,
				MemoryBytes: runtimespec.DefaultMemoryBytes,
			},
		},
		Environment:   []string{"MODE=production"},
		ContainerName: "owndock-runtime",
	}
}
