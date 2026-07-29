package data

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

const (
	deploymentLabel = "net.owndock.deployment_id"
	fencingLabel    = "net.owndock.fencing_token"
)

type dockerEngine interface {
	Ping(context.Context, mobyclient.PingOptions) (mobyclient.PingResult, error)
	ImageInspect(context.Context, string, ...mobyclient.ImageInspectOption) (mobyclient.ImageInspectResult, error)
	ImagePull(context.Context, string, mobyclient.ImagePullOptions) (mobyclient.ImagePullResponse, error)
	ContainerInspect(context.Context, string, mobyclient.ContainerInspectOptions) (mobyclient.ContainerInspectResult, error)
	ContainerCreate(context.Context, mobyclient.ContainerCreateOptions) (mobyclient.ContainerCreateResult, error)
	ContainerStart(context.Context, string, mobyclient.ContainerStartOptions) (mobyclient.ContainerStartResult, error)
	ContainerRemove(context.Context, string, mobyclient.ContainerRemoveOptions) (mobyclient.ContainerRemoveResult, error)
	ContainerRename(context.Context, string, mobyclient.ContainerRenameOptions) (mobyclient.ContainerRenameResult, error)
	Close() error
}

type dockerEngineFactory func(biz.ExecutionPlan, biz.RuntimeCredential) (dockerEngine, error)

type DockerGateway struct {
	newEngine    dockerEngineFactory
	fence        biz.FenceValidator
	now          func() time.Time
	pollInterval time.Duration
}

func NewDockerGateway() *DockerGateway {
	return &DockerGateway{
		newEngine: newTLSDockerEngine, now: time.Now, pollInterval: 500 * time.Millisecond,
	}
}

func (g *DockerGateway) WithFence(validator biz.FenceValidator) *DockerGateway {
	g.fence = validator
	return g
}

func (g *DockerGateway) Prepare(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	engine, err := g.newEngine(plan, credential)
	if err != nil {
		return &biz.ExecutionError{Category: biz.FailureCredential, Cause: err}
	}
	defer func() { _ = engine.Close() }()
	if _, err := engine.Ping(ctx, mobyclient.PingOptions{}); err != nil {
		return &biz.ExecutionError{Category: biz.FailureTargetUnreachable, Cause: err}
	}
	if _, err := engine.ImageInspect(ctx, plan.ImageDigest); err == nil {
		// Digest-addressed local content is immutable and safe to reuse. This
		// also allows a prepared runtime target to deploy during a registry
		// outage without silently falling back to a mutable tag.
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	}
	pull, err := engine.ImagePull(ctx, plan.ImageDigest, mobyclient.ImagePullOptions{
		RegistryAuth: string(credential.RegistryAuthorization),
	})
	if err != nil {
		return &biz.ExecutionError{Category: biz.FailureImagePull, Cause: err}
	}
	if err := pull.Wait(ctx); err != nil {
		return &biz.ExecutionError{Category: biz.FailureImagePull, Cause: err}
	}
	return nil
}

func (g *DockerGateway) Deploy(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	engine, err := g.newEngine(plan, credential)
	if err != nil {
		return &biz.ExecutionError{Category: biz.FailureCredential, Cause: err}
	}
	defer func() { _ = engine.Close() }()

	current, err := engine.ContainerInspect(ctx, plan.ContainerName, mobyclient.ContainerInspectOptions{})
	if err == nil {
		if hasNewerFence(current, plan) {
			return staleExecutionError()
		}
		if ownsExecution(current, plan) {
			if err := g.waitUntilReady(ctx, engine, current.Container.ID, plan); err != nil {
				return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
			}
			g.removeContainer(previousContainerName(plan), engine)
			return nil
		}
	} else if !cerrdefs.IsNotFound(err) {
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	}

	candidateName := candidateContainerName(plan)
	candidate, candidateErr := engine.ContainerInspect(
		ctx, candidateName, mobyclient.ContainerInspectOptions{},
	)
	var candidateID string
	switch {
	case candidateErr == nil && hasNewerFence(candidate, plan):
		return staleExecutionError()
	case candidateErr == nil && ownsExecution(candidate, plan):
		candidateID = candidate.Container.ID
	case candidateErr == nil:
		if _, err := engine.ContainerRemove(
			ctx, candidate.Container.ID, mobyclient.ContainerRemoveOptions{Force: true},
		); err != nil {
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
		}
	case !cerrdefs.IsNotFound(candidateErr):
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: candidateErr}
	}
	if candidateID == "" {
		created, err := engine.ContainerCreate(ctx, dockerCreateOptions(plan, candidateName))
		if err != nil {
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
		}
		candidateID = created.ID
	}
	candidate, err = engine.ContainerInspect(ctx, candidateID, mobyclient.ContainerInspectOptions{})
	if err != nil {
		g.removeCandidate(candidateID, engine)
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	}
	if candidate.Container.State == nil || !candidate.Container.State.Running {
		if _, startErr := engine.ContainerStart(
			ctx, candidateID, mobyclient.ContainerStartOptions{},
		); startErr != nil {
			g.removeCandidate(candidateID, engine)
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: startErr}
		}
	}
	if err := g.waitUntilReady(ctx, engine, candidateID, plan); err != nil {
		g.removeCandidate(candidateID, engine)
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	}
	if err := g.validateFence(ctx, plan); err != nil {
		g.removeCandidate(candidateID, engine)
		return staleExecutionError()
	}

	current, err = engine.ContainerInspect(ctx, plan.ContainerName, mobyclient.ContainerInspectOptions{})
	var previousID string
	switch {
	case err == nil && hasNewerFence(current, plan):
		g.removeCandidate(candidateID, engine)
		return staleExecutionError()
	case err == nil && ownsExecution(current, plan):
		g.removeCandidate(candidateID, engine)
		return nil
	case err == nil:
		g.removeContainer(previousContainerName(plan), engine)
		if _, renameErr := engine.ContainerRename(
			ctx, current.Container.ID,
			mobyclient.ContainerRenameOptions{NewName: previousContainerName(plan)},
		); renameErr != nil {
			g.removeCandidate(candidateID, engine)
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: renameErr}
		}
		previousID = current.Container.ID
	case !cerrdefs.IsNotFound(err):
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	default:
		previous, previousErr := engine.ContainerInspect(
			ctx, previousContainerName(plan), mobyclient.ContainerInspectOptions{},
		)
		if previousErr == nil {
			previousID = previous.Container.ID
		} else if !cerrdefs.IsNotFound(previousErr) {
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: previousErr}
		}
	}
	if err := g.validateFence(ctx, plan); err != nil {
		g.restorePrevious(previousID, plan, engine)
		g.removeCandidate(candidateID, engine)
		return staleExecutionError()
	}
	if _, err := engine.ContainerRename(
		ctx, candidateID, mobyclient.ContainerRenameOptions{NewName: plan.ContainerName},
	); err != nil {
		g.restorePrevious(previousID, plan, engine)
		g.removeCandidate(candidateID, engine)
		return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
	}
	if previousID != "" {
		g.removeContainer(previousID, engine)
	}
	return nil
}

func (g *DockerGateway) Cancel(
	ctx context.Context,
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) error {
	engine, err := g.newEngine(plan, credential)
	if err != nil {
		return &biz.ExecutionError{Category: biz.FailureCredential, Cause: err}
	}
	defer func() { _ = engine.Close() }()
	if err := g.validateFence(ctx, plan); err != nil {
		return staleExecutionError()
	}
	for _, name := range []string{
		candidateContainerName(plan), previousContainerName(plan), plan.ContainerName,
	} {
		current, err := engine.ContainerInspect(ctx, name, mobyclient.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
		}
		// Never let cancellation of an older operation delete a container that
		// a newer deployment has installed under either name.
		if !ownsExecution(current, plan) {
			continue
		}
		if _, err := engine.ContainerRemove(
			ctx, current.Container.ID, mobyclient.ContainerRemoveOptions{Force: true},
		); err != nil {
			return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: err}
		}
	}
	return nil
}

func ownsDeployment(result mobyclient.ContainerInspectResult, deploymentID string) bool {
	return result.Container.Config != nil &&
		result.Container.Config.Labels[deploymentLabel] == deploymentID
}

func ownsExecution(result mobyclient.ContainerInspectResult, plan biz.ExecutionPlan) bool {
	return ownsDeployment(result, plan.DeploymentID) &&
		fencingToken(result) == plan.FencingToken
}

func hasNewerFence(result mobyclient.ContainerInspectResult, plan biz.ExecutionPlan) bool {
	// A lease generation is monotonic only within one Deployment. A separate,
	// newer Deployment starts at generation 1 and must still be able to replace
	// an older Deployment that happened to be reclaimed several times.
	return ownsDeployment(result, plan.DeploymentID) &&
		fencingToken(result) > plan.FencingToken
}

func fencingToken(result mobyclient.ContainerInspectResult) uint64 {
	if result.Container.Config == nil {
		return 0
	}
	token, _ := strconv.ParseUint(result.Container.Config.Labels[fencingLabel], 10, 64)
	return token
}

func candidateContainerName(plan biz.ExecutionPlan) string {
	return fmt.Sprintf(
		"%s-candidate-%s-%d",
		plan.ContainerName, executionNamePart(plan.DeploymentID), plan.FencingToken,
	)
}

func previousContainerName(plan biz.ExecutionPlan) string {
	return fmt.Sprintf(
		"%s-previous-%s-%d",
		plan.ContainerName, executionNamePart(plan.DeploymentID), plan.FencingToken,
	)
}

func executionNamePart(deploymentID string) string {
	sum := sha256.Sum256([]byte(deploymentID))
	return fmt.Sprintf("%x", sum[:6])
}

func dockerCreateOptions(plan biz.ExecutionPlan, name string) mobyclient.ContainerCreateOptions {
	exposedPorts := make(network.PortSet, len(plan.RuntimeSpec.Ports))
	for _, port := range plan.RuntimeSpec.Ports {
		exposedPorts[network.MustParsePort(
			fmt.Sprintf("%d/%s", port.ContainerPort, port.Protocol),
		)] = struct{}{}
	}
	config := &container.Config{
		Env: plan.Environment, ExposedPorts: exposedPorts,
		Labels: map[string]string{
			deploymentLabel:              plan.DeploymentID,
			fencingLabel:                 strconv.FormatUint(plan.FencingToken, 10),
			"net.owndock.project_id":     plan.ProjectID,
			"net.owndock.application_id": plan.ApplicationID,
			"net.owndock.environment_id": plan.EnvironmentID,
		},
	}
	if health := plan.RuntimeSpec.HealthCheck; health != nil {
		config.Healthcheck = &container.HealthConfig{
			Test:        append([]string{"CMD"}, health.Command...),
			Interval:    time.Duration(health.IntervalSeconds) * time.Second,
			Timeout:     time.Duration(health.TimeoutSeconds) * time.Second,
			Retries:     health.Retries,
			StartPeriod: time.Duration(health.StartPeriodSeconds) * time.Second,
		}
	}
	return mobyclient.ContainerCreateOptions{
		Name: name, Image: plan.ImageDigest, Config: config,
		HostConfig: &container.HostConfig{Resources: container.Resources{
			NanoCPUs: plan.RuntimeSpec.Resources.CPUMilli * 1_000_000,
			Memory:   plan.RuntimeSpec.Resources.MemoryBytes,
		}},
	}
}

func (g *DockerGateway) waitUntilReady(
	ctx context.Context,
	engine dockerEngine,
	containerID string,
	plan biz.ExecutionPlan,
) error {
	for {
		current, err := engine.ContainerInspect(ctx, containerID, mobyclient.ContainerInspectOptions{})
		if err != nil {
			return err
		}
		state := current.Container.State
		if state == nil || state.Dead || (!state.Running && state.Status != container.StateCreated) {
			return errors.New("candidate container stopped before becoming ready")
		}
		if state.Running {
			if plan.RuntimeSpec.HealthCheck == nil {
				return nil
			}
			if state.Health != nil {
				switch state.Health.Status {
				case container.Healthy:
					return nil
				case container.Unhealthy:
					return errors.New("candidate container is unhealthy")
				}
			}
		}
		timer := time.NewTimer(g.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (g *DockerGateway) validateFence(ctx context.Context, plan biz.ExecutionPlan) error {
	if g.fence == nil {
		return nil
	}
	return g.fence.ValidateFence(
		ctx, plan.ProjectID, plan.DeploymentID, plan.WorkerID,
		plan.FencingToken, g.now().UTC(),
	)
}

func (g *DockerGateway) removeCandidate(containerID string, engine dockerEngine) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = engine.ContainerRemove(
		cleanupContext, containerID, mobyclient.ContainerRemoveOptions{Force: true},
	)
}

func (g *DockerGateway) removeContainer(container string, engine dockerEngine) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := engine.ContainerRemove(
		cleanupContext, container, mobyclient.ContainerRemoveOptions{Force: true},
	)
	if err != nil && !cerrdefs.IsNotFound(err) {
		return
	}
}

func (g *DockerGateway) restorePrevious(
	previousID string,
	plan biz.ExecutionPlan,
	engine dockerEngine,
) {
	if previousID == "" {
		return
	}
	cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = engine.ContainerRename(
		cleanupContext, previousID,
		mobyclient.ContainerRenameOptions{NewName: plan.ContainerName},
	)
}

func staleExecutionError() error {
	return &biz.ExecutionError{Category: biz.FailureRuntime, Cause: biz.ErrStaleExecution}
}

func newTLSDockerEngine(
	plan biz.ExecutionPlan,
	credential biz.RuntimeCredential,
) (dockerEngine, error) {
	if plan.TargetConnection.Mode != runtimeaccess.ModeDirectDocker ||
		plan.TargetConnection.DirectDocker == nil {
		return nil, runtimeaccess.ErrInvalidConnection
	}
	if credential.DirectDocker == nil {
		return nil, errors.New("direct Docker credential is required")
	}
	connection := plan.TargetConnection.DirectDocker
	directCredential := credential.DirectDocker
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(directCredential.CACertificate) {
		return nil, errors.New("runtime CA certificate is invalid")
	}
	certificate, err := tls.X509KeyPair(
		directCredential.ClientCertificate,
		directCredential.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("runtime client certificate is invalid: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   connection.TLSServerName,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}}
	httpClient := &http.Client{
		Transport: transport, CheckRedirect: mobyclient.CheckRedirect,
	}
	return mobyclient.New(
		mobyclient.WithHTTPClient(httpClient),
		mobyclient.WithHost(connection.Endpoint),
		mobyclient.WithScheme("https"),
		mobyclient.WithAPIVersionNegotiation(),
	)
}
