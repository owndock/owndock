package data

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	mobyclient "github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/adapters/dockerengine"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimeidentity"
)

const containerIdentityPollInterval = 2 * time.Second

var ErrInvalidContainerGateway = errors.New("container terminal gateway is invalid")

type containerCredentialResolver interface {
	ResolveDirectCredential(
		context.Context,
		runtimeaccess.Connection,
	) (dockerengine.TLSCredential, error)
}

type containerExecEngine interface {
	ContainerInspect(
		context.Context,
		string,
		mobyclient.ContainerInspectOptions,
	) (mobyclient.ContainerInspectResult, error)
	ExecCreate(
		context.Context,
		string,
		mobyclient.ExecCreateOptions,
	) (mobyclient.ExecCreateResult, error)
	ExecAttach(
		context.Context,
		string,
		mobyclient.ExecAttachOptions,
	) (mobyclient.ExecAttachResult, error)
	ExecResize(
		context.Context,
		string,
		mobyclient.ExecResizeOptions,
	) (mobyclient.ExecResizeResult, error)
	Close() error
}

type containerEngineFactory func(
	runtimeaccess.Connection,
	dockerengine.TLSCredential,
) (containerExecEngine, error)

// DirectContainerGateway opens a constrained interactive shell through the
// mTLS Docker API. Target identity is derived by the server and checked both
// before and after the exec attachment to prevent deployment replacement from
// redirecting an authorized session to a different container.
type DirectContainerGateway struct {
	credentials  containerCredentialResolver
	openEngine   containerEngineFactory
	pollInterval time.Duration
}

func NewDirectContainerGateway(
	credentials containerCredentialResolver,
) (*DirectContainerGateway, error) {
	if credentials == nil {
		return nil, ErrInvalidContainerGateway
	}
	return &DirectContainerGateway{
		credentials: credentials,
		openEngine: func(
			connection runtimeaccess.Connection,
			credential dockerengine.TLSCredential,
		) (containerExecEngine, error) {
			return dockerengine.NewTLS(connection, credential)
		},
		pollInterval: containerIdentityPollInterval,
	}, nil
}

func (g *DirectContainerGateway) OpenContainer(
	ctx context.Context,
	_ string,
	target terminalbiz.Target,
	size terminalbiz.TerminalSize,
) (terminalbiz.TerminalStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateDirectContainerTarget(target); err != nil {
		return nil, err
	}
	if err := size.Validate(); err != nil {
		return nil, err
	}
	credential, err := g.credentials.ResolveDirectCredential(ctx, target.Connection)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve Docker credential", terminalbiz.ErrStreamUnavailable)
	}
	defer clearContainerCredential(&credential)
	engine, err := g.openEngine(target.Connection, credential)
	if err != nil {
		return nil, fmt.Errorf("%w: open Docker connection", terminalbiz.ErrStreamUnavailable)
	}
	closeEngine := true
	defer func() {
		if closeEngine {
			_ = engine.Close()
		}
	}()

	initial, err := inspectAuthorizedContainer(ctx, engine, target)
	if err != nil {
		return nil, err
	}
	var attachment mobyclient.ExecAttachResult
	var execID string
	for _, shell := range []string{"/bin/sh", "/bin/bash", "/bin/ash"} {
		created, createErr := engine.ExecCreate(
			ctx,
			initial.Container.ID,
			mobyclient.ExecCreateOptions{
				TTY: true, AttachStdin: true, AttachStdout: true, AttachStderr: true,
				ConsoleSize: mobyclient.ConsoleSize{Height: uint(size.Rows), Width: uint(size.Columns)},
				Cmd:         []string{shell},
			},
		)
		if createErr != nil || created.ID == "" {
			continue
		}
		attached, attachErr := engine.ExecAttach(
			ctx,
			created.ID,
			mobyclient.ExecAttachOptions{
				TTY:         true,
				ConsoleSize: mobyclient.ConsoleSize{Height: uint(size.Rows), Width: uint(size.Columns)},
			},
		)
		if attachErr != nil {
			continue
		}
		attachment, execID = attached, created.ID
		break
	}
	if execID == "" {
		return nil, fmt.Errorf("%w: start fixed container shell", terminalbiz.ErrStreamUnavailable)
	}
	current, err := inspectAuthorizedContainer(ctx, engine, target)
	if err != nil || current.Container.ID != initial.Container.ID {
		attachment.Close()
		return nil, terminalbiz.ErrTargetUnavailable
	}

	streamContext, cancel := context.WithCancel(ctx)
	stream := &directContainerStream{
		engine: engine, attachment: attachment, execID: execID,
		containerID: initial.Container.ID, containerName: target.ContainerName,
		target: target, cancel: cancel, closed: make(chan struct{}),
	}
	closeEngine = false
	go stream.watchIdentity(streamContext, g.pollInterval)
	return stream, nil
}

func validateDirectContainerTarget(target terminalbiz.Target) error {
	if target.Kind != terminalbiz.KindContainer || target.ContainerName == "" ||
		target.OrganizationID == "" || target.ProjectID == "" ||
		target.ApplicationID == "" || target.EnvironmentID == "" ||
		target.ManagedHostID == "" || target.RuntimeTargetID == "" ||
		target.DeploymentID == "" || target.InstanceGeneration == 0 ||
		target.ConnectionMode != runtimeaccess.ModeDirectDocker ||
		target.Connection.Mode != runtimeaccess.ModeDirectDocker ||
		target.Connection.ManagedHostID != target.ManagedHostID ||
		target.Connection.Validate() != nil {
		return terminalbiz.ErrTargetUnavailable
	}
	return nil
}

func inspectAuthorizedContainer(
	ctx context.Context,
	engine containerExecEngine,
	target terminalbiz.Target,
) (mobyclient.ContainerInspectResult, error) {
	result, err := engine.ContainerInspect(
		ctx,
		target.ContainerName,
		mobyclient.ContainerInspectOptions{},
	)
	if err != nil || !matchesAuthorizedContainer(result, target) {
		return mobyclient.ContainerInspectResult{}, terminalbiz.ErrTargetUnavailable
	}
	return result, nil
}

func matchesAuthorizedContainer(
	result mobyclient.ContainerInspectResult,
	target terminalbiz.Target,
) bool {
	if result.Container.ID == "" || result.Container.State == nil ||
		!result.Container.State.Running || result.Container.Config == nil {
		return false
	}
	labels := result.Container.Config.Labels
	return labels[runtimeidentity.DeploymentIDLabel] == target.DeploymentID &&
		labels[runtimeidentity.CutoverSequenceLabel] == fmt.Sprint(target.InstanceGeneration) &&
		labels[runtimeidentity.ProjectIDLabel] == target.ProjectID &&
		labels[runtimeidentity.ApplicationIDLabel] == target.ApplicationID &&
		labels[runtimeidentity.EnvironmentIDLabel] == target.EnvironmentID
}

type directContainerStream struct {
	engine        containerExecEngine
	attachment    mobyclient.ExecAttachResult
	execID        string
	containerID   string
	containerName string
	target        terminalbiz.Target
	cancel        context.CancelFunc
	closeOnce     sync.Once
	closed        chan struct{}
}

func (s *directContainerStream) Read(payload []byte) (int, error) {
	return s.attachment.Reader.Read(payload)
}

func (s *directContainerStream) Write(payload []byte) (int, error) {
	return s.attachment.Conn.Write(payload)
}

func (s *directContainerStream) Resize(
	ctx context.Context,
	size terminalbiz.TerminalSize,
) error {
	if err := size.Validate(); err != nil {
		return err
	}
	select {
	case <-s.done():
		return terminalbiz.ErrStreamUnavailable
	default:
	}
	_, err := s.engine.ExecResize(ctx, s.execID, mobyclient.ExecResizeOptions{
		Height: uint(size.Rows), Width: uint(size.Columns),
	})
	if err != nil {
		return fmt.Errorf("%w: resize container terminal", terminalbiz.ErrStreamUnavailable)
	}
	return nil
}

func (s *directContainerStream) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.attachment.Close()
		_ = s.engine.Close()
		if s.closed != nil {
			close(s.closed)
		}
	})
	return nil
}

func (s *directContainerStream) done() <-chan struct{} {
	return s.closed
}

func (s *directContainerStream) watchIdentity(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = containerIdentityPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return
		case <-ticker.C:
			result, err := inspectAuthorizedContainer(ctx, s.engine, s.target)
			if err != nil || result.Container.ID != s.containerID {
				_ = s.Close()
				return
			}
		}
	}
}

func clearContainerCredential(credential *dockerengine.TLSCredential) {
	for _, value := range [][]byte{
		credential.CACertificate,
		credential.ClientCertificate,
		credential.ClientKey,
	} {
		clear(value)
	}
}

var _ terminalbiz.ContainerGateway = (*DirectContainerGateway)(nil)
var _ terminalbiz.TerminalStream = (*directContainerStream)(nil)
