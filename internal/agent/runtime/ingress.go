package agentruntime

import (
	"context"
	"errors"
	"sync"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

var (
	ErrIngressGatewayUnavailable = errors.New("Agent ingress gateway is unavailable")
	ErrIngressConfiguration      = errors.New("Agent ingress gateway configuration was rejected")
	ErrIngressPortConflict       = errors.New("Agent ingress public ports are unavailable")
	ErrIngressBackendUnhealthy   = errors.New("Agent ingress backend private probe failed")
)

type IngressGateway interface {
	Apply(context.Context, agentprotocol.IngressCommand) (configDigest string, err error)
	Probe(context.Context, agentprotocol.IngressCommand) error
	Clear(context.Context) error
}

type IngressExecutor struct {
	mu      sync.Mutex
	store   IngressFenceStore
	gateway IngressGateway
}

func NewIngressExecutor(store IngressFenceStore, gateway IngressGateway) (*IngressExecutor, error) {
	if store == nil || gateway == nil {
		return nil, ErrRuntimeExecutorMissing
	}
	return &IngressExecutor{store: store, gateway: gateway}, nil
}

func (e *IngressExecutor) Prepare(ctx context.Context, command agentprotocol.IngressCommand) (agentprotocol.IngressResult, error) {
	if command.Validate() != nil {
		return agentprotocol.IngressResult{}, ErrIngressConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	state, err := e.store.Begin(command)
	if err != nil {
		return agentprotocol.IngressResult{}, err
	}
	digest, err := e.gateway.Apply(ctx, command)
	if err == nil && digest != command.ConfigDigest {
		err = ErrIngressConfiguration
	}
	if err == nil {
		err = e.gateway.Probe(ctx, command)
	}
	if err != nil {
		if state != IngressPrepareCommitted {
			if restoreErr := e.restoreCommitted(ctx); restoreErr == nil {
				_ = e.store.Abort(command)
			}
		}
		return agentprotocol.IngressResult{}, err
	}
	return agentprotocol.IngressResult{HostRevision: command.HostRevision,
		ConfigDigest: command.ConfigDigest}, nil
}

func (e *IngressExecutor) Commit(ctx context.Context, command agentprotocol.IngressCommand) (agentprotocol.IngressResult, error) {
	if command.Validate() != nil {
		return agentprotocol.IngressResult{}, ErrIngressConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	alreadyCommitted, err := e.store.CanCommit(command)
	if err != nil {
		return agentprotocol.IngressResult{}, err
	}
	digest, err := e.gateway.Apply(ctx, command)
	if err != nil {
		return agentprotocol.IngressResult{}, err
	}
	if digest != command.ConfigDigest {
		return agentprotocol.IngressResult{}, ErrIngressConfiguration
	}
	if !alreadyCommitted {
		if err := e.store.Commit(command); err != nil {
			return agentprotocol.IngressResult{}, err
		}
	}
	return agentprotocol.IngressResult{HostRevision: command.HostRevision,
		ConfigDigest: command.ConfigDigest}, nil
}

func (e *IngressExecutor) Abort(ctx context.Context, command agentprotocol.IngressCommand) (agentprotocol.IngressResult, error) {
	if command.Validate() != nil {
		return agentprotocol.IngressResult{}, ErrIngressConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	alreadyAborted, err := e.store.CanAbort(command)
	if err != nil {
		return agentprotocol.IngressResult{}, err
	}
	if !alreadyAborted {
		if err := e.restoreCommitted(ctx); err != nil {
			return agentprotocol.IngressResult{}, err
		}
		if err := e.store.Abort(command); err != nil {
			return agentprotocol.IngressResult{}, err
		}
	}
	return agentprotocol.IngressResult{HostRevision: command.HostRevision,
		ConfigDigest: command.ConfigDigest}, nil
}

func (e *IngressExecutor) restoreCommitted(ctx context.Context) error {
	committed, exists := e.store.Committed()
	if !exists {
		return e.gateway.Clear(ctx)
	}
	digest, err := e.gateway.Apply(ctx, committed)
	if err != nil {
		return err
	}
	if digest != committed.ConfigDigest {
		return ErrIngressConfiguration
	}
	return nil
}
