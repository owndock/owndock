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
)

type IngressGateway interface {
	Apply(context.Context, agentprotocol.IngressCommand) (configDigest string, err error)
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

func (e *IngressExecutor) Reconcile(ctx context.Context, command agentprotocol.IngressCommand) (agentprotocol.IngressResult, error) {
	if command.Validate() != nil {
		return agentprotocol.IngressResult{}, ErrIngressConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	idempotent, err := e.store.Check(command)
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
	if !idempotent {
		if err := e.store.Commit(command); err != nil {
			return agentprotocol.IngressResult{}, err
		}
	}
	return agentprotocol.IngressResult{HostRevision: command.HostRevision,
		ConfigDigest: command.ConfigDigest}, nil
}
