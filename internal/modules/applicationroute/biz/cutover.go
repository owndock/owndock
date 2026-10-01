package biz

import (
	"context"
	"errors"
	"maps"
	"strings"
)

var (
	ErrCutoverUnavailable = errors.New("application route cutover is unavailable")
	ErrCutoverConflict    = errors.New("application route cutover conflicts")
	ErrCutoverAmbiguous   = errors.New("application route cutover outcome is ambiguous")
)

// CutoverRequest is the secret-free immutable identity shared by the
// Deployment worker and the route controller. Runtime execution fencing is
// retained so the exact activated container can be retired after route commit.
type CutoverRequest struct {
	OrganizationID  string
	ProjectID       string
	ApplicationID   string
	EnvironmentID   string
	RuntimeTargetID string
	ManagedHostID   string
	DeploymentID    string
	WorkerID        string
	ContainerName   string
	FencingToken    uint64
	CutoverSequence uint64
	Ports           map[string]uint16
}

func (r CutoverRequest) Validate() error {
	identifiers := []string{r.OrganizationID, r.ProjectID, r.ApplicationID,
		r.EnvironmentID, r.RuntimeTargetID, r.ManagedHostID, r.DeploymentID,
		r.WorkerID, r.ContainerName}
	for _, identifier := range identifiers {
		if !validID(strings.TrimSpace(identifier)) {
			return ErrCutoverUnavailable
		}
	}
	if r.FencingToken == 0 || r.CutoverSequence == 0 || len(r.Ports) > 16 {
		return ErrCutoverUnavailable
	}
	for name, port := range r.Ports {
		if !portNamePattern.MatchString(strings.TrimSpace(name)) || port == 0 {
			return ErrCutoverUnavailable
		}
	}
	return nil
}

// SameCutover reports whether two requests describe the same immutable
// runtime and route cutover. WorkerID and FencingToken are deliberately not
// compared: a replacement Worker lease authorizes replay of the transaction
// originally allocated by its predecessor.
func (r CutoverRequest) SameCutover(other CutoverRequest) bool {
	return r.OrganizationID == other.OrganizationID &&
		r.ProjectID == other.ProjectID &&
		r.ApplicationID == other.ApplicationID &&
		r.EnvironmentID == other.EnvironmentID &&
		r.RuntimeTargetID == other.RuntimeTargetID &&
		r.ManagedHostID == other.ManagedHostID &&
		r.DeploymentID == other.DeploymentID &&
		r.ContainerName == other.ContainerName &&
		r.CutoverSequence == other.CutoverSequence &&
		maps.Equal(r.Ports, other.Ports)
}

type CutoverTransaction struct {
	Request               CutoverRequest
	Desired               HostDesiredConfig
	ControlPlaneCommitted bool
}

// CutoverStore owns durable Server-side transaction state. Begin must allocate
// a monotonic Host revision once and replay the exact same desired config.
// MarkControlPlaneCommitted runs inside the Deployment status transaction.
type CutoverStore interface {
	Required(context.Context, CutoverRequest) (bool, error)
	Begin(context.Context, CutoverRequest) (CutoverTransaction, error)
	Prepared(context.Context, CutoverTransaction, GatewayObservation) error
	MarkControlPlaneCommitted(context.Context, CutoverRequest) error
	Get(context.Context, string) (CutoverTransaction, bool, error)
	Complete(context.Context, CutoverTransaction, GatewayObservation) error
	Finish(context.Context, CutoverTransaction) error
	Abort(context.Context, CutoverTransaction) error
}

type CutoverCoordinator struct {
	store   CutoverStore
	gateway Gateway
}

func NewCutoverCoordinator(store CutoverStore, gateway Gateway) (*CutoverCoordinator, error) {
	if store == nil || gateway == nil {
		return nil, ErrCutoverUnavailable
	}
	return &CutoverCoordinator{store: store, gateway: gateway}, nil
}

func (c *CutoverCoordinator) Required(ctx context.Context, request CutoverRequest) (bool, error) {
	if request.Validate() != nil {
		return false, ErrCutoverUnavailable
	}
	return c.store.Required(ctx, request)
}

// Begin durably allocates the Host revision before runtime staging. Replays
// return the original activation identity even when a new Worker lease owns
// authorization, so later retire still targets the exact previous backend.
func (c *CutoverCoordinator) Begin(ctx context.Context, request CutoverRequest) (CutoverRequest, error) {
	if request.Validate() != nil {
		return CutoverRequest{}, ErrCutoverUnavailable
	}
	transaction, err := c.store.Begin(ctx, request)
	if err != nil {
		return CutoverRequest{}, err
	}
	if transaction.Request.Validate() != nil ||
		!request.SameCutover(transaction.Request) {
		return CutoverRequest{}, ErrCutoverConflict
	}
	return transaction.Request, nil
}

func (c *CutoverCoordinator) Prepare(ctx context.Context, deploymentID string) error {
	transaction, exists, err := c.store.Get(ctx, strings.TrimSpace(deploymentID))
	if err != nil {
		return err
	}
	if !exists || transaction.ControlPlaneCommitted {
		return ErrCutoverConflict
	}
	observation, err := c.gateway.Prepare(ctx, transaction.Desired)
	if err != nil {
		// The Agent prepare path already restores its committed config on a
		// deterministic load/probe failure. Abort is still issued because a
		// response may have been lost after the prepare actually succeeded.
		if _, abortErr := c.gateway.Abort(ctx, transaction.Desired); abortErr != nil {
			return errors.Join(ErrCutoverAmbiguous, err, abortErr)
		}
		return err
	}
	if err := c.store.Prepared(ctx, transaction, observation); err != nil {
		if _, abortErr := c.gateway.Abort(ctx, transaction.Desired); abortErr != nil {
			return errors.Join(ErrCutoverAmbiguous, err, abortErr)
		}
		return err
	}
	return nil
}

func (c *CutoverCoordinator) MarkControlPlaneCommitted(ctx context.Context, request CutoverRequest) error {
	if request.Validate() != nil {
		return ErrCutoverUnavailable
	}
	return c.store.MarkControlPlaneCommitted(ctx, request)
}

// Pending returns the original execution identity retained by an unfinished
// cutover. Cancellation uses it to remove the exact candidate even after the
// Deployment has been claimed by a replacement Worker lease.
func (c *CutoverCoordinator) Pending(ctx context.Context, deploymentID string) (CutoverRequest, bool, error) {
	transaction, exists, err := c.store.Get(ctx, strings.TrimSpace(deploymentID))
	if err != nil || !exists {
		return CutoverRequest{}, exists, err
	}
	if transaction.Request.Validate() != nil {
		return CutoverRequest{}, false, ErrCutoverConflict
	}
	return transaction.Request, true, nil
}

func (c *CutoverCoordinator) Commit(ctx context.Context, deploymentID string) (CutoverRequest, bool, error) {
	transaction, exists, err := c.store.Get(ctx, strings.TrimSpace(deploymentID))
	if err != nil {
		return CutoverRequest{}, false, err
	}
	if !exists {
		return CutoverRequest{}, false, nil
	}
	if !transaction.ControlPlaneCommitted {
		return CutoverRequest{}, false, ErrCutoverConflict
	}
	observation, err := c.gateway.Commit(ctx, transaction.Desired)
	if err != nil {
		return CutoverRequest{}, false, err
	}
	if err := c.store.Complete(ctx, transaction, observation); err != nil {
		return CutoverRequest{}, false, err
	}
	return transaction.Request, true, nil
}

func (c *CutoverCoordinator) Abort(ctx context.Context, deploymentID string) error {
	if err := c.Restore(ctx, deploymentID); err != nil {
		return err
	}
	return c.FinalizeAbort(ctx, deploymentID)
}

// Restore switches the Gateway back to its committed config but deliberately
// retains the Server transaction. Runtime rollback must finish before the
// durable identity can be discarded.
func (c *CutoverCoordinator) Restore(ctx context.Context, deploymentID string) error {
	transaction, exists, err := c.store.Get(ctx, strings.TrimSpace(deploymentID))
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if _, err := c.gateway.Abort(ctx, transaction.Desired); err != nil {
		return err
	}
	return nil
}

// FinalizeAbort clears Server state only after both Gateway and runtime have
// been restored. It is independently replayable after a MongoDB response loss.
func (c *CutoverCoordinator) FinalizeAbort(ctx context.Context, deploymentID string) error {
	transaction, exists, err := c.store.Get(ctx, strings.TrimSpace(deploymentID))
	if err != nil || !exists {
		return err
	}
	return c.store.Abort(ctx, transaction)
}

// Finish removes the durable Server transaction only after the old runtime
// backend has been retired. Until then Commit remains exactly replayable.
func (c *CutoverCoordinator) Finish(ctx context.Context, deploymentID string) error {
	transaction, exists, err := c.store.Get(ctx, strings.TrimSpace(deploymentID))
	if err != nil || !exists {
		return err
	}
	return c.store.Finish(ctx, transaction)
}
