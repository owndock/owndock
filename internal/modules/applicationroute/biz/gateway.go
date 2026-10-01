package biz

import (
	"context"
	"errors"
)

var (
	ErrGatewayUnavailable   = errors.New("application ingress gateway is unavailable")
	ErrGatewayFenceStale    = errors.New("application ingress gateway fence is stale")
	ErrGatewayFenceConflict = errors.New("application ingress gateway fence conflicts")
	ErrGatewayConfiguration = errors.New("application ingress gateway configuration is invalid")
	ErrGatewayStateFull     = errors.New("application ingress gateway state is full")
	ErrGatewayPortConflict  = errors.New("application ingress public ports are unavailable")
)

type GatewayRoute struct {
	RouteID         string
	Revision        uint64
	DeploymentID    string
	CutoverSequence uint64
	RuntimeTargetID string
	Hostname        string
	BackendAlias    string
	BackendPort     uint16
	TLSMode         TLSMode
}

type HostDesiredConfig struct {
	ManagedHostID string
	HostRevision  uint64
	Routes        []GatewayRoute
}

type GatewayObservation struct {
	HostRevision uint64
	ConfigDigest string
}

type Gateway interface {
	Reconcile(context.Context, HostDesiredConfig) (GatewayObservation, error)
}
