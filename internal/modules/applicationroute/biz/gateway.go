package biz

import (
	"context"
	"errors"
)

var (
	ErrGatewayUnavailable            = errors.New("application ingress gateway is unavailable")
	ErrGatewayFenceStale             = errors.New("application ingress gateway fence is stale")
	ErrGatewayFenceConflict          = errors.New("application ingress gateway fence conflicts")
	ErrGatewayConfiguration          = errors.New("application ingress gateway configuration is invalid")
	ErrGatewayStateFull              = errors.New("application ingress gateway state is full")
	ErrGatewayPortConflict           = errors.New("application ingress public ports are unavailable")
	ErrGatewayCertificateUnavailable = errors.New("application ingress automatic certificate is unavailable")
	ErrGatewayBackendUnhealthy       = errors.New("application ingress backend private probe failed")
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
	ProbeRouteIDs []string
}

type GatewayObservation struct {
	HostRevision uint64
	ConfigDigest string
}

type Gateway interface {
	Prepare(context.Context, HostDesiredConfig) (GatewayObservation, error)
	Commit(context.Context, HostDesiredConfig) (GatewayObservation, error)
	Abort(context.Context, HostDesiredConfig) (GatewayObservation, error)
}

func FailureCodeFromError(err error) FailureCode {
	switch {
	case errors.Is(err, ErrGatewayPortConflict):
		return FailurePortConflict
	case errors.Is(err, ErrGatewayCertificateUnavailable):
		return FailureCertificateUnavailable
	case errors.Is(err, ErrGatewayBackendUnhealthy):
		return FailureBackendUnhealthy
	case errors.Is(err, ErrGatewayFenceStale), errors.Is(err, ErrGatewayFenceConflict),
		errors.Is(err, ErrCutoverConflict):
		return FailureFenceConflict
	case errors.Is(err, ErrGatewayStateFull):
		return FailureStateFull
	case errors.Is(err, ErrGatewayConfiguration), errors.Is(err, ErrCutoverUnavailable):
		return FailureConfiguration
	case errors.Is(err, ErrGatewayUnavailable), errors.Is(err, ErrCutoverAmbiguous):
		return FailureGatewayUnavailable
	default:
		return FailureUnknown
	}
}
