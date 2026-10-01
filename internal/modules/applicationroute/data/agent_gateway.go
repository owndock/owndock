package data

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

type AgentGateway struct {
	dispatcher managedhostbiz.AgentCommandDispatcher
	newID      func() (string, error)
	now        func() time.Time
	timeout    time.Duration
}

func NewAgentGateway(dispatcher managedhostbiz.AgentCommandDispatcher, newID func() (string, error),
	now func() time.Time, timeout time.Duration) (*AgentGateway, error) {
	if dispatcher == nil || newID == nil || now == nil || timeout <= 0 || timeout > 5*time.Minute {
		return nil, applicationroutebiz.ErrGatewayUnavailable
	}
	return &AgentGateway{dispatcher: dispatcher, newID: newID, now: now, timeout: timeout}, nil
}

func (g *AgentGateway) Prepare(ctx context.Context, desired applicationroutebiz.HostDesiredConfig) (applicationroutebiz.GatewayObservation, error) {
	return g.execute(ctx, desired, agentprotocol.AgentCommandIngressPrepare)
}

func (g *AgentGateway) Commit(ctx context.Context, desired applicationroutebiz.HostDesiredConfig) (applicationroutebiz.GatewayObservation, error) {
	return g.execute(ctx, desired, agentprotocol.AgentCommandIngressCommit)
}

func (g *AgentGateway) Abort(ctx context.Context, desired applicationroutebiz.HostDesiredConfig) (applicationroutebiz.GatewayObservation, error) {
	return g.execute(ctx, desired, agentprotocol.AgentCommandIngressAbort)
}

func (g *AgentGateway) execute(ctx context.Context, desired applicationroutebiz.HostDesiredConfig, kind agentprotocol.AgentCommandKind) (applicationroutebiz.GatewayObservation, error) {
	managedHostID := strings.TrimSpace(desired.ManagedHostID)
	if managedHostID == "" || desired.HostRevision == 0 || len(desired.Routes) > agentprotocol.MaxIngressRoutes {
		return applicationroutebiz.GatewayObservation{}, applicationroutebiz.ErrGatewayConfiguration
	}
	routes := make([]agentprotocol.IngressRoute, len(desired.Routes))
	for index, route := range desired.Routes {
		tlsMode := agentprotocol.IngressTLSMode(route.TLSMode)
		routes[index] = agentprotocol.IngressRoute{RouteID: route.RouteID, Revision: route.Revision,
			DeploymentID: route.DeploymentID, CutoverSequence: route.CutoverSequence,
			RuntimeTargetID: route.RuntimeTargetID, Hostname: route.Hostname,
			BackendAlias: route.BackendAlias, BackendPort: route.BackendPort, TLSMode: tlsMode}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].RouteID < routes[j].RouteID })
	probeRouteIDs := append([]string(nil), desired.ProbeRouteIDs...)
	sort.Strings(probeRouteIDs)
	digest, err := agentprotocol.IngressConfigDigest(desired.HostRevision, routes)
	if err != nil {
		return applicationroutebiz.GatewayObservation{}, applicationroutebiz.ErrGatewayConfiguration
	}
	ingress := agentprotocol.IngressCommand{HostRevision: desired.HostRevision,
		ConfigDigest: digest, Routes: routes, ProbeRouteIDs: probeRouteIDs}
	if err := ingress.Validate(); err != nil {
		return applicationroutebiz.GatewayObservation{}, applicationroutebiz.ErrGatewayConfiguration
	}
	commandID, err := g.newID()
	if err != nil {
		return applicationroutebiz.GatewayObservation{}, applicationroutebiz.ErrGatewayUnavailable
	}
	deadline := g.now().UTC().Add(g.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC()
	}
	command := managedhostbiz.AgentCommand{ID: commandID,
		Kind: kind, Deadline: deadline, Ingress: &ingress}
	result, err := g.dispatcher.Dispatch(ctx, managedHostID, command)
	if err != nil {
		return applicationroutebiz.GatewayObservation{}, mapAgentIngressDispatchError(ctx, err)
	}
	if result.Validate(command) != nil {
		return applicationroutebiz.GatewayObservation{}, applicationroutebiz.ErrGatewayUnavailable
	}
	if result.Status != agentprotocol.AgentCommandSucceeded {
		return applicationroutebiz.GatewayObservation{}, mapAgentIngressResultError(result.ErrorCode)
	}
	return applicationroutebiz.GatewayObservation{HostRevision: result.Ingress.HostRevision,
		ConfigDigest: result.Ingress.ConfigDigest}, nil
}

func mapAgentIngressDispatchError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return applicationroutebiz.ErrGatewayUnavailable
	}
	switch {
	case errors.Is(err, managedhostbiz.ErrAgentCapabilityUnavailable),
		errors.Is(err, managedhostbiz.ErrAgentNotConnected),
		errors.Is(err, managedhostbiz.ErrAgentDisconnected),
		errors.Is(err, managedhostbiz.ErrAgentCommandExpired),
		errors.Is(err, managedhostbiz.ErrAgentBackpressure):
		return applicationroutebiz.ErrGatewayUnavailable
	default:
		return applicationroutebiz.ErrGatewayUnavailable
	}
}

func mapAgentIngressResultError(code string) error {
	switch code {
	case "ingress_fence_stale":
		return applicationroutebiz.ErrGatewayFenceStale
	case "ingress_fence_conflict":
		return applicationroutebiz.ErrGatewayFenceConflict
	case "ingress_state_full":
		return applicationroutebiz.ErrGatewayStateFull
	case "ingress_port_conflict":
		return applicationroutebiz.ErrGatewayPortConflict
	case "ingress_backend_unhealthy":
		return applicationroutebiz.ErrGatewayBackendUnhealthy
	case "ingress_configuration":
		return applicationroutebiz.ErrGatewayConfiguration
	default:
		return applicationroutebiz.ErrGatewayUnavailable
	}
}

var _ applicationroutebiz.Gateway = (*AgentGateway)(nil)
