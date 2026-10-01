package agentprotocol

const (
	CapabilityRuntimeProbe       = "runtime.probe"
	CapabilityDeploymentPrepare  = "deployment.prepare"
	CapabilityDeploymentStage    = "deployment.stage"
	CapabilityDeploymentActivate = "deployment.activate"
	CapabilityDeploymentRetire   = "deployment.retire"
	CapabilityDeploymentCancel   = "deployment.cancel"
	CapabilityRuntimeRemove      = "deployment.runtime.remove"
	CapabilityCutoverRelease     = "deployment.cutover.release"
	CapabilityInventoryPrepare   = "runtime.inventory.prepare"
	CapabilityInventoryChunk     = "runtime.inventory.chunk"
	CapabilityInventoryRelease   = "runtime.inventory.release"
	CapabilityInventoryEvents    = "runtime.inventory.events"
	CapabilityTerminalContainer  = "terminal.container"
	CapabilityTerminalHost       = "terminal.host"
	CapabilityIngressPrepare     = "ingress.prepare"
	CapabilityIngressCommit      = "ingress.commit"
	CapabilityIngressAbort       = "ingress.abort"
)

var supportedCapabilities = []string{
	CapabilityRuntimeProbe,
	CapabilityDeploymentPrepare,
	CapabilityDeploymentStage,
	CapabilityDeploymentActivate,
	CapabilityDeploymentRetire,
	CapabilityDeploymentCancel,
	CapabilityRuntimeRemove,
	CapabilityCutoverRelease,
	CapabilityInventoryPrepare,
	CapabilityInventoryChunk,
	CapabilityInventoryRelease,
	CapabilityInventoryEvents,
	CapabilityTerminalContainer,
	CapabilityTerminalHost,
	CapabilityIngressPrepare,
	CapabilityIngressCommit,
	CapabilityIngressAbort,
}

// SupportedCapabilities returns the exact capabilities implemented by this
// Agent build. The returned slice is detached from package state.
func SupportedCapabilities() []string {
	return append([]string(nil), supportedCapabilities...)
}

func SupportsCapability(value string) bool {
	for _, supported := range supportedCapabilities {
		if value == supported {
			return true
		}
	}
	return false
}

// RequiredCapability maps a typed command to the capability that must have
// been authenticated in the current Agent hello.
func RequiredCapability(kind AgentCommandKind) (string, bool) {
	switch kind {
	case AgentCommandRuntimeProbe:
		return CapabilityRuntimeProbe, true
	case AgentCommandDeploymentPrepare:
		return CapabilityDeploymentPrepare, true
	case AgentCommandDeploymentStage:
		return CapabilityDeploymentStage, true
	case AgentCommandDeploymentActivate:
		return CapabilityDeploymentActivate, true
	case AgentCommandDeploymentRetire:
		return CapabilityDeploymentRetire, true
	case AgentCommandDeploymentCancel:
		return CapabilityDeploymentCancel, true
	case AgentCommandRuntimeRemove:
		return CapabilityRuntimeRemove, true
	case AgentCommandCutoverRelease:
		return CapabilityCutoverRelease, true
	case AgentCommandInventoryPrepare:
		return CapabilityInventoryPrepare, true
	case AgentCommandInventoryChunk:
		return CapabilityInventoryChunk, true
	case AgentCommandInventoryRelease:
		return CapabilityInventoryRelease, true
	case AgentCommandInventoryEvents:
		return CapabilityInventoryEvents, true
	case AgentCommandIngressPrepare:
		return CapabilityIngressPrepare, true
	case AgentCommandIngressCommit:
		return CapabilityIngressCommit, true
	case AgentCommandIngressAbort:
		return CapabilityIngressAbort, true
	default:
		return "", false
	}
}
