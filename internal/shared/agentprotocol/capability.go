package agentprotocol

const (
	CapabilityRuntimeProbe       = "runtime.probe"
	CapabilityDeploymentPrepare  = "deployment.prepare"
	CapabilityDeploymentStage    = "deployment.stage"
	CapabilityDeploymentActivate = "deployment.activate"
	CapabilityDeploymentCancel   = "deployment.cancel"
	CapabilityInventoryPrepare   = "runtime.inventory.prepare"
	CapabilityInventoryChunk     = "runtime.inventory.chunk"
	CapabilityInventoryRelease   = "runtime.inventory.release"
)

var supportedCapabilities = []string{
	CapabilityRuntimeProbe,
	CapabilityDeploymentPrepare,
	CapabilityDeploymentStage,
	CapabilityDeploymentActivate,
	CapabilityDeploymentCancel,
	CapabilityInventoryPrepare,
	CapabilityInventoryChunk,
	CapabilityInventoryRelease,
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
	case AgentCommandDeploymentCancel:
		return CapabilityDeploymentCancel, true
	case AgentCommandInventoryPrepare:
		return CapabilityInventoryPrepare, true
	case AgentCommandInventoryChunk:
		return CapabilityInventoryChunk, true
	case AgentCommandInventoryRelease:
		return CapabilityInventoryRelease, true
	default:
		return "", false
	}
}
