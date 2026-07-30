package agentprotocol

import "testing"

func TestEveryCommandKindHasAnAdvertisedCapability(t *testing.T) {
	kinds := []AgentCommandKind{
		AgentCommandRuntimeProbe,
		AgentCommandDeploymentPrepare,
		AgentCommandDeploymentStage,
		AgentCommandDeploymentActivate,
		AgentCommandDeploymentCancel,
		AgentCommandInventoryPrepare,
		AgentCommandInventoryChunk,
		AgentCommandInventoryRelease,
	}
	advertised := make(map[string]struct{})
	for _, capability := range SupportedCapabilities() {
		if _, exists := advertised[capability]; exists {
			t.Fatalf("duplicate capability %q", capability)
		}
		advertised[capability] = struct{}{}
	}
	for _, kind := range kinds {
		capability, exists := RequiredCapability(kind)
		if !exists || capability != string(kind) {
			t.Fatalf(
				"kind %q capability = %q, exists = %v",
				kind,
				capability,
				exists,
			)
		}
		if _, exists := advertised[capability]; !exists {
			t.Fatalf("capability %q is not advertised", capability)
		}
	}

	first := SupportedCapabilities()
	first[0] = "mutated"
	if SupportedCapabilities()[0] == "mutated" {
		t.Fatal("supported capabilities returned shared state")
	}
}
