package main

import (
	"testing"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
)

func TestSelectGatewayConfigKeepsScopesIndependent(t *testing.T) {
	config := platformconfig.Config{Runtime: platformconfig.Runtime{
		BuildEgress: platformconfig.EgressGateway{
			Enabled: true, AllowedDestinations: []platformconfig.EgressDestination{{Authority: "build.example:443"}},
		},
		EvidenceEgress: platformconfig.EgressGateway{
			Enabled: true, AllowedDestinations: []platformconfig.EgressDestination{{Authority: "registry.example:443"}},
		},
	}}
	for scope, authority := range map[string]string{
		"build": "build.example:443", "evidence": "registry.example:443",
	} {
		selected, err := selectGatewayConfig(config, scope)
		if err != nil || len(selected.AllowedDestinations) != 1 ||
			selected.AllowedDestinations[0].Authority != authority {
			t.Fatalf("scope %q selected %+v, %v", scope, selected, err)
		}
	}
	if _, err := selectGatewayConfig(config, ""); err == nil {
		t.Fatal("empty scope was accepted")
	}
	if _, err := selectGatewayConfig(config, "other"); err == nil {
		t.Fatal("unknown scope was accepted")
	}
}
