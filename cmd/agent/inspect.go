package main

import (
	"encoding/json"
	"flag"
	"io"

	agentconfig "github.com/owndock/owndock/internal/agent/config"
)

type configInspection struct {
	ManagedIngress bool `json:"managed_ingress"`
}

// runConfigInspection exposes only the feature bit needed by the privileged
// installer after enrollment recovery. It deliberately does not serialize the
// Agent configuration, identities, endpoints, or credential paths.
func runConfigInspection(arguments []string, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet(serviceName+" inspect-config", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	var configPath string
	flags.StringVar(&configPath, "conf", "/etc/owndock/agent.yaml", "Agent configuration file or directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return agentconfig.ErrInvalidConfig
	}
	config, err := agentconfig.Load(configPath)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(configInspection{ManagedIngress: config.Ingress.Enabled})
}
