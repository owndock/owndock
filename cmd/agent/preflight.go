package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"time"

	agentpreflight "github.com/owndock/owndock/internal/agent/preflight"
)

func runHostPreflight(ctx context.Context, arguments []string, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet(serviceName+" preflight", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return agentpreflight.ErrUnsupportedHost
	}
	checkContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := agentpreflight.Check(checkContext, agentpreflight.DefaultEnvironment())
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
