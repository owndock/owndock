package main

import (
	"bytes"
	"testing"
)

func TestHostPreflightRejectsArgumentsWithoutOutput(t *testing.T) {
	var output bytes.Buffer
	if err := runHostPreflight(t.Context(), []string{"extra"}, &output, &bytes.Buffer{}); err == nil {
		t.Fatal("preflight accepted an argument")
	}
	if output.Len() != 0 {
		t.Fatalf("preflight emitted output on failure: %q", output.String())
	}
}
