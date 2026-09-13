package data

import (
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
)

func TestRuntimeTargetConvergenceRejectsMissingStoreAndScope(t *testing.T) {
	convergence := NewRuntimeTargetConvergence(nil)
	if _, err := convergence.ConvergeRuntimeTarget(
		t.Context(), "", "", "", "", "",
	); !errors.Is(err, biz.ErrInvalidTarget) {
		t.Fatalf("ConvergeRuntimeTarget() error = %v", err)
	}
}
