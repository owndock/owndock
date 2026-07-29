package biz

import (
	"errors"
	"testing"
)

func TestExecutionErrorExposesOnlySafeCategory(t *testing.T) {
	cause := errors.New("tcp://user:password@private.example.com")
	err := &ExecutionError{Category: FailureTargetUnreachable, Cause: cause}
	if err.Error() != string(FailureTargetUnreachable) {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("execution error did not retain its internal cause")
	}
	if got := CategorizeExecutionError(err, FailureUnknown); got != FailureTargetUnreachable {
		t.Fatalf("category = %s", got)
	}
}
