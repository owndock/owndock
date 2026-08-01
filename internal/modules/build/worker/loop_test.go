package worker

import (
	"context"
	"errors"
	"testing"
)

func TestLoopResultUsesBoundedOperationalOutcomes(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{want: "success"},
		{err: errors.New("failed"), want: "error"},
		{err: context.DeadlineExceeded, want: "timeout"},
		{err: context.Canceled, want: "canceled"},
	}
	for _, test := range tests {
		if got := loopResult(test.err); got != test.want {
			t.Errorf("loopResult(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}
