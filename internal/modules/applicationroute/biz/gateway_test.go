package biz

import (
	"errors"
	"testing"
)

func TestFailureCodeFromErrorUsesOnlyStableCategories(t *testing.T) {
	tests := []struct {
		err  error
		want FailureCode
	}{
		{err: ErrGatewayCertificateUnavailable, want: FailureCertificateUnavailable},
		{err: errors.Join(errors.New("private detail"), ErrGatewayBackendUnhealthy), want: FailureBackendUnhealthy},
		{err: ErrGatewayPortConflict, want: FailurePortConflict},
		{err: ErrGatewayFenceStale, want: FailureFenceConflict},
		{err: ErrGatewayStateFull, want: FailureStateFull},
		{err: ErrGatewayConfiguration, want: FailureConfiguration},
		{err: errors.New("private raw failure"), want: FailureUnknown},
	}
	for _, test := range tests {
		if got := FailureCodeFromError(test.err); got != test.want {
			t.Fatalf("FailureCodeFromError(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}
