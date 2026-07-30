package data

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/client"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
)

type runtimeTargetEngineStub struct {
	err error
}

func (e runtimeTargetEngineStub) Ping(
	context.Context,
	client.PingOptions,
) (client.PingResult, error) {
	return client.PingResult{}, e.err
}

func (runtimeTargetEngineStub) Close() error { return nil }

func TestDockerRuntimeTargetProberClassifiesResults(t *testing.T) {
	for name, test := range map[string]struct {
		configured bool
		engineErr  error
		pingErr    error
		want       biz.RuntimeTargetStatus
	}{
		"ready": {
			configured: true, want: biz.RuntimeTargetStatusReady,
		},
		"credential missing": {
			want: biz.RuntimeTargetStatusCredentialError,
		},
		"credential invalid": {
			configured: true, engineErr: errors.New("certificate"),
			want: biz.RuntimeTargetStatusCredentialError,
		},
		"unreachable": {
			configured: true, pingErr: errors.New("dial"),
			want: biz.RuntimeTargetStatusUnreachable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			prober := &DockerRuntimeTargetProber{
				lookup: func(string) (string, bool) {
					return "pem", test.configured
				},
				newEngine: func(
					biz.RuntimeTarget, []byte, []byte, []byte,
				) (runtimeTargetEngine, error) {
					return runtimeTargetEngineStub{err: test.pingErr}, test.engineErr
				},
			}
			status, err := prober.ProbeRuntimeTarget(t.Context(), biz.RuntimeTarget{
				CredentialRef: "secret://production",
			})
			if err != nil {
				t.Fatal(err)
			}
			if status != test.want {
				t.Fatalf("status = %s, want %s", status, test.want)
			}
		})
	}
}
