package data

import (
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
)

func TestViewCursorRoundTrip(t *testing.T) {
	want := viewCursor{
		Version: 1, RuntimeTargetID: "target-1", Kind: biz.KindContainer,
		Name: "api", RuntimeID: "container-1",
	}
	encoded, err := encodeViewCursor(want)
	if err != nil {
		t.Fatalf("encodeViewCursor() error = %v", err)
	}
	got, err := decodeViewCursor(encoded)
	if err != nil {
		t.Fatalf("decodeViewCursor() error = %v", err)
	}
	if got != want {
		t.Fatalf("decoded cursor = %+v, want %+v", got, want)
	}
	for _, invalid := range []string{"not-base64!", "e30", "bnVsbA"} {
		if _, err := decodeViewCursor(invalid); !errors.Is(err, biz.ErrInvalidViewQuery) {
			t.Errorf("decodeViewCursor(%q) error = %v", invalid, err)
		}
	}
}
