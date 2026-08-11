package terminalprotocol

import (
	"errors"
	"strings"
	"testing"
)

func TestControlRoundTrip(t *testing.T) {
	want := Control{
		Version: Version, Type: TypeOpen, Sequence: 1, Columns: 120, Rows: 30,
	}
	payload, err := EncodeControl(want, DirectionClientToServer)
	if err != nil {
		t.Fatalf("EncodeControl() error = %v", err)
	}
	got, err := DecodeControl(payload, DirectionClientToServer)
	if err != nil {
		t.Fatalf("DecodeControl() error = %v", err)
	}
	if got != want {
		t.Fatalf("DecodeControl() = %+v, want %+v", got, want)
	}
}

func TestControlRejectsWrongDirectionUnknownFieldsAndTrailingJSON(t *testing.T) {
	tests := [][]byte{
		[]byte(`{"version":"v1","type":"ready","sequence":1}`),
		[]byte(`{"version":"v1","type":"open","sequence":1,"columns":120,"rows":30,"ticket":"secret"}`),
		[]byte(`{"version":"v1","type":"open","sequence":1,"columns":120,"rows":30}{}`),
	}
	for _, payload := range tests {
		if _, err := DecodeControl(payload, DirectionClientToServer); !errors.Is(err, ErrInvalidControlMessage) {
			t.Fatalf("DecodeControl(%s) error = %v", payload, err)
		}
	}
}

func TestControlRejectsInvalidSizeAndUnsafeCode(t *testing.T) {
	invalid := []Control{
		{Version: Version, Type: TypeOpen, Sequence: 1, Columns: 0, Rows: 30},
		{Version: Version, Type: TypeResize, Sequence: 1, Columns: MaximumColumns + 1, Rows: 30},
		{Version: Version, Type: TypeError, Sequence: 1, Code: "raw error: connection refused"},
		{Version: Version, Type: TypePing, Sequence: 0},
	}
	for _, message := range invalid {
		direction := DirectionClientToServer
		if message.Type == TypeError {
			direction = DirectionServerToClient
		}
		if _, err := EncodeControl(message, direction); !errors.Is(err, ErrInvalidControlMessage) {
			t.Fatalf("EncodeControl(%+v) error = %v", message, err)
		}
	}
}

func TestMessageLimits(t *testing.T) {
	oversizedControl := []byte(strings.Repeat("x", MaximumControlMessageBytes+1))
	if _, err := DecodeControl(oversizedControl, DirectionClientToServer); !errors.Is(err, ErrControlMessageTooLarge) {
		t.Fatalf("oversized control error = %v", err)
	}
	if err := ValidateData(make([]byte, MaximumDataMessageBytes)); err != nil {
		t.Fatalf("maximum data message error = %v", err)
	}
	if err := ValidateData(make([]byte, MaximumDataMessageBytes+1)); !errors.Is(err, ErrDataMessageTooLarge) {
		t.Fatalf("oversized data error = %v", err)
	}
}
