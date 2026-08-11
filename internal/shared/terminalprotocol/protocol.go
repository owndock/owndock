// Package terminalprotocol defines the payload-free control messages and
// bounded binary data messages used by the browser terminal transport.
package terminalprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	Version = "v1"

	MaximumControlMessageBytes    = 4 * 1024
	MaximumDataMessageBytes       = 32 * 1024
	MaximumPendingOutputBytes     = 256 * 1024
	MaximumInputMessagesPerSecond = 200

	DefaultColumns = 120
	DefaultRows    = 30
	MaximumColumns = 1000
	MaximumRows    = 500
)

var (
	ErrInvalidControlMessage  = errors.New("terminal control message is invalid")
	ErrControlMessageTooLarge = errors.New("terminal control message is too large")
	ErrDataMessageTooLarge    = errors.New("terminal data message is too large")
)

type Direction uint8

const (
	DirectionClientToServer Direction = iota + 1
	DirectionServerToClient
)

type ControlType string

const (
	TypeOpen   ControlType = "open"
	TypeReady  ControlType = "ready"
	TypeResize ControlType = "resize"
	TypePing   ControlType = "ping"
	TypePong   ControlType = "pong"
	TypeClose  ControlType = "close"
	TypeError  ControlType = "error"
)

// Control contains transport metadata only. Terminal stdin/stdout is carried
// in bounded WebSocket binary messages and must never be copied into this
// structure, logs, traces, metrics labels, or persisted state.
type Control struct {
	Version  string      `json:"version"`
	Type     ControlType `json:"type"`
	Sequence uint64      `json:"sequence"`
	Columns  uint16      `json:"columns,omitempty"`
	Rows     uint16      `json:"rows,omitempty"`
	Code     string      `json:"code,omitempty"`
}

func (message Control) Validate(direction Direction) error {
	if message.Version != Version || message.Sequence == 0 ||
		!directionAllows(direction, message.Type) {
		return ErrInvalidControlMessage
	}
	switch message.Type {
	case TypeOpen, TypeResize:
		if message.Columns < 1 || message.Rows < 1 ||
			message.Columns > MaximumColumns || message.Rows > MaximumRows ||
			message.Code != "" {
			return ErrInvalidControlMessage
		}
	case TypeError:
		if !validCode(message.Code) || message.Columns != 0 || message.Rows != 0 {
			return ErrInvalidControlMessage
		}
	case TypeClose:
		if message.Code != "" && !validCode(message.Code) {
			return ErrInvalidControlMessage
		}
		if message.Columns != 0 || message.Rows != 0 {
			return ErrInvalidControlMessage
		}
	default:
		if message.Columns != 0 || message.Rows != 0 || message.Code != "" {
			return ErrInvalidControlMessage
		}
	}
	return nil
}

func EncodeControl(message Control, direction Direction) ([]byte, error) {
	if err := message.Validate(direction); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, ErrInvalidControlMessage
	}
	if len(payload) > MaximumControlMessageBytes {
		return nil, ErrControlMessageTooLarge
	}
	return payload, nil
}

func DecodeControl(payload []byte, direction Direction) (Control, error) {
	if len(payload) == 0 {
		return Control{}, ErrInvalidControlMessage
	}
	if len(payload) > MaximumControlMessageBytes {
		return Control{}, ErrControlMessageTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var message Control
	if err := decoder.Decode(&message); err != nil {
		return Control{}, ErrInvalidControlMessage
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Control{}, ErrInvalidControlMessage
	}
	if err := message.Validate(direction); err != nil {
		return Control{}, err
	}
	return message, nil
}

func ValidateData(payload []byte) error {
	if len(payload) == 0 {
		return ErrInvalidControlMessage
	}
	if len(payload) > MaximumDataMessageBytes {
		return ErrDataMessageTooLarge
	}
	return nil
}

func directionAllows(direction Direction, messageType ControlType) bool {
	switch direction {
	case DirectionClientToServer:
		return messageType == TypeOpen || messageType == TypeResize ||
			messageType == TypePing || messageType == TypeClose
	case DirectionServerToClient:
		return messageType == TypeReady || messageType == TypePong ||
			messageType == TypeClose || messageType == TypeError
	default:
		return false
	}
}

func validCode(value string) bool {
	if value == "" || len(value) > 64 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
