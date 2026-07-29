package runtimeaccess

import (
	"errors"
	"strings"
)

var (
	ErrInvalidConnection = errors.New("runtime connection is invalid")
	ErrUnsupportedMode   = errors.New("runtime connection mode is unsupported")
)

type Mode string

const (
	ModeDirectDocker Mode = "direct"
	ModeAgent        Mode = "agent"
)

func (m Mode) Valid() bool {
	return m == ModeDirectDocker || m == ModeAgent
}

// Connection is the transport-neutral description of how a runtime operation
// reaches its target. It contains references and routing metadata only; secret
// material is resolved immediately before a gateway call.
type Connection struct {
	Mode          Mode
	ManagedHostID string
	DirectDocker  *DirectDocker
}

type DirectDocker struct {
	Endpoint      string
	TLSServerName string
	CredentialRef string
}

func NewDirectDocker(
	managedHostID, endpoint, tlsServerName, credentialRef string,
) (Connection, error) {
	connection := Connection{
		Mode:          ModeDirectDocker,
		ManagedHostID: strings.TrimSpace(managedHostID),
		DirectDocker: &DirectDocker{
			Endpoint:      strings.TrimSpace(endpoint),
			TLSServerName: strings.TrimSpace(tlsServerName),
			CredentialRef: strings.TrimSpace(credentialRef),
		},
	}
	if err := connection.Validate(); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func NewAgent(managedHostID string) (Connection, error) {
	connection := Connection{
		Mode:          ModeAgent,
		ManagedHostID: strings.TrimSpace(managedHostID),
	}
	if err := connection.Validate(); err != nil {
		return Connection{}, err
	}
	return connection, nil
}

func (c Connection) Validate() error {
	if !c.Mode.Valid() {
		return ErrUnsupportedMode
	}
	switch c.Mode {
	case ModeDirectDocker:
		if c.DirectDocker == nil ||
			strings.TrimSpace(c.DirectDocker.Endpoint) == "" ||
			strings.TrimSpace(c.DirectDocker.TLSServerName) == "" ||
			strings.TrimSpace(c.DirectDocker.CredentialRef) == "" {
			return ErrInvalidConnection
		}
	case ModeAgent:
		if strings.TrimSpace(c.ManagedHostID) == "" || c.DirectDocker != nil {
			return ErrInvalidConnection
		}
	}
	return nil
}
