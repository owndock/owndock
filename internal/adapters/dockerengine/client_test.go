package dockerengine

import (
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func TestNewTLSRejectsNonDirectConnection(t *testing.T) {
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTLS(connection, TLSCredential{}); !errors.Is(
		err,
		runtimeaccess.ErrInvalidConnection,
	) {
		t.Fatalf("NewTLS() error = %v", err)
	}
}

func TestNewTLSRejectsInvalidCAWithoutOpeningConnection(t *testing.T) {
	connection, err := runtimeaccess.NewDirectDocker(
		"host-1",
		"tcp://runtime.example:2376",
		"runtime.example",
		"secret://runtime-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTLS(connection, TLSCredential{
		CACertificate: []byte("not-a-certificate"),
	}); err == nil {
		t.Fatal("NewTLS() accepted an invalid CA certificate")
	}
}
