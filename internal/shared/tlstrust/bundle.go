// Package tlstrust validates explicit installation-scoped TLS trust bundles.
package tlstrust

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

var ErrInvalidBundle = errors.New("TLS certificate bundle is invalid")

// ReadBundle reads a bounded regular file without following symbolic links and
// accepts only one or more header-free X.509 CERTIFICATE PEM blocks. The
// returned bytes are an owned immutable snapshot from the caller's point of
// view; later changes to the source file do not affect it.
func ReadBundle(path string, maximumBytes int64) ([]byte, error) {
	if path == "" || maximumBytes < 1 {
		return nil, ErrInvalidBundle
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumBytes {
		return nil, ErrInvalidBundle
	}
	bundle, err := os.ReadFile(path)
	if err != nil || int64(len(bundle)) > maximumBytes || !ValidBundle(bundle) {
		return nil, ErrInvalidBundle
	}
	return append([]byte(nil), bundle...), nil
}

// ValidBundle reports whether all input is consumed by valid certificate PEM
// blocks. Private keys, PEM headers, trailing text and empty input are rejected.
func ValidBundle(bundle []byte) bool {
	remaining, certificates := bundle, 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		certificates++
		remaining = rest
	}
	return certificates > 0
}
