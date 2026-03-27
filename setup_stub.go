//go:build !linux

package ktls

import (
	"errors"
	"net"
)

var ErrNotSupported = errors.New("ktls: not supported on this platform")

func enableKTLS(_ net.Conn, _, _ []byte, _ uint16, _ uint64) (bool, error) {
	return false, ErrNotSupported
}

func deriveNextSecret(_ []byte, _ uint16) ([]byte, error) {
	return nil, ErrNotSupported
}

func updateRX(_ int, _ []byte, _ uint16) error {
	return ErrNotSupported
}

func isEKEYEXPIRED(_ error) bool {
	return false
}

func Available() bool {
	return false
}
