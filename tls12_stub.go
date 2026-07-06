//go:build !linux

package ktls

import (
	"crypto/tls"
	"net"
)

func (l *Listener) setupKTLS12(net.Conn, *recordCounter, tls.ConnectionState, *keyLogBuffer) *conn {
	return nil
}
