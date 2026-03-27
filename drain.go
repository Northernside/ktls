package ktls

import (
	"bytes"
	"crypto/tls"
	"time"
)

var (
	immediateDeadline = time.Unix(1, 0)
	noDeadline        time.Time
)

// drainTLSBuffer pulls out any data that tls.Conn already decrypted during the handshake
// Call this before enabling kTLS RX, otherwise the kernel will try to decrypt data that's already plaintext
func drainTLSBuffer(tlsConn *tls.Conn) []byte {
	buf := make([]byte, 16384)
	tlsConn.SetReadDeadline(immediateDeadline) // past deadline makes Read return immediately with any data thats already available
	n, _ := tlsConn.Read(buf)
	tlsConn.SetReadDeadline(noDeadline) // reset for future reads

	if n == 0 {
		return nil
	}

	var drained bytes.Buffer
	drained.Write(buf[:n])

	for {
		tlsConn.SetReadDeadline(immediateDeadline)
		n, _ = tlsConn.Read(buf)
		tlsConn.SetReadDeadline(noDeadline)
		if n == 0 {
			break
		}

		drained.Write(buf[:n])
	}

	return drained.Bytes()
}
