package ktls

import (
	"crypto/tls"
	"net"
	"syscall"
)

// Post handshake connection, reads and writes hit kTLS
type conn struct {
	net.Conn
	state        tls.ConnectionState
	drainedOnce  bool
	drainedBytes []byte

	// for RX key updates
	fd            int
	cipherSuiteID uint16
	rxSecret      []byte
}

// drains any bytes that were decrypted by tls.Conn during the handshake but not yet read by the user
func (c *conn) Read(b []byte) (int, error) {
	if c.drainedOnce { // first drain the handshake leftovers before reading from the kernel
		n := copy(b, c.drainedBytes)
		c.drainedBytes = c.drainedBytes[n:]
		if len(c.drainedBytes) == 0 {
			c.drainedOnce = false
			c.drainedBytes = nil
		}

		return n, nil
	}

	n, err := c.Conn.Read(b) // we need to update it with the next secret
	if err != nil && c.rxSecret != nil && isEKEYEXPIRED(err) {
		if rerr := c.handleKeyUpdate(); rerr != nil {
			return n, rerr
		}

		return c.Conn.Read(b)
	}

	return n, err
}

func (c *conn) handleKeyUpdate() error {
	next, err := deriveNextSecret(c.rxSecret, c.cipherSuiteID)
	if err != nil {
		return err
	}

	if err := updateRX(c.fd, next, c.cipherSuiteID); err != nil {
		return err
	}

	c.rxSecret = next
	return nil
}

// Implements syscall.Conn so that callers (e.g. zerocopy splice) can extract the raw file descriptor from the underlying TCP connection
func (c *conn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, net.ErrClosed
	}

	return sc.SyscallConn()
}

// ConnectionState allows net/http to populate Request.TLS, else it would think we're using plaintext
func (c *conn) ConnectionState() tls.ConnectionState {
	return c.state
}
