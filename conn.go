package ktls

import (
	"crypto/tls"
	"net"
	"syscall"
)

// implemented by a connection returned from Listener.Accept when kTLS was successfully enabled
// type-assert net.Conn to this interface to distinguish kTLS-active connections from plain *tls.Conn fallbacks
type Conn interface {
	net.Conn
	syscall.Conn

	ConnectionState() tls.ConnectionState
	DidResume() bool
}

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

	onKeyUpdate func() error // kernel issued
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

	// the kernel pauses decryption and returns EKEYEXPIRED when a peer
	// sends a KeyUpdate
	// derive the next RX secret, rearm the socket and resume
	// loop so that multiple KeyUpdates (including back-to-back ones with no application data
	// between them) are all consumed
	//
	// maxConsecutiveKeyUpdates bounds a peer flooding KeyUpdates with no data,
	// which would otherwise spin here
	const maxConsecutiveKeyUpdates = 32
	for updates := 0; ; {
		n, err := c.Conn.Read(b)

		if err == nil || c.rxSecret == nil || !isEKEYEXPIRED(err) {
			return n, err
		}

		// kernel might hand back application data alongside the key update signal
		// discarding it here would drop plaintext and desync the record stream
		// (surfacing later as EINVAL/EMSGSIZE) -> return it first
		// the pending EKEYEXPIRED resurfaces on the next Read (with n == 0) and is
		// handled by then
		if n > 0 {
			return n, nil
		}

		if updates++; updates > maxConsecutiveKeyUpdates {
			return 0, err
		}

		ku := c.onKeyUpdate
		if ku == nil {
			ku = c.handleKeyUpdate
		}
		if rerr := ku(); rerr != nil {
			return 0, rerr
		}
		// retry the read under the freshly installed RX key
	}
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

// equivalent to ConnectionState().DidResume (was established via TLS session resumption (psk / session tickets))
func (c *conn) DidResume() bool {
	return c.state.DidResume
}
