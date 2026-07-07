package ktls

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"syscall"
)

// implemented by a connection returned from Listener.Accept when kTLS was successfully enabled
// type-assert net.Conn to this interface to distinguish kTLS-active connections from plain *tls.Conn fallbacks
type Conn interface {
	net.Conn
	syscall.Conn
	io.ReaderFrom // zerocopy splice on io.Copy(conn, rawFdSource) (TX)
	io.WriterTo   // zerocopy splice on io.Copy(rawFdSink, conn) (RX)

	ConnectionState() tls.ConnectionState
	DidResume() bool

	// ReadFrom / WriteTo with an optional userspace peek (see SpliceConfig)
	ReadFromConfig(r io.Reader, cfg SpliceConfig) (int64, error)
	WriteToConfig(w io.Writer, cfg SpliceConfig) (int64, error)
}

// Post handshake connection, reads and writes hit kTLS
type conn struct {
	net.Conn
	state tls.ConnectionState

	fd            int
	cipherSuiteID uint16

	// RX key updates happen on the read goroutine
	rxSecret []byte

	// TX key updates (our response to a peer's update_requested) race concurrent
	// writers, so txMu guards both Write and the TX rekey
	txMu     sync.Mutex
	txSecret []byte

	onKeyUpdate func() error // test seam for the RX rekey (nil in production)
}

// holds txMu so a concurrent TX rekey (see sendKeyUpdateAndRekeyTX) cannot
// swap the send key mid-write
// uncontended in the common case (no key update)
func (c *conn) Write(b []byte) (int, error) {
	c.txMu.Lock()
	n, err := c.Conn.Write(b)
	c.txMu.Unlock()
	return n, err
}

func (c *conn) Read(b []byte) (int, error) {
	// a TLS 1.3 peer can send post handshake control records (KeyUpdate) at any time
	// the kernel will not hand a non data record to a plain read() and returns EIO
	// (some kernels signal EKEYEXPIRED instead)
	// when that happens we fetch the record via recvmsg, act on it (rekey RX for a KeyUpdate)
	// and resume
	// maxControlRecords bounds a peer flooding control records with no data
	const maxControlRecords = 32
	for handled := 0; ; {
		n, err := c.Conn.Read(b)
		if err == nil {
			return n, nil
		}

		// data handed back alongside the signal must be returned, not dropped
		// -> the signal resurfaces on the next read with n == 0
		if n > 0 {
			return n, nil
		}

		if c.rxSecret == nil || !isPostHandshakeSignal(err) {
			return n, err
		}
		if handled++; handled > maxControlRecords {
			return 0, err
		}

		if rerr := c.handlePostHandshake(err); rerr != nil {
			return 0, rerr
		}
		// control record consumed + RX rekeyed as needed -> retry the read
	}
}

// rekeyRX advances the RX traffic secret one generation and rearms the kernel (RFC 8446 7.2)
// uses the onKeyUpdate seam when set (tests)
func (c *conn) rekeyRX() error {
	if c.onKeyUpdate != nil {
		return c.onKeyUpdate()
	}

	return c.handleKeyUpdate()
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
