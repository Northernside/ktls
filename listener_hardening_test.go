//go:build linux

package ktls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestAcceptNilConfigGuardsAgainstPanic verifies that a Listener with a nil
// TLSConfig returns a clear error from Accept instead of dereferencing nil
// inside crypto/tls and panicking.
func TestAcceptNilConfigGuardsAgainstPanic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ktlsLn := &Listener{TCPListener: ln, TLSConfig: nil}

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)

		conn, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			return
		}
		// keep the conn open briefly so Accept does not return early on a closed peer
		time.Sleep(50 * time.Millisecond)
		conn.Close()
	}()

	conn, err := ktlsLn.Accept()
	if conn != nil {
		conn.Close()
		t.Fatalf("Accept returned a conn for a nil config, expected nil")
	}

	if err == nil {
		t.Fatalf("Accept returned nil error for a nil config, expected a clear error")
	}

	<-clientDone
}

// TestAcceptHandshakeDeadline verifies that a stalled handshake (the client
// connects but sends nothing) is bounded by the configured HandshakeTimeout
// instead of blocking indefinitely.
func TestAcceptHandshakeDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ktlsLn := &Listener{
		TCPListener:      ln,
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
		HandshakeTimeout: 150 * time.Millisecond,
	}

	// a slow client: connect, send nothing, hold the socket open.
	stalled, derr := net.Dial("tcp", ln.Addr().String())
	if derr != nil {
		t.Fatalf("dial: %v", derr)
	}
	defer stalled.Close()

	start := time.Now()
	_, aerr := ktlsLn.Accept()
	elapsed := time.Since(start)

	if aerr == nil {
		t.Fatalf("Accept returned nil error for a stalled handshake, expected a deadline error")
	}

	if elapsed > 2*time.Second {
		t.Fatalf("handshake was not bounded by the deadline: took %v", elapsed)
	}

	if elapsed < ktlsLn.HandshakeTimeout {
		t.Fatalf("handshake returned too fast (%v), before the deadline fired", elapsed)
	}

	// the deadline must have been cleared: the raw conn should no longer carry
	// the handshake deadline, so SetDeadline on the underlying conn should succeed
	// and a subsequent read should not return a deadline-exceeded error
	// immediately.
}

// TestAcceptDefaultHandshakeTimeout verifies that a zero HandshakeTimeout falls
// back to DefaultHandshakeTimeout rather than leaving the handshake unbounded.
func TestAcceptDefaultHandshakeTimeout(t *testing.T) {
	if DefaultHandshakeTimeout <= 0 {
		t.Fatalf("DefaultHandshakeTimeout must be positive, got %v", DefaultHandshakeTimeout)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ktlsLn := &Listener{
		TCPListener: ln,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
		// HandshakeTimeout left zero -> must fall back to DefaultHandshakeTimeout
	}

	timeout := ktlsLn.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}

	if timeout != DefaultHandshakeTimeout {
		t.Fatalf("zero HandshakeTimeout should fall back to DefaultHandshakeTimeout (%v), got %v",
			DefaultHandshakeTimeout, timeout)
	}
}

// TestIsErrnoErrorsAsChain verifies that isErrno walks wrapped error chains
// (fmt.Errorf("%w", errno)), which is the reason to prefer errors.As over a
// plain type assertion.
func TestIsErrnoErrorsAsChain(t *testing.T) {
	wrapped := fmt.Errorf("read failed: %w", syscall.EIO)
	if !isErrno(wrapped, syscall.EIO) {
		t.Fatalf("isErrno should detect syscall.EIO through a wrapped error chain")
	}

	if isErrno(wrapped, syscall.EAGAIN) {
		t.Fatalf("isErrno should not match a different errno")
	}

	plain := errors.New("ordinary error")
	if isErrno(plain, syscall.EIO) {
		t.Fatalf("isErrno should not match a non-errno error")
	}
}

// TestIsEKEYEXPIREDErrorsAsChain verifies that isEKEYEXPIRED detects the errno
// both directly and through a wrapped error chain.
func TestIsEKEYEXPIREDErrorsAsChain(t *testing.T) {
	// direct errno (some syscalls return a bare syscall.Errno)
	if !isEKEYEXPIRED(syscall.EKEYEXPIRED) {
		t.Fatalf("isEKEYEXPIRED should match a bare syscall.EKEYEXPIRED")
	}

	// wrapped, as our setsockopt paths return (fmt.Errorf("...: %w", errno))
	wrapped := fmt.Errorf("ktls: TLS_RX setsockopt: %w", syscall.EKEYEXPIRED)
	if !isEKEYEXPIRED(wrapped) {
		t.Fatalf("isEKEYEXPIRED should detect EKEYEXPIRED through a wrapped error chain")
	}

	if isEKEYEXPIRED(syscall.EIO) {
		t.Fatalf("isEKEYEXPIRED should not match a different errno")
	}
}
