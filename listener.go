package ktls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// DefaultHandshakeTimeout is the maximum time a single TLS handshake is allowed
// to take when the caller has not configured HandshakeTimeout explicitly.
// It bounds the server goroutine a slow or malicious client can hold open during
// the handshake (the TCP listener deadline only bounds Accept, not Handshake).
const DefaultHandshakeTimeout = 10 * time.Second

// Listener wraps a TCP listener, does the TLS handshake in userspace,
// then hands the socket off to the kernel for TLS record encryption and decryption
type Listener struct {
	TCPListener net.Listener
	TLSConfig   *tls.Config

	// HandshakeTimeout bounds the TLS handshake performed during Accept. A zero or
	// negative value falls back to DefaultHandshakeTimeout. Without a deadline a
	// malicious or slow client can open a TCP connection, complete nothing, and
	// hold a server goroutine indefinitely (slowloris). The deadline is applied to
	// the raw conn only for the duration of Handshake and cleared afterwards.
	HandshakeTimeout time.Duration

	// OnError is called when kTLS setup fails on a connection
	// it still works through userspace TLS, nil ignores the error
	OnError func(error)
}

func (l *Listener) Accept() (net.Conn, error) {
	rawConn, err := l.TCPListener.Accept()
	if err != nil {
		return nil, err
	}

	// a nil config would dereference nil on Clone and panic deep inside
	// crypto/tls; surface it as a clear, actionable error instead.
	if l.TLSConfig == nil {
		rawConn.Close()

		return nil, errors.New("ktls: Listener.TLSConfig must not be nil")
	}

	counter := &recordCounter{Conn: rawConn}
	keyBuf := &keyLogBuffer{}

	// clone per-connection so we can set a per-connection KeyLogWriter
	// without racing against other concurrent Accept() calls
	cfg := l.TLSConfig.Clone()
	cfg.KeyLogWriter = keyBuf

	tlsConn := tls.Server(counter, cfg)

	// Bound the handshake so a slow/stalled client cannot hold this server
	// goroutine open indefinitely (slowloris). The deadline applies to the raw
	// conn only for the handshake and is cleared immediately after, so the
	// returned connection inherits no inherited deadline. We use SetDeadline
	// (both read+write) because Handshake reads and writes on the same conn.
	timeout := l.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}

	deadline := time.Now().Add(timeout)
	_ = rawConn.SetDeadline(deadline)

	handshakeErr := tlsConn.Handshake()

	// always clear the handshake deadline so it does not leak onto post-handshake I/O
	_ = rawConn.SetDeadline(time.Time{})

	if handshakeErr != nil {
		rawConn.Close()

		return nil, handshakeErr
	}

	state := tlsConn.ConnectionState()
	switch state.Version {
	case tls.VersionTLS13:
		// handled below
	case tls.VersionTLS12:
		if kc := l.setupKTLS12(rawConn, counter, state, keyBuf); kc != nil {
			return kc, nil
		}

		return tlsConn, nil // unsupported 1.2 cipher or setup failed -> userspace
	default:
		return tlsConn, nil
	}

	// TLS 1.3: extract the server and client application traffic secrets
	var serverSecretBuf, clientSecretBuf [48]byte

	serverSecret, err := parseTrafficSecret(keyBuf.String(), "SERVER_TRAFFIC_SECRET_0 ", serverSecretBuf[:])
	if err != nil {
		l.onError(fmt.Errorf("ktls: parse server secret: %w", err))

		return tlsConn, nil
	}

	clientSecret, err := parseTrafficSecret(keyBuf.String(), "CLIENT_TRAFFIC_SECRET_0 ", clientSecretBuf[:])
	if err != nil {
		l.onError(fmt.Errorf("ktls: parse client secret: %w", err))

		return tlsConn, nil
	}

	rxRecSeq := uint64(counter.clientAppRecords()) // apprecs - 1, the first record is the Finished

	if _, err = enableKTLS(rawConn, serverSecret, clientSecret, state.CipherSuite, rxRecSeq); err != nil {
		l.onError(err)

		return tlsConn, nil
	}

	fd, err := getRawFd(rawConn)
	if err != nil {
		return nil, err
	}

	var ownedRxSecret []byte
	if clientSecret != nil {
		ownedRxSecret = make([]byte, len(clientSecret))
		copy(ownedRxSecret, clientSecret)
	}

	// TX secret kept so we can answer a peer's update_requested KeyUpdate by
	// rotating our own send key (RFC 8446 4.6.3)
	ownedTxSecret := make([]byte, len(serverSecret))
	copy(ownedTxSecret, serverSecret)

	kc := &conn{
		Conn:          rawConn,
		state:         state,
		fd:            fd,
		cipherSuiteID: state.CipherSuite,
		rxSecret:      ownedRxSecret,
		txSecret:      ownedTxSecret,
	}

	return kc, nil
}

func (l *Listener) Close() error {
	return l.TCPListener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.TCPListener.Addr()
}

func (l *Listener) onError(err error) {
	if l.OnError != nil {
		l.OnError(err)
	}
}
