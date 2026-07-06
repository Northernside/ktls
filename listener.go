package ktls

import (
	"crypto/tls"
	"fmt"
	"net"
)

// Listener wraps a TCP listener, does the TLS handshake in userspace,
// then hands the socket off to the kernel for TLS record encryption and decryption
type Listener struct {
	TCPListener net.Listener
	TLSConfig   *tls.Config

	// OnError is called when kTLS setup fails on a connection
	// it still works hrough userspace TLS, nil ignores the error
	OnError func(error)
}

func (l *Listener) Accept() (net.Conn, error) {
	rawConn, err := l.TCPListener.Accept()
	if err != nil {
		return nil, err
	}

	counter := &recordCounter{Conn: rawConn}
	keyBuf := &keyLogBuffer{}

	// clone per-connection so we can set a per-connection KeyLogWriter
	// without racing against other concurrent Accept() calls
	cfg := l.TLSConfig.Clone()
	cfg.KeyLogWriter = keyBuf

	tlsConn := tls.Server(counter, cfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
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

	fd, _ := getRawFd(rawConn)

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
