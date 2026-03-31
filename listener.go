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

	// todo: might be unstable, opt in for now
	RX bool

	// connection still works fine through userspace TLS
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
	if state.Version != tls.VersionTLS13 {
		return tlsConn, nil
	}

	// extract server and client traffic secrets

	var serverSecretBuf, clientSecretBuf [48]byte
	serverSecret, err := parseTrafficSecret(keyBuf.String(), "SERVER_TRAFFIC_SECRET_0 ", serverSecretBuf[:])
	if err != nil {
		l.onError(fmt.Errorf("ktls: parse server secret: %w", err))
		return tlsConn, nil
	}

	var clientSecret []byte
	var rxRecSeq uint64
	if l.RX {
		clientSecret, err = parseTrafficSecret(keyBuf.String(), "CLIENT_TRAFFIC_SECRET_0 ", clientSecretBuf[:])
		if err != nil {
			l.onError(fmt.Errorf("ktls: parse client secret: %w", err))
			return tlsConn, nil
		}

		rxRecSeq = uint64(counter.clientAppRecords()) // apprecs - 1, because the first record is just Finished
	}

	// drain any bytes that tls.Conn has already decrypted during the handshake
	drained := drainTLSBuffer(tlsConn)

	_, err = enableKTLS(rawConn, serverSecret, clientSecret, state.CipherSuite, rxRecSeq)
	if err != nil {
		l.onError(err)
		return tlsConn, nil
	}

	fd, _ := getRawFd(rawConn)

	var ownedRxSecret []byte
	if clientSecret != nil {
		ownedRxSecret = make([]byte, len(clientSecret))
		copy(ownedRxSecret, clientSecret) // copy to owned buffer because conn outlives Accept() (clientSecret is on stack)
	}

	kc := &conn{
		Conn:          rawConn,
		state:         state,
		drainedOnce:   len(drained) > 0,
		drainedBytes:  drained,
		fd:            fd,
		cipherSuiteID: state.CipherSuite,
		rxSecret:      ownedRxSecret,
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
