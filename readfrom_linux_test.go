//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func rawSource(t *testing.T, payload []byte) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write(payload)
		c.Close()
		ln.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn)
}

func ktlsServer(t *testing.T) (*Listener, string) {
	t.Helper()
	cert := selfSigned(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &Listener{TCPListener: raw, TLSConfig: cfg, OnError: func(e error) { t.Logf("onError: %v", e) }}
	t.Cleanup(func() { raw.Close() })
	return ln, raw.Addr().String()
}

// io.Copy(ktlsConn, rawTCPConn) must go through the splice ReadFrom and deliver
// every byte intact through kTLS TX
func TestReadFromSpliceRoundTrip(t *testing.T) {
	ln, addr := ktlsServer(t)

	payload := make([]byte, 700*1024) // multirecord, multi-pipe-chunk
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	cerr := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			cerr <- err
			return
		}
		defer c.Close()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil {
			cerr <- err
			return
		}
		if !bytes.Equal(got, payload) {
			cerr <- io.ErrUnexpectedEOF
			return
		}
		cerr <- nil
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kc, ok := conn.(Conn)
	if !ok {
		t.Fatal("kTLS not enabled (userspace fallback) - splice path not exercised")
	}

	src := rawSource(t, payload)
	defer src.Close()
	n, err := io.Copy(kc, src) // must dispatch to conn.ReadFrom -> splice
	if err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
	if err := <-cerr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestReadFromPeek(t *testing.T) {
	ln, addr := ktlsServer(t)

	payload := make([]byte, 400*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	const peekN = 512

	cerr := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			cerr <- err
			return
		}
		defer c.Close()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil {
			cerr <- err
			return
		}
		if !bytes.Equal(got, payload) {
			cerr <- io.ErrUnexpectedEOF
			return
		}
		cerr <- nil
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kc := conn.(Conn)

	src := rawSource(t, payload)
	defer src.Close()

	var peeked []byte
	n, err := kc.ReadFromConfig(src, SpliceConfig{
		PeekN: peekN,
		Peek:  func(b []byte) { peeked = append(peeked, b...) },
	})
	if err != nil {
		t.Fatalf("ReadFromConfig: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d, want %d", n, len(payload))
	}
	if len(peeked) != peekN || !bytes.Equal(peeked, payload[:peekN]) {
		t.Fatalf("peek got %d bytes, want first %d of payload", len(peeked), peekN)
	}
	if err := <-cerr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestWriteThenSpliceMix(t *testing.T) {
	ln, addr := ktlsServer(t)

	header := []byte("HTTP/1.1 200 OK\r\nContent-Length: 409600\r\n\r\n")
	body := make([]byte, 400*1024)
	for i := range body {
		body[i] = byte(i * 3)
	}
	want := append(append([]byte{}, header...), body...)

	cerr := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			cerr <- err
			return
		}
		defer c.Close()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil {
			cerr <- err
			return
		}
		if !bytes.Equal(got, want) {
			cerr <- io.ErrUnexpectedEOF
			return
		}
		cerr <- nil
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kc := conn.(Conn)
	kc.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if _, err := kc.Write(header); err != nil { // userspace Write (sendmsg)
		t.Fatalf("write header: %v", err)
	}
	src := rawSource(t, body)
	defer src.Close()
	if _, err := io.Copy(kc, src); err != nil { // splice
		t.Fatalf("splice body: %v", err)
	}

	if err := <-cerr; err != nil {
		t.Fatalf("client (corruption if this fails): %v", err)
	}
}
