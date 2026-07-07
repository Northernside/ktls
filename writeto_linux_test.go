//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func rawSink(t *testing.T) (*net.TCPConn, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		data, _ := io.ReadAll(c)
		out <- data
		ln.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn), out
}

func TestWriteToSpliceRoundTrip(t *testing.T) {
	ln, addr := ktlsServer(t)

	payload := make([]byte, 500*1024) // multirecord, multi-pipe-chunk
	for i := range payload {
		payload[i] = byte(i * 11)
	}

	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			return
		}
		c.Write(payload)
		c.Close() // close_notify -> clean EOF on the server splice
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kc, ok := conn.(Conn)
	if !ok {
		t.Fatal("kTLS not enabled (userspace fallback) - RX splice path not exercised")
	}

	sink, out := rawSink(t)
	n, err := io.Copy(sink, kc) // WriteTo -> splice kTLS RX -> sink fd
	sink.Close()
	if err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	got := <-out
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("sink got %d bytes, not matching the decrypted upload", len(got))
	}
}

func TestWriteToPeek(t *testing.T) {
	ln, addr := ktlsServer(t)

	payload := make([]byte, 300*1024)
	for i := range payload {
		payload[i] = byte(i * 5)
	}
	const peekN = 512

	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			return
		}
		c.Write(payload)
		c.Close()
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	kc := conn.(Conn)

	sink, out := rawSink(t)
	var peeked []byte
	n, err := kc.WriteToConfig(sink, SpliceConfig{
		PeekN: peekN,
		Peek:  func(b []byte) { peeked = append(peeked, b...) },
	})
	sink.Close()
	if err != nil {
		t.Fatalf("WriteToConfig: %v", err)
	}
	got := <-out
	if n != int64(len(payload)) {
		t.Fatalf("copied %d, want %d", n, len(payload))
	}
	if len(peeked) != peekN || !bytes.Equal(peeked, payload[:peekN]) {
		t.Fatalf("peek got %d bytes, want first %d of upload", len(peeked), peekN)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("sink got %d bytes, not matching upload", len(got))
	}
}
