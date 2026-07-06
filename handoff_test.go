//go:build linux

package ktls

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// reproduces the kTLS handoff framing desync: crypto/tls over-reads the socket
// during the handshake and can buffer the client's early app data ciphertext
// in its internal rawInput
// those bytes are invisible to the kernel once kTLS takes over, so the kernel reads
// records from the wrong offset -> EINVAL/EMSGSIZE (or silent corruption)
// the client sends a large payload immediately  after the handshake to make the overread
// land on app data
func TestKTLSHandoffNoByteLoss(t *testing.T) {
	cert := selfSigned(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := &Listener{TCPListener: raw, TLSConfig: cfg, RX: true, OnError: func(e error) {}}
	addr := raw.Addr().String()

	const payloadLen = 512 * 1024
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i * 2654435761 >> 13) // deterministic pattern
	}

	const iterations = 200
	fails := 0
	var firstErr string
	for it := 0; it < iterations; it++ {
		clientErr := make(chan error, 1)
		go func() {
			c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			if err != nil {
				clientErr <- err
				return
			}
			defer c.Close()

			// no explicit Handshake -> crypto/tls tends to coalesce the client
			// finished with this first app data write into one flush/segment,
			// so the server overreads app-data ciphertext during the handshake
			_, werr := c.Write(payload)
			clientErr <- werr
		}()

		conn, err := ln.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if _, ok := conn.(Conn); !ok {
			conn.Close()
			t.Skip("kTLS not enabled (userspace fallback)")
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, payloadLen)
		_, rerr := io.ReadFull(conn, got)
		mismatch := -1
		if rerr == nil {
			for i := range got {
				if got[i] != payload[i] {
					mismatch = i
					break
				}
			}
		}
		if rerr != nil || mismatch >= 0 {
			fails++
			if firstErr == "" {
				firstErr = fmt.Sprintf("iter %d: readErr=%v mismatchAt=%d", it, rerr, mismatch)
			}
		}

		conn.Close()
		<-clientErr
	}

	t.Logf("handoff failures: %d/%d", fails, iterations)
	if firstErr != "" {
		t.Logf("first failure: %s", firstErr)
	}

	if fails > 0 {
		t.Fatalf("REPRODUCED: %d/%d connections lost bytes at kTLS handoff", fails, iterations)
	}
}
