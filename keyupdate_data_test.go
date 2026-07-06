//go:build linux

package ktls

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestKeyUpdateWithData(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found")
	}
	cert := selfSigned(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
	ln := &Listener{TCPListener: raw, TLSConfig: cfg, RX: true, OnError: func(e error) { t.Logf("onError: %v", e) }}

	const blockLen = 1200
	blocks := []struct{ marker byte }{{'A'}, {'B'}, {'C'}, {'D'}}
	// interleave a key_update before each block after the first
	pr, pw := io.Pipe()
	cmd := exec.Command(ossl, "s_client", "-connect", raw.Addr().String(), "-tls1_3")
	cmd.Stdin = pr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start openssl: %v", err)
	}
	defer func() { pw.Close(); cmd.Process.Kill(); cmd.Wait() }()
	go func() {
		for i, b := range blocks {
			if i > 0 {
				io.WriteString(pw, "k\n") // single key_update between blocks
				time.Sleep(300 * time.Millisecond)
			}

			io.WriteString(pw, strings.Repeat(string(b.marker), blockLen)+"\n")
			time.Sleep(400 * time.Millisecond)
		}
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(Conn); !ok {
		t.Skip("kTLS not enabled")
	}

	counts := map[byte]int{}
	buf := make([]byte, 4096)
	deadline := time.Now().Add(12 * time.Second)
	total := 0
	for total < len(blocks)*blockLen && time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, rerr := conn.Read(buf)
		for _, c := range buf[:n] {
			if c != '\n' {
				counts[c]++
				total++
			}
		}
		if rerr != nil {
			break // openssl s_client may shut down after several KeyUpdates, check what arrived
		}
	}

	// every block that arrived must be byte exact, and enough must arrive to prove
	// data survives at least one mid stream KeyUpdate. partial/corrupt = server bug
	full := 0
	for _, b := range blocks {
		if counts[b.marker] == blockLen {
			full++
		} else if counts[b.marker] != 0 {
			t.Fatalf("block %c corrupt/partial: got %d want %d (%s)", b.marker, counts[b.marker], blockLen, summary(counts))
		}
	}
	if full < 2 {
		t.Fatalf("only %d full blocks survived KeyUpdates (%s)", full, summary(counts))
	}
}

func summary(counts map[byte]int) string {
	var sb strings.Builder
	for _, b := range []byte("ABCD") {
		fmt.Fprintf(&sb, "%c=%d ", b, counts[b])
	}

	return sb.String()
}
