//go:build linux

package ktls

import (
	"crypto/tls"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestKeyUpdateViaOpenSSL(t *testing.T) {
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
	raw.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)) // bound Accept
	ln := &Listener{TCPListener: raw, TLSConfig: cfg, OnError: func(e error) { t.Logf("onError: %v", e) }}

	// s_client interprets a line "k"/"K" as a key_update command
	// feed with small gaps so each command is processed as its own record in order
	pr, pw := io.Pipe()
	cmd := exec.Command(ossl, "s_client", "-connect", raw.Addr().String(), "-tls1_3")
	cmd.Stdin = pr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start openssl: %v", err)
	}
	defer func() { pw.Close(); cmd.Process.Kill(); cmd.Wait() }()
	go func() {
		for _, line := range []string{"m1", "k", "m2", "K", "m3", "k", "k", "m4"} {
			io.WriteString(pw, line+"\n")
			time.Sleep(250 * time.Millisecond)
		}
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(Conn); !ok {
		t.Fatal("kTLS not enabled (userspace fallback)")
	}

	var got []string
	buf := make([]byte, 4096)
	deadline := time.Now().Add(12 * time.Second)
	for len(got) < 4 && time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(buf)
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				got = append(got, line)
			}
		}
		if err != nil && len(got) < 4 {
			t.Fatalf("read broke after %v (KeyUpdate not handled): %v", got, err)
		}
	}

	if strings.Join(got, ",") != "m1,m2,m3,m4" {
		t.Fatalf("after KeyUpdates got %v, want [m1 m2 m3 m4]", got)
	}
}
