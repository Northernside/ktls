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

func tls12Client(t *testing.T, addr string, suite uint16) *tls.Conn {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suite},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	return c
}

// validates that a TLS 1.2 connection is offloaded to the kernel and that data
// flows correctly in both directions across many records (exercises the PRF key
// derivation, GCM nonce/salt, and the record sequence numbers)
func TestKTLS12RoundTrip(t *testing.T) {
	for _, suite := range []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 0xC02B
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // 0xC02C
	} {
		t.Run("", func(t *testing.T) {
			cert := selfSigned(t)
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}

			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()

			ln := &Listener{TCPListener: raw, TLSConfig: cfg, OnError: func(e error) { t.Logf("onError: %v", e) }}

			payload := make([]byte, 300*1024) // multi-record, exercises seq 1,2,3...
			for i := range payload {
				payload[i] = byte(i)
			}

			cerr := make(chan error, 1)

			go func() {
				c := tls12Client(t, raw.Addr().String(), suite)
				defer c.Close()

				if _, err := c.Write([]byte("ping")); err != nil {
					cerr <- err

					return
				}

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
				t.Fatalf("accept: %v", err)
			}
			defer conn.Close()

			if _, ok := conn.(Conn); !ok {
				t.Fatalf("suite 0x%04x: kTLS NOT enabled (userspace fallback)", suite)
			}

			if v := conn.(Conn).ConnectionState().Version; v != tls.VersionTLS12 {
				t.Fatalf("version %x, want TLS 1.2", v)
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			hdr := make([]byte, 4)
			if _, err := io.ReadFull(conn, hdr); err != nil || string(hdr) != "ping" {
				t.Fatalf("server read %q err=%v (RX decrypt failed?)", hdr, err)
			}

			if _, err := conn.Write(payload); err != nil { // TX: many records
				t.Fatalf("server write: %v", err)
			}

			if err := <-cerr; err != nil {
				t.Fatalf("client (TX decrypt failed?): %v", err)
			}
		})
	}
}

func TestKTLS12RSASuites(t *testing.T) {
	for _, suite := range []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // 0xC02F
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // 0xC030
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,       // 0x009C
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,       // 0x009D
	} {
		t.Run("", func(t *testing.T) {
			cert := selfSignedRSA(t)
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}}

			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()

			ln := &Listener{TCPListener: raw, TLSConfig: cfg, OnError: func(e error) { t.Logf("onError: %v", e) }}

			msg := bytes.Repeat([]byte("x"), 64*1024)
			cerr := make(chan error, 1)

			go func() {
				c := tls12Client(t, raw.Addr().String(), suite)
				defer c.Close()

				got := make([]byte, len(msg))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
					cerr <- io.ErrUnexpectedEOF

					return
				}

				_, err := c.Write([]byte("ok"))
				cerr <- err
			}()

			conn, err := ln.Accept()
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			defer conn.Close()

			if _, ok := conn.(Conn); !ok {
				t.Fatalf("suite 0x%04x: kTLS not enabled", suite)
			}

			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			ack := make([]byte, 2)
			if _, err := io.ReadFull(conn, ack); err != nil || string(ack) != "ok" {
				t.Fatalf("read ack %q: %v", ack, err)
			}

			if err := <-cerr; err != nil {
				t.Fatalf("client: %v", err)
			}
		})
	}
}

// validates TLS 1.2 ChaCha20-Poly1305 (RFC 7905)
// different nonce layout than GCM (12-byte fixed IV, no salt, nonce = iv XOR seq)
func TestKTLS12ChaCha20(t *testing.T) {
	for _, suite := range []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // 0xCCA9
	} {
		cert := selfSigned(t)
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}}

		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()

		ln := &Listener{TCPListener: raw, TLSConfig: cfg, OnError: func(e error) { t.Logf("onError: %v", e) }}

		msg := bytes.Repeat([]byte("z"), 200*1024)
		cerr := make(chan error, 1)

		go func() {
			c := tls12Client(t, raw.Addr().String(), suite)
			defer c.Close()

			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
				cerr <- io.ErrUnexpectedEOF

				return
			}

			_, err := c.Write([]byte("ok"))
			cerr <- err
		}()

		conn, err := ln.Accept()
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		defer conn.Close()

		if _, ok := conn.(Conn); !ok {
			t.Fatalf("ChaCha20-1.2: kTLS not enabled")
		}

		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		ack := make([]byte, 2)
		if _, err := io.ReadFull(conn, ack); err != nil || string(ack) != "ok" {
			t.Fatalf("read ack: %v", err)
		}

		if err := <-cerr; err != nil {
			t.Fatalf("client: %v", err)
		}
	}
}
