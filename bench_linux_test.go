//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

// The benchmarks substantiate (or refute) the performance claims in the README:
//   - splice (zerocopy) vs generic buffered copy for the TX and RX directions
//   - raw kTLS Write vs Go's userspace *tls.Conn Write ("roughly a wash")
//   - the per-Accept cost of the recordCounter + keylog parse
//
// Run with: make bench   (go test -run='^$' -bench=. -benchmem ./...)
// Compare runs with benchstat:
//
//	benchstat old.txt new.txt
//
// Every benchmark skips when kTLS is not engaged (no kernel module / fallback),
// so the suite stays meaningful on a kernel without tls.

// benchPayload is a deterministic fill so two sides can compare byte-equality
// without holding a second copy of the whole buffer.
func benchPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}

	return b
}

// drain runs in a goroutine and reads exactly len(payload) bytes from r,
// reporting the result on done. It is the consumer side of the TX benchmarks
// and the producer side is a rawSource; for the Write benchmarks the client
// side reads back what the server wrote.
func drainInto(b *testing.B, r io.Reader, want []byte, done chan error) {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		done <- err

		return
	}

	if !bytes.Equal(got, want) {
		done <- io.ErrUnexpectedEOF

		return
	}

	done <- nil
}

// rawSourceConn returns a *net.TCPConn whose server side serves payload once.
// Mirrors rawSource but is reused here under its own listener to keep the
// benchmark self-contained.
func rawSourceConn(b *testing.B, payload []byte) *net.TCPConn {
	b.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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
		b.Fatal(err)
	}

	return c.(*net.TCPConn)
}

// rawSinkConn returns a *net.TCPConn whose server side collects everything it
// reads and reports it on out. Mirrors rawSink.
func rawSinkConn(b *testing.B) (*net.TCPConn, <-chan []byte) {
	b.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
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
		b.Fatal(err)
	}

	return c.(*net.TCPConn), out
}

// ---------------------------------------------------------------------------
// TX direction: io.Copy(ktlsConn, src) -> kernel encrypts via splice
// ---------------------------------------------------------------------------

// BenchmarkSpliceReadFrom measures zerocopy splice into the kTLS TX path
// (src fd -> pipe -> kTLS socket, kernel encrypts).
func BenchmarkSpliceReadFrom(b *testing.B) {
	for _, size := range []int{64 * 1024, 1024 * 1024} {
		b.Run(byteSize(size), func(b *testing.B) {
			benchReadFrom(b, size, true)
		})
	}
}

// BenchmarkGenericReadFrom measures the buffered userspace fallback for the TX
// path (no splice: src -> buffer -> Write -> kernel encrypts).
func BenchmarkGenericReadFrom(b *testing.B) {
	for _, size := range []int{64 * 1024, 1024 * 1024} {
		b.Run(byteSize(size), func(b *testing.B) {
			benchReadFrom(b, size, false)
		})
	}
}

// benchReadFrom runs one TX-direction benchmark. splice=true drives the raw-fd
// source through io.Copy (splice path); splice=false wraps the source in a
// bytes.Reader so ReadFrom falls back to genericReadFrom.
func benchReadFrom(b *testing.B, payloadSize int, splice bool) {
	ln, addr := ktlsServerB(b)
	defer ln.TCPListener.Close()

	payload := benchPayload(payloadSize)
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	b.ResetTimer()

	for range b.N {
		// fresh kTLS conn per iteration: handshake cost is excluded by ResetTimer
		kc, client := acceptKTLSB(b, ln, addr)

		done := make(chan error, 1)
		go drainInto(b, client, payload, done)

		var src io.Reader
		if splice {
			src = rawSourceConn(b, payload)
		} else {
			src = bytes.NewReader(payload) // no raw fd -> genericReadFrom
		}

		if _, err := io.Copy(kc, src); err != nil {
			b.Fatalf("io.Copy: %v", err)
		}
		// close the server side first so the kernel flushes + sends close_notify;
		// only close the client after the drain goroutine has read every byte,
		// otherwise an in-flight ReadFull aborts with "use of closed connection".
		kc.Close()

		if splice {
			if s, ok := src.(*net.TCPConn); ok {
				s.Close()
			}
		}

		err := <-done
		if err != nil {
			b.Fatalf("client read: %v", err)
		}

		client.Close()
	}
}

// ---------------------------------------------------------------------------
// RX direction: io.Copy(dst, ktlsConn) -> kernel decrypts via splice
// ---------------------------------------------------------------------------

// BenchmarkSpliceWriteTo measures zerocopy splice out of the kTLS RX path
// (kTLS socket -> pipe -> dst fd, kernel decrypts).
func BenchmarkSpliceWriteTo(b *testing.B) {
	for _, size := range []int{64 * 1024, 1024 * 1024} {
		b.Run(byteSize(size), func(b *testing.B) {
			benchWriteTo(b, size, true)
		})
	}
}

// BenchmarkGenericWriteTo measures the buffered userspace fallback for the RX
// path (no splice: Read -> buffer -> dst Write, kernel decrypts on Read).
func BenchmarkGenericWriteTo(b *testing.B) {
	for _, size := range []int{64 * 1024, 1024 * 1024} {
		b.Run(byteSize(size), func(b *testing.B) {
			benchWriteTo(b, size, false)
		})
	}
}

// benchWriteTo runs one RX-direction benchmark. The client writes payload over
// its *tls.Conn; the server copies it out via io.Copy(dst, kc). splice=true uses
// a raw-fd sink (splice path); splice=false uses a bytes.Buffer (genericWriteTo).
func benchWriteTo(b *testing.B, payloadSize int, splice bool) {
	ln, addr := ktlsServerB(b)
	defer ln.TCPListener.Close()

	payload := benchPayload(payloadSize)
	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()

	b.ResetTimer()

	for range b.N {
		kc, client := acceptKTLSB(b, ln, addr)

		// client pushes the payload; server drains it.
		go func() {
			client.Write(payload)
			client.Close()
		}()

		var (
			dst     io.Writer
			sinkOut <-chan []byte
			sink    *net.TCPConn
		)
		if splice {
			sink, sinkOut = rawSinkConn(b)
			dst = sink
		} else {
			dst = &bytes.Buffer{}
		}

		if _, err := io.Copy(dst, kc); err != nil {
			b.Fatalf("io.Copy: %v", err)
		}

		kc.Close()
		client.Close()

		if splice {
			sink.Close()

			got := <-sinkOut
			if len(got) != payloadSize {
				b.Fatalf("sink got %d bytes, want %d", len(got), payloadSize)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Raw Write path: kTLS vs userspace *tls.Conn
// ---------------------------------------------------------------------------

// BenchmarkKTLSWrite measures raw Write on a kTLS-active conn (the kernel
// encrypts each call). Substantiates or refutes the "roughly a wash against
// Go's userspace AES-GCM" claim.
func BenchmarkKTLSWrite(b *testing.B) {
	ln, addr := ktlsServerB(b)
	defer ln.TCPListener.Close()

	const size = 64 * 1024

	payload := benchPayload(size)

	kc, client := acceptKTLSB(b, ln, addr)
	defer kc.Close()
	defer client.Close()

	// keep a reader draining the other end so the kernel send buffer does not
	// backpressure the writes and skew the measurement.
	go io.Copy(io.Discard, client)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := kc.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
	}

	b.StopTimer()
}

// BenchmarkUserspaceTLSWrite is the comparison baseline: the same payload
// written through Go's userspace *tls.Conn (no kernel offload). A single
// long-lived TLS connection is used for the whole benchmark loop (matching the
// kTLS benchmark), with a background drain on the server side so client writes
// are not backpressured by kernel send-buffer limits.
func BenchmarkUserspaceTLSWrite(b *testing.B) {
	ln, addr := userspaceTLSServerB(b)
	defer ln.Close()

	const size = 64 * 1024

	payload := benchPayload(size)

	// The server *tls.Conn handshake is lazy, so the accept goroutine drives it
	// concurrently with the client dial; without this tls.Dial blocks forever
	// waiting for a ServerHello the server has not yet started to send.
	srvCh := make(chan net.Conn, 1)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- nil

			return
		}

		if tc, ok := c.(*tls.Conn); ok {
			herr := tc.Handshake()
			if herr != nil {
				c.Close()

				srvCh <- nil

				return
			}
		}

		srvCh <- c
	}()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	srv := <-srvCh
	if srv == nil {
		b.Fatal("server accept/handshake failed")
	}

	defer srv.Close()
	go io.Copy(io.Discard, srv) // drain for the connection lifetime

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
	}

	b.StopTimer()
}

// ---------------------------------------------------------------------------
// Handshake / Accept cost (recordCounter + keylog parse)
// ---------------------------------------------------------------------------

// BenchmarkHandshake measures the per-connection overhead Accept adds on top
// of a plain crypto/tls handshake: the recordCounter wrapping, key-log buffer
// capture, and traffic-secret parsing. It accepts a kTLS-active connection each
// iteration so the full Accept path (including enableKTLS) is measured.
func BenchmarkHandshake(b *testing.B) {
	ln, addr := ktlsServerB(b)
	defer ln.TCPListener.Close()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		go func() {
			c, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
			})
			if err != nil {
				return
			}
			// a tiny read keeps the conn alive long enough for Accept to finish
			one := make([]byte, 1)
			c.Read(one)
			c.Close()
		}()

		conn, err := ln.Accept()
		if err != nil {
			b.Fatalf("accept: %v", err)
		}

		conn.Close()
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// ktlsServerB is the benchmark variant of ktlsServer (b.Helper + b.Fatal).
func ktlsServerB(b *testing.B) (*Listener, string) {
	b.Helper()
	cert := selfSignedB(b)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	ln := &Listener{TCPListener: raw, TLSConfig: cfg, OnError: func(e error) {}}

	return ln, raw.Addr().String()
}

// userspaceTLSServerB returns a plain crypto/tls listener (no kTLS) so the
// userspace Write benchmark has a clean comparison baseline.
func userspaceTLSServerB(b *testing.B) (net.Listener, string) {
	b.Helper()
	cert := selfSignedB(b)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	return tls.NewListener(raw, cfg), raw.Addr().String()
}

// acceptKTLSB accepts one kTLS-active connection and returns it plus the
// matching client *tls.Conn so the benchmark can drive the other side.
func acceptKTLSB(b *testing.B, ln *Listener, addr string) (Conn, *tls.Conn) {
	b.Helper()

	type accepted struct {
		c   *tls.Conn
		err error
	}

	ch := make(chan accepted, 1)

	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		ch <- accepted{c, err}
	}()

	conn, err := ln.Accept()
	if err != nil {
		b.Fatalf("accept: %v", err)
	}

	kc, ok := conn.(Conn)
	if !ok {
		conn.Close()

		if a := <-ch; a.c != nil {
			a.c.Close()
		}

		b.Skip("kTLS not enabled (userspace fallback) - benchmark not meaningful")
	}

	a := <-ch
	if a.err != nil {
		conn.Close()
		b.Fatalf("client dial: %v", a.err)
	}

	return kc, a.c
}

// byteSize renders a byte count as a human-friendly benchmark sub-name.
func byteSize(n int) string {
	switch {
	case n >= 1024*1024:
		return "1MiB"
	case n >= 1024:
		return "64KiB"
	default:
		return "raw"
	}
}
