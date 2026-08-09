//go:build linux

package ktls

import (
	"crypto/tls"
	"net"
	"syscall"
	"testing"
)

// the userspace fallback returns tls.Server(recordCounter)
// callers unwrap the *tls.Conn via NetConn() and expect syscall.Conn to reach the raw fd
func TestRecordCounterSyscallConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer ln.Close()
	go func() { c, _ := net.Dial("tcp", ln.Addr().String()); _ = c; select {} }()

	raw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	counter := &recordCounter{Conn: raw}
	tc := tls.Server(counter, &tls.Config{})

	// mimics getRawFd
	// unwrap *tls.Conn -> NetConn() -> syscall.Conn -> fd
	nc := tc.NetConn()

	sc, ok := nc.(syscall.Conn)
	if !ok {
		t.Fatalf("NetConn() %T does not implement syscall.Conn", nc)
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	fd := -1

	rc.Control(func(f uintptr) { fd = int(f) })

	if fd <= 0 {
		t.Fatalf("got fd=%d, want >0", fd)
	}
}
