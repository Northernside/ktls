//go:build linux

package ktls

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeConn scripts a sequence of (n bytes written into b, error) results for
// successive Read calls, so the KeyUpdate loop can be exercised without kTLS
type fakeConn struct {
	stepReads []fakeRead
	i         int
	netConnStub
}

type fakeRead struct {
	data []byte
	err  error
}

func (f *fakeConn) Read(b []byte) (int, error) {
	if f.i >= len(f.stepReads) {
		return 0, io.EOF
	}

	r := f.stepReads[f.i]
	f.i++
	n := copy(b, r.data)
	return n, r.err
}

func ekeyexpired() error { return unix.EKEYEXPIRED }

func newTestConn(reads []fakeRead, ku func() error) *conn {
	return &conn{
		Conn:        &fakeConn{stepReads: reads},
		rxSecret:    []byte("secret"), // non nil so the update path is eligible
		onKeyUpdate: ku,
	}
}

func TestReadHandlesMultipleKeyUpdates(t *testing.T) {
	updates := 0
	c := newTestConn([]fakeRead{
		{nil, ekeyexpired()},   // KeyUpdate #1
		{nil, ekeyexpired()},   // KeyUpdate #2 back-to-back
		{[]byte("hello"), nil}, // real data after rekeying twice
	}, func() error { updates++; return nil })

	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want hello", buf[:n])
	}

	if updates != 2 {
		t.Fatalf("expected 2 key updates handled, got %d", updates)
	}
}

func TestReadReturnsDataBeforeKeyUpdate(t *testing.T) {
	// data arriving alongside the key update signal must be returned, not dropped
	updates := 0
	c := newTestConn([]fakeRead{
		{[]byte("payload"), ekeyexpired()},
	}, func() error { updates++; return nil })

	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if string(buf[:n]) != "payload" {
		t.Fatalf("data dropped: got %q, want payload", buf[:n])
	}

	if updates != 0 {
		t.Fatalf("should defer key update when data present, got %d", updates)
	}
}

func TestReadPassesThroughNonKeyUpdateErrors(t *testing.T) {
	sentinel := errors.New("boom")
	c := newTestConn([]fakeRead{{nil, sentinel}}, func() error { return nil })
	buf := make([]byte, 16)
	if _, err := c.Read(buf); !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want sentinel", err)
	}
}

func TestReadBoundsKeyUpdateFlood(t *testing.T) {
	// peer sending only KeyUpdates must not spin forever
	reads := make([]fakeRead, 1000)
	for i := range reads {
		reads[i] = fakeRead{nil, ekeyexpired()}
	}

	c := newTestConn(reads, func() error { return nil })
	buf := make([]byte, 16)
	if _, err := c.Read(buf); !isEKEYEXPIRED(err) {
		t.Fatalf("expected bounded loop to return EKEYEXPIRED, got %v", err)
	}
}
