package ktls

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// shortWriteWriter accepts every Write but only accepts a small chunk per
// call, returning nil error so the caller must loop to flush the full buffer.
// This simulates net.TCPConn.Write returning what the kernel accepted when the
// send buffer is partially full.
type shortWriteWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (s *shortWriteWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(b) == 0 {
		return 0, nil
	}

	take := min(len(b), s.max)

	n, err := s.buf.Write(b[:take])

	return n, err
}

// readerAt returns a Reader that emits payload in one Read call.
type singleReadReader struct {
	data []byte
	read bool
}

func (r *singleReadReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}

	r.read = true
	n := copy(p, r.data)

	return n, nil
}

// genericReadFrom must loop on short writes; before the fix it dropped the
// unaccepted tail of each record and silently corrupted the stream.
func TestGenericReadFromShortWrite(t *testing.T) {
	const chunk = 8 // kernel "accepts" only 8 bytes per syscall, far below record size

	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	sink := &shortWriteWriter{max: chunk}
	c := &conn{Conn: nopConn{sink}}

	src := &singleReadReader{data: payload}

	n, err := c.genericReadFrom(src, SpliceConfig{})
	if err != nil {
		t.Fatalf("genericReadFrom: %v", err)
	}

	if n != int64(len(payload)) {
		t.Fatalf("genericReadFrom copied %d bytes, want %d (short-write data loss)", n, len(payload))
	}

	if !bytes.Equal(sink.buf.Bytes(), payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d (short-write dropped tail)",
			sink.buf.Len(), len(payload))
	}
}

// nopConn wraps a writer so it satisfies net.Conn enough for the conn struct.
type nopConn struct {
	w io.Writer
}

func (nopConn) Read(p []byte) (int, error)       { return 0, io.EOF }
func (n nopConn) Write(p []byte) (int, error)    { return n.w.Write(p) }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return nopAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return nopAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

type nopAddr struct{}

func (nopAddr) Network() string { return "nop" }
func (nopAddr) String() string  { return "nop" }
