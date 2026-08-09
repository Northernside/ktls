//go:build linux

package ktls

import (
	"errors"
	"io"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	splicePipeSize = 1 << 20 // 1MB
	spliceFlags    = unix.SPLICE_F_MOVE | unix.SPLICE_F_NONBLOCK
)

// pooled kernel pipes with a 1MB buffer, used as the splice bounce buffer
// (you cannot splice socket -> socket directly, it has to go through a pipe, correct me if im wrong)
var splicePipePool = sync.Pool{
	New: func() any {
		var fds [2]int

		err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC)
		if err != nil {
			return nil
		}

		unix.FcntlInt(uintptr(fds[0]), unix.F_SETPIPE_SZ, splicePipeSize)

		return &fds
	},
}

func getSplicePipe() (*[2]int, bool) {
	v := splicePipePool.Get()
	if v == nil {
		return nil, false
	}

	return v.(*[2]int), true
}

func putSplicePipe(fds *[2]int) {
	// drain leftover so a reused pipe never carries stale bytes
	var buf [65536]byte
	for {
		n, _ := unix.Read(fds[0], buf[:])
		if n <= 0 {
			break
		}
	}

	splicePipePool.Put(fds)
}

// copies r into the kTLS conn zerocopy when r exposes a raw fd handled
// is false when r is not spliceable, so the caller falls back to a generic copy
// every byte reaches the socket through splice (never Write) so  the kTLS TX
// record sequence stays consistent even across the peek window
func (c *conn) spliceReadFrom(r io.Reader, cfg SpliceConfig) (n int64, handled bool, err error) {
	srcSC, ok := rawConnOf(r)
	if !ok {
		return 0, false, nil // not an fd source -> generic copy
	}

	dstSC, derr := c.SyscallConn()
	if derr != nil {
		return 0, false, nil
	}

	pipe, ok := getSplicePipe()
	if !ok {
		return 0, false, nil // no pipe -> let the generic path handle it
	}
	defer putSplicePipe(pipe)

	var total int64

	// peek: pull the leading window into userspace, observe it, then forward it
	// through the pipe -> splice path (not Write, which would desync the TX seq)
	if cfg.PeekN > 0 && cfg.Peek != nil {
		buf := make([]byte, cfg.PeekN)

		got, eof, rerr := readSome(srcSC, buf)
		if rerr != nil {
			return total, true, rerr
		}

		if got > 0 {
			cfg.Peek(buf[:got])
			sent, werr := pipeForward(dstSC, pipe, buf[:got])

			total += sent
			if werr != nil {
				return total, true, werr
			}
		}

		if eof {
			return total, true, nil
		}
	}

	m, serr := spliceStream(dstSC, srcSC, pipe)

	return total + m, true, serr
}

// drains the kTLS RX stream into w zerocopy when w exposes a raw fd
// data is spliced kTLS-fd -> pipe -> w-fd and the kernel decrypts on the way out
// handled is false when w is not an fd sink, so the caller falls backs
func (c *conn) spliceWriteTo(w io.Writer, cfg SpliceConfig) (n int64, handled bool, err error) {
	dstSC, ok := rawConnOf(w)
	if !ok {
		return 0, false, nil // not an fd sink -> generic copy
	}

	pipe, ok := getSplicePipe()
	if !ok {
		return 0, false, nil
	}
	defer putSplicePipe(pipe)

	var total int64

	// peek: pull the leading window via Read (which handles KeyUpdate), observe
	// it, then write it straight to the plain dst (no kTLS sequencing on w)
	if cfg.PeekN > 0 && cfg.Peek != nil {
		buf := make([]byte, cfg.PeekN)

		got, eof, rerr := c.readUpTo(buf)
		if got > 0 {
			cfg.Peek(buf[:got])
			sent, werr := writeAll(w, buf[:got])

			total += int64(sent)
			if werr != nil {
				return total, true, werr
			}
		}

		if rerr != nil {
			return total, true, rerr
		}

		if eof {
			return total, true, nil
		}
	}

	m, serr := c.spliceStreamRX(w, dstSC, pipe)

	return total + m, true, serr
}

// moves the kTLS RX stream -> pipe -> dst (w) until EOF
// splice(2) on a kTLS socket only works for a fully-arrived data record
// when the next record is still partial the kernel returns EINVAL (not EAGAIN)
// and a peer KeyUpdate/alert surfaces as EIO
// for every non-EAGAIN case we fall back to a single Read of that chunk
// Read waits for the full record, decrypts it, and handles KeyUpdate + close_notify
// so aligned records go zerocopy and the awkward boundaries take one buffered copy, should prevent busy spins
func (c *conn) spliceStreamRX(w io.Writer, dstSC syscall.RawConn, pipe *[2]int) (int64, error) {
	srcSC, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}

	var total int64

	var rbuf []byte // lazily allocated for the read fallback

	for {
		var (
			got      int64
			fallback bool
		)

		rerr := srcSC.Read(func(fd uintptr) bool {
			m, e := unix.Splice(int(fd), nil, pipe[1], nil, splicePipeSize, spliceFlags)
			if errors.Is(e, syscall.EAGAIN) {
				return false // no data at all -> park on the netpoller
			}

			if e != nil {
				fallback = true // partial record, control record, etc -> use Read

				return true
			}

			got = m

			return true
		})
		if rerr != nil {
			return total, rerr
		}

		if fallback {
			if rbuf == nil {
				rbuf = make([]byte, 64*1024)
			}

			n, e := c.Read(rbuf) // waits for a full record, KeyUpdate-aware
			if n > 0 {
				ww, we := writeAll(w, rbuf[:n])

				total += int64(ww)
				if we != nil {
					return total, we
				}
			}

			if e != nil {
				if errors.Is(e, io.EOF) {
					return total, nil // close_notify / clean end
				}

				return total, e
			}

			continue
		}

		if got == 0 {
			return total, nil // EOF
		}

		s, err := spliceFromPipe(dstSC, pipe[0], int(got))

		total += s
		if err != nil {
			return total, err
		}
	}
}

// fills buf via Read (KeyUpdate-aware), stopping at len(buf) or EOF
func (c *conn) readUpTo(buf []byte) (got int, eof bool, err error) {
	for got < len(buf) {
		n, e := c.Read(buf[got:])
		got += n

		if e != nil {
			if errors.Is(e, io.EOF) {
				return got, true, nil
			}

			return got, false, e
		}

		if n == 0 {
			return got, true, nil
		}
	}

	return got, false, nil
}

// returns v's RawConn if it exposes a raw fd (sockets, files, pipes)
// v must not have buffered data pending -> splice hits the fd directly
// works for both a source (io.Reader) and a sink (io.Writer)
func rawConnOf(v any) (syscall.RawConn, bool) {
	sc, ok := v.(syscall.Conn)
	if !ok {
		return nil, false
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, false
	}

	return rc, true
}

// waits (via the netpoller) for the first data, then greedily pulls whatever else
// is already buffered up to len(buf)
// it never blocks to fill the whole window, so a small peek can't stall a large transfer
// eof is true only when the source is at EOF before any byte.
func readSome(sc syscall.RawConn, buf []byte) (got int, eof bool, err error) {
	var firstErr error

	rerr := sc.Read(func(fd uintptr) bool {
		m, e := unix.Read(int(fd), buf)
		if errors.Is(e, syscall.EAGAIN) {
			return false // park, epoll-wait, retry
		}

		got = m
		firstErr = e

		return true
	})
	if rerr != nil {
		return 0, false, rerr
	}

	if firstErr != nil {
		return got, false, firstErr
	}

	if got == 0 {
		return 0, true, nil // EOF before any data
	}

	for got < len(buf) {
		var m int

		sc.Control(func(fd uintptr) {
			v, e := unix.Read(int(fd), buf[got:])
			if e != nil || v <= 0 {
				return // EAGAIN or EOF -> stop the greedy fill
			}

			m = v
		})

		if m == 0 {
			break
		}

		got += m
	}

	return got, false, nil
}

// pushes data to the socket through the pipe in <=pipeSize chunks
// pipe is empty at each chunk boundary (we splice each chunk out before
// writing the next), so a chunk that fits the pipe never blocks on write
func pipeForward(dstSC syscall.RawConn, pipe *[2]int, data []byte) (int64, error) {
	var total int64

	for off := 0; off < len(data); {
		end := min(off+splicePipeSize, len(data))

		chunk := data[off:end]

		for w := 0; w < len(chunk); {
			m, err := unix.Write(pipe[1], chunk[w:])
			if m > 0 {
				w += m
			}

			if err != nil && !errors.Is(err, syscall.EAGAIN) {
				return total, err
			}
		}

		s, err := spliceFromPipe(dstSC, pipe[0], len(chunk))

		total += s
		if err != nil {
			return total, err
		}

		off = end
	}

	return total, nil
}

// spliceStream moves src -> pipe -> dst in pipe-sized chunks until src EOFs,
// parking on the netpoller for both readability and writability
func spliceStream(dstSC, srcSC syscall.RawConn, pipe *[2]int) (int64, error) {
	var total int64

	for {
		var (
			inN   int64
			inErr error
		)

		rerr := srcSC.Read(func(fd uintptr) bool {
			m, err := unix.Splice(int(fd), nil, pipe[1], nil, splicePipeSize, spliceFlags)
			if errors.Is(err, syscall.EAGAIN) {
				return false
			}

			inN = m
			inErr = err

			return true
		})
		if rerr != nil {
			return total, rerr
		}

		if inErr != nil {
			return total, inErr
		}

		if inN == 0 {
			return total, nil // src EOF
		}

		s, err := spliceFromPipe(dstSC, pipe[0], int(inN))

		total += s
		if err != nil {
			return total, err
		}
	}
}

// spliceFromPipe splices exactly limit bytes pipe -> dst, parking on the
// netpoller when the socket is not writable.
func spliceFromPipe(dstSC syscall.RawConn, pipeRd int, limit int) (int64, error) {
	var written int64
	for written < int64(limit) {
		var (
			m     int64
			opErr error
		)

		werr := dstSC.Write(func(fd uintptr) bool {
			v, err := unix.Splice(pipeRd, nil, int(fd), nil, limit-int(written), spliceFlags)
			if errors.Is(err, syscall.EAGAIN) {
				return false
			}

			m = v
			opErr = err

			return true
		})
		if werr != nil {
			return written, werr
		}

		if opErr != nil {
			return written, opErr
		}

		if m == 0 {
			return written, io.ErrUnexpectedEOF
		}

		written += m
	}

	return written, nil
}
