//go:build linux

package ktls

import (
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
		if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
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

// returns r's RawConn if it exposes a raw fd (sockets, files, pipes)
// r must not have buffered reads pending -> splice reads straight from the fd
func rawConnOf(r io.Reader) (syscall.RawConn, bool) {
	sc, ok := r.(syscall.Conn)
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
		if e == syscall.EAGAIN {
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
		end := off + splicePipeSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]

		for w := 0; w < len(chunk); {
			m, err := unix.Write(pipe[1], chunk[w:])
			if m > 0 {
				w += m
			}
			if err != nil && err != syscall.EAGAIN {
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
		var inN int64
		var inErr error
		rerr := srcSC.Read(func(fd uintptr) bool {
			m, err := unix.Splice(int(fd), nil, pipe[1], nil, splicePipeSize, spliceFlags)
			if err == syscall.EAGAIN {
				return false
			}
			inN = int64(m)
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
		var m int64
		var opErr error
		werr := dstSC.Write(func(fd uintptr) bool {
			v, err := unix.Splice(pipeRd, nil, int(fd), nil, limit-int(written), spliceFlags)
			if err == syscall.EAGAIN {
				return false
			}
			m = int64(v)
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
