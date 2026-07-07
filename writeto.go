package ktls

import "io"

// implements io.WriterTo
// when w wraps a raw file descriptor (a TCP/unix socket, a file, a pipe)
// and the connection is kTLS-active, received data is spliced
// kTLS-socket -> pipe -> w and decrypted by the kernel with no userspace copy
// other destinations fall back to a normal buffered copy
// this makes io.Copy(backend, ktlsConn) zerocopy for the receive/upload direction
// only drive one logical stream through a single path though
func (c *conn) WriteTo(w io.Writer) (int64, error) {
	return c.WriteToConfig(w, SpliceConfig{})
}

// WriteTo with an optional userspace peek (see SpliceConfig)
// Peek observes the first decrypted bytes before they are forwarded to w
func (c *conn) WriteToConfig(w io.Writer, cfg SpliceConfig) (int64, error) {
	if n, handled, err := c.spliceWriteTo(w, cfg); handled {
		return n, err
	}

	return c.genericWriteTo(w, cfg)
}

// copies through a userspace buffer via Read/Write, honoring the peek window
// used when the destination is not a raw fd (nothing to splice into)
// Read handles post-handshake control records (KeyUpdate), so this stays correct
func (c *conn) genericWriteTo(w io.Writer, cfg SpliceConfig) (int64, error) {
	buf := make([]byte, 128*1024)
	var total int64

	peekLeft := 0
	var peek []byte
	if cfg.PeekN > 0 && cfg.Peek != nil {
		peekLeft = cfg.PeekN
		peek = make([]byte, 0, cfg.PeekN)
	}

	for {
		n, rerr := c.Read(buf)
		if n > 0 {
			if peekLeft > 0 {
				take := n
				if take > peekLeft {
					take = peekLeft
				}
				peek = append(peek, buf[:take]...)
				if peekLeft -= take; peekLeft == 0 {
					cfg.Peek(peek)
				}
			}
			ww, werr := writeAll(w, buf[:n])
			total += int64(ww)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			if peekLeft > 0 && len(peek) > 0 {
				cfg.Peek(peek)
			}
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func writeAll(w io.Writer, b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := w.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
	}

	return written, nil
}
