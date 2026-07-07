package ktls

import "io"

type SpliceConfig struct {
	// if > 0 and Peek is set, copies up to the first PeekN bytes of the
	// source into userspace and hands them to Peek before anything is
	// forwarded
	// those bytes are still sent to the peer (encrypted)
	PeekN int

	Peek func([]byte)
}

// implements io.ReaderFrom
// when r wraps a raw socket or file descriptor and the connection is kTLS-active,
// the copy runs zerocopy through the kernel via splice(2) -> the kernel encrypts
// each chunk with kTLS TX
// other sources fall back to a normal buffered copy
// makes io.Copy(ktlsConn, backend) zerocopy automatically
func (c *conn) ReadFrom(r io.Reader) (int64, error) {
	return c.ReadFromConfig(r, SpliceConfig{})
}

// ReadFrom with an optional userspace peek (see SpliceConfig)
func (c *conn) ReadFromConfig(r io.Reader, cfg SpliceConfig) (int64, error) {
	if n, handled, err := c.spliceReadFrom(r, cfg); handled {
		return n, err
	}

	return c.genericReadFrom(r, cfg)
}

// copies through a userspace buffer via Write, honoring the peek window
// used when the source is not a raw fd (nothing to splice)
// all output goes through Write, so there is no splice/Write mix
func (c *conn) genericReadFrom(r io.Reader, cfg SpliceConfig) (int64, error) {
	buf := make([]byte, 128*1024)
	var total int64

	peekLeft := 0
	var peek []byte
	if cfg.PeekN > 0 && cfg.Peek != nil {
		peekLeft = cfg.PeekN
		peek = make([]byte, 0, cfg.PeekN)
	}

	for {
		n, rerr := r.Read(buf)
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
			w, werr := c.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			if peekLeft > 0 && len(peek) > 0 { // stream ended before filling the window
				cfg.Peek(peek)
			}
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}
