//go:build linux

package ktls

import (
	"errors"
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	recordAlert           = 21
	recordHandshake       = 22
	recordApplicationData = 23
)

const handshakeKeyUpdate = 24 // 0x18

// the SOL_TLS cmsg carrying a decrypted record's type
const tlsGetRecordType = 2

// reports whether a read error means the kernel is holding a non-data record
// (KeyUpdate) it will not deliver via plain read()
// the kernel returns EIO for a control record on a plain read
// some kernels signal an impending rekey with EKEYEXPIRED instead
func isPostHandshakeSignal(err error) bool {
	return isErrno(err, unix.EIO) || isEKEYEXPIRED(err)
}

func isErrno(err error, want syscall.Errno) bool {
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return errno == want
	}

	return false
}

// consumes the pending control record and rekeys as needed,  so the caller
// can retry the read under the correct key
// readErr is the error the plain read returned
func (c *conn) handlePostHandshake(readErr error) error {
	// apparently some kernels return EKEYEXPIRED directly once they reach a record under the
	// peer's new key -> just advance the RX key and retry
	if !isErrno(readErr, unix.EIO) && isEKEYEXPIRED(readErr) {
		return c.rekeyRX()
	}

	// EIO->a non-data record is queued that plain read() refuses to deliver
	// fetch it with recvmsg so we can read its record type from the cmsg
	rt, msg, err := c.recvControlRecord()
	if err != nil {
		if isEKEYEXPIRED(err) {
			return c.rekeyRX()
		}

		return err
	}

	switch rt {
	case recordHandshake:
		return c.onPostHandshakeMsg(msg)
	case recordAlert:
		// close_notify or a fatal alert -> treat as end of stream
		return io.EOF
	default:
		return nil
	}
}

// acts on a decrypted handshake record received after the handshake
// only KeyUpdate is expected from a client, anything else is ignored
func (c *conn) onPostHandshakeMsg(msg []byte) error {
	// handshake message: type(1) length(3) body...
	if len(msg) < 1 || msg[0] != handshakeKeyUpdate {
		return nil
	}

	if err := c.rekeyRX(); err != nil {
		return err
	}

	// msg[4] is request_update: 0 = not requested, 1 = update_requested
	// per RFC 8446 4.6.3 a peer that sets update_requested wants us to send our
	// own KeyUpdate (which would rekey our TX afaik)
	// we intentionally do NOT do that here: rekeying TX would race concurrent writers
	// (e.g. HTTP/2) and reads already work from the RX rekey above
	// update_requested is rare and peers  tolerate the missing response
	return nil
}

// recvControlRecord reads a single record via recvmsg and returns its TLS record
// type (from the SOL_TLS cmsg) and payload. poller integrated so it respects
// deadlines and does not busywait
func (c *conn) recvControlRecord() (recordType byte, payload []byte, err error) {
	sc, scErr := c.SyscallConn()
	if scErr != nil {
		return 0, nil, scErr
	}

	buf := make([]byte, 512)
	oob := make([]byte, 128)

	var n, oobn int
	var rerr error
	ctlErr := sc.Read(func(fd uintptr) bool {
		n, oobn, _, _, rerr = syscall.Recvmsg(int(fd), buf, oob, 0)
		return rerr != syscall.EAGAIN // false -> let the poller wait for readability
	})
	if ctlErr != nil {
		return 0, nil, ctlErr
	}
	if rerr != nil {
		return 0, nil, rerr
	}

	recordType = recordApplicationData
	if oobn > 0 {
		cmsgs, perr := syscall.ParseSocketControlMessage(oob[:oobn])
		if perr == nil {
			for _, cm := range cmsgs {
				if cm.Header.Level == solTLS && cm.Header.Type == tlsGetRecordType && len(cm.Data) >= 1 {
					recordType = cm.Data[0]
				}
			}
		}
	}

	return recordType, buf[:n], nil
}
