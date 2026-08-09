//go:build linux

package ktls

import (
	"errors"
	"io"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	recordAlert           = 21
	recordHandshake       = 22
	recordApplicationData = 23
)

const handshakeKeyUpdate = 24 // 0x18

const (
	tlsGetRecordType = 2
	tlsSetRecordType = 1
)

// reports whether a read error means the kernel is holding a non-data record
// (KeyUpdate) it will not deliver via plain read()
// the kernel returns EIO for a control record on a plain read
// some kernels signal an impending rekey with EKEYEXPIRED instead
func isPostHandshakeSignal(err error) bool {
	return isErrno(err, unix.EIO) || isEKEYEXPIRED(err)
}

func isErrno(err error, want syscall.Errno) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
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

	err := c.rekeyRX()
	if err != nil {
		return err
	}

	// msg[4] is request_update: 0 = not requested, 1 = update_requested
	// per RFC 8446 4.6.3 a peer that sets update_requested requires us to send
	// our own KeyUpdate (which rekeys our TX) before our next application data
	if len(msg) >= 5 && msg[4] == 1 {
		return c.sendKeyUpdateAndRekeyTX()
	}

	return nil
}

// sendKeyUpdateAndRekeyTX answers a peer's update_requested
// emit a KeyUpdate(update_not_requested) handshake record under the current TX key,
// then advance the TX key
// txMu serializes this against Write so no record is ever sent split across the key change
func (c *conn) sendKeyUpdateAndRekeyTX() error {
	if c.txSecret == nil {
		return nil // TX secret unavailable, nothing to rotate
	}

	c.txMu.Lock()
	defer c.txMu.Unlock()

	// key_update handshake message: type(24) length(1) request_update(0)
	keyUpdateMsg := []byte{handshakeKeyUpdate, 0x00, 0x00, 0x01, 0x00}
	if err := c.sendControlRecord(recordHandshake, keyUpdateMsg); err != nil {
		return err
	}

	next, err := deriveNextSecret(c.txSecret, c.cipherSuiteID)
	if err != nil {
		return err
	}

	if err := updateTX(c.fd, next, c.cipherSuiteID); err != nil {
		return err
	}

	c.txSecret = next

	return nil
}

// sendControlRecord writes payload as a record of the given TLS record type via
// sendmsg with the SOL_TLS record-type cmsg (the kernel encrypts it under the
// current TX key)
func (c *conn) sendControlRecord(recordType byte, payload []byte) error {
	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}

	oob := recordTypeCmsg(recordType)

	var serr error

	ctlErr := sc.Write(func(fd uintptr) bool {
		serr = syscall.Sendmsg(int(fd), payload, oob, nil, 0)

		return serr != syscall.EAGAIN
	})
	if ctlErr != nil {
		return ctlErr
	}

	return serr
}

// recordTypeCmsg builds the SOL_TLS / TLS_SET_RECORD_TYPE control message that
// tells the kernel which TLS record type to stamp on the sent payload
func recordTypeCmsg(recordType byte) []byte {
	buf := make([]byte, syscall.CmsgSpace(1))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = solTLS
	h.Type = tlsSetRecordType
	h.SetLen(syscall.CmsgLen(1))
	buf[syscall.CmsgLen(0)] = recordType

	return buf
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

	var (
		n, oobn int
		rerr    error
	)

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
