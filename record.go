package ktls

import (
	"errors"
	"net"
	"syscall"
)

// recordCounter sits between the raw TCP conn and tls.Conn during the handshake
// counts TLS application_data records (type 0x17) going through so we can figure
// out the right RX record sequence number during kTLS setup
type recordCounter struct {
	net.Conn

	headerBuf [5]byte
	headerN   int

	bodyRem int
	inBody  bool

	appRecords int // 0x17 records seen so far (+ Finished)
	partial    bool

	// TLS 1.2 setup: the first outbound bytes hold the ServerHello (for
	// server_random), and records seen after the client ChangeCipherSpec give
	// the RX sequence number (Finished is seq 0, so the count is the next seq)
	outHead      []byte
	sawClientCCS bool
	postCCS      int
}

// captures the head of the first outbound flight (the ServerHello) so the
// TLS 1.2 path can read server_random (only the first 43 bytes) out of it
func (rc *recordCounter) Write(b []byte) (int, error) {
	if len(rc.outHead) < 43 {
		need := min(43-len(rc.outHead), len(b))
		rc.outHead = append(rc.outHead, b[:need]...)
	}

	return rc.Conn.Write(b)
}

// forwards to the wrapped conn, required because the userspace fallback returns
// a *tls.Conn built on the recordCounter (not the raw socket) and callers unwrap
// *tls.Conn via NetConn() then expect syscall.Conn to reach the fd
// without this, TLS 1.2 and any kTLS-setup-failure fallback cannot be wrapped for
// splice and gets dropped
func (rc *recordCounter) SyscallConn() (syscall.RawConn, error) {
	sc, ok := rc.Conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("ktls: wrapped conn does not implement syscall.Conn")
	}

	return sc.SyscallConn()
}

func (rc *recordCounter) Read(b []byte) (int, error) {
	// cap each read at the current record boundary so tls.Conn cannot overread
	// into the following record and buffer its ciphertext in rawInput
	// that buffered ciphertext would be invisible to the kernel after the kTLS handoff
	// -> the kernel reads records from the wrong offset -> EINVAL/EMSGSIZE
	// short reads should be fine, tls.Conn just reads again
	if limit := rc.recordRemaining(); limit > 0 && limit < len(b) {
		b = b[:limit]
	}

	n, err := rc.Conn.Read(b)
	if n > 0 {
		rc.parse(b[:n])
	}

	return n, err
}

// returns the 32-byte server_random from the captured ServerHello
// record header(5) + handshake header(4) + legacy_version(2) then random(32)
func (rc *recordCounter) serverRandom() ([]byte, bool) {
	if len(rc.outHead) < 43 || rc.outHead[0] != 0x16 || rc.outHead[5] != 0x02 {
		return nil, false
	}

	return rc.outHead[11:43], true
}

// the number of records the client sent under the new cipher (after its ChangeCipherSpec)
// equals the RX sequence number for kTLS 1.2
func (rc *recordCounter) postCCSCount() int {
	return rc.postCCS
}

// returns how many bytes are left in the record currently being read
// the rest of the 5-byte header, or the rest of the body once known
func (rc *recordCounter) recordRemaining() int {
	if !rc.inBody {
		return 5 - rc.headerN
	}

	return rc.bodyRem
}

func (rc *recordCounter) parse(data []byte) {
	for len(data) > 0 {
		if !rc.inBody {
			// TLS record header is 5 bytes: type(1) + version(2) + length(2)
			// might arrive split across multiple reads
			need := 5 - rc.headerN
			if len(data) < need {
				copy(rc.headerBuf[rc.headerN:], data)
				rc.headerN += len(data)
				rc.partial = true

				return
			}

			copy(rc.headerBuf[rc.headerN:], data[:need])
			data = data[need:]
			rc.headerN = 0

			// body length from the last 2 header bytes for the next read
			rc.bodyRem = int(rc.headerBuf[3])<<8 | int(rc.headerBuf[4])
			rc.inBody = true

			if rc.bodyRem == 0 {
				rc.onFullRecord(rc.headerBuf[0])
				rc.inBody = false
				rc.partial = false

				continue
			}
		}

		// body split across reads, consume what we can
		if len(data) < rc.bodyRem {
			rc.bodyRem -= len(data)
			rc.partial = true

			return
		}

		// full record consumed
		data = data[rc.bodyRem:]
		rc.bodyRem = 0
		rc.inBody = false
		rc.partial = false

		rc.onFullRecord(rc.headerBuf[0])
	}
}

// updates the counters when a complete inbound record is seen
// records after the client ChangeCipherSpec (0x14) count toward
// the TLS 1.2 RX sequence
// 0x17 (app data) counts toward the TLS 1.3 sequence
func (rc *recordCounter) onFullRecord(recType byte) {
	if recType == 0x17 {
		rc.appRecords++
	}

	if rc.sawClientCCS {
		rc.postCCS++
	}

	if recType == 0x14 {
		rc.sawClientCCS = true // count records after this one, not the CCS itself
	}
}

// clientAppRecords returns appRecords-1 since the first 0x17 record
// is the Finished message, not real app data.
func (rc *recordCounter) clientAppRecords() int {
	n := rc.appRecords - 1
	if n < 0 {
		return 0
	}

	return n
}
