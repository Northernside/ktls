package ktls

import "net"

// recordCounter sits between the raw TCP conn and tls.Conn during the handshake
// It counts TLS application_data records (type 0x17) going through so we can figure out the right RX record sequence number during kTLS setup
type recordCounter struct {
	net.Conn

	headerBuf [5]byte
	headerN   int

	bodyRem int
	inBody  bool

	appRecords int // 0x17 records seen so far (+ Finished)
	partial    bool
}

func (rc *recordCounter) Read(b []byte) (int, error) {
	n, err := rc.Conn.Read(b)
	if n > 0 {
		rc.parse(b[:n])
	}

	return n, err
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
				if rc.headerBuf[0] == 0x17 {
					rc.appRecords++
				}

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

		// full record consumed, count it if it's app data
		data = data[rc.bodyRem:]
		rc.bodyRem = 0
		rc.inBody = false
		rc.partial = false

		if rc.headerBuf[0] == 0x17 {
			rc.appRecords++
		}
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
