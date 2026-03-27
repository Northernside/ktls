//go:build linux

package ktls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	solTLS = 0x11a // SOL_TLS from linux/tls.h (https://docs.kernel.org/networking/tls.html)
	tlsTX  = 1
	tlsRX  = 2

	tlsVersionTLS13 = 0x0304
)

type cipherParams struct {
	kernelCipher uint16
	keyLen       int
	ivLen        int
	saltLen      int
	secretLen    int // hash output length, also the traffic secret length
	hashFunc     func() hash.Hash
	infoSize     uintptr
}

var cipherLookup = map[uint16]cipherParams{ // only three defined by RFC 8446
	0x1301: {51, 16, 8, 4, 32, sha256.New, 40},    // AES-128-GCM
	0x1302: {52, 32, 8, 4, 48, sha512.New384, 56}, // AES-256-GCM
	0x1303: {54, 32, 12, 0, 32, sha256.New, 56},   // ChaCha20-Poly1305

	// todo: add support for TLS 1.2 cipher suites
}

// crypto_info structs all start with a 4 byte header (uint16 version + uint16 cipher type)
// then iv, key, salt, recSeq
func buildCryptoInfo(secret []byte, cipherSuiteID uint16, recSeq uint64) (unsafe.Pointer, uintptr, error) {
	// hank, do NOT abbreviate ciperParams with cp
	cp, ok := cipherLookup[cipherSuiteID]
	if !ok {
		return nil, 0, fmt.Errorf("ktls: unsupported cipher suite 0x%04x", cipherSuiteID)
	}

	// kTLS expects the key and IV to be derived from the traffic secret
	// using HKDF-Expand-Label with "key" and "iv" labels respectively (RFC 8446 7.1)
	key, err := hkdfExpandLabel(secret, "key", cp.keyLen, cp.hashFunc)
	if err != nil {
		return nil, 0, err
	}

	iv, err := hkdfExpandLabel(secret, "iv", cp.saltLen+cp.ivLen, cp.hashFunc)
	if err != nil {
		return nil, 0, err
	}

	// construct the crypto_info struct for setsockopt
	buf := make([]byte, cp.infoSize)
	off := 0

	binary.LittleEndian.PutUint16(buf[off:], tlsVersionTLS13)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], cp.kernelCipher)
	off += 2

	copy(buf[off:], iv[cp.saltLen:])
	off += cp.ivLen

	copy(buf[off:], key)
	off += cp.keyLen

	copy(buf[off:], iv[:cp.saltLen])
	off += cp.saltLen

	binary.BigEndian.PutUint64(buf[off:], recSeq)

	return unsafe.Pointer(&buf[0]), cp.infoSize, nil
}

// enableKTLS sets up kTLS on the given connection with the provided secrets and cipher suite
// If rxSecret is nil, only TX will be enabled and the caller can choose to enable RX later when the secret is available (e.g. after a key update)
func enableKTLS(conn net.Conn, txSecret, rxSecret []byte, cipherSuiteID uint16, rxRecSeq uint64) (rxEnabled bool, err error) {
	fd, err := getRawFd(conn)
	if err != nil {
		return false, fmt.Errorf("ktls: get fd: %w", err)
	}

	if err := syscall.SetsockoptString(fd, syscall.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
		return false, fmt.Errorf("ktls: TCP_ULP: %w", err)
	}

	txInfo, txLen, err := buildCryptoInfo(txSecret, cipherSuiteID, 0)
	if err != nil {
		return false, err
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(solTLS),
		uintptr(tlsTX),
		uintptr(txInfo),
		txLen,
		0,
	)
	if errno != 0 {
		return false, fmt.Errorf("ktls: TLS_TX setsockopt: %w", errno)
	}

	if rxSecret == nil {
		return false, nil
	}

	rxInfo, rxLen, err := buildCryptoInfo(rxSecret, cipherSuiteID, rxRecSeq)
	if err != nil {
		return false, fmt.Errorf("ktls: RX build failed: %w", err)
	}

	_, _, errno = syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(solTLS),
		uintptr(tlsRX),
		uintptr(rxInfo),
		rxLen,
		0,
	)
	if errno != 0 {
		return false, fmt.Errorf("ktls: TLS_RX setsockopt: %w", errno)
	}

	return true, nil
}

// deriveNextSecret computes the next application traffic secret (RFC 8446 7.2)
// application_traffic_secret_N+1 = HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
func deriveNextSecret(currentSecret []byte, cipherSuiteID uint16) ([]byte, error) {
	cp, ok := cipherLookup[cipherSuiteID]
	if !ok {
		return nil, fmt.Errorf("ktls: unsupported cipher suite 0x%04x", cipherSuiteID)
	}

	return hkdfExpandLabel(currentSecret, "traffic upd", cp.secretLen, cp.hashFunc)
}

// provides kTLS RX with a new secret, used when the peer initiates a key update
// https://docs.kernel.org/networking/tls.html#tls-1-3-key-updates
func updateRX(fd int, secret []byte, cipherSuiteID uint16) error {
	info, infoLen, err := buildCryptoInfo(secret, cipherSuiteID, 0) // reqSec is ignored for RX updates
	if err != nil {
		return err
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(solTLS),
		uintptr(tlsRX),
		uintptr(info),
		infoLen,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("ktls: TLS_RX update setsockopt: %w", errno)
	}

	return nil
}

// triggered from a recv syscall
// indicates that the peer has initiated a key update
func isEKEYEXPIRED(err error) bool {
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return errno == unix.EKEYEXPIRED
	}

	return false
}

// trying to set TCP_ULP on a throwaway socket to check for kTLS support
func Available() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptString(fd, syscall.SOL_TCP, unix.TCP_ULP, "tls")
	return err == nil
}

// TLS 1.3 HKDF-Expand-Label RFC 8446 sec 7.1
func hkdfExpandLabel(secret []byte, label string, length int, hashFunc func() hash.Hash) ([]byte, error) {
	fullLabel := "tls13 " + label

	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1)
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = 0

	return hkdf.Expand(hashFunc, secret, string(hkdfLabel), length)
}
