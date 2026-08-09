//go:build linux

package ktls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tlsVersionTLS12 = 0x0303

// tls12Params describes an offloadable TLS 1.2 AEAD suite (AES-GCM or ChaCha20-Poly1305)
// the two families pack crypto_info differently, see gcm
type tls12Params struct {
	kernelCipher uint16
	keyLen       int
	fixedIVLen   int // write_IV length in the key block: 4 (GCM) or 12 (ChaCha20)
	prfHash      func() hash.Hash
	infoSize     uintptr
	gcm          bool // GCM: iv = 8-byte explicit nonce (seq), salt = fixedIV.
	// ChaCha20 (RFC 7905): iv = the 12-byte fixed IV, no salt, nonce = iv XOR seq
}

// keyed by cipher suite
// only the bulk AEAD matters to the kernel, so the key exchange (ECDHE / RSA)
// is irrelevant and every suite of a given AEAD maps to the same params
// the PRF hash is fixed by the suite's SHA variant
var tls12Lookup = map[uint16]tls12Params{
	0xC02B: {51, 16, 4, sha256.New, 40, true},    // ECDHE_ECDSA_AES_128_GCM_SHA256
	0xC02F: {51, 16, 4, sha256.New, 40, true},    // ECDHE_RSA_AES_128_GCM_SHA256
	0x009C: {51, 16, 4, sha256.New, 40, true},    // RSA_AES_128_GCM_SHA256
	0xC02C: {52, 32, 4, sha512.New384, 56, true}, // ECDHE_ECDSA_AES_256_GCM_SHA384
	0xC030: {52, 32, 4, sha512.New384, 56, true}, // ECDHE_RSA_AES_256_GCM_SHA384
	0x009D: {52, 32, 4, sha512.New384, 56, true}, // RSA_AES_256_GCM_SHA384
	0xCCA8: {54, 32, 12, sha256.New, 56, false},  // ECDHE_RSA_CHACHA20_POLY1305
	0xCCA9: {54, 32, 12, sha256.New, 56, false},  // ECDHE_ECDSA_CHACHA20_POLY1305
}

// tls12PRF is the TLS 1.2 PRF (RFC 5246 5)
// PRF(secret, label, seed) = P_hash(secret, label + seed)
// where P_hash(secret, seed) = HMAC(secret, A(1)+seed) | HMAC(secret, A(2)+seed) | ...
// A(0)=seed, A(i)=HMAC(secret, A(i-1))
func tls12PRF(secret []byte, label string, seed, out []byte, h func() hash.Hash) {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)

	a := labelSeed // A(0)

	for n := 0; n < len(out); {
		am := hmac.New(h, secret)
		am.Write(a)
		a = am.Sum(nil) // A(i)

		bm := hmac.New(h, secret)
		bm.Write(a)
		bm.Write(labelSeed)
		n += copy(out[n:], bm.Sum(nil))
	}
}

// deriveTLS12KeyBlock runs the key_expansion PRF and slices out the AEAD write
// keys and fixed IVs
// key_block = PRF(master, "key expansion", server_random + client_random)
// order (no MAC keys for AEAD):
// client_write_key | server_write_key | client_write_IV | server_write_IV
func deriveTLS12KeyBlock(master, clientRandom, serverRandom []byte, p tls12Params) (serverKey, serverIV, clientKey, clientIV []byte) {
	seed := make([]byte, 0, 64)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	kb := make([]byte, 2*p.keyLen+2*p.fixedIVLen)
	tls12PRF(master, "key expansion", seed, kb, p.prfHash)

	off := 0
	clientKey = kb[off : off+p.keyLen]
	off += p.keyLen
	serverKey = kb[off : off+p.keyLen]
	off += p.keyLen
	clientIV = kb[off : off+p.fixedIVLen]
	off += p.fixedIVLen
	serverIV = kb[off : off+p.fixedIVLen]

	return
}

// buildCryptoInfo12 packs a tls12_crypto_info_aes_gcm struct: version, cipher,
// iv(8), key, salt(4), rec_seq(8)
// for TLS 1.2 GCM the 8-byte explicit nonce is the record sequence number
// (matching crypto/tls and OpenSSL), so iv and rec_seq both start at the
// post handshake sequence value
func buildCryptoInfo12(key, fixedIV []byte, recSeq uint64, p tls12Params) (unsafe.Pointer, uintptr) {
	buf := make([]byte, p.infoSize)
	off := 0
	binary.LittleEndian.PutUint16(buf[off:], tlsVersionTLS12)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], p.kernelCipher)
	off += 2

	if p.gcm {
		binary.BigEndian.PutUint64(buf[off:], recSeq) // iv = explicit nonce = seq
		off += 8
		copy(buf[off:], key)
		off += p.keyLen
		copy(buf[off:], fixedIV) // salt = 4-byte fixed IV
		off += p.fixedIVLen
	} else {
		copy(buf[off:], fixedIV) // ChaCha20: iv = 12-byte fixed IV, no salt
		off += p.fixedIVLen
		copy(buf[off:], key)
		off += p.keyLen
	}

	binary.BigEndian.PutUint64(buf[off:], recSeq) // rec_seq

	return unsafe.Pointer(&buf[0]), p.infoSize
}

// pulls client_random and master_secret out of the NSS-keylog
// "CLIENT_RANDOM <client_random> <master_secret>"
// clientRandom must be >=32, master >=48 bytes
func parseClientRandomLine(keyLog string, clientRandom, master []byte) (int, int, error) {
	const prefix = "CLIENT_RANDOM "
	for line := range strings.SplitSeq(keyLog, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		rest := line[len(prefix):]

		sp := strings.IndexByte(rest, ' ')
		if sp != 64 { // client_random is always 32 bytes = 64 hex chars
			continue
		}

		cn, e := hex.Decode(clientRandom, []byte(rest[:64]))
		if e != nil {
			continue
		}

		mn, e := hex.Decode(master, []byte(rest[65:]))
		if e != nil {
			continue
		}

		return cn, mn, nil
	}

	return 0, 0, errors.New("ktls: CLIENT_RANDOM not found in key log")
}

// installs pre-built TLS 1.2 crypto_info for both directions
func enableKTLS12(fd int, txInfo unsafe.Pointer, txLen uintptr, rxInfo unsafe.Pointer, rxLen uintptr) error {
	err := syscall.SetsockoptString(fd, syscall.SOL_TCP, unix.TCP_ULP, "tls")
	if err != nil {
		return fmt.Errorf("ktls: TCP_ULP: %w", err)
	}

	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(solTLS), uintptr(tlsTX), uintptr(txInfo), txLen, 0); errno != 0 {
		return fmt.Errorf("ktls: TLS_TX setsockopt: %w", errno)
	}

	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(solTLS), uintptr(tlsRX), uintptr(rxInfo), rxLen, 0); errno != 0 {
		return fmt.Errorf("ktls: TLS_RX setsockopt: %w", errno)
	}

	return nil
}

// setupKTLS12 offloads a completed TLS 1.2 handshake, it reruns the PRF
// from the master secret + randoms (crypto/tls does not expose the derived keys),
// builds the crypto_info for both directions and hands them to the kernel
// returns nil (userspace fallback) for unsupported ciphers or any failure
func (l *Listener) setupKTLS12(rawConn net.Conn, counter *recordCounter, state tls.ConnectionState, keyBuf *keyLogBuffer) *conn {
	p, ok := tls12Lookup[state.CipherSuite]
	if !ok {
		return nil // non-AEAD / ChaCha20 -> userspace
	}

	var (
		clientRandom [32]byte
		master       [48]byte
	)

	crN, mN, err := parseClientRandomLine(keyBuf.String(), clientRandom[:], master[:])
	if err != nil || crN != 32 || mN != 48 {
		l.onError(fmt.Errorf("ktls12: key log: %w", err))

		return nil
	}

	serverRandom, ok := counter.serverRandom()
	if !ok {
		l.onError(errors.New("ktls12: server_random not captured from ServerHello"))

		return nil
	}

	serverKey, serverIV, clientKey, clientIV := deriveTLS12KeyBlock(master[:], clientRandom[:], serverRandom, p)

	// both sides sent exactly their Finished (seq 0) under the new cipher, so the
	// next record is seq 1. RX uses the observed post-CCS count for robustness
	rxSeq := uint64(counter.postCCSCount())
	if rxSeq == 0 {
		rxSeq = 1
	}

	const txSeq = 1

	txInfo, txLen := buildCryptoInfo12(serverKey, serverIV, txSeq, p)
	rxInfo, rxLen := buildCryptoInfo12(clientKey, clientIV, rxSeq, p)

	fd, err := getRawFd(rawConn)
	if err != nil {
		l.onError(err)

		return nil
	}

	if err := enableKTLS12(fd, txInfo, txLen, rxInfo, rxLen); err != nil {
		l.onError(err)

		return nil
	}

	// TLS 1.2 has no KeyUpdate, so rxSecret/txSecret stay nil (no post handshake rekey machinery)
	// renegotiation is not supported by kTLS
	return &conn{
		Conn:          rawConn,
		state:         state,
		fd:            fd,
		cipherSuiteID: state.CipherSuite,
	}
}
