# kTLS

A Go library that offloads TLS encryption to the Linux kernel. It wraps `net.Listener` so you can use it with `net/http` (or anything that accepts a `net.Listener`) without changing your application code.

The TLS handshake still happens in userspace via `crypto/tls`. After the handshake completes, the library extracts the negotiated keys and hands them to the kernel via `setsockopt`. From that point on, the kernel handles record encryption and decryption directly, bypassing the userspace TLS stack entirely.

If kTLS setup fails for any reason (unsupported kernel, unsupported cipher, missing module), the connection silently falls back to regular userspace TLS. Your server keeps working either way.

Both TLS 1.3 and TLS 1.2 are offloaded, across every AEAD cipher suite they define (AES-GCM and ChaCha20-Poly1305). Legacy CBC suites can't be offloaded by kTLS (general kTLS constraint) and stay in userspace.

See the [kernel TLS docs](https://docs.kernel.org/networking/tls.html) for background on how kTLS works at the kernel level.

## Requirements

- Linux with the `tls` kernel module loaded (`modprobe tls`)
- Go 1.24+
- TLS 1.3 or TLS 1.2 with an AEAD cipher suite (AES-GCM or ChaCha20-Poly1305)

You can also check at runtime:

```go
if ktls.Available() {
    // kernel supports kTLS
}
```

## Usage

```go
package main

import (
    "crypto/tls"
    "fmt"
    "net"
    "net/http"

    ktls "github.com/northernside/ktls"
)

func main() {
    cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
    if err != nil {
        panic(err)
    }

    tcpLn, err := net.Listen("tcp", ":443")
    if err != nil {
        panic(err)
    }

    ln := &ktls.Listener{
        TCPListener: tcpLn,
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
        },
        OnError: func(err error) {
            fmt.Println("kTLS setup failed, using userspace TLS:", err)
        },
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "hello from kTLS")
    })

    http.Serve(ln, mux)
}
```

Both encryption (TX) and decryption (RX) are offloaded. `Request.TLS` is populated correctly even when kTLS is active, so middleware that checks for TLS (HSTS, cert info, etc.) works as expected.

## How it works

1. `Listener.Accept()` accepts a TCP connection and runs a normal TLS handshake via `crypto/tls`
2. During the handshake, a `KeyLogWriter` captures the key material `crypto/tls` outputs in NSS key log format
3. A record counter sits between the raw TCP connection and `tls.Conn`. It caps each read at the current TLS record boundary so `tls.Conn` cannot overread the next record's ciphertext into its internal buffer -> those bytes would be invisible to the kernel after the handoff and desync the record stream. It also observes the handshake records to compute the correct starting sequence numbers
4. The library derives the encryption keys, IVs, and record sequence numbers for both directions and packs them into the kernel's `crypto_info` struct:
   - **TLS 1.3**: from `SERVER_TRAFFIC_SECRET_0` / `CLIENT_TRAFFIC_SECRET_0` via HKDF-Expand-Label (RFC 8446 §7.1)
   - **TLS 1.2**: reruns the PRF (RFC 5246 §5) over the master secret and randoms to reproduce the key block (`crypto/tls` does not expose the derived keys). `server_random` is read from the ServerHello the library observes on the write path
5. `setsockopt` with `SOL_TLS` / `TLS_TX` / `TLS_RX` hands the keys to the kernel for both directions
6. The returned `net.Conn` reads and writes directly through the kernel TLS layer

If any step fails, `Accept()` returns the original `tls.Conn` and calls `OnError`. The connection works fine either way.

## Zerocopy (splice)

A kTLS-active `Conn` splices in both directions, so the payload never enters userspace and userspace never runs the cipher:

- **Send (TX)** (download/response) - `Conn` implements `io.ReaderFrom`. `io.Copy(conn, src)` splices src-fd -> pipe -> the kTLS socket (the kernel encrypts each chunk on the way out)
- **Receive (RX)** (upload/request) - `Conn` implements `io.WriterTo`. `io.Copy(dst, conn)` splices the kTLS socket -> pipe -> dst-fd (the kernel decrypts on the way out)

```go
// backend and conn are both raw-fd endpoints (conn is the kTLS Conn)
io.Copy(conn, backend) // download: splice into TX, kernel-encrypted
io.Copy(backend, conn) // upload:   splice out of RX, kernel-decrypted
```

There is no zerocopy `Write([]byte)` from a userspace buffer. The bytes already live in userspace and the cipher has to read them, so `copy_from_user` is unavoidable. Zerocopy only exists when both ends are file descriptors and the kernel can move the data itself. That's what `ReadFrom`/`WriteTo` (i.e. `io.Copy` to/from another fd) give you.

Encryption offload on its own is roughly a wash against Go's (already fast) userspace AES-GCM. The win comes from splice removing the userspace copy and the syscall overhead. On a plain proxy download it lands H1-style streaming within ~10% of the line rate at a fraction of the CPU. It only applies where the body is an untransformed byte stream from a raw fd. HTTP/2 (which frames in userspace), compressed, ranged, or otherwise transformed bodies can't splice and fall back automatically.

One asymmetry: splicing *out of* a kTLS socket (RX) only works for a fully-arrived record - when the next record is still partial the kernel returns `EINVAL`. `WriteTo` handles this transparently by falling back to a single buffered `Read` for that record (which also covers KeyUpdate and close_notify), so aligned records go zerocopy and awkward boundaries take one copy. On a fast local link most records splice. Over a lossy WAN more of them fall back.

### Peeking while you splice

Sometimes you want the first few bytes in userspace (log a line, sniff a content type, sample a body) without giving up zerocopy for the rest. `ReadFromConfig` / `WriteToConfig` copy a small leading window into userspace, hand it to a callback, then splice everything after it:

```go
// download: observe the first bytes we send
n, err := conn.ReadFromConfig(backend, ktls.SpliceConfig{
    PeekN: 512,
    Peek:  func(b []byte) { log.Printf("first %d bytes: %q", len(b), b) },
})

// upload: observe the first bytes we receive (e.g. request line + headers)
n, err := conn.WriteToConfig(backend, ktls.SpliceConfig{
    PeekN: 512,
    Peek:  func(b []byte) { log.Printf("upload head: %q", b) },
})
```

Only those first `PeekN` bytes cost a userspace copy; the remainder stays in the kernel. The peeked bytes are still forwarded - `Peek` is read-only (mutating the slice changes nothing) and the slice is valid only for the duration of the call, so copy out anything you keep.

Constraints:

- **Raw-fd endpoint only.** If the other end doesn't expose a file descriptor (or has buffered data pending in userspace), `ReadFrom`/`WriteTo` transparently fall back to a normal buffered copy. Correctness is never at stake, only the zerocopy fast path.
- **Keep `PeekN` small.** It's a few-KB window for headers/sniffing. A large `PeekN` just shrinks the zerocopy portion.
- **Don't interleave `Write`/`Read` with `ReadFrom`/`WriteTo` for one logical stream.** Both advance the kTLS record sequence. The peek is deliberately routed back through the splice/Read path for this reason. Interleaving sequences correctly on the kernels tested here, but routing a given stream through one path is the safe contract.
- **splice only, `net/http` unaffected.** `net/http` buffers bodies through its own writer, so it doesn't hit this path unless it takes its `sendfile` shortcut for a `*os.File` body - which is exactly the case splice is meant for.

## Key updates (TLS 1.3)

TLS 1.3 peers can send a `KeyUpdate` at any point on a long-lived connection. The kernel will not deliver a control record to a plain `read()` - it returns `EIO` (some kernels signal `EKEYEXPIRED` instead). The library detects this, fetches the record with `recvmsg` plus the `TLS_GET_RECORD_TYPE` control message, and:

- on a peer `KeyUpdate`, derives the next RX traffic secret (`"traffic upd"`, RFC 8446 §7.2), re-arms the kernel's RX key, then resumes reading
- if the peer set `update_requested`, sends its own `KeyUpdate` (RFC 8446 §4.6.3) via `sendmsg` with the record-type control message and rotates the TX key (serialized against concurrent writes)

Your application code doesn't need to do anything.

TLS 1.2 has no KeyUpdate. Renegotiation is not supported (the connection is closed if a peer attempts it).

## Supported ciphers

The kernel's `crypto_info` interface covers AES-GCM, ChaCha20-Poly1305, and AES-CCM, and nothing else. Every AEAD suite that TLS 1.3 and TLS 1.2 define is offloaded here:

**TLS 1.3** - all three suites (the only ones RFC 8446 defines):

- `TLS_AES_128_GCM_SHA256` (0x1301)
- `TLS_AES_256_GCM_SHA384` (0x1302)
- `TLS_CHACHA20_POLY1305_SHA256` (0x1303)

**TLS 1.2** - every AEAD suite. The key exchange (ECDHE / RSA) is irrelevant to the offload, so all variants of a given cipher are covered:

- `TLS_{ECDHE_ECDSA,ECDHE_RSA,RSA}_WITH_AES_128_GCM_SHA256` (0xC02B / 0xC02F / 0x009C)
- `TLS_{ECDHE_ECDSA,ECDHE_RSA,RSA}_WITH_AES_256_GCM_SHA384` (0xC02C / 0xC030 / 0x009D)
- `TLS_ECDHE_{RSA,ECDSA}_WITH_CHACHA20_POLY1305_SHA256` (0xCCA8 / 0xCCA9)

The legacy CBC suites (`AES_*_CBC_SHA`, 3DES, RC4) are the only ones left in userspace, and by design: they are MAC-then-encrypt, not AEAD, so the kernel has no interface to offload them (no TLS stack can). They are also deprecated and disabled by default in modern TLS configs. So in practice every cipher a current client negotiates gets offloaded.

## API

### `Listener`

```go
type Listener struct {
    TCPListener net.Listener
    TLSConfig   *tls.Config
    OnError     func(error)
}
```

Implements `net.Listener`. Pass it to `http.Serve`, `http.Server.Serve`, or anything else that takes a listener.

- `TCPListener` - the underlying TCP listener
- `TLSConfig` - standard `crypto/tls` config. Must have at least one certificate
- `OnError` - called when kTLS setup fails on a connection. The connection still works through userspace TLS. nil means silently ignore errors

### `Conn`

Connections that were successfully offloaded satisfy `ktls.Conn` (a `net.Conn` that also implements `syscall.Conn` and `io.ReaderFrom`, and exposes `ConnectionState()` / `DidResume()` / `ReadFromConfig()`). Type-assert to it to distinguish kTLS-active connections from userspace fallbacks, to reach the raw fd for `sendfile` / `splice`, or to drive zerocopy transfers (see [zerocopy](#zerocopy-splice)).

### `Available() bool`

Returns true if the kernel supports kTLS. Tries to set `TCP_ULP` on a throwaway socket.

## HTTP/3

HTTP/3 is not supported. kTLS hooks into the TCP stack via `TCP_ULP`, but HTTP/3 runs over QUIC (UDP), so kernel TLS offloading cannot apply.

## Non-linux platforms

Everything compiles on all platforms. `Available()` returns false, and connections always use userspace TLS.
