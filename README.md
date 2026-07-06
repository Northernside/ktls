# kTLS

A Go library that offloads TLS encryption to the Linux kernel. It wraps `net.Listener` so you can use it with `net/http` (or anything that accepts a `net.Listener`) without changing your application code.

The TLS handshake still happens in userspace via `crypto/tls`. After the handshake completes, the library extracts the negotiated keys and hands them to the kernel via `setsockopt`. From that point on, the kernel handles record encryption and decryption directly, bypassing the userspace TLS stack entirely.

If kTLS setup fails for any reason (unsupported kernel, unsupported cipher, missing module), the connection silently falls back to regular userspace TLS. Your server keeps working either way.

Only TLS 1.3 connections get offloaded. TLS 1.2 connections work fine but stay in userspace (working on adding support for kTLS 1.2).

See the [kernel TLS docs](https://docs.kernel.org/networking/tls.html) for background on how kTLS works at the kernel level.

## Requirements

- Linux with the `tls` kernel module loaded (`modprobe tls`)
- Go 1.24+
- TLS 1.3, or TLS 1.2 with an AES-GCM cipher suite

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

## Key updates (TLS 1.3)

TLS 1.3 peers can send a `KeyUpdate` at any point on a long-lived connection. The kernel will not deliver a control record to a plain `read()` - it returns `EIO` (some kernels signal `EKEYEXPIRED` instead). The library detects this, fetches the record with `recvmsg` plus the `TLS_GET_RECORD_TYPE` control message, and:

- on a peer `KeyUpdate`, derives the next RX traffic secret (`"traffic upd"`, RFC 8446 §7.2), re-arms the kernel's RX key, then resumes reading
- if the peer set `update_requested`, sends its own `KeyUpdate` (RFC 8446 §4.6.3) via `sendmsg` with the record-type control message and rotates the TX key (serialized against concurrent writes)

Your application code doesn't need to do anything.

TLS 1.2 has no KeyUpdate. Renegotiation is not supported (the connection is closed if a peer attempts it).

## Supported ciphers

**TLS 1.3** - all three suites (the only ones defined by RFC 8446):

- `TLS_AES_128_GCM_SHA256` (0x1301)
- `TLS_AES_256_GCM_SHA384` (0x1302)
- `TLS_CHACHA20_POLY1305_SHA256` (0x1303)

**TLS 1.2** - the AES-GCM suites:

- `TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256` (0xC02F / 0xC02B)
- `TLS_ECDHE_{RSA,ECDSA}_WITH_AES_256_GCM_SHA384` (0xC030 / 0xC02C)

Anything else (CBC suites, TLS 1.2 ChaCha20-Poly1305) stays in userspace.

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

Connections that were successfully offloaded satisfy `ktls.Conn` (a `net.Conn` that also implements `syscall.Conn` and exposes `ConnectionState()` / `DidResume()`). Type-assert to it to distinguish kTLS-active connections from userspace fallbacks, or to reach the raw fd for `sendfile` / `splice`.

### `Available() bool`

Returns true if the kernel supports kTLS. Tries to set `TCP_ULP` on a throwaway socket.

## HTTP/3

HTTP/3 is not supported. kTLS hooks into the TCP stack via `TCP_ULP`, but HTTP/3 runs over QUIC (UDP), so kernel TLS offloading cannot apply.

## Non-linux platforms

Everything compiles on all platforms. `Available()` returns false, and connections always use userspace TLS.
