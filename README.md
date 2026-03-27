# go-ktls

A Go library that offloads TLS encryption to the Linux kernel. It wraps `net.Listener` so you can use it with `net/http` (or anything that accepts a `net.Listener`) without changing your application code.

The TLS handshake still happens in userspace via `crypto/tls`. After the handshake completes, the library extracts the negotiated keys and hands them to the kernel via `setsockopt`. From that point on, the kernel handles record encryption and decryption directly, bypassing the userspace TLS stack entirely.

If kTLS setup fails for any reason (unsupported kernel, wrong cipher, missing module), the connection silently falls back to regular userspace TLS. Your server keeps working either way.

Only TLS 1.3 connections get offloaded. TLS 1.2 connections work fine but stay in userspace (working on adding support for kTLS 1.2).

See the [kernel TLS offload docs](https://docs.kernel.org/networking/tls-offload.html) for background on how kTLS works at the kernel level.

## Requirements

- Linux with the `tls` kernel module loaded (`modprobe tls`)
- Go 1.24+
- TLS 1.3

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

    ktls "github.com/northernside/http-ktls"
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
        RX: true, // also offload decryption (not just encryption), opt in for now because of possible instability
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

`Request.TLS` is populated correctly even when kTLS is active, so middleware that checks for TLS (HSTS, cert info, etc.) works as expected.

## How it works

1. `Listener.Accept()` accepts a TCP connection and does a normal TLS 1.3 handshake via `crypto/tls`
2. During the handshake, a `KeyLogWriter` captures the traffic secrets that `crypto/tls` outputs in NSS key log format
3. A record counter sits between the raw TCP connection and `tls.Conn`, counting application data records to determine the correct RX sequence number
4. Any data already decrypted by `tls.Conn` during the handshake gets drained so it's not lost
5. The library parses the key log to extract `SERVER_TRAFFIC_SECRET_0` and `CLIENT_TRAFFIC_SECRET_0`, derives the encryption key and IV via HKDF-Expand-Label (RFC 8446 section 7.1), and packs them into the kernel's `crypto_info` struct
6. `setsockopt` with `SOL_TLS` / `TLS_TX` / `TLS_RX` hands the keys to the kernel
7. The returned `net.Conn` reads and writes directly through the kernel TLS layer

If any step fails, `Accept()` returns the original `tls.Conn` and calls `OnError`. The connection works fine either way.

## RX key updates

When a TLS 1.3 client sends a KeyUpdate message, the kernel pauses decryption and returns `EKEYEXPIRED` on the next read. The library handles this transparently: it derives the next traffic secret using HKDF-Expand-Label with the `"traffic upd"` label (RFC 8446 section 7.2), re-arms the kernel with the new key via `setsockopt`, and retries the read. Your application code doesn't need to do anything.

## Supported ciphers

All three TLS 1.3 cipher suites defined by RFC 8446:

- `TLS_AES_128_GCM_SHA256` (0x1301)
- `TLS_AES_256_GCM_SHA384` (0x1302)
- `TLS_CHACHA20_POLY1305_SHA256` (0x1303)

These are the only cipher suites in TLS 1.3, so all TLS 1.3 connections are eligible for offloading.

## API

### `Listener`

```go
type Listener struct {
    TCPListener net.Listener
    TLSConfig   *tls.Config
    RX          bool
    OnError     func(error)
}
```

Implements `net.Listener`. Pass it to `http.Serve`, `http.Server.Serve`, or anything else that takes a listener.

- `TCPListener` -- the underlying TCP listener
- `TLSConfig` -- standard `crypto/tls` config. Must have at least one certificate
- `RX` -- enable kernel-side decryption. TX (encryption) is always enabled when kTLS is active
- `OnError` -- called when kTLS setup fails on a connection. The connection still works through userspace TLS. nil means silently ignore errors

### `Available() bool`

Returns true if the kernel supports kTLS. Tries to set `TCP_ULP` on a throwaway socket.

## Non-linux platforms

Everything compiles on all platforms. `Available()` returns false, and connections always use userspace TLS.
