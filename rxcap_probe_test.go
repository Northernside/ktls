//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProbeRXSpliceMaxLen(t *testing.T) {
	for _, L := range []int{16384, 65536, 131072, 262144, 524288, 1048576} {
		ln, addr := ktlsServer(t)
		payload := bytes.Repeat([]byte("x"), 200*1024)
		go func() {
			c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
			if err != nil {
				return
			}
			c.Write(payload)
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}()
		conn, _ := ln.Accept()
		kc := conn.(Conn)
		kc.SetReadDeadline(time.Now().Add(2 * time.Second))
		var pf [2]int
		unix.Pipe2(pf[:], unix.O_NONBLOCK|unix.O_CLOEXEC)
		unix.FcntlInt(uintptr(pf[0]), unix.F_SETPIPE_SZ, 1<<20)
		sc, _ := kc.SyscallConn()
		var einval, ok bool
		sc.Read(func(fd uintptr) bool {
			n, e := unix.Splice(int(fd), nil, pf[1], nil, L, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if e == syscall.EAGAIN {
				return false
			}
			if e == syscall.EINVAL {
				einval = true
			} else if e == nil && n > 0 {
				ok = true
			}
			return true
		})
		t.Logf("len=%7d -> EINVAL=%v ok=%v", L, einval, ok)
		unix.Close(pf[0])
		unix.Close(pf[1])
		conn.Close()
	}
}
