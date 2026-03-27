package ktls

import (
	"errors"
	"net"
	"syscall"
)

func getRawFd(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return -1, errors.New("conn does not implement syscall.Conn")
	}

	rawConn, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}

	var fd int
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}

	return fd, nil
}
