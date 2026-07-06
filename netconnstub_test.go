package ktls

import (
	"net"
	"time"
)

type netConnStub struct{}

func (netConnStub) Write(b []byte) (int, error)      { return len(b), nil }
func (netConnStub) Close() error                     { return nil }
func (netConnStub) LocalAddr() net.Addr              { return nil }
func (netConnStub) RemoteAddr() net.Addr             { return nil }
func (netConnStub) SetDeadline(time.Time) error      { return nil }
func (netConnStub) SetReadDeadline(time.Time) error  { return nil }
func (netConnStub) SetWriteDeadline(time.Time) error { return nil }
