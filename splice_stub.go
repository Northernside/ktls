//go:build !linux

package ktls

import "io"

func (c *conn) spliceReadFrom(io.Reader, SpliceConfig) (int64, bool, error) {
	return 0, false, nil
}

func (c *conn) spliceWriteTo(io.Writer, SpliceConfig) (int64, bool, error) {
	return 0, false, nil
}
