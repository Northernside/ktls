//go:build !linux

package ktls

import "io"

func (c *conn) spliceReadFrom(io.Reader, SpliceConfig) (int64, bool, error) {
	return 0, false, nil
}
