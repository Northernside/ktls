//go:build !linux

package ktls

func isPostHandshakeSignal(error) bool { return false }

func (c *conn) handlePostHandshake(readErr error) error { return readErr }
