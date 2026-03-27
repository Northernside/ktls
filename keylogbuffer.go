package ktls

import (
	"bytes"
	"sync"
)

type keyLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (k *keyLogBuffer) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.buf.Write(p)
}

func (k *keyLogBuffer) String() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.buf.String()
}
