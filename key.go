package ktls

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// client_random is always 32 bytes = 64 hex chars
const clientRandomHexLen = 64

// max secret is 48 bytes (SHA-384 for AES-256-GCM)
const maxSecretHexLen = 96

// parseTrafficSecret decodes the secret into dst and returns the
// populated slice. dst must be at least 48 bytes
// using this approach to avoid an extra allocation for the decoded secret
// <label> <client_random> <hex secret>\n
func parseTrafficSecret(keyLog, prefix string, dst []byte) ([]byte, error) {
	for line := range strings.SplitSeq(keyLog, "\n") {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if len(line) < len(prefix) || line[:len(prefix)] != prefix {
			continue
		}

		rest := line[len(prefix):]
		if len(rest) < clientRandomHexLen+1 || rest[clientRandomHexLen] != ' ' {
			continue
		}

		hexSecret := rest[clientRandomHexLen+1:]
		if len(hexSecret) > maxSecretHexLen {
			continue
		}

		n, err := hex.Decode(dst, []byte(hexSecret))
		if err != nil {
			continue
		}

		return dst[:n], nil
	}

	return nil, fmt.Errorf("ktls: %snot found in key log", prefix)
}
