package tokengenerator

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateToken_LengthAndAlphabet(t *testing.T) {
	token, err := GenerateToken()
	require.NoError(t, err)

	// 32 random bytes, raw-url base64: 43 characters, no padding.
	require.Len(t, token, 43)
	require.NotContains(t, token, "=")
	require.NotContains(t, token, "+")
	require.NotContains(t, token, "/")

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)
	require.Len(t, decoded, 32)
}

// The token goes into a verification URL, so it must survive being placed in a
// query string without escaping.
func TestGenerateToken_IsURLSafe(t *testing.T) {
	for range 100 {
		token, err := GenerateToken()
		require.NoError(t, err)
		for _, r := range token {
			isSafe := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			require.True(t, isSafe, "token contains a character that needs escaping: %q", r)
		}
	}
}

func TestGenerateToken_NoRepeats(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for range n {
		token, err := GenerateToken()
		require.NoError(t, err)
		_, dup := seen[token]
		require.False(t, dup, "generated a duplicate token")
		seen[token] = struct{}{}
	}
}
