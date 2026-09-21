// Lib for generating random tokens for email verification and other purposes.
package tokengenerator

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateToken() (string, error) {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
