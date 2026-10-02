// Codes for email verification.
package generation

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateCode returns a six digit code, zero padded, drawn from the system
// source rather than math/rand: it guards an account.
func GenerateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n), nil
}
