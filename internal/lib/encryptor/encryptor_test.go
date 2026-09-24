package encryptor

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestE2E_EncryptDecryptString(t *testing.T) {
	testCases := []struct {
		name        string
		masterkey   string
		data        string
		isValid     bool
		expectedErr error
	}{
		{
			name:      "success",
			masterkey: "1234567890123456", // len = 16
			data:      "secret information",
			isValid:   true,
		},
		{
			name:        "invalid masterkey",
			masterkey:   "12345",
			data:        "sss",
			isValid:     false,
			expectedErr: lenErr,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.isValid {
				s, err := EncryptString([]byte(tc.masterkey), []byte(tc.data))
				require.NoError(t, err)
				ds, err := DecryptString([]byte(tc.masterkey), s)
				assert.NoError(t, err)
				assert.Equal(t, tc.data, ds)
			} else {
				s, err := EncryptString([]byte(tc.masterkey), []byte(tc.data))
				assert.Error(t, err)
				assert.Equal(t, err, lenErr)
				assert.Empty(t, s)
			}
		})
	}
}

// --- added coverage -------------------------------------------------------

func TestDecryptString_ShortCiphertextDoesNotPanic(t *testing.T) {
	// DecryptString slices the nonce off the front without checking the length
	// first, so a value shorter than the nonce panics instead of returning an
	// error. The input is attacker-influenced in the sense that it comes from
	// a database column, so a truncated or corrupted row takes the process
	// down rather than failing one request.
	key := []byte("12345678901234567890123456789012")

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"one byte", base64.StdEncoding.EncodeToString([]byte("x"))},
		{"shorter than the nonce", base64.StdEncoding.EncodeToString(make([]byte, 5))},
		{"exactly the nonce, no payload", base64.StdEncoding.EncodeToString(make([]byte, 12))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := DecryptString(key, tc.input)
				require.Error(t, err)
			})
		})
	}
}

func TestDecryptString_RejectsInvalidBase64(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	_, err := DecryptString(key, "!!!not base64!!!")
	require.Error(t, err)
}

func TestDecryptString_RejectsTamperedCiphertext(t *testing.T) {
	// GCM is authenticated: flipping a byte must fail rather than decrypt.
	key := []byte("12345678901234567890123456789012")
	sealed, err := EncryptString(key, []byte("app-secret"))
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(sealed)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0xFF

	_, err = DecryptString(key, base64.StdEncoding.EncodeToString(raw))
	require.Error(t, err)
}

func TestDecryptString_WrongKeyFails(t *testing.T) {
	sealed, err := EncryptString([]byte("12345678901234567890123456789012"), []byte("app-secret"))
	require.NoError(t, err)

	_, err = DecryptString([]byte("22345678901234567890123456789012"), sealed)
	require.Error(t, err)
}

func TestKeyLengthValidation(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("accepts %d bytes", size), func(t *testing.T) {
			key := bytes.Repeat([]byte("a"), size)
			sealed, err := EncryptString(key, []byte("payload"))
			require.NoError(t, err)

			out, err := DecryptString(key, sealed)
			require.NoError(t, err)
			require.Equal(t, "payload", out)
		})
	}

	for _, size := range []int{0, 1, 15, 17, 31, 33, 64} {
		t.Run(fmt.Sprintf("rejects %d bytes", size), func(t *testing.T) {
			key := bytes.Repeat([]byte("a"), size)
			_, err := EncryptString(key, []byte("payload"))
			require.Error(t, err)
			_, err = DecryptString(key, "anything")
			require.Error(t, err)
		})
	}
}

// A fresh nonce per call means the same plaintext never encrypts to the same
// ciphertext; otherwise identical application secrets would be linkable.
func TestEncryptString_NonceIsFreshPerCall(t *testing.T) {
	key := []byte("12345678901234567890123456789012")

	first, err := EncryptString(key, []byte("same-input"))
	require.NoError(t, err)
	second, err := EncryptString(key, []byte("same-input"))
	require.NoError(t, err)

	require.NotEqual(t, first, second)

	a, err := DecryptString(key, first)
	require.NoError(t, err)
	b, err := DecryptString(key, second)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

func TestPasswordHasher_Compare(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("Password1"), bcrypt.MinCost)
	require.NoError(t, err)

	ph := NewPasswordHasher()
	require.NoError(t, ph.Compare(hash, []byte("Password1")))
	require.Error(t, ph.Compare(hash, []byte("Password2")))
	require.Error(t, ph.Compare([]byte("not-a-hash"), []byte("Password1")))
	require.Error(t, ph.Compare(nil, []byte("Password1")))
}
