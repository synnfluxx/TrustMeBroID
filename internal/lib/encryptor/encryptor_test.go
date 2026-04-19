package encryptor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
