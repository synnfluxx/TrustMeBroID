package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
)

var lenErr = errors.New("masterkey must be 16, 24 or 32 characters")

func EncryptString(masterkey []byte, data []byte) (string, error) {
	switch len(masterkey) {
	case 16, 24, 32:
	default:
		return "", lenErr
	}

	block, err := aes.NewCipher(masterkey)
	if err != nil {
		return "", err
	}

	aesGSM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGSM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	seal := aesGSM.Seal(nonce, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(seal), nil
}

func DecryptString(masterkey []byte, encoded string) (string, error) {
	switch len(masterkey) {
	case 16, 24, 32:
	default:
		return "", lenErr
	}

	cipherText, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(masterkey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Slicing the nonce off without a length check panics on any stored value
	// shorter than the nonce, which takes the process down instead of failing
	// one decryption.
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", fmt.Errorf("ciphertext is %d bytes, shorter than the %d-byte nonce", len(cipherText), nonceSize)
	}

	nonce := cipherText[:nonceSize]
	data := cipherText[nonceSize:]

	plainText, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

type PasswordHasher struct{}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{}
}

func (ph *PasswordHasher) Compare(hash []byte, pw []byte) error {
	return bcrypt.CompareHashAndPassword(hash, pw)
}
