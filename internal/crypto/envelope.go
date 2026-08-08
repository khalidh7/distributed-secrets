package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const KeySize = 32

type Ciphertext struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
}

func RandomKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	return key, nil
}

func EncodeKey(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

func DecodeKey(encoded string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != KeySize {
		return nil, errors.New("invalid key: expected a base64url-encoded 256-bit key")
	}
	return key, nil
}

func Encrypt(key, plaintext, aad []byte) (Ciphertext, error) {
	aead, err := newGCM(key)
	if err != nil {
		return Ciphertext{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Ciphertext{}, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return Ciphertext{
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
	}, nil
}

func Decrypt(key []byte, encrypted Ciphertext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, errors.New("decode nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, errors.New("decode ciphertext")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decrypt: authentication failed")
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("AES-256-GCM requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
