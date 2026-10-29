package secretcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// keysize will be 32bytes = 256 bits for AES-256
const KeySize = 32

type Ciphertext struct {
	//holds the encrypted bytes
	Ciphertext string `json:"ciphertext"`
	//holds the value needed to decrypt the bytes
	Nonce string `json:"nonce"`
}

// Envelope is an encrypted payload plus its independently generated and wrapped
// data-encryption key. KeyVersion identifies the key-encryption key used.
type Envelope struct {
	Ciphertext       string `json:"ciphertext"`
	Nonce            string `json:"nonce"`
	EncryptedDataKey string `json:"encrypted_data_key"`
	DataKeyNonce     string `json:"data_key_nonce"`
	KeyVersion       int    `json:"key_version"`
}

func RandomKey() ([]byte, error) {
	//allocate 32 byte slice
	key := make([]byte, KeySize)
	//
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

func SealEnvelope(kek, plaintext, aad []byte, keyVersion int) (Envelope, error) {
	dek, err := RandomKey()
	if err != nil {
		return Envelope{}, err
	}
	defer Zero(dek)
	payload, err := Encrypt(dek, plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}
	wrapped, err := Encrypt(kek, dek, append([]byte("wrapped-dek:"), aad...))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Ciphertext: payload.Ciphertext, Nonce: payload.Nonce,
		EncryptedDataKey: wrapped.Ciphertext, DataKeyNonce: wrapped.Nonce, KeyVersion: keyVersion}, nil
}

func OpenEnvelope(kek []byte, envelope Envelope, aad []byte) ([]byte, error) {
	dek, err := Decrypt(kek, Ciphertext{Ciphertext: envelope.EncryptedDataKey, Nonce: envelope.DataKeyNonce}, append([]byte("wrapped-dek:"), aad...))
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}
	defer Zero(dek)
	return Decrypt(dek, Ciphertext{Ciphertext: envelope.Ciphertext, Nonce: envelope.Nonce}, aad)
}

func WrapKey(rootKey, key []byte) (Ciphertext, error) {
	return Encrypt(rootKey, key, []byte("distributed-secrets:kek:v1"))
}

func UnwrapKey(rootKey []byte, wrapped Ciphertext) ([]byte, error) {
	key, err := Decrypt(rootKey, wrapped, []byte("distributed-secrets:kek:v1"))
	if err != nil {
		return nil, fmt.Errorf("invalid unseal key: %w", err)
	}
	return key, nil
}

func Zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
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
