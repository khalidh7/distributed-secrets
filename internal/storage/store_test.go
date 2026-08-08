package storage

import (
	"bytes"
	"os"
	"testing"

	secretcrypto "github.com/example/distributed-secrets/internal/crypto"
)

func TestEncryptedPersistenceAndRestart(t *testing.T) {
	dir := t.TempDir()
	key, err := secretcrypto.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("prod/database", map[string]string{"username": "app", "password": "supersecret"}); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(store.file)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{[]byte("supersecret"), []byte("username"), []byte("password")} {
		if bytes.Contains(onDisk, plaintext) {
			t.Fatalf("plaintext %q leaked to disk", plaintext)
		}
	}
	reopened, err := Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get("prod/database")
	if err != nil {
		t.Fatal(err)
	}
	if got["password"] != "supersecret" || got["username"] != "app" {
		t.Fatalf("unexpected secret: %#v", got)
	}
}

func TestWrongKeyCannotDecrypt(t *testing.T) {
	dir := t.TempDir()
	key, _ := secretcrypto.RandomKey()
	store, _ := Open(dir, key)
	if err := store.Put("prod/database", map[string]string{"password": "secret"}); err != nil {
		t.Fatal(err)
	}
	wrongKey, _ := secretcrypto.RandomKey()
	reopened, err := Open(dir, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Get("prod/database"); err == nil {
		t.Fatal("expected decryption with wrong key to fail")
	}
}
