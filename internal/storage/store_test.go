package storage

import (
	"bytes"
	"errors"
	"os"
	"testing"

	secretcrypto "github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
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

func TestImmutableVersionsAndSoftDelete(t *testing.T) {
	key, _ := secretcrypto.RandomKey()
	store, _ := Open(t.TempDir(), key)
	first, _ := store.PutVersion("prod/db", map[string]string{"password": "one"})
	second, _ := store.PutVersion("prod/db", map[string]string{"password": "two"})
	if first.Version != 1 || second.Version != 2 {
		t.Fatalf("versions: %d %d", first.Version, second.Version)
	}
	value, _ := store.GetVersion("prod/db", 1)
	if value["password"] != "one" {
		t.Fatalf("historical value: %#v", value)
	}
	if err := store.DeleteVersion("prod/db", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetVersion("prod/db", 1); !errors.Is(err, ErrDeleted) {
		t.Fatalf("deleted version: %v", err)
	}
	latest, _ := store.Get("prod/db")
	if latest["password"] != "two" {
		t.Fatalf("latest changed: %#v", latest)
	}
}
