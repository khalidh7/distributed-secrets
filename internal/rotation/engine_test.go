package rotation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
)

type flakyExternal struct{ calls int }

func (f *flakyExternal) Rotate(_ context.Context, _ string, _ string) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("temporary external failure")
	}
	return nil
}

type fakeExternal struct{ password string }

func (f *fakeExternal) Rotate(_ context.Context, _ string, password string) error {
	f.password = password
	return nil
}

type fakeSecrets struct{ value map[string]string }

func (f *fakeSecrets) WriteRotated(_ string, value map[string]string) error {
	f.value = value
	return nil
}
func (f *fakeSecrets) ReadRotated(_ string) (map[string]string, error) { return f.value, nil }
func TestRotationCompletesWithoutPlaintextPersistence(t *testing.T) {
	dir := t.TempDir()
	key, _ := secretcrypto.RandomKey()
	external := &fakeExternal{}
	secrets := &fakeSecrets{}
	engine, err := Open(dir, key, external, secrets)
	if err != nil {
		t.Fatal(err)
	}
	record, err := engine.Start(context.Background(), "prod/db", "app", map[string]string{"username": "app", "password": "old"})
	if err != nil {
		t.Fatal(err)
	}
	if record.Stage != Complete || external.password == "" || secrets.value["password"] != external.password {
		t.Fatalf("rotation: %#v", record)
	}
	disk, _ := os.ReadFile(dir + "/rotations.json")
	if bytes.Contains(disk, []byte(external.password)) {
		t.Fatal("rotation password leaked to disk")
	}
}
func TestRotationRetryResumesPendingCredential(t *testing.T) {
	dir := t.TempDir()
	key, _ := secretcrypto.RandomKey()
	external := &flakyExternal{}
	secrets := &fakeSecrets{value: map[string]string{"username": "app", "password": "old"}}
	engine, _ := Open(dir, key, external, secrets)
	record, err := engine.Start(context.Background(), "prod/db", "app", secrets.value)
	if err == nil || record.Stage != Pending {
		t.Fatalf("first attempt: %#v %v", record, err)
	}
	retried, err := engine.Retry(context.Background(), record.ID)
	if err != nil || retried.Stage != Complete {
		t.Fatalf("retry: %#v %v", retried, err)
	}
	if external.calls != 2 {
		t.Fatalf("external calls: %d", external.calls)
	}
}
