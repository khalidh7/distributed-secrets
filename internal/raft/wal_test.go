package raft

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWALDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	wal, _, _, _, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = wal.Append(Entry{Index: 1, Term: 1, Data: []byte("secret-command")}); err != nil {
		t.Fatal(err)
	}
	_ = wal.Close()
	path := filepath.Join(dir, "raft.wal")
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if recovered, _, _, _, err := OpenWAL(dir); err == nil {
		recovered.Close()
		t.Fatal("expected corruption to be detected")
	}
}
