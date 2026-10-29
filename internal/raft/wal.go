package raft

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Entry struct {
	Index    uint64 `json:"index"`
	Term     uint64 `json:"term"`
	Data     []byte `json:"data"`
	Checksum string `json:"checksum"`
}
type HardState struct {
	CurrentTerm uint64 `json:"current_term"`
	VotedFor    string `json:"voted_for"`
	CommitIndex uint64 `json:"commit_index"`
}
type Snapshot struct {
	LastIndex uint64 `json:"last_index"`
	LastTerm  uint64 `json:"last_term"`
	Data      []byte `json:"data"`
	Checksum  string `json:"checksum"`
}
type WAL struct {
	mu        sync.Mutex
	dir, path string
	file      *os.File
}

func OpenWAL(dir string) (*WAL, []Entry, HardState, *Snapshot, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, HardState{}, nil, err
	}
	w := &WAL{dir: dir, path: filepath.Join(dir, "raft.wal")}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, HardState{}, nil, err
	}
	w.file = f
	entries := []Entry{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16<<20)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			f.Close()
			return nil, nil, HardState{}, nil, fmt.Errorf("decode WAL: %w", err)
		}
		if !validEntry(e) {
			f.Close()
			return nil, nil, HardState{}, nil, fmt.Errorf("WAL checksum mismatch at index %d", e.Index)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return nil, nil, HardState{}, nil, err
	}
	var hard HardState
	if data, err := os.ReadFile(filepath.Join(dir, "hard-state.json")); err == nil {
		if json.Unmarshal(data, &hard) != nil {
			f.Close()
			return nil, nil, hard, nil, errors.New("invalid hard state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		f.Close()
		return nil, nil, hard, nil, err
	}
	var snapshot *Snapshot
	if data, err := os.ReadFile(filepath.Join(dir, "snapshot.json")); err == nil {
		var value Snapshot
		if json.Unmarshal(data, &value) != nil || !validSnapshot(value) {
			f.Close()
			return nil, nil, hard, nil, errors.New("invalid snapshot")
		}
		snapshot = &value
	} else if !errors.Is(err, os.ErrNotExist) {
		f.Close()
		return nil, nil, hard, nil, err
	}
	return w, entries, hard, snapshot, nil
}
func (w *WAL) Append(e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	e.Checksum = entryChecksum(e)
	data, _ := json.Marshal(e)
	data = append(data, '\n')
	if _, err := w.file.Write(data); err != nil {
		return err
	}
	return w.file.Sync()
}
func (w *WAL) Rewrite(entries []Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.file.Close(); err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	for _, e := range entries {
		e.Checksum = entryChecksum(e)
		data, _ := json.Marshal(e)
		if _, err = f.Write(append(data, '\n')); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, w.path); err != nil {
		return err
	}
	w.file, err = os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	return err
}
func (w *WAL) SaveHardState(state HardState) error {
	data, _ := json.Marshal(state)
	return atomicFile(filepath.Join(w.dir, "hard-state.json"), data)
}
func (w *WAL) SaveSnapshot(snapshot Snapshot) error {
	snapshot.Checksum = snapshotChecksum(snapshot)
	data, _ := json.Marshal(snapshot)
	return atomicFile(filepath.Join(w.dir, "snapshot.json"), data)
}
func (w *WAL) Close() error { w.mu.Lock(); defer w.mu.Unlock(); return w.file.Close() }
func entryChecksum(e Entry) string {
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("%d:%d:", e.Index, e.Term)), e.Data...))
	return hex.EncodeToString(sum[:])
}
func validEntry(e Entry) bool { return e.Checksum == entryChecksum(e) }
func snapshotChecksum(s Snapshot) string {
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("%d:%d:", s.LastIndex, s.LastTerm)), s.Data...))
	return hex.EncodeToString(sum[:])
}
func validSnapshot(s Snapshot) bool { return s.Checksum == snapshotChecksum(s) }
func atomicFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
