package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	secretcrypto "github.com/example/distributed-secrets/internal/crypto"
)

var ErrNotFound = errors.New("secret not found")

type Record struct {
	Path      string                  `json:"path"`
	Encrypted secretcrypto.Ciphertext `json:"encrypted"`
	CreatedAt time.Time               `json:"created_at"`
}

type diskState struct {
	Format  int               `json:"format"`
	Records map[string]Record `json:"records"`
}

type Store struct {
	mu      sync.RWMutex
	file    string
	key     []byte
	records map[string]Record
}

func Open(dir string, key []byte) (*Store, error) {
	if len(key) != secretcrypto.KeySize {
		return nil, errors.New("storage key must be 32 bytes")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	s := &Store{file: filepath.Join(dir, "secrets.db"), key: append([]byte(nil), key...), records: make(map[string]Record)}
	data, err := os.ReadFile(s.file)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read store: %w", err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode store: %w", err)
	}
	if state.Format != 1 || state.Records == nil {
		return nil, errors.New("unsupported or invalid store format")
	}
	s.records = state.Records
	return s, nil
}

func (s *Store) Put(path string, value map[string]string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode secret: %w", err)
	}
	encrypted, err := secretcrypto.Encrypt(s.key, plaintext, []byte(path))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.records[path]
	s.records[path] = Record{Path: path, Encrypted: encrypted, CreatedAt: time.Now().UTC()}
	if err := s.persistLocked(); err != nil {
		if existed {
			s.records[path] = previous
		} else {
			delete(s.records, path)
		}
		return err
	}
	return nil
}

func (s *Store) Get(path string) (map[string]string, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	s.mu.RLock()
	record, ok := s.records[path]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	plaintext, err := secretcrypto.Decrypt(s.key, record.Encrypted, []byte(path))
	if err != nil {
		return nil, err
	}
	var value map[string]string
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	return value, nil
}

func (s *Store) Delete(path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.records[path]
	if !ok {
		return ErrNotFound
	}
	delete(s.records, path)
	if err := s.persistLocked(); err != nil {
		s.records[path] = previous
		return err
	}
	return nil
}

func ValidatePath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return errors.New("secret path must be a non-empty relative path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("secret path contains an invalid segment")
		}
	}
	return nil
}

func (s *Store) persistLocked() error {
	state := diskState{Format: 1, Records: s.records}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := s.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.file); err != nil {
		return err
	}
	ok = true
	return syncDirectory(filepath.Dir(s.file))
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func SortedKeys(value map[string]string) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
