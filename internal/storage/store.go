package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
)

var (
	ErrNotFound = errors.New("secret not found")
	ErrDeleted  = errors.New("secret version is deleted")
)

type Version struct {
	Version   int                   `json:"version"`
	Encrypted secretcrypto.Envelope `json:"encrypted"`
	CreatedAt time.Time             `json:"created_at"`
	DeletedAt *time.Time            `json:"deleted_at,omitempty"`
}

type Record struct {
	Path     string    `json:"path"`
	Versions []Version `json:"versions"`
}

type diskState struct {
	Format  int               `json:"format"`
	Records map[string]Record `json:"records"`
}

type legacyRecord struct {
	Path      string                  `json:"path"`
	Encrypted secretcrypto.Ciphertext `json:"encrypted"`
	CreatedAt time.Time               `json:"created_at"`
}

type legacyState struct {
	Format  int                     `json:"format"`
	Records map[string]legacyRecord `json:"records"`
}

type Store struct {
	mu      sync.RWMutex
	file    string
	kek     []byte
	records map[string]Record
}

type Mutation struct {
	Type          string  `json:"type"`
	Path          string  `json:"path"`
	Version       Version `json:"version,omitempty"`
	VersionNumber int     `json:"version_number,omitempty"`
}

func Open(dir string, kek []byte) (*Store, error) {
	if len(kek) != secretcrypto.KeySize {
		return nil, errors.New("key-encryption key must be 32 bytes")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	s := &Store{file: filepath.Join(dir, "secrets.db"), kek: append([]byte(nil), kek...), records: map[string]Record{}}
	data, err := os.ReadFile(s.file)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read store: %w", err)
	}
	var header struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("decode store: %w", err)
	}
	if header.Format == 1 {
		if err := s.migrateLegacy(data); err != nil {
			return nil, err
		}
		return s, nil
	}
	var state diskState
	if header.Format != 2 || json.Unmarshal(data, &state) != nil || state.Records == nil {
		return nil, errors.New("unsupported or invalid store format")
	}
	s.records = state.Records
	return s, nil
}

func (s *Store) Close() { secretcrypto.Zero(s.kek) }

func (s *Store) Put(path string, value map[string]string) error {
	_, err := s.PutVersion(path, value)
	return err
}

func (s *Store) PutVersion(path string, value map[string]string) (Version, error) {
	mutation, err := s.PreparePut(path, value)
	if err != nil {
		return Version{}, err
	}
	if err = s.Apply(mutation); err != nil {
		return Version{}, err
	}
	return mutation.Version, nil
}

func (s *Store) PreparePut(path string, value map[string]string) (Mutation, error) {
	if err := ValidatePath(path); err != nil {
		return Mutation{}, err
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return Mutation{}, fmt.Errorf("encode secret: %w", err)
	}
	s.mu.RLock()
	record := s.records[path]
	version := len(record.Versions) + 1
	s.mu.RUnlock()
	aad := versionAAD(path, version)
	encrypted, err := secretcrypto.SealEnvelope(s.kek, plaintext, aad, 1)
	if err != nil {
		return Mutation{}, err
	}
	entry := Version{Version: version, Encrypted: encrypted, CreatedAt: time.Now().UTC()}
	return Mutation{Type: "put", Path: path, Version: entry}, nil
}

func (s *Store) PrepareDelete(path string, requested int) (Mutation, error) {
	if err := ValidatePath(path); err != nil {
		return Mutation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[path]
	if !ok || len(record.Versions) == 0 {
		return Mutation{}, ErrNotFound
	}
	if requested == 0 {
		requested = len(record.Versions)
	}
	if requested < 1 || requested > len(record.Versions) {
		return Mutation{}, ErrNotFound
	}
	if record.Versions[requested-1].DeletedAt != nil {
		return Mutation{}, ErrDeleted
	}
	return Mutation{Type: "delete", Path: path, VersionNumber: requested}, nil
}

func (s *Store) Apply(m Mutation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.Type {
	case "put":
		record := s.records[m.Path]
		if m.Version.Version != len(record.Versions)+1 {
			return errors.New("secret version sequence conflict")
		}
		record.Path = m.Path
		record.Versions = append(record.Versions, m.Version)
		s.records[m.Path] = record
	case "delete":
		record, ok := s.records[m.Path]
		if !ok || m.VersionNumber < 1 || m.VersionNumber > len(record.Versions) {
			return ErrNotFound
		}
		if record.Versions[m.VersionNumber-1].DeletedAt != nil {
			return nil
		}
		now := time.Now().UTC()
		record.Versions[m.VersionNumber-1].DeletedAt = &now
		s.records[m.Path] = record
	default:
		return errors.New("unknown storage mutation")
	}
	return s.persistLocked()
}

func (s *Store) Get(path string) (map[string]string, error) { return s.GetVersion(path, 0) }

func (s *Store) GetVersion(path string, requested int) (map[string]string, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	s.mu.RLock()
	record, ok := s.records[path]
	if !ok || len(record.Versions) == 0 {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	index := requested - 1
	if requested == 0 {
		index = len(record.Versions) - 1
	}
	if index < 0 || index >= len(record.Versions) {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	version := record.Versions[index]
	s.mu.RUnlock()
	if version.DeletedAt != nil {
		if requested == 0 {
			return nil, ErrNotFound
		}
		return nil, ErrDeleted
	}
	plaintext, err := secretcrypto.OpenEnvelope(s.kek, version.Encrypted, versionAAD(path, version.Version))
	if err != nil {
		return nil, err
	}
	var value map[string]string
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	return value, nil
}

func (s *Store) Versions(path string) ([]Version, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[path]
	if !ok {
		return nil, ErrNotFound
	}
	out := append([]Version(nil), record.Versions...)
	for i := range out {
		out[i].Encrypted = secretcrypto.Envelope{}
	}
	return out, nil
}

// Delete soft-deletes the latest version. Historical ciphertext is retained.
func (s *Store) Delete(path string) error { return s.DeleteVersion(path, 0) }

func (s *Store) DeleteVersion(path string, requested int) error {
	mutation, err := s.PrepareDelete(path, requested)
	if err != nil {
		return err
	}
	return s.Apply(mutation)
}

func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(diskState{Format: 2, Records: s.records})
}

func (s *Store) Restore(data []byte) error {
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil || state.Format != 2 || state.Records == nil {
		return errors.New("invalid snapshot")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = state.Records
	return s.persistLocked()
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

func (s *Store) migrateLegacy(data []byte) error {
	var legacy legacyState
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	for path, old := range legacy.Records {
		plaintext, err := secretcrypto.Decrypt(s.kek, old.Encrypted, []byte(path))
		if err != nil {
			return fmt.Errorf("migrate %s: %w", path, err)
		}
		envelope, err := secretcrypto.SealEnvelope(s.kek, plaintext, versionAAD(path, 1), 1)
		if err != nil {
			return err
		}
		s.records[path] = Record{Path: path, Versions: []Version{{Version: 1, Encrypted: envelope, CreatedAt: old.CreatedAt}}}
	}
	return s.persistLocked()
}

func versionAAD(path string, version int) []byte {
	return []byte(fmt.Sprintf("secret:%s:version:%d", path, version))
}

func (s *Store) persistLocked() error {
	data, err := json.Marshal(diskState{Format: 2, Records: s.records})
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
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, s.file); err != nil {
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
