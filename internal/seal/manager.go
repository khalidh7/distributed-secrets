package seal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
)

var (
	ErrAlreadyInitialized = errors.New("seal is already initialized")
	ErrNotInitialized     = errors.New("seal is not initialized")
	ErrSealed             = errors.New("server is sealed")
)

type metadata struct {
	Format     int                     `json:"format"`
	WrappedKEK secretcrypto.Ciphertext `json:"wrapped_kek"`
	Shares     int                     `json:"shares"`
	Threshold  int                     `json:"threshold"`
}

type InitResult struct {
	Shares    []string `json:"unseal_keys"`
	Threshold int      `json:"threshold"`
}

type Status struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Shares      int  `json:"shares"`
	Threshold   int  `json:"threshold"`
	Progress    int  `json:"progress"`
}

type Manager struct {
	mu       sync.RWMutex
	file     string
	meta     metadata
	kek      []byte
	provided map[string]struct{}
}

func Open(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{file: filepath.Join(dir, "seal.json"), provided: map[string]struct{}{}}
	data, err := os.ReadFile(m.file)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &m.meta); err != nil {
		return nil, err
	}
	if m.meta.Format != 1 {
		return nil, errors.New("unsupported seal metadata")
	}
	return m, nil
}

func (m *Manager) Initialize(shares, threshold int) (InitResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.meta.Format != 0 {
		return InitResult{}, ErrAlreadyInitialized
	}
	root, err := secretcrypto.RandomKey()
	if err != nil {
		return InitResult{}, err
	}
	defer secretcrypto.Zero(root)
	kek, err := secretcrypto.RandomKey()
	if err != nil {
		return InitResult{}, err
	}
	wrapped, err := secretcrypto.WrapKey(root, kek)
	if err != nil {
		secretcrypto.Zero(kek)
		return InitResult{}, err
	}
	parts, err := secretcrypto.Split(root, shares, threshold)
	if err != nil {
		secretcrypto.Zero(kek)
		return InitResult{}, err
	}
	m.meta = metadata{Format: 1, WrappedKEK: wrapped, Shares: shares, Threshold: threshold}
	data, _ := json.Marshal(m.meta)
	if err := atomicWrite(m.file, data); err != nil {
		m.meta = metadata{}
		secretcrypto.Zero(kek)
		return InitResult{}, err
	}
	m.kek = kek
	return InitResult{Shares: parts, Threshold: threshold}, nil
}

func (m *Manager) Unseal(keyOrShare string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.meta.Format == 0 {
		if data, err := os.ReadFile(m.file); err == nil {
			_ = json.Unmarshal(data, &m.meta)
		}
		if m.meta.Format == 0 {
			return m.statusLocked(), ErrNotInitialized
		}
	}
	if len(m.kek) > 0 {
		return m.statusLocked(), nil
	}
	if _, err := secretcrypto.DecodeKey(keyOrShare); err == nil {
		root, _ := secretcrypto.DecodeKey(keyOrShare)
		defer secretcrypto.Zero(root)
		return m.unlockLocked(root)
	}
	m.provided[keyOrShare] = struct{}{}
	if len(m.provided) < m.meta.Threshold {
		return m.statusLocked(), nil
	}
	parts := make([]string, 0, len(m.provided))
	for value := range m.provided {
		parts = append(parts, value)
	}
	root, err := secretcrypto.Combine(parts)
	if err != nil {
		return m.statusLocked(), err
	}
	defer secretcrypto.Zero(root)
	status, err := m.unlockLocked(root)
	if err != nil {
		m.provided = map[string]struct{}{}
	}
	return status, err
}

func (m *Manager) unlockLocked(root []byte) (Status, error) {
	kek, err := secretcrypto.UnwrapKey(root, m.meta.WrappedKEK)
	if err != nil {
		return m.statusLocked(), err
	}
	m.kek = kek
	m.provided = map[string]struct{}{}
	return m.statusLocked(), nil
}

func (m *Manager) Seal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	secretcrypto.Zero(m.kek)
	m.kek = nil
	m.provided = map[string]struct{}{}
}
func (m *Manager) Key() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.kek) == 0 {
		return nil, ErrSealed
	}
	return append([]byte(nil), m.kek...), nil
}
func (m *Manager) Status() Status { m.mu.RLock(); defer m.mu.RUnlock(); return m.statusLocked() }
func (m *Manager) statusLocked() Status {
	return Status{Initialized: m.meta.Format != 0, Sealed: len(m.kek) == 0, Shares: m.meta.Shares, Threshold: m.meta.Threshold, Progress: len(m.provided)}
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
