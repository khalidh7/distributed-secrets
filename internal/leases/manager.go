package leases

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrNotFound = errors.New("lease not found")

type Status string

const (
	Active  Status = "active"
	Revoked Status = "revoked"
	Expired Status = "expired"
)

type Lease struct {
	ID         string    `json:"id"`
	Principal  string    `json:"principal"`
	SecretPath string    `json:"secret_path"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Renewable  bool      `json:"renewable"`
	Status     Status    `json:"status"`
	Dynamic    bool      `json:"dynamic,omitempty"`
	ExternalID string    `json:"external_id,omitempty"`
}
type Mutation struct {
	Type      string    `json:"type"`
	Lease     Lease     `json:"lease"`
	ID        string    `json:"id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}
type state struct {
	Format int              `json:"format"`
	Leases map[string]Lease `json:"leases"`
}
type Manager struct {
	mu    sync.RWMutex
	file  string
	state state
}

func Open(dir string) (*Manager, error) {
	m := &Manager{file: filepath.Join(dir, "leases.json"), state: state{Format: 1, Leases: map[string]Lease{}}}
	data, err := os.ReadFile(m.file)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &m.state); err != nil {
		return nil, err
	}
	return m, nil
}
func PrepareIssue(principal, path string, ttl time.Duration, renewable bool) (Mutation, error) {
	if ttl <= 0 {
		return Mutation{}, errors.New("lease ttl must be positive")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Mutation{}, err
	}
	now := time.Now().UTC()
	lease := Lease{ID: hex.EncodeToString(id[:]), Principal: principal, SecretPath: path, IssuedAt: now, ExpiresAt: now.Add(ttl), Renewable: renewable, Status: Active}
	return Mutation{Type: "issue", Lease: lease}, nil
}
func (m *Manager) PrepareRenew(id, principal string, ttl time.Duration) (Mutation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	lease, ok := m.state.Leases[id]
	if !ok || lease.Principal != principal {
		return Mutation{}, ErrNotFound
	}
	if lease.Status != Active || !lease.Renewable {
		return Mutation{}, errors.New("lease is not renewable")
	}
	return Mutation{Type: "renew", ID: id, ExpiresAt: time.Now().UTC().Add(ttl)}, nil
}
func (m *Manager) PrepareRevoke(id, principal string) (Mutation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	lease, ok := m.state.Leases[id]
	if !ok || lease.Principal != principal {
		return Mutation{}, ErrNotFound
	}
	return Mutation{Type: "revoke", ID: id}, nil
}
func (m *Manager) Expired(now time.Time) []Mutation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Mutation{}
	for id, lease := range m.state.Leases {
		if lease.Status == Active && !now.Before(lease.ExpiresAt) {
			out = append(out, Mutation{Type: "expire", ID: id})
		}
	}
	return out
}
func (m *Manager) Apply(mut Mutation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch mut.Type {
	case "issue":
		if _, ok := m.state.Leases[mut.Lease.ID]; ok {
			return nil
		}
		m.state.Leases[mut.Lease.ID] = mut.Lease
	case "renew":
		lease, ok := m.state.Leases[mut.ID]
		if !ok {
			return ErrNotFound
		}
		lease.ExpiresAt = mut.ExpiresAt
		m.state.Leases[mut.ID] = lease
	case "revoke", "expire":
		lease, ok := m.state.Leases[mut.ID]
		if !ok {
			return ErrNotFound
		}
		if mut.Type == "revoke" {
			lease.Status = Revoked
		} else {
			lease.Status = Expired
		}
		m.state.Leases[mut.ID] = lease
	default:
		return errors.New("unknown lease mutation")
	}
	return m.persistLocked()
}
func (m *Manager) Get(id string) (Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	lease, ok := m.state.Leases[id]
	if !ok {
		return Lease{}, ErrNotFound
	}
	return lease, nil
}
func (m *Manager) Snapshot() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.Marshal(m.state)
}
func (m *Manager) Restore(data []byte) error {
	var value state
	if json.Unmarshal(data, &value) != nil || value.Format != 1 {
		return errors.New("invalid lease snapshot")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = value
	return m.persistLocked()
}
func (m *Manager) persistLocked() error {
	data, _ := json.Marshal(m.state)
	tmp := m.file + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.file)
}
