package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/policy"
)

var ErrUnauthenticated = errors.New("invalid or expired token")

type Principal struct {
	ID       string   `json:"id"`
	Groups   []string `json:"groups,omitempty"`
	Policies []string `json:"policies"`
}
type Token struct {
	Fingerprint string    `json:"fingerprint"`
	Principal   Principal `json:"principal"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type state struct {
	Format   int                      `json:"format"`
	Tokens   []Token                  `json:"tokens"`
	Policies map[string]policy.Policy `json:"policies"`
}
type Mutation struct {
	Type   string        `json:"type"`
	Token  Token         `json:"token,omitempty"`
	Policy policy.Policy `json:"policy,omitempty"`
}
type Manager struct {
	mu     sync.RWMutex
	file   string
	pepper []byte
	state  state
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.pepper {
		m.pepper[i] = 0
	}
	m.pepper = nil
}

func Open(dir string, pepper []byte) (*Manager, error) {
	m := &Manager{file: filepath.Join(dir, "auth.json"), pepper: append([]byte(nil), pepper...), state: state{Format: 1, Policies: map[string]policy.Policy{}}}
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
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "dst_" + base64.RawURLEncoding.EncodeToString(b), nil
}
func (m *Manager) AddToken(raw string, principal Principal, ttl time.Duration) error {
	return m.Apply(m.PrepareToken(raw, principal, ttl))
}
func (m *Manager) PrepareToken(raw string, principal Principal, ttl time.Duration) Mutation {
	now := time.Now().UTC()
	return Mutation{Type: "token", Token: Token{Fingerprint: m.fingerprint(raw), Principal: principal, CreatedAt: now, ExpiresAt: now.Add(ttl)}}
}
func (m *Manager) Authenticate(raw string) (Principal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	fingerprint := m.fingerprint(raw)
	now := time.Now()
	for _, token := range m.state.Tokens {
		if hmac.Equal([]byte(token.Fingerprint), []byte(fingerprint)) && now.Before(token.ExpiresAt) {
			return token.Principal, nil
		}
	}
	return Principal{}, ErrUnauthenticated
}
func (m *Manager) PutPolicy(value policy.Policy) error {
	return m.Apply(Mutation{Type: "policy", Policy: value})
}
func (m *Manager) Apply(mutation Mutation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch mutation.Type {
	case "token":
		m.state.Tokens = append(m.state.Tokens, mutation.Token)
	case "policy":
		m.state.Policies[mutation.Policy.Name] = mutation.Policy
	default:
		return errors.New("unknown auth mutation")
	}
	return m.persistLocked()
}
func (m *Manager) Authorize(principal Principal, capability, path string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	values := make([]policy.Policy, 0, len(principal.Policies))
	for _, name := range principal.Policies {
		if p, ok := m.state.Policies[name]; ok {
			values = append(values, p)
		}
	}
	return policy.Allowed(values, capability, path)
}
func (m *Manager) fingerprint(raw string) string {
	mac := hmac.New(sha256.New, m.pepper)
	_, _ = mac.Write([]byte("token:v1:" + raw))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (m *Manager) persistLocked() error {
	data, _ := json.Marshal(m.state)
	tmp := m.file + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.file)
}
func (m *Manager) Snapshot() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.Marshal(m.state)
}
func (m *Manager) Restore(data []byte) error {
	var value state
	if json.Unmarshal(data, &value) != nil || value.Format != 1 {
		return errors.New("invalid auth snapshot")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = value
	return m.persistLocked()
}
