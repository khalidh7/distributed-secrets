package rotation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
)

type Stage string

const (
	Pending         Stage = "PENDING"
	ExternalUpdated Stage = "EXTERNAL_UPDATED"
	SecretUpdated   Stage = "SECRET_UPDATED"
	Complete        Stage = "COMPLETE"
	Failed          Stage = "FAILED"
)

type Record struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Stage     Stage     `json:"stage"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}
type External interface {
	Rotate(context.Context, string, string) error
}
type Secrets interface {
	WriteRotated(string, map[string]string) error
	ReadRotated(string) (map[string]string, error)
}
type Engine struct {
	mu       sync.Mutex
	file     string
	records  map[string]Record
	external External
	secrets  Secrets
	key      []byte
}

func (e *Engine) Close() { e.mu.Lock(); defer e.mu.Unlock(); secretcrypto.Zero(e.key); e.key = nil }

type diskRecord struct {
	ID                string                `json:"id"`
	Path              string                `json:"path"`
	Username          string                `json:"username"`
	EncryptedPassword secretcrypto.Envelope `json:"encrypted_password"`
	Stage             Stage                 `json:"stage"`
	Error             string                `json:"error,omitempty"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

func Open(dir string, key []byte, external External, secrets Secrets) (*Engine, error) {
	if len(key) != secretcrypto.KeySize {
		return nil, errors.New("rotation key must be 32 bytes")
	}
	e := &Engine{file: filepath.Join(dir, "rotations.json"), records: map[string]Record{}, external: external, secrets: secrets, key: append([]byte(nil), key...)}
	data, err := os.ReadFile(e.file)
	if err == nil {
		var stored map[string]diskRecord
		if json.Unmarshal(data, &stored) != nil {
			return nil, errors.New("invalid rotation state")
		}
		for id, item := range stored {
			password, err := secretcrypto.OpenEnvelope(e.key, item.EncryptedPassword, []byte("rotation:"+id))
			if err != nil {
				return nil, err
			}
			e.records[id] = Record{ID: id, Path: item.Path, Username: item.Username, Password: string(password), Stage: item.Stage, Error: item.Error, UpdatedAt: item.UpdatedAt}
			secretcrypto.Zero(password)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return e, nil
}
func (e *Engine) Start(ctx context.Context, path, username string, current map[string]string) (Record, error) {
	var idbuf [12]byte
	_, _ = rand.Read(idbuf[:])
	id := base64.RawURLEncoding.EncodeToString(idbuf[:])
	pwbuf := make([]byte, 32)
	_, _ = rand.Read(pwbuf)
	record := Record{ID: id, Path: path, Username: username, Password: base64.RawURLEncoding.EncodeToString(pwbuf), Stage: Pending, UpdatedAt: time.Now().UTC()}
	e.mu.Lock()
	e.records[id] = record
	_ = e.persistLocked()
	e.mu.Unlock()
	return e.resume(ctx, record, current)
}
func (e *Engine) Retry(ctx context.Context, id string) (Record, error) {
	e.mu.Lock()
	record, ok := e.records[id]
	e.mu.Unlock()
	if !ok {
		return Record{}, errors.New("rotation not found")
	}
	current, err := e.secrets.ReadRotated(record.Path)
	if err != nil {
		return record, err
	}
	record.Error = ""
	return e.resume(ctx, record, current)
}
func (e *Engine) resume(ctx context.Context, record Record, value map[string]string) (Record, error) {
	if record.Stage == Pending {
		if e.external == nil {
			return e.fail(record, errors.New("external rotation provider is not configured"))
		}
		if err := e.external.Rotate(ctx, record.Username, record.Password); err != nil {
			return e.fail(record, err)
		}
		record.Stage = ExternalUpdated
		e.save(record)
	}
	if record.Stage == ExternalUpdated {
		value["password"] = record.Password
		if err := e.secrets.WriteRotated(record.Path, value); err != nil {
			return e.fail(record, err)
		}
		record.Stage = SecretUpdated
		e.save(record)
	}
	record.Stage = Complete
	record.Password = ""
	e.save(record)
	return record, nil
}
func (e *Engine) fail(record Record, err error) (Record, error) {
	record.Error = err.Error()
	e.save(record)
	record.Password = ""
	return record, err
}
func (e *Engine) save(record Record) {
	e.mu.Lock()
	defer e.mu.Unlock()
	record.UpdatedAt = time.Now().UTC()
	e.records[record.ID] = record
	_ = e.persistLocked()
}
func (e *Engine) persistLocked() error {
	stored := make(map[string]diskRecord, len(e.records))
	for id, record := range e.records {
		encrypted, err := secretcrypto.SealEnvelope(e.key, []byte(record.Password), []byte("rotation:"+id), 1)
		if err != nil {
			return err
		}
		stored[id] = diskRecord{ID: id, Path: record.Path, Username: record.Username, EncryptedPassword: encrypted, Stage: record.Stage, Error: record.Error, UpdatedAt: record.UpdatedAt}
	}
	data, _ := json.Marshal(stored)
	tmp := e.file + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, e.file)
}
