package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/audit"
	"github.com/kabouelrous/distributed-secrets/internal/auth"
	"github.com/kabouelrous/distributed-secrets/internal/dynamic"
	"github.com/kabouelrous/distributed-secrets/internal/leases"
	"github.com/kabouelrous/distributed-secrets/internal/policy"
	"github.com/kabouelrous/distributed-secrets/internal/rotation"
	"github.com/kabouelrous/distributed-secrets/internal/seal"
	"github.com/kabouelrous/distributed-secrets/internal/storage"
)

type Config struct {
	DataDir string
	SealDir string
	Logger  *slog.Logger
	NodeID  string
}
type Proposer interface {
	Propose(context.Context, []byte) error
	Leader() string
}
type contextKey string

const principalKey contextKey = "principal"

type Server struct {
	mu         sync.RWMutex
	store      *storage.Store
	auth       *auth.Manager
	seal       *seal.Manager
	audit      *audit.Log
	dataDir    string
	logger     *slog.Logger
	open       bool
	legacy     bool
	handler    http.Handler
	proposer   Proposer
	leases     *leases.Manager
	nodeID     string
	expiryOnce sync.Once
	dynamic    *dynamic.Postgres
	rotation   *rotation.Engine
	unsealHook func() error
}

// New retains the small embeddable handler used by unit tests and applications
// that supply an already-open store. NewRuntime enables seal and identity flows.
func New(store *storage.Store, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return (&Server{store: store, logger: logger, open: true, legacy: true}).routes()
}

func NewRuntime(config Config) (*Server, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.DataDir == "" {
		return nil, errors.New("data directory is required")
	}
	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, err
	}
	sealDir := config.SealDir
	if sealDir == "" {
		sealDir = config.DataDir
	}
	sealManager, err := seal.Open(sealDir)
	if err != nil {
		return nil, err
	}
	auditLog, err := audit.Open(filepath.Join(config.DataDir, "audit.log"))
	if err != nil {
		return nil, err
	}
	s := &Server{seal: sealManager, audit: auditLog, dataDir: config.DataDir, logger: config.Logger, nodeID: config.NodeID}
	s.handler = s.routes()
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }
func (s *Server) SetProposer(p Proposer)                           { s.mu.Lock(); defer s.mu.Unlock(); s.proposer = p }
func (s *Server) SetUnsealHook(hook func() error) error {
	s.mu.Lock()
	s.unsealHook = hook
	open := s.open
	s.mu.Unlock()
	if open && hook != nil {
		return hook()
	}
	return nil
}
func (s *Server) SetPostgres(provider *dynamic.Postgres) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dynamic = provider
	key, err := s.seal.Key()
	if errors.Is(err, seal.ErrSealed) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	engine, err := rotation.Open(s.dataDir, key, provider, s)
	if err != nil {
		return err
	}
	s.rotation = engine
	return nil
}
func (s *Server) OperatorUnseal(keys []string) error {
	for _, key := range keys {
		status, err := s.seal.Unseal(key)
		if err != nil {
			return err
		}
		if !status.Sealed {
			return s.ensureOpen()
		}
	}
	return seal.ErrSealed
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sys/health", s.health)
	mux.HandleFunc("GET /v1/sys/seal-status", s.sealStatus)
	mux.HandleFunc("POST /v1/sys/init", s.initialize)
	mux.HandleFunc("POST /v1/sys/unseal", s.unsealRequest)
	mux.Handle("POST /v1/sys/seal", s.protected("sudo", "sys/seal", http.HandlerFunc(s.sealRequest)))
	mux.Handle("POST /v1/auth/tokens", s.protected("sudo", "auth/tokens", http.HandlerFunc(s.createToken)))
	mux.Handle("PUT /v1/policies/{name}", s.protected("sudo", "policies", http.HandlerFunc(s.putPolicy)))
	mux.Handle("PUT /v1/secrets/{path...}", s.protected("create", "", http.HandlerFunc(s.putSecret)))
	mux.Handle("GET /v1/secrets/{path...}", s.protected("read", "", http.HandlerFunc(s.getSecret)))
	mux.Handle("DELETE /v1/secrets/{path...}", s.protected("delete", "", http.HandlerFunc(s.deleteSecret)))
	mux.Handle("GET /v1/metadata/{path...}", s.protected("read", "", http.HandlerFunc(s.getMetadata)))
	mux.Handle("POST /v1/leases/{path...}", s.protected("read", "", http.HandlerFunc(s.issueLease)))
	mux.Handle("POST /v1/lease-renew/{id}", s.authenticated(http.HandlerFunc(s.renewLease)))
	mux.Handle("POST /v1/lease-revoke/{id}", s.authenticated(http.HandlerFunc(s.revokeLease)))
	mux.Handle("POST /v1/dynamic/postgres/{role}", s.protected("create", "dynamic/postgres", http.HandlerFunc(s.issueDynamic)))
	mux.Handle("POST /v1/rotate/{path...}", s.protected("rotate", "", http.HandlerFunc(s.rotateSecret)))
	mux.Handle("POST /v1/rotations/{id}/retry", s.protected("sudo", "rotations", http.HandlerFunc(s.retryRotation)))
	return requestIDMiddleware(recoverMiddleware(s.logger, mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	status := "ok"
	code := http.StatusOK
	if !s.legacy && s.seal.Status().Sealed {
		status = "sealed"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status})
}
func (s *Server) sealStatus(w http.ResponseWriter, _ *http.Request) {
	if s.legacy {
		writeJSON(w, http.StatusOK, map[string]any{"initialized": true, "sealed": false})
		return
	}
	writeJSON(w, http.StatusOK, s.seal.Status())
}

func (s *Server) initialize(w http.ResponseWriter, r *http.Request) {
	if s.legacy {
		writeError(w, http.StatusNotFound, "not supported")
		return
	}
	var body struct {
		Shares    int `json:"shares"`
		Threshold int `json:"threshold"`
	}
	if decodeJSON(w, r, &body) != nil {
		return
	}
	if body.Shares == 0 {
		body.Shares = 5
	}
	if body.Threshold == 0 {
		body.Threshold = 3
	}
	result, err := s.seal.Initialize(body.Shares, body.Threshold)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if err = s.ensureOpen(); err != nil {
		writeDomainError(w, err)
		return
	}
	token, err := auth.GenerateToken()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	adminPolicy := policy.Policy{Name: "root", Rules: []policy.Rule{{Path: "**", Capabilities: []string{"sudo"}}}}
	_ = s.auth.PutPolicy(adminPolicy)
	if err = s.auth.AddToken(token, auth.Principal{ID: "root", Policies: []string{"root"}}, 24*time.Hour); err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unseal_keys": result.Shares, "threshold": result.Threshold, "root_token": token})
}

func (s *Server) unsealRequest(w http.ResponseWriter, r *http.Request) {
	if s.legacy {
		writeJSON(w, http.StatusOK, map[string]bool{"sealed": false})
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if decodeJSON(w, r, &body) != nil {
		return
	}
	status, err := s.seal.Unseal(body.Key)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if !status.Sealed {
		if err = s.ensureOpen(); err != nil {
			writeDomainError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, status)
}
func (s *Server) sealRequest(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.store != nil {
		s.store.Close()
	}
	if s.auth != nil {
		s.auth.Close()
	}
	if s.rotation != nil {
		s.rotation.Close()
	}
	s.store = nil
	s.auth = nil
	s.rotation = nil
	s.open = false
	s.mu.Unlock()
	s.seal.Seal()
	s.auditEvent(r, "system.seal", "", "allowed")
	writeJSON(w, http.StatusOK, s.seal.Status())
}

func (s *Server) ensureOpen() error {
	s.mu.Lock()
	if s.open {
		s.mu.Unlock()
		return nil
	}
	key, err := s.seal.Key()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	store, err := storage.Open(s.dataDir, key)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	authManager, err := auth.Open(s.dataDir, key)
	if err != nil {
		store.Close()
		s.mu.Unlock()
		return err
	}
	leaseManager, err := leases.Open(s.dataDir)
	if err != nil {
		store.Close()
		s.mu.Unlock()
		return err
	}
	s.store = store
	s.auth = authManager
	s.leases = leaseManager
	if s.dynamic != nil && s.rotation == nil {
		engine, err := rotation.Open(s.dataDir, key, s.dynamic, s)
		if err != nil {
			store.Close()
			s.mu.Unlock()
			return err
		}
		s.rotation = engine
	}
	s.open = true
	hook := s.unsealHook
	s.expiryOnce.Do(func() { go s.expireLeases() })
	s.mu.Unlock()
	if hook != nil {
		return hook()
	}
	return nil
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	var value map[string]string
	if decodeJSON(w, r, &value) != nil || value == nil {
		return
	}
	store, err := s.currentStore()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	mutation, err := store.PreparePut(r.PathValue("path"), value)
	if err == nil {
		err = s.applyMutation(r.Context(), store, mutation)
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	version := mutation.Version
	s.auditEvent(r, "secret.write", r.PathValue("path"), "allowed")
	writeJSON(w, http.StatusCreated, map[string]any{"path": r.PathValue("path"), "version": version.Version, "created_at": version.CreatedAt})
}
func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	store, err := s.currentStore()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	version, _ := strconv.Atoi(r.URL.Query().Get("version"))
	value, err := store.GetVersion(r.PathValue("path"), version)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.auditEvent(r, "secret.read", r.PathValue("path"), "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"path": r.PathValue("path"), "version": version, "data": value})
}
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	store, err := s.currentStore()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	version, _ := strconv.Atoi(r.URL.Query().Get("version"))
	mutation, err := store.PrepareDelete(r.PathValue("path"), version)
	if err == nil {
		err = s.applyMutation(r.Context(), store, mutation)
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.auditEvent(r, "secret.delete", r.PathValue("path"), "allowed")
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) getMetadata(w http.ResponseWriter, r *http.Request) {
	store, err := s.currentStore()
	if err != nil {
		writeDomainError(w, err)
		return
	}
	versions, err := store.Versions(r.PathValue("path"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": r.PathValue("path"), "versions": versions})
}

func (s *Server) issueLease(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTL       string `json:"ttl"`
		Renewable bool   `json:"renewable"`
	}
	if decodeJSON(w, r, &body) != nil {
		return
	}
	ttl, err := time.ParseDuration(body.TTL)
	if err != nil {
		writeError(w, 400, "ttl must be a duration")
		return
	}
	principal := r.Context().Value(principalKey).(auth.Principal)
	mutation, err := leases.PrepareIssue(principal.ID, r.PathValue("path"), ttl, body.Renewable)
	if err == nil {
		err = s.applyLease(r.Context(), mutation)
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	store, _ := s.currentStore()
	value, err := store.Get(r.PathValue("path"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.auditEvent(r, "lease.issue", r.PathValue("path"), "allowed")
	writeJSON(w, 201, map[string]any{"lease": mutation.Lease, "data": value})
}
func (s *Server) renewLease(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTL string `json:"ttl"`
	}
	if decodeJSON(w, r, &body) != nil {
		return
	}
	ttl, err := time.ParseDuration(body.TTL)
	if err != nil {
		writeError(w, 400, "ttl must be a duration")
		return
	}
	principal := r.Context().Value(principalKey).(auth.Principal)
	s.mu.RLock()
	manager := s.leases
	s.mu.RUnlock()
	mutation, err := manager.PrepareRenew(r.PathValue("id"), principal.ID, ttl)
	if err == nil {
		err = s.applyLease(r.Context(), mutation)
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	lease, _ := manager.Get(mutation.ID)
	writeJSON(w, 200, lease)
}
func (s *Server) revokeLease(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey).(auth.Principal)
	s.mu.RLock()
	manager := s.leases
	provider := s.dynamic
	s.mu.RUnlock()
	lease, _ := manager.Get(r.PathValue("id"))
	mutation, err := manager.PrepareRevoke(r.PathValue("id"), principal.ID)
	if err == nil {
		err = s.applyLease(r.Context(), mutation)
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	if lease.Dynamic && provider != nil {
		_ = provider.Revoke(r.Context(), lease.ExternalID)
	}
	w.WriteHeader(204)
}
func (s *Server) issueDynamic(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTL string `json:"ttl"`
	}
	if decodeJSON(w, r, &body) != nil {
		return
	}
	ttl, err := time.ParseDuration(body.TTL)
	if err != nil {
		writeError(w, 400, "ttl must be a duration")
		return
	}
	principal := r.Context().Value(principalKey).(auth.Principal)
	mutation, err := leases.PrepareIssue(principal.ID, "dynamic/postgres/"+r.PathValue("role"), ttl, false)
	s.mu.RLock()
	provider := s.dynamic
	s.mu.RUnlock()
	if provider == nil {
		writeError(w, 503, "postgres provider is not configured")
		return
	}
	credential, err := provider.Issue(r.Context(), mutation.Lease.ID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	mutation.Lease.Dynamic = true
	mutation.Lease.ExternalID = credential.Username
	if err = s.applyLease(r.Context(), mutation); err != nil {
		_ = provider.Revoke(r.Context(), credential.Username)
		writeDomainError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"lease": mutation.Lease, "data": credential})
}
func (s *Server) rotateSecret(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	engine := s.rotation
	s.mu.RUnlock()
	if engine == nil {
		writeError(w, 503, "rotation provider is not configured")
		return
	}
	store, _ := s.currentStore()
	value, err := store.Get(r.PathValue("path"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	record, err := engine.Start(r.Context(), r.PathValue("path"), value["username"], value)
	if err != nil {
		s.auditEvent(r, "secret.rotate", r.PathValue("path"), "failed")
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "rotation": record})
		return
	}
	s.auditEvent(r, "secret.rotate", r.PathValue("path"), "allowed")
	writeJSON(w, 200, record)
}
func (s *Server) retryRotation(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	engine := s.rotation
	s.mu.RUnlock()
	if engine == nil {
		writeError(w, 503, "rotation provider is not configured")
		return
	}
	record, err := engine.Retry(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "rotation": record})
		return
	}
	s.auditEvent(r, "secret.rotate.retry", record.Path, "allowed")
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Principal auth.Principal `json:"principal"`
		TTL       string         `json:"ttl"`
	}
	if decodeJSON(w, r, &body) != nil {
		return
	}
	ttl, err := time.ParseDuration(body.TTL)
	if err != nil || ttl <= 0 {
		writeError(w, http.StatusBadRequest, "ttl must be a positive duration")
		return
	}
	token, err := auth.GenerateToken()
	if err == nil {
		err = s.applyAuth(r.Context(), s.auth.PrepareToken(token, body.Principal, ttl))
	}
	if err != nil {
		writeDomainError(w, err)
		return
	}
	s.auditEvent(r, "token.create", body.Principal.ID, "allowed")
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expires_at": time.Now().Add(ttl).UTC()})
}
func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) {
	var value policy.Policy
	if decodeJSON(w, r, &value) != nil {
		return
	}
	value.Name = r.PathValue("name")
	if err := s.applyAuth(r.Context(), auth.Mutation{Type: "policy", Policy: value}); err != nil {
		writeDomainError(w, err)
		return
	}
	s.auditEvent(r, "policy.write", value.Name, "allowed")
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) protected(capability, fixedPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.legacy {
			next.ServeHTTP(w, r)
			return
		}
		if s.seal.Status().Sealed {
			writeError(w, http.StatusServiceUnavailable, "server is sealed")
			return
		}
		if err := s.ensureOpen(); err != nil {
			writeDomainError(w, err)
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		principal, err := s.auth.Authenticate(raw)
		if err != nil {
			s.auditDenied(r, "unknown", capability)
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		resource := fixedPath
		if resource == "" {
			resource = r.PathValue("path")
		}
		if !s.auth.Authorize(principal, capability, resource) {
			s.auditDenied(r, principal.ID, capability)
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
	})
}
func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.legacy {
			next.ServeHTTP(w, r)
			return
		}
		if s.seal.Status().Sealed {
			writeError(w, http.StatusServiceUnavailable, "server is sealed")
			return
		}
		if err := s.ensureOpen(); err != nil {
			writeDomainError(w, err)
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		principal, err := s.auth.Authenticate(raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
	})
}

func (s *Server) currentStore() (*storage.Store, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return nil, seal.ErrSealed
	}
	return s.store, nil
}

type replicatedCommand struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Server) propose(ctx context.Context, kind string, value any, local func() error) error {
	s.mu.RLock()
	proposer := s.proposer
	s.mu.RUnlock()
	if proposer == nil {
		return local()
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(replicatedCommand{Kind: kind, Payload: payload})
	return proposer.Propose(ctx, data)
}
func (s *Server) applyMutation(ctx context.Context, store *storage.Store, mutation storage.Mutation) error {
	return s.propose(ctx, "secret", mutation, func() error { return store.Apply(mutation) })
}
func (s *Server) applyLease(ctx context.Context, mutation leases.Mutation) error {
	s.mu.RLock()
	manager := s.leases
	s.mu.RUnlock()
	return s.propose(ctx, "lease", mutation, func() error { return manager.Apply(mutation) })
}
func (s *Server) applyAuth(ctx context.Context, mutation auth.Mutation) error {
	return s.propose(ctx, "auth", mutation, func() error { return s.auth.Apply(mutation) })
}
func (s *Server) ApplyRaft(data []byte) error {
	var command replicatedCommand
	if err := json.Unmarshal(data, &command); err != nil {
		return err
	}
	switch command.Kind {
	case "secret":
		store, err := s.currentStore()
		if err != nil {
			return err
		}
		var mutation storage.Mutation
		if err = json.Unmarshal(command.Payload, &mutation); err != nil {
			return err
		}
		return store.Apply(mutation)
	case "lease":
		s.mu.RLock()
		manager := s.leases
		s.mu.RUnlock()
		var mutation leases.Mutation
		if err := json.Unmarshal(command.Payload, &mutation); err != nil {
			return err
		}
		return manager.Apply(mutation)
	case "auth":
		var mutation auth.Mutation
		if err := json.Unmarshal(command.Payload, &mutation); err != nil {
			return err
		}
		return s.auth.Apply(mutation)
	default:
		return errors.New("unknown replicated command")
	}
}
func (s *Server) Snapshot() ([]byte, error) {
	store, err := s.currentStore()
	if err != nil {
		return nil, err
	}
	secretsData, err := store.Snapshot()
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	manager := s.leases
	authManager := s.auth
	s.mu.RUnlock()
	leaseData, err := manager.Snapshot()
	if err != nil {
		return nil, err
	}
	authData, err := authManager.Snapshot()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]json.RawMessage{"secrets": secretsData, "leases": leaseData, "auth": authData})
}
func (s *Server) Restore(data []byte) error {
	var snapshot map[string]json.RawMessage
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	store, err := s.currentStore()
	if err != nil {
		return err
	}
	if err = store.Restore(snapshot["secrets"]); err != nil {
		return err
	}
	s.mu.RLock()
	manager := s.leases
	authManager := s.auth
	s.mu.RUnlock()
	if err := manager.Restore(snapshot["leases"]); err != nil {
		return err
	}
	return authManager.Restore(snapshot["auth"])
}
func (s *Server) WriteRotated(path string, value map[string]string) error {
	store, err := s.currentStore()
	if err != nil {
		return err
	}
	mutation, err := store.PreparePut(path, value)
	if err != nil {
		return err
	}
	return s.applyMutation(context.Background(), store, mutation)
}
func (s *Server) ReadRotated(path string) (map[string]string, error) {
	store, err := s.currentStore()
	if err != nil {
		return nil, err
	}
	return store.Get(path)
}
func (s *Server) expireLeases() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.RLock()
		manager := s.leases
		proposer := s.proposer
		nodeID := s.nodeID
		provider := s.dynamic
		open := s.open
		s.mu.RUnlock()
		if !open || manager == nil {
			continue
		}
		if proposer != nil && proposer.Leader() != nodeID {
			continue
		}
		for _, mutation := range manager.Expired(time.Now()) {
			lease, _ := manager.Get(mutation.ID)
			if s.applyLease(context.Background(), mutation) == nil && lease.Dynamic && provider != nil {
				_ = provider.Revoke(context.Background(), lease.ExternalID)
			}
		}
	}
}
func (s *Server) auditDenied(r *http.Request, principal, operation string) {
	if s.audit != nil {
		_ = s.audit.Append(audit.Event{Principal: principal, Operation: operation, Path: r.PathValue("path"), Result: "denied", RequestID: requestID(r)})
	}
}
func (s *Server) auditEvent(r *http.Request, operation, path, result string) {
	if s.audit == nil {
		return
	}
	principal := "system"
	if p, ok := r.Context().Value(principalKey).(auth.Principal); ok {
		principal = p.ID
	}
	_ = s.audit.Append(audit.Event{Principal: principal, Operation: operation, Path: path, Result: result, RequestID: requestID(r)})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request body")
		return err
	}
	return nil
}
func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "secret not found")
	case errors.Is(err, storage.ErrDeleted):
		writeError(w, http.StatusGone, "secret version is deleted")
	case errors.Is(err, seal.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "server is sealed")
	case errors.Is(err, seal.ErrAlreadyInitialized):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, leases.ErrNotFound):
		writeError(w, http.StatusNotFound, "lease not found")
	case strings.Contains(err.Error(), "not the leader"):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case strings.Contains(err.Error(), "path"), strings.Contains(err.Error(), "share"):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func recoverMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("request panic", "error", fmt.Sprint(recovered))
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			var b [12]byte
			_, _ = rand.Read(b[:])
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey("request_id"), id)))
	})
}
func requestID(r *http.Request) string {
	value, _ := r.Context().Value(contextKey("request_id")).(string)
	return value
}
