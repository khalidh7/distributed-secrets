package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/example/distributed-secrets/internal/storage"
)

type Server struct {
	store  *storage.Store
	logger *slog.Logger
}

func New(store *storage.Store, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{store: store, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sys/health", s.health)
	mux.HandleFunc("PUT /v1/secrets/{path...}", s.putSecret)
	mux.HandleFunc("GET /v1/secrets/{path...}", s.getSecret)
	mux.HandleFunc("DELETE /v1/secrets/{path...}", s.deleteSecret)
	return recoverMiddleware(logger, mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	var value map[string]string
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value == nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object with string values")
		return
	}
	if err := s.store.Put(path, value); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"path": path})
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	value, err := s.store.Get(path)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "data": value})
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("path")); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "secret not found")
	case strings.Contains(err.Error(), "path"):
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
