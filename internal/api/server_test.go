package api

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	secretcrypto "github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
	"github.com/kabouelrous/distributed-secrets/internal/storage"
)

func TestSecretLifecycleOverTLS(t *testing.T) {
	key, _ := secretcrypto.RandomKey()
	store, err := storage.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	handler := New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	request(t, handler, http.MethodPut, "/v1/secrets/prod/database", `{"username":"app","password":"abc123"}`, http.StatusCreated)
	body := request(t, handler, http.MethodGet, "/v1/secrets/prod/database", "", http.StatusOK)
	if !bytes.Contains(body, []byte(`"password":"abc123"`)) {
		t.Fatalf("unexpected response: %s", body)
	}
	request(t, handler, http.MethodDelete, "/v1/secrets/prod/database", "", http.StatusNoContent)
	request(t, handler, http.MethodGet, "/v1/secrets/prod/database", "", http.StatusNotFound)
}

func request(t *testing.T, handler http.Handler, method, url, body string, wantStatus int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	data := recorder.Body.Bytes()
	if recorder.Code != wantStatus {
		t.Fatalf("status %d, want %d: %s", recorder.Code, wantStatus, data)
	}
	return data
}
