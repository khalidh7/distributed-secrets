package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSealedAuthenticatedVersionedRuntime(t *testing.T) {
	runtime, err := NewRuntime(Config{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if response := runtimeRequest(t, runtime, "GET", "/v1/sys/health", "", ""); response.Code != 503 {
		t.Fatalf("sealed health: %d", response.Code)
	}
	initialized := runtimeRequest(t, runtime, "POST", "/v1/sys/init", `{"shares":3,"threshold":2}`, "")
	if initialized.Code != 200 {
		t.Fatalf("init: %d %s", initialized.Code, initialized.Body.String())
	}
	var initBody struct {
		RootToken string   `json:"root_token"`
		Keys      []string `json:"unseal_keys"`
	}
	if err := json.Unmarshal(initialized.Body.Bytes(), &initBody); err != nil {
		t.Fatal(err)
	}
	if response := runtimeRequest(t, runtime, "PUT", "/v1/secrets/prod/db", `{"password":"one"}`, ""); response.Code != 401 {
		t.Fatalf("unauthenticated write: %d", response.Code)
	}
	for _, password := range []string{"one", "two"} {
		response := runtimeRequest(t, runtime, "PUT", "/v1/secrets/prod/db", `{"password":"`+password+`"}`, initBody.RootToken)
		if response.Code != 201 {
			t.Fatalf("put: %d %s", response.Code, response.Body.String())
		}
	}
	response := runtimeRequest(t, runtime, "GET", "/v1/secrets/prod/db?version=1", "", initBody.RootToken)
	if response.Code != 200 || !bytes.Contains(response.Body.Bytes(), []byte(`"password":"one"`)) {
		t.Fatalf("historical read: %d %s", response.Code, response.Body.String())
	}
	if response = runtimeRequest(t, runtime, "POST", "/v1/sys/seal", `{}`, initBody.RootToken); response.Code != 200 {
		t.Fatalf("seal: %d", response.Code)
	}
	if response = runtimeRequest(t, runtime, "GET", "/v1/secrets/prod/db", "", initBody.RootToken); response.Code != 503 {
		t.Fatalf("sealed read: %d", response.Code)
	}
	for _, key := range initBody.Keys[:2] {
		response = runtimeRequest(t, runtime, "POST", "/v1/sys/unseal", `{"key":"`+key+`"}`, "")
		if response.Code != 200 {
			t.Fatalf("unseal: %d %s", response.Code, response.Body.String())
		}
	}
	if response = runtimeRequest(t, runtime, "GET", "/v1/secrets/prod/db", "", initBody.RootToken); response.Code != 200 {
		t.Fatalf("read after unseal: %d %s", response.Code, response.Body.String())
	}
}

func runtimeRequest(t *testing.T, handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
