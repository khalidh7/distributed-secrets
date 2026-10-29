package playground

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kabouelrous/distributed-secrets/internal/api"
)

func TestLiveServiceThroughPlayground(t *testing.T) {
	runtime, err := api.NewRuntime(api.Config{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(runtime)
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	handler := Handler(target, upstream.Client().Transport)
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:3000"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	page := request("GET", "/", "", "")
	if page.Code != 200 || !bytes.Contains(page.Body.Bytes(), []byte("Under the hood")) {
		t.Fatalf("UI: %d", page.Code)
	}
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive responses must not be cached")
	}
	init := request("POST", "/v1/sys/init", `{"shares":3,"threshold":2}`, "")
	if init.Code != 200 {
		t.Fatalf("init: %s", init.Body.String())
	}
	var credentials struct {
		Token string `json:"root_token"`
	}
	if err := json.Unmarshal(init.Body.Bytes(), &credentials); err != nil {
		t.Fatal(err)
	}
	if got := request("PUT", "/v1/secrets/sandbox/test", `{"value":"sample"}`, ""); got.Code != 401 {
		t.Fatalf("unauthorized: %d", got.Code)
	}
	if got := request("PUT", "/v1/secrets/sandbox/test", `{"value":"sample"}`, credentials.Token); got.Code != 201 {
		t.Fatalf("write: %d %s", got.Code, got.Body.String())
	}
	if got := request("GET", "/v1/secrets/sandbox/test?version=1", "", credentials.Token); got.Code != 200 || !strings.Contains(got.Body.String(), `"sample"`) {
		t.Fatalf("read: %d %s", got.Code, got.Body.String())
	}
	if got := request("GET", "/v1/metadata/sandbox/test", "", credentials.Token); got.Code != 200 || !strings.Contains(got.Body.String(), `"versions"`) {
		t.Fatalf("versions: %d", got.Code)
	}
}

func TestRejectsForeignHostsAndOrigins(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	handler := Handler(target, http.DefaultTransport)
	for _, test := range []struct{ host, origin string }{
		{"attacker.example:3000", ""},
		{"127.0.0.1:3000", "https://attacker.example"},
		{"localhost:3000", "null"},
	} {
		r := httptest.NewRequest("POST", "http://"+test.host+"/v1/sys/init", strings.NewReader(`{}`))
		r.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%+v: %d", test, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("rejected request reached service")
	}
}
