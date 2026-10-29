package playground

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kabouelrous/distributed-secrets/internal/auth"
	"github.com/kabouelrous/distributed-secrets/internal/raft"
	"github.com/kabouelrous/distributed-secrets/internal/seal"
	"github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
)

func TestBootstrapRetainsTokenAcceptedByRecoveredAuth(t *testing.T) {
	dir := t.TempDir()
	first := &Lab{directory: dir}
	if err := first.bootstrap(); err != nil {
		t.Fatal(err)
	}
	manager, err := seal.Open(filepath.Join(dir, "seal"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Seal()
	for _, share := range first.credentials.Shares[:3] {
		if _, err := manager.Unseal(share); err != nil {
			t.Fatal(err)
		}
	}
	key, err := manager.Key()
	if err != nil {
		t.Fatal(err)
	}
	defer secretcrypto.Zero(key)
	identity, err := auth.Open(filepath.Join(dir, "node1"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	snapshot, err := identity.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	second := &Lab{directory: dir}
	if err := second.bootstrap(); err != nil {
		t.Fatal(err)
	}
	if second.credentials.RootToken != first.credentials.RootToken {
		t.Fatal("restart replaced the token retained in the Raft snapshot")
	}
	persisted, err := os.ReadFile(filepath.Join(dir, "node1", "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persisted, snapshot) {
		t.Fatal("bootstrap modified existing identity state outside Raft")
	}
	if err := identity.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Authenticate(second.credentials.RootToken); err != nil {
		t.Fatalf("session token rejected after snapshot recovery: %v", err)
	}
}

func TestClusterQuorumAndLeaderSelection(t *testing.T) {
	nodes := []LabNode{
		{Status: raft.Status{ID: "node1", Role: raft.Leader, Term: 1}, Online: true},
		{Status: raft.Status{ID: "node2", Role: raft.Follower, Term: 1}, Online: true},
		{Status: raft.Status{ID: "node3", Role: raft.Follower, Term: 1}, Online: true},
	}
	if got := summarizeLab(nodes); !got.Writable || got.Leader != "node1" {
		t.Fatalf("healthy: %+v", got)
	}
	nodes[2].Online = false
	if !summarizeLab(nodes).Writable {
		t.Fatal("one failure must retain quorum")
	}
	nodes[1].Online = false
	if summarizeLab(nodes).Writable {
		t.Fatal("a lone leader must not be writable")
	}
	nodes[1].Online = true
	nodes[1].Role = raft.Candidate
	nodes[1].Term = 2
	if got := summarizeLab(nodes); got.Writable || got.Leader != "" {
		t.Fatal("old-term leader must not route writes during an election")
	}
	nodes[1].Role = raft.Leader
	if got := summarizeLab(nodes); !got.Writable || got.Leader != "node2" {
		t.Fatal("new-term leader must take over")
	}
}
func TestClusterRejectsUnsafeControlsAndNoQuorumWrites(t *testing.T) {
	lab := &Lab{processes: map[string]*labProcess{}, snapshot: LabSnapshot{Quorum: 2}}
	upstream, _ := url.Parse("https://127.0.0.1:8443")
	handler := Handler(upstream, http.DefaultTransport, lab)
	for _, test := range []struct {
		method, path, origin, content string
		code                          int
	}{
		{"POST", "/playground/nodes/node1/stop", "https://foreign.example", "application/json", 403},
		{"POST", "/playground/nodes/node1/stop", "", "text/plain", 415},
		{"POST", "/playground/nodes/arbitrary/stop", "", "application/json", 400},
		{"POST", "/v1/sys/init", "", "application/json", 403},
		{"PUT", "/v1/secrets/test", "", "application/json", 423},
	} {
		request := httptest.NewRequest(test.method, "http://127.0.0.1:3000"+test.path, strings.NewReader(`{}`))
		request.Header.Set("Origin", test.origin)
		request.Header.Set("Content-Type", test.content)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.code {
			t.Errorf("%s: got %d, want %d", test.path, response.Code, test.code)
		}
	}
}
