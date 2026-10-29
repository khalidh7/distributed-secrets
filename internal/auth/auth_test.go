package auth

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/policy"
)

func TestTokensAreHashedAndExpire(t *testing.T) {
	dir := t.TempDir()
	manager, _ := Open(dir, []byte("01234567890123456789012345678901"))
	raw, _ := GenerateToken()
	_ = manager.AddToken(raw, Principal{ID: "svc", Policies: []string{"reader"}}, 20*time.Millisecond)
	data, _ := os.ReadFile(dir + "/auth.json")
	if strings.Contains(string(data), raw) {
		t.Fatal("raw token persisted")
	}
	if _, err := manager.Authenticate(raw); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := manager.Authenticate(raw); err == nil {
		t.Fatal("expired token authenticated")
	}
	_ = manager.PutPolicy(policy.Policy{Name: "reader", Rules: []policy.Rule{{Path: "prod/*", Capabilities: []string{"read"}}}})
}
