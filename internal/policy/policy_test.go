package policy

import "testing"

func TestExplicitDenyWins(t *testing.T) {
	policies := []Policy{{Rules: []Rule{{Path: "prod/*", Capabilities: []string{"read"}}, {Path: "prod/admin", Capabilities: []string{"read"}, Deny: true}}}}
	if !Allowed(policies, "read", "prod/database") {
		t.Fatal("expected allow")
	}
	if Allowed(policies, "read", "prod/admin") {
		t.Fatal("deny must win")
	}
}
