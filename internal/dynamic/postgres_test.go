package dynamic

import (
	"context"
	"strings"
	"testing"
)

func TestIssueAndRevokeUseValidatedStatements(t *testing.T) {
	var statements []string
	provider := &Postgres{Prefix: "test", Run: func(_ context.Context, statement string, _ ...string) error {
		statements = append(statements, statement)
		return nil
	}}
	credential, err := provider.Issue(context.Background(), "1234567890abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(credential.Username, "test_") || credential.Password == "" {
		t.Fatalf("credential: %#v", credential)
	}
	if err = provider.Revoke(context.Background(), credential.Username); err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 || !strings.Contains(statements[0], "CREATE ROLE") || !strings.Contains(statements[1], "DROP ROLE") {
		t.Fatalf("statements: %#v", statements)
	}
}
