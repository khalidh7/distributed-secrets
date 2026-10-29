package leases

import (
	"testing"
	"time"
)

func TestLeaseLifecycle(t *testing.T) {
	m, _ := Open(t.TempDir())
	issue, _ := PrepareIssue("svc", "prod/db", time.Minute, true)
	if err := m.Apply(issue); err != nil {
		t.Fatal(err)
	}
	renew, err := m.PrepareRenew(issue.Lease.ID, "svc", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Apply(renew)
	revoke, _ := m.PrepareRevoke(issue.Lease.ID, "svc")
	_ = m.Apply(revoke)
	lease, _ := m.Get(issue.Lease.ID)
	if lease.Status != Revoked {
		t.Fatalf("got %s", lease.Status)
	}
}
