package audit

import (
	"os"
	"testing"
)

func TestTamperEvidence(t *testing.T) {
	path := t.TempDir() + "/audit.log"
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = log.Append(Event{Principal: "svc", Operation: "secret.read", Path: "prod/db", Result: "allowed"})
	_ = log.Append(Event{Principal: "svc", Operation: "secret.write", Path: "prod/db", Result: "denied"})
	_ = log.Close()
	if err = Verify(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	data[20] ^= 1
	_ = os.WriteFile(path, data, 0600)
	if Verify(path) == nil {
		t.Fatal("tampering was not detected")
	}
}
