package seal

import "testing"

func TestInitializeSealAndThresholdUnseal(t *testing.T) {
	m, _ := Open(t.TempDir())
	result, err := m.Initialize(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	m.Seal()
	if _, err := m.Key(); err != ErrSealed {
		t.Fatalf("expected sealed, got %v", err)
	}
	for i := 0; i < 2; i++ {
		status, err := m.Unseal(result.Shares[i])
		if err != nil || !status.Sealed {
			t.Fatalf("share %d: %#v %v", i, status, err)
		}
	}
	status, err := m.Unseal(result.Shares[4])
	if err != nil || status.Sealed {
		t.Fatalf("final share: %#v %v", status, err)
	}
	if _, err := m.Key(); err != nil {
		t.Fatal(err)
	}
}
