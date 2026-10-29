package secretcrypto

import (
	"bytes"
	"testing"
)

func TestEnvelopeUsesIndependentDataKeys(t *testing.T) {
	kek, _ := RandomKey()
	first, _ := SealEnvelope(kek, []byte("same"), []byte("path:v1"), 1)
	second, _ := SealEnvelope(kek, []byte("same"), []byte("path:v2"), 1)
	if first.EncryptedDataKey == second.EncryptedDataKey || first.Ciphertext == second.Ciphertext {
		t.Fatal("envelopes reused encryption material")
	}
	plain, err := OpenEnvelope(kek, first, []byte("path:v1"))
	if err != nil || !bytes.Equal(plain, []byte("same")) {
		t.Fatalf("open: %q %v", plain, err)
	}
}
