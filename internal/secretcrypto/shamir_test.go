package secretcrypto

import "testing"

func TestShamirThreshold(t *testing.T) {
	secret, _ := RandomKey()
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Combine([]string{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if EncodeKey(recovered) != EncodeKey(secret) {
		t.Fatal("reconstructed key differs")
	}
}
