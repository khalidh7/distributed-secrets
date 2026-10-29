package secretcrypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Split divides secret into shares using byte-wise Shamir secret sharing over
// GF(256). Share byte zero is its non-zero x-coordinate.
func Split(secret []byte, shares, threshold int) ([]string, error) {
	if threshold < 2 || shares < threshold || shares > 255 || len(secret) == 0 {
		return nil, errors.New("shares must satisfy 2 <= threshold <= shares <= 255")
	}
	out := make([][]byte, shares)
	for i := range out {
		out[i] = make([]byte, len(secret)+1)
		out[i][0] = byte(i + 1)
	}
	coeff := make([]byte, threshold-1)
	for pos, value := range secret {
		if _, err := io.ReadFull(rand.Reader, coeff); err != nil {
			return nil, fmt.Errorf("generate share coefficients: %w", err)
		}
		for i := range out {
			x, y := out[i][0], value
			power := byte(1)
			for _, c := range coeff {
				power = gfMul(power, x)
				y ^= gfMul(c, power)
			}
			out[i][pos+1] = y
		}
	}
	encoded := make([]string, shares)
	for i := range out {
		encoded[i] = base64.RawURLEncoding.EncodeToString(out[i])
	}
	return encoded, nil
}

func Combine(encoded []string) ([]byte, error) {
	if len(encoded) < 2 {
		return nil, errors.New("at least two shares are required")
	}
	shares := make([][]byte, len(encoded))
	seen := map[byte]bool{}
	for i, value := range encoded {
		share, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(share) < 2 || share[0] == 0 {
			return nil, errors.New("invalid unseal share")
		}
		if i > 0 && len(share) != len(shares[0]) {
			return nil, errors.New("unseal shares have different lengths")
		}
		if seen[share[0]] {
			return nil, errors.New("duplicate unseal share")
		}
		seen[share[0]] = true
		shares[i] = share
	}
	secret := make([]byte, len(shares[0])-1)
	for pos := range secret {
		for i, share := range shares {
			xi, basis := share[0], byte(1)
			for j, other := range shares {
				if i == j {
					continue
				}
				xj := other[0]
				basis = gfMul(basis, gfDiv(xj, xi^xj))
			}
			secret[pos] ^= gfMul(share[pos+1], basis)
		}
	}
	return secret, nil
}

func gfMul(a, b byte) byte {
	var product byte
	for b != 0 {
		if b&1 != 0 {
			product ^= a
		}
		high := a & 0x80
		a <<= 1
		if high != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return product
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(256)")
	}
	return gfMul(a, gfPow(b, 254))
}

func gfPow(value byte, power int) byte {
	result := byte(1)
	for power > 0 {
		if power&1 != 0 {
			result = gfMul(result, value)
		}
		value = gfMul(value, value)
		power >>= 1
	}
	return result
}
