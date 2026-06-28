// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	"testing"

	refblake3 "github.com/luxfi/crypto/hash/blake3"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

// blake3Ref computes the canonical BLAKE3-256 digest the precompile must emit.
func blake3Ref(data []byte) []byte {
	h := refblake3.New()
	h.Write(data)
	out := make([]byte, DigestLength32)
	h.Reader().Read(out)
	return out
}

// blake2bRef computes BLAKE2b-256 -- the WRONG digest the removed accel
// "HashBlake3" path actually returned (accel/ops/crypto/crypto_cpu.go).
func blake2bRef(data []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(data)
	return h.Sum(nil)
}

// TestBlake3_Hash256IsRealBlake3NotBlake2b is the regression proof for the
// wrong-hash accel divergence. accelcrypto.Hash(HashBlake3, ...) returned a
// BLAKE2b digest (its GPU branch has no BLAKE3 kernel and its CPU branch calls
// blake2b), and -- because accelcrypto.Hash returns a nil error on that CPU
// fallback -- the precompile's "real BLAKE3" branch was dead code in EVERY
// build. The OpHash256 output must now be BLAKE3 and must differ from BLAKE2b.
func TestBlake3_Hash256IsRealBlake3NotBlake2b(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("abc"),
		[]byte("the quick brown fox jumps over the lazy dog"),
		make([]byte, 1000),
	}
	for _, data := range cases {
		input := append([]byte{OpHash256}, data...)
		gas := Blake3Precompile.RequiredGas(input)
		out, _, err := Blake3Precompile.Run(
			nil, common.Address{}, ContractAddress, input, gas, true,
		)
		require.NoError(t, err)

		want := blake3Ref(data)
		require.Equal(t, want, out,
			"OpHash256 must output canonical BLAKE3 for len=%d", len(data))
		require.NotEqual(t, blake2bRef(data), out,
			"OpHash256 must NOT output BLAKE2b (the accel divergence) for len=%d", len(data))
	}
}

// TestBlake3_MerkleRootUsesBlake3 proves the Merkle path is BLAKE3 too: the
// removed accel branch would have built the tree from BLAKE2b node hashes.
func TestBlake3_MerkleRootUsesBlake3(t *testing.T) {
	p := &blake3Precompile{}
	leafA := make([]byte, DigestLength32)
	leafB := make([]byte, DigestLength32)
	for i := range leafA {
		leafA[i] = byte(i)
		leafB[i] = byte(255 - i)
	}

	got := p.computeMerkleRoot([][]byte{leafA, leafB})

	// Reference parent = BLAKE3(leafA || leafB).
	want := blake3Ref(append(append([]byte{}, leafA...), leafB...))
	require.Equal(t, want, got, "merkle parent must be BLAKE3(left||right)")
	require.NotEqual(t, blake2bRef(append(append([]byte{}, leafA...), leafB...)), got,
		"merkle parent must NOT be BLAKE2b")
}
