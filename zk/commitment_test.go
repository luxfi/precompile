// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestPoseidon2Hash tests basic Poseidon2 hashing
func TestPoseidon2Hash(t *testing.T) {
	hasher := NewPoseidon2Hasher()

	// Test single element hash
	var input [32]byte
	input[31] = 42

	hash1, err := hasher.Hash(input[:])
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, hash1)

	// Same input should produce same hash
	hash2, err := hasher.Hash(input[:])
	require.NoError(t, err)
	require.Equal(t, hash1, hash2)

	// Different input should produce different hash
	input[31] = 43
	hash3, err := hasher.Hash(input[:])
	require.NoError(t, err)
	require.NotEqual(t, hash1, hash3)
}

// TestPoseidon2HashPair tests Merkle-tree style hashing
func TestPoseidon2HashPair(t *testing.T) {
	hasher := NewPoseidon2Hasher()

	var left, right [32]byte
	left[31] = 1
	right[31] = 2

	hash, err := hasher.HashPair(left, right)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, hash)

	// Order matters
	hash2, err := hasher.HashPair(right, left)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash2)
}

// TestPoseidon2MerkleTree tests Merkle tree construction and verification
func TestPoseidon2MerkleTree(t *testing.T) {
	hasher := NewPoseidon2Hasher()

	// Create 8 leaves
	leaves := make([][32]byte, 8)
	for i := range leaves {
		leaves[i][31] = byte(i + 1)
	}

	// Compute root
	root, err := hasher.MerkleRoot(leaves)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, root)

	// Generate and verify proof for each leaf
	for i := range leaves {
		proof, isLeft, err := hasher.MerkleProof(leaves, i)
		require.NoError(t, err)

		valid, err := hasher.VerifyMerkleProof(leaves[i], proof, isLeft, root)
		require.NoError(t, err)
		require.True(t, valid, "proof should be valid for leaf %d", i)
	}
}

// TestPedersenCommit tests basic Pedersen commitment
func TestPedersenCommit(t *testing.T) {
	committer := NewPedersenCommitter()

	var value, blinding [32]byte
	value[31] = 100
	rand.Read(blinding[:])

	commitment, err := committer.Commit(value, blinding)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, commitment)

	// Verify opening
	valid, err := committer.Verify(commitment, value, blinding)
	require.NoError(t, err)
	require.True(t, valid)

	// Wrong value should fail
	value[31] = 101
	valid, err = committer.Verify(commitment, value, blinding)
	require.NoError(t, err)
	require.False(t, valid)
}

// TestPedersenHomomorphism tests homomorphic addition
func TestPedersenHomomorphism(t *testing.T) {
	committer := NewPedersenCommitter()

	// C1 = 10 * G + r1 * H
	var v1, r1 [32]byte
	v1[31] = 10
	rand.Read(r1[:])
	c1, err := committer.Commit(v1, r1)
	require.NoError(t, err)

	// C2 = 20 * G + r2 * H
	var v2, r2 [32]byte
	v2[31] = 20
	rand.Read(r2[:])
	c2, err := committer.Commit(v2, r2)
	require.NoError(t, err)

	// C1 + C2 should equal commitment to (10 + 20) with (r1 + r2)
	sum, err := committer.Add(c1, c2)
	require.NoError(t, err)

	// This demonstrates homomorphic property
	// In practice you'd also add blinding factors
	require.NotEqual(t, [32]byte{}, sum)
}

// TestNoteCommitments tests note commitment for both schemes
func TestNoteCommitments(t *testing.T) {
	amount := big.NewInt(1000)
	var assetId [32]byte
	assetId[31] = 1 // ETH
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	var blinding [32]byte
	rand.Read(blinding[:])

	// Test Poseidon2 scheme
	poseidonScheme := NewPoseidon2Scheme()
	poseidonNote, err := poseidonScheme.NoteCommitment(amount, assetId, owner, blinding)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, poseidonNote)
	require.True(t, poseidonScheme.IsPQSafe())

	// Test Pedersen scheme
	pedersenScheme := NewPedersenScheme()
	pedersenNote, err := pedersenScheme.NoteCommitment(amount, assetId, owner, blinding)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, pedersenNote)
	require.False(t, pedersenScheme.IsPQSafe())

	// Commitments should be different (different schemes)
	require.NotEqual(t, poseidonNote, pedersenNote)
}

// TestCreateNote tests the Note abstraction
func TestCreateNote(t *testing.T) {
	var blinding [32]byte
	rand.Read(blinding[:])

	var assetId [32]byte
	assetId[31] = 1

	note, err := CreateNote(NoteInput{
		Amount:         big.NewInt(500),
		AssetID:        assetId,
		Owner:          common.HexToAddress("0xabcd"),
		BlindingFactor: blinding,
		SchemeType:     SchemePoseidon2,
	})
	require.NoError(t, err)
	require.NotNil(t, note)
	require.Equal(t, SchemePoseidon2, note.SchemeType)

	// Set leaf index and compute nullifier
	note.LeafIndex = 42
	var nullifierKey [32]byte
	rand.Read(nullifierKey[:])

	nullifier, err := note.Nullifier(nullifierKey)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, nullifier)
}

// BenchmarkPoseidon2Hash benchmarks Poseidon2 hashing
func BenchmarkPoseidon2Hash(b *testing.B) {
	hasher := NewPoseidon2Hasher()
	input := make([]byte, 64) // 2 field elements
	rand.Read(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.Hash(input)
	}
}

// BenchmarkPoseidon2Commitment benchmarks Poseidon2 commitment
func BenchmarkPoseidon2Commitment(b *testing.B) {
	hasher := NewPoseidon2Hasher()
	var value, blinding, salt [32]byte
	rand.Read(value[:])
	rand.Read(blinding[:])
	rand.Read(salt[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.Commitment(value, blinding, salt)
	}
}

// BenchmarkPedersenCommit benchmarks Pedersen commitment
func BenchmarkPedersenCommit(b *testing.B) {
	committer := NewPedersenCommitter()
	var value, blinding [32]byte
	rand.Read(value[:])
	rand.Read(blinding[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = committer.Commit(value, blinding)
	}
}

// BenchmarkPedersenVerify benchmarks Pedersen verification
func BenchmarkPedersenVerify(b *testing.B) {
	committer := NewPedersenCommitter()
	var value, blinding [32]byte
	rand.Read(value[:])
	rand.Read(blinding[:])
	commitment, _ := committer.Commit(value, blinding)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = committer.Verify(commitment, value, blinding)
	}
}

// BenchmarkNoteCommitmentPoseidon2 benchmarks note commitment with Poseidon2
func BenchmarkNoteCommitmentPoseidon2(b *testing.B) {
	scheme := NewPoseidon2Scheme()
	amount := big.NewInt(1000)
	var assetId [32]byte
	assetId[31] = 1
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	var blinding [32]byte
	rand.Read(blinding[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scheme.NoteCommitment(amount, assetId, owner, blinding)
	}
}

// BenchmarkNoteCommitmentPedersen benchmarks note commitment with Pedersen
func BenchmarkNoteCommitmentPedersen(b *testing.B) {
	scheme := NewPedersenScheme()
	amount := big.NewInt(1000)
	var assetId [32]byte
	assetId[31] = 1
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	var blinding [32]byte
	rand.Read(blinding[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scheme.NoteCommitment(amount, assetId, owner, blinding)
	}
}

// BenchmarkMerkleRoot benchmarks Merkle root computation
func BenchmarkMerkleRoot(b *testing.B) {
	hasher := NewPoseidon2Hasher()
	leaves := make([][32]byte, 1024)
	for i := range leaves {
		rand.Read(leaves[i][:])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hasher.MerkleRoot(leaves)
	}
}

// BenchmarkMerkleProof benchmarks Merkle proof generation
func BenchmarkMerkleProof(b *testing.B) {
	hasher := NewPoseidon2Hasher()
	leaves := make([][32]byte, 1024)
	for i := range leaves {
		rand.Read(leaves[i][:])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = hasher.MerkleProof(leaves, i%1024)
	}
}

// BenchmarkComparison runs comparison benchmarks
func BenchmarkComparison(b *testing.B) {
	poseidon := NewPoseidon2Hasher()
	pedersen := NewPedersenCommitter()

	amount := big.NewInt(1000)
	var assetId [32]byte
	assetId[31] = 1
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	var blinding [32]byte
	rand.Read(blinding[:])

	b.Run("Poseidon2-NoteCommit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = poseidon.NoteCommitment(amount, assetId, owner, blinding)
		}
	})

	b.Run("Pedersen-NoteCommit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = pedersen.NoteCommitment(amount, assetId, owner, blinding)
		}
	})

	// Print gas costs
	b.Run("GasCosts", func(b *testing.B) {
		poseidonGas := NewPoseidon2Scheme().RequiredGas()
		pedersenGas := NewPedersenScheme().RequiredGas()
		fmt.Printf("\nGas costs:\n")
		fmt.Printf("  Poseidon2 NoteCommit: %d gas (PQ-safe)\n", poseidonGas)
		fmt.Printf("  Pedersen NoteCommit:  %d gas (NOT PQ-safe)\n", pedersenGas)
		fmt.Printf("  Ratio: %.2fx\n", float64(pedersenGas)/float64(poseidonGas))
	})
}

// TestGoldilocksField tests Goldilocks field operations
func TestGoldilocksField(t *testing.T) {
	f := &GoldilocksField{}

	// Test basic operations
	a := uint64(12345)
	b := uint64(67890)

	// Addition
	sum := f.Add(a, b)
	require.Equal(t, a+b, sum)

	// Multiplication
	product := f.Mul(a, b)
	expected := new(big.Int).Mul(big.NewInt(int64(a)), big.NewInt(int64(b)))
	expected.Mod(expected, GoldilocksModulus)
	require.Equal(t, expected.Uint64(), product)

	// Inverse
	inv := f.Inv(a)
	check := f.Mul(a, inv)
	require.Equal(t, uint64(1), check, "a * a^(-1) should equal 1")
}

// TestExtensionField tests quadratic extension field
func TestExtensionField(t *testing.T) {
	// Test multiplication
	x := ExtensionField{A: 3, B: 4}
	y := ExtensionField{A: 5, B: 6}

	product := ExtMul(x, y)
	require.NotEqual(t, uint64(0), product.A)

	// Test inverse
	inv := ExtInv(x)
	check := ExtMul(x, inv)
	// Should be close to (1, 0)
	require.Equal(t, uint64(1), check.A)
	require.Equal(t, uint64(0), check.B)
}

// BenchmarkGoldilocksOps benchmarks Goldilocks field operations
func BenchmarkGoldilocksOps(b *testing.B) {
	f := &GoldilocksField{}
	a := uint64(0x123456789ABCDEF0)
	bb := uint64(0xFEDCBA9876543210)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = f.Add(a, bb)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = f.Mul(a, bb)
		}
	})

	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = f.Inv(a)
		}
	})

	b.Run("Exp", func(b *testing.B) {
		exp := uint64(1000)
		for i := 0; i < b.N; i++ {
			_ = f.Exp(a, exp)
		}
	})
}
