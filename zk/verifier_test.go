// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// TestNewZKVerifier tests verifier creation.
func TestNewZKVerifier(t *testing.T) {
	zv := NewZKVerifier()
	if zv == nil {
		t.Fatal("Expected non-nil ZKVerifier")
	}
	if zv.VerifyingKeys == nil {
		t.Error("Expected VerifyingKeys map to be initialized")
	}
	if zv.Nullifiers == nil {
		t.Error("Expected Nullifiers map to be initialized")
	}
	if zv.Commitments == nil {
		t.Error("Expected Commitments map to be initialized")
	}
	if zv.Pools == nil {
		t.Error("Expected Pools map to be initialized")
	}
}

// TestRegisterVerifyingKey tests verifying-key metadata registration.
// Note: no on-chain pairing-based verifier exists; this is bookkeeping only.
func TestRegisterVerifyingKey(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	alpha := []byte("alpha_point")
	beta := []byte("beta_point")
	gamma := []byte("gamma_point")
	delta := []byte("delta_point")
	ic := [][]byte{[]byte("ic0"), []byte("ic1"), []byte("ic2")}

	keyID, err := zv.RegisterVerifyingKey(
		owner,
		ProofSystemStark,
		CircuitTransfer,
		alpha, beta, gamma, delta, ic,
	)
	if err != nil {
		t.Fatalf("RegisterVerifyingKey failed: %v", err)
	}
	if keyID == [32]byte{} {
		t.Error("Expected non-zero key ID")
	}

	vk := zv.VerifyingKeys[keyID]
	if vk == nil {
		t.Fatal("Verifying key not stored")
	}
	if vk.ProofSystem != ProofSystemStark {
		t.Errorf("Expected STARK, got %v", vk.ProofSystem)
	}
	if vk.Owner != owner {
		t.Error("Owner mismatch")
	}
	if len(vk.IC) != 3 {
		t.Errorf("Expected 3 IC points, got %d", len(vk.IC))
	}
}

// TestCheckNullifier tests nullifier checking.
func TestCheckNullifier(t *testing.T) {
	zv := NewZKVerifier()

	nullifierHash := [32]byte{0x01, 0x02, 0x03}

	spent, err := zv.CheckNullifier(nullifierHash)
	if err != nil {
		t.Fatalf("CheckNullifier failed: %v", err)
	}
	if spent {
		t.Error("Expected nullifier to be unspent")
	}

	txHash := common.HexToHash("0xABCDEF")
	if err := zv.SpendNullifier(nullifierHash, txHash, 100); err != nil {
		t.Fatalf("SpendNullifier failed: %v", err)
	}

	spent, err = zv.CheckNullifier(nullifierHash)
	if err != nil {
		t.Fatalf("CheckNullifier failed: %v", err)
	}
	if !spent {
		t.Error("Expected nullifier to be spent")
	}
}

// TestSpendNullifierAlreadySpent tests double-spend prevention.
func TestSpendNullifierAlreadySpent(t *testing.T) {
	zv := NewZKVerifier()

	nullifierHash := [32]byte{0x01, 0x02, 0x03}
	txHash := common.HexToHash("0xABCDEF")

	if err := zv.SpendNullifier(nullifierHash, txHash, 100); err != nil {
		t.Fatalf("First spend failed: %v", err)
	}
	if err := zv.SpendNullifier(nullifierHash, txHash, 101); err != ErrNullifierSpent {
		t.Errorf("Expected ErrNullifierSpent, got %v", err)
	}
}

// TestCreateConfidentialPool tests pool creation.
func TestCreateConfidentialPool(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	poolID, err := zv.CreateConfidentialPool(owner, token, 32)
	if err != nil {
		t.Fatalf("CreateConfidentialPool failed: %v", err)
	}
	if poolID == [32]byte{} {
		t.Error("Expected non-zero pool ID")
	}

	pool := zv.Pools[poolID]
	if pool == nil {
		t.Fatal("Pool not stored")
	}
	if pool.Token != token {
		t.Error("Token mismatch")
	}
	if pool.MerkleDepth != 32 {
		t.Errorf("Expected depth 32, got %d", pool.MerkleDepth)
	}
	if !pool.Enabled {
		t.Error("Expected pool to be enabled")
	}
}

// TestAddCommitment tests adding a commitment to a pool.
func TestAddCommitment(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	poolID, _ := zv.CreateConfidentialPool(owner, token, 32)

	commitment := &Commitment{
		Value:    []byte("commitment_hash"),
		Amount:   big.NewInt(1e18),
		Blinding: []byte("blinding_factor"),
	}

	commitID, err := zv.AddCommitment(poolID, commitment)
	if err != nil {
		t.Fatalf("AddCommitment failed: %v", err)
	}
	if commitID == [32]byte{} {
		t.Error("Expected non-zero commitment ID")
	}

	pool := zv.Pools[poolID]
	if pool.TotalDeposits.Cmp(big.NewInt(1e18)) != 0 {
		t.Error("Total deposits not updated")
	}
}

// TestAddCommitmentPoolNotFound tests error for non-existent pool.
func TestAddCommitmentPoolNotFound(t *testing.T) {
	zv := NewZKVerifier()

	nonExistent := [32]byte{0xFF}
	if _, err := zv.AddCommitment(nonExistent, &Commitment{}); err != ErrPoolNotFound {
		t.Errorf("Expected ErrPoolNotFound, got %v", err)
	}
}

// TestAddCommitmentPoolDisabled tests error for disabled pool.
func TestAddCommitmentPoolDisabled(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	poolID, _ := zv.CreateConfidentialPool(owner, token, 32)
	zv.Pools[poolID].Enabled = false

	if _, err := zv.AddCommitment(poolID, &Commitment{Amount: big.NewInt(1)}); err != ErrPoolDisabled {
		t.Errorf("Expected ErrPoolDisabled, got %v", err)
	}
}

// TestVerifyCommitmentInclusion tests hash-based Merkle inclusion.
func TestVerifyCommitmentInclusion(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	poolID, _ := zv.CreateConfidentialPool(owner, token, 32)

	// Empty proof against a zero root: the leaf hash will not match
	// the zero root, so inclusion must be reported as false.
	valid, err := zv.VerifyCommitmentInclusion(poolID, [32]byte{0x01}, [][]byte{}, 0)
	if err != nil {
		t.Fatalf("VerifyCommitmentInclusion failed: %v", err)
	}
	if valid {
		t.Error("Expected non-matching leaf to be reported as not included")
	}
}

func BenchmarkSpendNullifier(b *testing.B) {
	zv := NewZKVerifier()
	txHash := common.HexToHash("0xABCDEF")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nullifier := [32]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		_ = zv.SpendNullifier(nullifier, txHash, uint64(i))
	}
}

func BenchmarkCheckNullifier(b *testing.B) {
	zv := NewZKVerifier()

	for i := range 10000 {
		nullifier := [32]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		zv.Nullifiers[nullifier] = &Nullifier{}
	}

	nullifier := [32]byte{0x00, 0x00, 0x27, 0x10} // 10000

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = zv.CheckNullifier(nullifier)
	}
}
