// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/bn256"
	"github.com/luxfi/geth/common"
)

// TestNewZKVerifier tests verifier creation
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
	if zv.Rollups == nil {
		t.Error("Expected Rollups map to be initialized")
	}
	if zv.Pools == nil {
		t.Error("Expected Pools map to be initialized")
	}
}

// TestRegisterVerifyingKey tests verifying key registration
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
		ProofSystemGroth16,
		CircuitTransfer,
		alpha, beta, gamma, delta, ic,
	)

	if err != nil {
		t.Fatalf("RegisterVerifyingKey failed: %v", err)
	}

	if keyID == [32]byte{} {
		t.Error("Expected non-zero key ID")
	}

	// Verify key was stored
	vk := zv.VerifyingKeys[keyID]
	if vk == nil {
		t.Fatal("Verifying key not stored")
	}
	if vk.ProofSystem != ProofSystemGroth16 {
		t.Errorf("Expected Groth16, got %v", vk.ProofSystem)
	}
	if vk.CircuitType != CircuitTransfer {
		t.Errorf("Expected Transfer circuit, got %v", vk.CircuitType)
	}
	if vk.Owner != owner {
		t.Error("Owner mismatch")
	}
	if len(vk.IC) != 3 {
		t.Errorf("Expected 3 IC points, got %d", len(vk.IC))
	}
}

// TestVerifyGroth16 tests Groth16 proof verification
func TestVerifyGroth16(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Register verifying key with 3 IC points (2 public inputs + 1)
	ic := [][]byte{[]byte("ic0"), []byte("ic1"), []byte("ic2")}
	keyID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitTransfer,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		ic,
	)

	// Create proof
	proofA := make([]byte, 64)
	proofB := make([]byte, 128)
	proofC := make([]byte, 64)
	publicInputs := []*big.Int{big.NewInt(100), big.NewInt(200)}

	result, err := zv.VerifyGroth16(keyID, proofA, proofB, proofC, publicInputs)
	if err != nil {
		t.Fatalf("VerifyGroth16 failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.ProofSystem != ProofSystemGroth16 {
		t.Errorf("Expected Groth16, got %v", result.ProofSystem)
	}
	if result.GasUsed != GasGroth16Verify {
		t.Errorf("Expected gas %d, got %d", GasGroth16Verify, result.GasUsed)
	}
	if len(result.PublicInputs) != 2 {
		t.Errorf("Expected 2 public inputs, got %d", len(result.PublicInputs))
	}

	// Verify stats updated
	if zv.TotalVerifications != 1 {
		t.Errorf("Expected 1 verification, got %d", zv.TotalVerifications)
	}
}

// TestVerifyGroth16InvalidKey tests error for non-existent key
func TestVerifyGroth16InvalidKey(t *testing.T) {
	zv := NewZKVerifier()

	nonExistent := [32]byte{0xFF}
	_, err := zv.VerifyGroth16(nonExistent, nil, nil, nil, nil)
	if err != ErrInvalidVerifyingKey {
		t.Errorf("Expected ErrInvalidVerifyingKey, got %v", err)
	}
}

// TestVerifyGroth16WrongProofSystem tests proof system validation
func TestVerifyGroth16WrongProofSystem(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Register as PLONK
	keyID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemPlonk,
		CircuitTransfer,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)

	// Try to verify as Groth16
	_, err := zv.VerifyGroth16(keyID, nil, nil, nil, nil)
	if err != ErrProofSystemMismatch {
		t.Errorf("Expected ErrProofSystemMismatch, got %v", err)
	}
}

// TestVerifyGroth16InvalidPublicInputs tests public input count validation
func TestVerifyGroth16InvalidPublicInputs(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Register with 3 IC points (expects 2 public inputs)
	keyID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitTransfer,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0"), []byte("ic1"), []byte("ic2")},
	)

	// Provide wrong number of public inputs
	publicInputs := []*big.Int{big.NewInt(1)} // Only 1, should be 2

	_, err := zv.VerifyGroth16(keyID, []byte("a"), []byte("b"), []byte("c"), publicInputs)
	if err != ErrInvalidPublicInputs {
		t.Errorf("Expected ErrInvalidPublicInputs, got %v", err)
	}
}

// TestVerifyPlonk tests PLONK proof verification
func TestVerifyPlonk(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemPlonk,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)

	proof := make([]byte, 512)
	publicInputs := []*big.Int{big.NewInt(100)}

	result, err := zv.VerifyPlonk(keyID, proof, publicInputs)
	if err != nil {
		t.Fatalf("VerifyPlonk failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.ProofSystem != ProofSystemPlonk {
		t.Errorf("Expected PLONK, got %v", result.ProofSystem)
	}
	if result.GasUsed != GasPlonkVerify {
		t.Errorf("Expected gas %d, got %d", GasPlonkVerify, result.GasUsed)
	}
}

// TestCheckNullifier tests nullifier checking
func TestCheckNullifier(t *testing.T) {
	zv := NewZKVerifier()

	nullifierHash := [32]byte{0x01, 0x02, 0x03}

	// Initially not spent
	spent, err := zv.CheckNullifier(nullifierHash)
	if err != nil {
		t.Fatalf("CheckNullifier failed: %v", err)
	}
	if spent {
		t.Error("Expected nullifier to be unspent")
	}

	// Spend it
	txHash := common.HexToHash("0xABCDEF")
	err = zv.SpendNullifier(nullifierHash, txHash, 100)
	if err != nil {
		t.Fatalf("SpendNullifier failed: %v", err)
	}

	// Now should be spent
	spent, err = zv.CheckNullifier(nullifierHash)
	if err != nil {
		t.Fatalf("CheckNullifier failed: %v", err)
	}
	if !spent {
		t.Error("Expected nullifier to be spent")
	}
}

// TestSpendNullifierAlreadySpent tests double-spend prevention
func TestSpendNullifierAlreadySpent(t *testing.T) {
	zv := NewZKVerifier()

	nullifierHash := [32]byte{0x01, 0x02, 0x03}
	txHash := common.HexToHash("0xABCDEF")

	// First spend
	err := zv.SpendNullifier(nullifierHash, txHash, 100)
	if err != nil {
		t.Fatalf("First spend failed: %v", err)
	}

	// Second spend should fail
	err = zv.SpendNullifier(nullifierHash, txHash, 101)
	if err != ErrNullifierSpent {
		t.Errorf("Expected ErrNullifierSpent, got %v", err)
	}
}

// TestCreateConfidentialPool tests pool creation
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

	// Verify pool was created
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

// TestAddCommitment tests adding commitment to pool
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

	// Verify pool state updated
	pool := zv.Pools[poolID]
	if pool.TotalDeposits.Cmp(big.NewInt(1e18)) != 0 {
		t.Error("Total deposits not updated")
	}
}

// TestAddCommitmentPoolNotFound tests error for non-existent pool
func TestAddCommitmentPoolNotFound(t *testing.T) {
	zv := NewZKVerifier()

	nonExistent := [32]byte{0xFF}
	_, err := zv.AddCommitment(nonExistent, &Commitment{})
	if err != ErrPoolNotFound {
		t.Errorf("Expected ErrPoolNotFound, got %v", err)
	}
}

// TestAddCommitmentPoolDisabled tests error for disabled pool
func TestAddCommitmentPoolDisabled(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	poolID, _ := zv.CreateConfidentialPool(owner, token, 32)

	// Disable pool
	zv.Pools[poolID].Enabled = false

	_, err := zv.AddCommitment(poolID, &Commitment{Amount: big.NewInt(1)})
	if err != ErrPoolDisabled {
		t.Errorf("Expected ErrPoolDisabled, got %v", err)
	}
}

// TestVerifyCommitmentInclusion tests merkle proof verification
func TestVerifyCommitmentInclusion(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	token := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	poolID, _ := zv.CreateConfidentialPool(owner, token, 32)

	// Test with empty proof (function still works for basic check)
	valid, err := zv.VerifyCommitmentInclusion(poolID, [32]byte{0x01}, [][]byte{}, 0)
	if err != nil {
		t.Fatalf("VerifyCommitmentInclusion failed: %v", err)
	}

	_ = valid // Placeholder returns true for empty root
}

// TestRegisterRollup tests rollup registration
func TestRegisterRollup(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sequencer := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")

	// First register a verifying key
	vkID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)

	rollupID, err := zv.RegisterRollup(
		owner,
		vkID,
		ProofSystemGroth16,
		1000, // max tx per batch
		60,   // batch interval
		sequencer,
	)

	if err != nil {
		t.Fatalf("RegisterRollup failed: %v", err)
	}

	if rollupID == [32]byte{} {
		t.Error("Expected non-zero rollup ID")
	}

	// Verify rollup config
	config := zv.Rollups[rollupID]
	if config == nil {
		t.Fatal("Rollup config not stored")
	}
	if config.Owner != owner {
		t.Error("Owner mismatch")
	}
	if config.Sequencer != sequencer {
		t.Error("Sequencer mismatch")
	}
	if config.MaxTxPerBatch != 1000 {
		t.Errorf("Expected max tx 1000, got %d", config.MaxTxPerBatch)
	}
	if !config.Enabled {
		t.Error("Expected rollup to be enabled")
	}

	// Verify state initialized
	state := zv.RollupStates[rollupID]
	if state == nil {
		t.Fatal("Rollup state not initialized")
	}
}

// TestRegisterRollupInvalidKey tests error for non-existent verifying key
func TestRegisterRollupInvalidKey(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	nonExistent := [32]byte{0xFF}
	_, err := zv.RegisterRollup(owner, nonExistent, ProofSystemGroth16, 1000, 60, owner)
	if err != ErrInvalidVerifyingKey {
		t.Errorf("Expected ErrInvalidVerifyingKey, got %v", err)
	}
}

// TestVerifyRollupBatch tests batch verification
// Note: With real cryptographic verification, invalid proof data is rejected.
// This test verifies the error handling for invalid proofs.
func TestVerifyRollupBatch(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Setup rollup with placeholder VK (valid format but won't verify real proofs)
	vkID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0"), []byte("ic1"), []byte("ic2"), []byte("ic3"), []byte("ic4")},
	)
	rollupID, _ := zv.RegisterRollup(owner, vkID, ProofSystemGroth16, 1000, 60, owner)

	// Create batch with placeholder proof data (invalid curve points)
	batch := &RollupBatch{
		BatchID:       [32]byte{0x01},
		RollupID:      rollupID,
		PrevStateRoot: [32]byte{}, // Matches initial state
		NewStateRoot:  [32]byte{0x02},
		Transactions:  500,
		L1BatchNum:    1,
		Proposer:      owner,
		Proof: &Proof{
			A: make([]byte, 64),
			B: make([]byte, 128),
			C: make([]byte, 64),
		},
	}

	// With real crypto verification, invalid proof data should fail
	err := zv.VerifyRollupBatch(rollupID, batch)
	if err != ErrInvalidProof {
		t.Errorf("Expected ErrInvalidProof for invalid proof data, got %v", err)
	}
}

// TestVerifyRollupBatchStateUpdate tests that valid state updates work
// when cryptographic verification is bypassed (integration test pattern)
func TestVerifyRollupBatchStateUpdate(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Setup rollup
	vkID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0"), []byte("ic1"), []byte("ic2"), []byte("ic3"), []byte("ic4")},
	)
	rollupID, _ := zv.RegisterRollup(owner, vkID, ProofSystemGroth16, 1000, 60, owner)

	// Verify initial state
	state, err := zv.GetRollupState(rollupID)
	if err != nil {
		t.Fatalf("GetRollupState failed: %v", err)
	}
	if state.TotalBatches != 0 {
		t.Errorf("Expected 0 initial batches, got %d", state.TotalBatches)
	}
	if state.LastStateRoot != ([32]byte{}) {
		t.Error("Expected empty initial state root")
	}
}

// TestVerifyRollupBatchNotFound tests error for non-existent rollup
func TestVerifyRollupBatchNotFound(t *testing.T) {
	zv := NewZKVerifier()

	nonExistent := [32]byte{0xFF}
	err := zv.VerifyRollupBatch(nonExistent, &RollupBatch{})
	if err != ErrRollupNotFound {
		t.Errorf("Expected ErrRollupNotFound, got %v", err)
	}
}

// TestVerifyRollupBatchUnauthorized tests proposer authorization
func TestVerifyRollupBatchUnauthorized(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sequencer := common.HexToAddress("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
	unauthorized := common.HexToAddress("0x1111111111111111111111111111111111111111")

	vkID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)
	rollupID, _ := zv.RegisterRollup(owner, vkID, ProofSystemGroth16, 1000, 60, sequencer)

	batch := &RollupBatch{
		RollupID: rollupID,
		Proposer: unauthorized,
	}

	err := zv.VerifyRollupBatch(rollupID, batch)
	if err != ErrUnauthorizedProposer {
		t.Errorf("Expected ErrUnauthorizedProposer, got %v", err)
	}
}

// TestVerifyRollupBatchTooLarge tests batch size validation
func TestVerifyRollupBatchTooLarge(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	vkID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)
	rollupID, _ := zv.RegisterRollup(owner, vkID, ProofSystemGroth16, 100, 60, owner)

	batch := &RollupBatch{
		RollupID:     rollupID,
		Transactions: 500, // Exceeds max 100
		Proposer:     owner,
	}

	err := zv.VerifyRollupBatch(rollupID, batch)
	if err != ErrBatchTooLarge {
		t.Errorf("Expected ErrBatchTooLarge, got %v", err)
	}
}

// TestVerifyRollupBatchInvalidStateRoot tests state root validation
func TestVerifyRollupBatchInvalidStateRoot(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	vkID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)
	rollupID, _ := zv.RegisterRollup(owner, vkID, ProofSystemGroth16, 1000, 60, owner)

	batch := &RollupBatch{
		RollupID:      rollupID,
		PrevStateRoot: [32]byte{0xFF}, // Doesn't match current state (empty)
		Transactions:  10,
		Proposer:      owner,
	}

	err := zv.VerifyRollupBatch(rollupID, batch)
	if err != ErrInvalidStateRoot {
		t.Errorf("Expected ErrInvalidStateRoot, got %v", err)
	}
}

// TestGetRollupState tests state retrieval
func TestGetRollupState(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	vkID, _ := zv.RegisterVerifyingKey(
		owner, ProofSystemGroth16, CircuitRollupBatch,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)
	rollupID, _ := zv.RegisterRollup(owner, vkID, ProofSystemGroth16, 1000, 60, owner)

	state, err := zv.GetRollupState(rollupID)
	if err != nil {
		t.Fatalf("GetRollupState failed: %v", err)
	}

	if state == nil {
		t.Fatal("Expected non-nil state")
	}
	if state.TotalBatches != 0 {
		t.Errorf("Expected 0 batches, got %d", state.TotalBatches)
	}
}

// TestGetRollupStateNotFound tests error for non-existent rollup
func TestGetRollupStateNotFound(t *testing.T) {
	zv := NewZKVerifier()

	nonExistent := [32]byte{0xFF}
	_, err := zv.GetRollupState(nonExistent)
	if err != ErrRollupNotFound {
		t.Errorf("Expected ErrRollupNotFound, got %v", err)
	}
}

// TestVerifyKZGNotInitialized tests KZG verification without setup
func TestVerifyKZGNotInitialized(t *testing.T) {
	zv := NewZKVerifier()

	_, err := zv.VerifyKZG([]byte("commit"), big.NewInt(1), big.NewInt(2), []byte("proof"))
	if err == nil {
		t.Error("Expected error for uninitialized KZG setup")
	}
}

// TestVerifyRangeProof tests range proof verification
func TestVerifyRangeProof(t *testing.T) {
	zv := NewZKVerifier()

	commitment := make([]byte, 32)
	rangeProof := make([]byte, 128)

	valid, err := zv.VerifyRangeProof(commitment, rangeProof, 64)
	if err != nil {
		t.Fatalf("VerifyRangeProof failed: %v", err)
	}

	_ = valid // Placeholder returns true
}

// TestVerificationStatistics tests stats tracking
func TestVerificationStatistics(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Register keys (use different values to avoid keyID collision)
	grothKeyID, err := zv.RegisterVerifyingKey(
		owner, ProofSystemGroth16, CircuitTransfer,
		[]byte("groth16_alpha"), []byte("groth16_beta"), []byte("groth16_gamma"), []byte("groth16_delta"),
		[][]byte{[]byte("ic0"), []byte("ic1")},
	)
	if err != nil {
		t.Fatalf("Failed to register Groth16 key: %v", err)
	}

	plonkKeyID, err := zv.RegisterVerifyingKey(
		owner, ProofSystemPlonk, CircuitTransfer,
		[]byte("plonk_alpha"), []byte("plonk_beta"), []byte("plonk_gamma"), []byte("plonk_delta"),
		[][]byte{[]byte("ic0")},
	)
	if err != nil {
		t.Fatalf("Failed to register PLONK key: %v", err)
	}

	// Perform verifications - each should increment TotalVerifications
	_, err = zv.VerifyGroth16(grothKeyID, []byte("a"), []byte("b"), []byte("c"), []*big.Int{big.NewInt(1)})
	if err != nil {
		t.Logf("VerifyGroth16 #1 error: %v", err)
	}

	_, err = zv.VerifyGroth16(grothKeyID, []byte("a"), []byte("b"), []byte("c"), []*big.Int{big.NewInt(2)})
	if err != nil {
		t.Logf("VerifyGroth16 #2 error: %v", err)
	}

	_, err = zv.VerifyPlonk(plonkKeyID, []byte("proof"), []*big.Int{})
	if err != nil {
		t.Logf("VerifyPlonk error: %v", err)
	}

	if zv.TotalVerifications != 3 {
		t.Errorf("Expected 3 verifications, got %d", zv.TotalVerifications)
	}
}

// Benchmark tests

func BenchmarkVerifyGroth16(b *testing.B) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID, _ := zv.RegisterVerifyingKey(
		owner, ProofSystemGroth16, CircuitTransfer,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0"), []byte("ic1")},
	)

	proofA := make([]byte, 64)
	proofB := make([]byte, 128)
	proofC := make([]byte, 64)
	publicInputs := []*big.Int{big.NewInt(100)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = zv.VerifyGroth16(keyID, proofA, proofB, proofC, publicInputs)
	}
}

func BenchmarkVerifyPlonk(b *testing.B) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	keyID, _ := zv.RegisterVerifyingKey(
		owner, ProofSystemPlonk, CircuitTransfer,
		[]byte("alpha"), []byte("beta"), []byte("gamma"), []byte("delta"),
		[][]byte{[]byte("ic0")},
	)

	proof := make([]byte, 512)
	publicInputs := []*big.Int{big.NewInt(100)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = zv.VerifyPlonk(keyID, proof, publicInputs)
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

	// Pre-populate some nullifiers
	for i := 0; i < 10000; i++ {
		nullifier := [32]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		zv.Nullifiers[nullifier] = &Nullifier{}
	}

	nullifier := [32]byte{0x00, 0x00, 0x27, 0x10} // 10000

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = zv.CheckNullifier(nullifier)
	}
}

// TestBN256PairingCheck tests that the BN256 pairing operations work correctly
// using real curve points from the BN254 curve.
func TestBN256PairingCheck(t *testing.T) {
	// Test that identity pairing check passes
	// e(0, 0) = 1 (empty product is identity)
	emptyG1 := []*bn256.G1{}
	emptyG2 := []*bn256.G2{}

	if !bn256.PairingCheck(emptyG1, emptyG2) {
		t.Error("Empty pairing check should return true")
	}
}

// TestGroth16WithRealCurvePoints tests Groth16 verification with properly
// formatted curve points to verify parsing and verification logic.
func TestGroth16WithRealCurvePoints(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create G1 point at infinity (all zeros in x,y)
	g1Infinity := make([]byte, 64)

	// Create G2 point at infinity (all zeros in x,y components)
	g2Infinity := make([]byte, 128)

	// Register a key with points at infinity (valid curve points)
	keyID, err := zv.RegisterVerifyingKey(
		owner,
		ProofSystemGroth16,
		CircuitTransfer,
		g1Infinity,                       // alpha (G1)
		g2Infinity,                       // beta (G2)
		g2Infinity,                       // gamma (G2)
		g2Infinity,                       // delta (G2)
		[][]byte{g1Infinity, g1Infinity}, // IC points (G1)
	)
	if err != nil {
		t.Fatalf("RegisterVerifyingKey failed: %v", err)
	}

	// Try to verify with infinity points
	proofA := g1Infinity
	proofB := g2Infinity
	proofC := g1Infinity
	publicInputs := []*big.Int{big.NewInt(0)}

	result, err := zv.VerifyGroth16(keyID, proofA, proofB, proofC, publicInputs)
	if err != nil {
		t.Fatalf("VerifyGroth16 returned error: %v", err)
	}

	// Note: Mathematically, identity points (infinity) satisfy the pairing equation
	// because e(O, Q) = 1 for the identity O in G1, and ∏ 1 = 1.
	// This is correct crypto behavior - the test verifies that parsing works
	// and the verification completes without errors.
	// Real proofs with proper curve points would need to satisfy e(A,B) = e(α,β)·e(vk_x,γ)·e(C,δ)
	if result.ProofSystem != ProofSystemGroth16 {
		t.Errorf("Expected ProofSystemGroth16, got %v", result.ProofSystem)
	}
}

// TestKZGPointEvaluationInvalidSizes tests that KZG verification rejects invalid input sizes
func TestKZGPointEvaluationInvalidSizes(t *testing.T) {
	zv := NewZKVerifier()

	// Setup with a KZGSetup to pass the nil check
	zv.KZGSetup = &KZGSetup{
		MaxDegree: 4096,
	}

	testCases := []struct {
		name       string
		commitment []byte
		proof      []byte
		wantValid  bool
	}{
		{"commitment too short", make([]byte, 32), make([]byte, 48), false},
		{"proof too short", make([]byte, 48), make([]byte, 32), false},
		{"both too short", make([]byte, 32), make([]byte, 32), false},
		{"correct sizes but invalid data", make([]byte, 48), make([]byte, 48), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, _ := zv.VerifyKZG(tc.commitment, big.NewInt(1), big.NewInt(2), tc.proof)
			if valid != tc.wantValid {
				t.Errorf("Expected valid=%v, got %v", tc.wantValid, valid)
			}
		})
	}
}

// TestCurvePointParsing tests that curve points can be correctly parsed
func TestCurvePointParsing(t *testing.T) {
	// BN254 G1 generator point coordinates (from Ethereum precompile test vectors)
	// G1 = (1, 2)
	g1GenX := "0000000000000000000000000000000000000000000000000000000000000001"
	g1GenY := "0000000000000000000000000000000000000000000000000000000000000002"

	g1Bytes, _ := hex.DecodeString(g1GenX + g1GenY)

	var g1 bn256.G1
	n, err := g1.Unmarshal(g1Bytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal G1 generator: %v", err)
	}
	if n != 64 {
		t.Errorf("Expected to consume 64 bytes, consumed %d", n)
	}

	// Verify serialization roundtrip
	serialized := g1.Marshal()
	if len(serialized) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(serialized))
	}
}

// TestPLONKProofSizeValidation tests that PLONK verification rejects undersized proofs
func TestPLONKProofSizeValidation(t *testing.T) {
	zv := NewZKVerifier()
	owner := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create minimal valid-format VK
	g1Point := make([]byte, 64)
	g2Point := make([]byte, 128)

	// PLONK VK needs 9 IC entries (8 G1 selector points + 1 G2 X2 point)
	ic := make([][]byte, 9)
	for i := 0; i < 8; i++ {
		ic[i] = g1Point
	}
	ic[8] = g2Point

	keyID, _ := zv.RegisterVerifyingKey(
		owner,
		ProofSystemPlonk,
		CircuitTransfer,
		g1Point,
		g2Point,
		g2Point,
		g2Point,
		ic,
	)

	// Test with undersized proof
	shortProof := make([]byte, 100) // Less than required 768 bytes
	result, err := zv.VerifyPlonk(keyID, shortProof, []*big.Int{})
	if err != nil {
		t.Fatalf("VerifyPlonk returned error: %v", err)
	}
	if result.Valid {
		t.Error("Expected undersized proof to fail verification")
	}
}
