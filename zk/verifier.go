// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"crypto/sha256"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
)

// ZKVerifier provides the Go-side bookkeeping that backs the EVM
// precompile at 0x0900.
//
// PQ POLICY — IMPORTANT:
// Classical pairing-based SNARK verification (Groth16, PLONK, fflonk,
// KZG opening proofs, Bulletproofs range proofs) has been REMOVED.
// Those systems rely on the discrete-log / pairing-product assumption
// over BN254 or BLS12-381 and are broken by Shor's algorithm. Only
// hash-based primitives (nullifier lookups, Merkle commitment
// inclusion) remain accessible through this verifier.
//
// PQ STARK verification is handled by the P3Q backend dispatched via
// consensus/protocol/zchain/verify.go, not from this verifier.
type ZKVerifier struct {
	// Verification key metadata (kept for Go-side bookkeeping by
	// off-chain rollup builders; no on-chain verification path uses it).
	VerifyingKeys map[[32]byte]*VerifyingKey

	// Nullifier tracking (for privacy)
	Nullifiers map[[32]byte]*Nullifier

	// Commitment tracking
	Commitments map[[32]byte]*Commitment

	// Confidential pools
	Pools map[[32]byte]*ConfidentialPool

	mu sync.RWMutex
}

// NewZKVerifier creates a new ZK verifier.
func NewZKVerifier() *ZKVerifier {
	return &ZKVerifier{
		VerifyingKeys: make(map[[32]byte]*VerifyingKey),
		Nullifiers:    make(map[[32]byte]*Nullifier),
		Commitments:   make(map[[32]byte]*Commitment),
		Pools:         make(map[[32]byte]*ConfidentialPool),
	}
}

// RegisterVerifyingKey records verifying-key metadata for off-chain use.
// This is bookkeeping only — no on-chain pairing-based verifier exists.
func (zv *ZKVerifier) RegisterVerifyingKey(
	owner common.Address,
	proofSystem ProofSystem,
	circuitType CircuitType,
	alpha, beta, gamma, delta []byte,
	ic [][]byte,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	keyData := append(alpha, beta...)
	keyData = append(keyData, gamma...)
	keyData = append(keyData, delta...)
	keyID := sha256.Sum256(keyData)

	zv.VerifyingKeys[keyID] = &VerifyingKey{
		KeyID:       keyID,
		ProofSystem: proofSystem,
		CircuitType: circuitType,
		Alpha:       alpha,
		Beta:        beta,
		Gamma:       gamma,
		Delta:       delta,
		IC:          ic,
		Hash:        sha256.Sum256(keyData),
		Owner:       owner,
		CreatedAt:   uint64(time.Now().Unix()),
	}
	return keyID, nil
}

// CheckNullifier checks if a nullifier has been spent.
func (zv *ZKVerifier) CheckNullifier(nullifierHash [32]byte) (bool, error) {
	zv.mu.RLock()
	defer zv.mu.RUnlock()

	_, spent := zv.Nullifiers[nullifierHash]
	return spent, nil
}

// SpendNullifier marks a nullifier as spent.
func (zv *ZKVerifier) SpendNullifier(
	nullifierHash [32]byte,
	txHash common.Hash,
	blockHeight uint64,
) error {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	if _, exists := zv.Nullifiers[nullifierHash]; exists {
		return ErrNullifierSpent
	}

	zv.Nullifiers[nullifierHash] = &Nullifier{
		Hash:    nullifierHash,
		SpentAt: blockHeight,
		SpentTx: txHash,
	}
	return nil
}

// AddCommitment adds a new commitment to a confidential pool.
func (zv *ZKVerifier) AddCommitment(
	poolID [32]byte,
	commitment *Commitment,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	pool := zv.Pools[poolID]
	if pool == nil {
		return [32]byte{}, ErrPoolNotFound
	}
	if !pool.Enabled {
		return [32]byte{}, ErrPoolDisabled
	}

	commitID := sha256.Sum256(commitment.Value)
	pool.Commitments[commitID] = commitment
	pool.TotalDeposits.Add(pool.TotalDeposits, commitment.Amount)
	return commitID, nil
}

// VerifyCommitmentInclusion verifies a commitment is in the pool via a
// hash-based Merkle proof. Hash-based Merkle proofs are PQ-safe.
func (zv *ZKVerifier) VerifyCommitmentInclusion(
	poolID [32]byte,
	commitmentID [32]byte,
	merkleProof [][]byte,
	leafIndex uint64,
) (bool, error) {
	zv.mu.RLock()
	defer zv.mu.RUnlock()

	pool := zv.Pools[poolID]
	if pool == nil {
		return false, ErrPoolNotFound
	}
	return zv.verifyMerkleProof(pool.MerkleRoot, commitmentID[:], merkleProof, leafIndex), nil
}

// CreateConfidentialPool creates a new confidential transaction pool.
func (zv *ZKVerifier) CreateConfidentialPool(
	owner common.Address,
	token common.Address,
	merkleDepth uint32,
) ([32]byte, error) {
	zv.mu.Lock()
	defer zv.mu.Unlock()

	poolData := append(owner.Bytes(), token.Bytes()...)
	poolID := sha256.Sum256(poolData)

	zv.Pools[poolID] = &ConfidentialPool{
		PoolID:         poolID,
		Token:          token,
		Commitments:    make(map[[32]byte]*Commitment),
		Nullifiers:     make(map[[32]byte]*Nullifier),
		MerkleRoot:     [32]byte{},
		MerkleDepth:    merkleDepth,
		TotalDeposits:  big.NewInt(0),
		TotalWithdraws: big.NewInt(0),
		Enabled:        true,
	}
	return poolID, nil
}

// verifyMerkleProof verifies a SHA-256 Merkle inclusion proof.
func (zv *ZKVerifier) verifyMerkleProof(
	root [32]byte,
	leaf []byte,
	proof [][]byte,
	index uint64,
) bool {
	current := sha256.Sum256(leaf)
	for i, sibling := range proof {
		var combined []byte
		if (index>>uint(i))&1 == 0 {
			combined = append(current[:], sibling...)
		} else {
			combined = append(sibling, current[:]...)
		}
		current = sha256.Sum256(combined)
	}
	return current == root
}
