// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zk provides the EVM-callable ZK precompile at address 0x0900.
//
// This precompile is PQ-safe-only. It exposes hash-based nullifiers and
// Merkle commitment inclusion checks. Classical pairing-based SNARK
// verification (Groth16, PLONK, fflonk, Halo2, KZG, IPA, Bulletproofs)
// has been removed because Shor's algorithm breaks the discrete-log /
// pairing assumptions those systems rely on.
//
// PQ STARK verification is handled by the P3Q backend dispatched via the
// Z-Chain envelope path (consensus/protocol/zchain/verify.go), not from
// this EVM precompile.
package zk

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// Note: ErrInvalidPublicInputs is defined in types.go
	ErrInvalidInput         = contract.ErrInvalidInput
	ErrInvalidOperation     = errors.New("invalid operation selector")
	ErrVerificationFailed   = errors.New("proof verification failed")
	ErrVerifierRequired     = errors.New("verifier context required")
	ErrInvalidCommitmentLen = errors.New("invalid commitment length")
)

// Operation selectors (first byte of input)
const (
	OpVerifyNullifier  = 0x21 // Verify nullifier (hash-based, PQ-safe)
	OpVerifyCommitment = 0x22 // Verify Merkle commitment inclusion (PQ-safe)
)

// Gas costs
const (
	GasNullifierBase  = 10000 // Base cost for nullifier check
	GasCommitmentBase = 20000 // Base cost for commitment
)

type zkVerifyPrecompile struct {
	verifier *ZKVerifier
}

// Address returns the precompile address
func (p *zkVerifyPrecompile) Address() common.Address {
	return ZKVerifyContractAddress
}

// MinCallGas is charged for any precompile call, including unknown opcodes,
// to prevent zero-cost abuse.
const MinCallGas uint64 = 21_000

// RequiredGas calculates gas for ZK operations
func (p *zkVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return MinCallGas
	}

	switch input[0] {
	case OpVerifyNullifier:
		return GasNullifierBase
	case OpVerifyCommitment:
		return GasCommitmentBase
	default:
		return MinCallGas
	}
}

// Run executes the ZK verify precompile
func (p *zkVerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	// Calculate required gas
	requiredGas := p.RequiredGas(input)
	remainingGas, err = contract.DeductGas(suppliedGas, requiredGas)
	if err != nil {
		return nil, 0, err
	}

	if len(input) < 1 {
		return nil, remainingGas, ErrInvalidInput
	}

	op := input[0]
	data := input[1:]

	switch op {
	case OpVerifyNullifier:
		valid, err := p.verifyNullifier(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyCommitment:
		valid, err := p.verifyCommitment(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	default:
		return nil, remainingGas, ErrInvalidOperation
	}
}

// encodeBool encodes a boolean as 32-byte EVM word
func encodeBool(b bool) []byte {
	result := make([]byte, 32)
	if b {
		result[31] = 1
	}
	return result
}

// verifyNullifier checks if a nullifier has been used (spent).
//
// Nullifiers are hash-based commitments used in privacy-preserving protocols
// to prevent double-spending without revealing which note is being spent.
// Hash-based nullifiers are PQ-safe (Grover-resistant at 256-bit hash width).
//
// Input format:
// - [0:32] nullifierHash - the nullifier hash to check
//
// Returns:
// - true if the nullifier has NOT been spent (is valid for use)
// - false if the nullifier has already been spent (double-spend attempt)
func (p *zkVerifyPrecompile) verifyNullifier(data []byte) (bool, error) {
	if len(data) < 32 {
		return false, ErrInvalidInput
	}

	var nullifierHash [32]byte
	copy(nullifierHash[:], data[:32])

	if p.verifier != nil {
		spent, err := p.verifier.CheckNullifier(nullifierHash)
		if err != nil {
			return false, err
		}
		// Return true if NOT spent (valid for use)
		return !spent, nil
	}

	// Without a verifier context, we can't check state
	return false, ErrVerifierRequired
}

// verifyCommitment verifies Merkle inclusion of a commitment in a pool.
//
// Input format:
// - [0:32]   poolID - pool identifier
// - [32:64]  commitmentID - commitment to verify
// - [64:72]  leafIndex - position in Merkle tree (big-endian uint64)
// - [72:76]  proofLen - number of sibling hashes (big-endian uint32)
// - [76:...] merkleProof - sibling hashes (proofLen * 32 bytes)
//
// Hash-based Merkle proofs are PQ-safe.
func (p *zkVerifyPrecompile) verifyCommitment(data []byte) (bool, error) {
	// poolID(32) + commitmentID(32) + leafIndex(8) + proofLen(4) = 76 bytes minimum
	if len(data) < 76 {
		return false, ErrInvalidInput
	}

	var poolID [32]byte
	copy(poolID[:], data[:32])

	var commitmentID [32]byte
	copy(commitmentID[:], data[32:64])

	leafIndex := binary.BigEndian.Uint64(data[64:72])
	proofLen := binary.BigEndian.Uint32(data[72:76])

	// Validate proof length
	expectedLen := 76 + int(proofLen)*32
	if len(data) < expectedLen {
		return false, ErrInvalidInput
	}

	// Parse merkle proof
	merkleProof := make([][]byte, proofLen)
	offset := 76
	for i := range proofLen {
		merkleProof[i] = make([]byte, 32)
		copy(merkleProof[i], data[offset:offset+32])
		offset += 32
	}

	if p.verifier != nil {
		return p.verifier.VerifyCommitmentInclusion(poolID, commitmentID, merkleProof, leafIndex)
	}

	return false, ErrVerifierRequired
}
