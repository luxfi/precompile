// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kzg4844 was the EIP-4844 KZG polynomial commitment precompile.
//
// REMOVED: KZG opening proofs are verified with a BLS12-381 pairing check
// (e(C - [y]G1, G2) == e(proof, [tau - z]G2)). The discrete-log assumption
// that anchors the pairing's security is broken by Shor's algorithm on a
// cryptographically relevant quantum computer, so KZG-based blob
// commitments give zero confidentiality and zero soundness against a
// future quantum adversary. The Lux EVM is PQ-only; we therefore retire
// this precompile.
//
// The address 0xB002 is kept reserved (the module still registers) so
// that the precompile registry numbering is stable across releases.
// Any call to this contract returns contract.ErrClassicalForbiddenInPQ.
//
// Blob availability for the Lux EVM is provided by hash-based commitments
// (Blake3 / Poseidon2) and STARK-validated state roots, not KZG.
package kzg4844

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the (reserved) address of the retired KZG4844
	// precompile. Calls to this address return ErrClassicalForbiddenInPQ.
	ContractAddress = common.HexToAddress("0xB002")

	// KZG4844Precompile is the retired-stub singleton.
	KZG4844Precompile = &kzg4844Precompile{}

	_ contract.StatefulPrecompiledContract = &kzg4844Precompile{}
)

// MinCallGas is charged on every call so that the retired precompile
// cannot be probed for free.
const MinCallGas uint64 = 21_000

type kzg4844Precompile struct{}

// Address returns the reserved address of the retired KZG4844 precompile.
func (p *kzg4844Precompile) Address() common.Address {
	return ContractAddress
}

// RequiredGas always returns MinCallGas; the precompile is retired and
// rejects every call.
func (p *kzg4844Precompile) RequiredGas(input []byte) uint64 {
	return MinCallGas
}

// Run refuses all calls with ErrClassicalForbiddenInPQ. The minimum gas
// is still deducted so that callers cannot use the retired address as a
// zero-cost oracle.
func (p *kzg4844Precompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	remainingGas, err := contract.DeductGas(suppliedGas, MinCallGas)
	if err != nil {
		return nil, 0, err
	}
	return nil, remainingGas, contract.ErrClassicalForbiddenInPQ
}
