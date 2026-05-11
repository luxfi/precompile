// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package babyjubjub was the Baby Jubjub twisted Edwards curve precompile.
//
// REMOVED: Baby Jubjub is the ZK-friendly companion curve to BN254 used
// by circom / iden3 / Polygon zkEVM / Semaphore / RLN / EdDSA-on-BN254.
// Its security reduces to discrete-log over BN254's scalar field, which
// is broken by Shor's algorithm. Every consumer of Baby Jubjub is a
// classical pairing-based SNARK gadget that has no PQ analogue: the
// Lux EVM retires the precompile rather than offer a quantum-broken
// primitive.
//
// The address 0x0500..0007 stays reserved so the precompile registry
// numbering is stable, but every call returns
// contract.ErrClassicalForbiddenInPQ. The 21000 minimum gas is deducted
// so the retired address cannot be used as a zero-cost probe.
//
// PQ-safe ZK gadgets on the Lux EVM use Poseidon2 hashing (0x3201) +
// Blake3 (0x3202) + STARK verification on Z-chain.
package babyjubjub

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the (reserved) address of the retired Baby Jubjub
	// precompile. Calls to this address return ErrClassicalForbiddenInPQ.
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000007")

	// BabyJubJubPrecompile is the retired-stub singleton.
	BabyJubJubPrecompile = &babyJubJubPrecompile{}

	_ contract.StatefulPrecompiledContract = &babyJubJubPrecompile{}
)

// MinCallGas is charged on every call so that the retired precompile
// cannot be probed for free.
const MinCallGas uint64 = 21_000

type babyJubJubPrecompile struct{}

// RequiredGas always returns MinCallGas; the precompile is retired.
func (p *babyJubJubPrecompile) RequiredGas(input []byte) uint64 {
	return MinCallGas
}

// Run refuses all calls with ErrClassicalForbiddenInPQ.
func (p *babyJubJubPrecompile) Run(
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
