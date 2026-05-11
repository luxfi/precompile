// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pedersen was the BN254 Pedersen commitment / hash precompile.
//
// REMOVED: The implementation built homomorphic Pedersen commitments
// over BN254 G1 (C = v*G + r*H). Both binding and hiding reduce to the
// discrete-log assumption on BN254, which Shor's algorithm breaks. The
// Lux EVM retires the precompile rather than offer a quantum-broken
// commitment.
//
// The address 0x0500..0006 stays reserved so the precompile registry
// numbering is stable, but every call returns
// contract.ErrClassicalForbiddenInPQ. The 21000 minimum gas is deducted
// so the retired address cannot be probed for free.
//
// PQ-safe commitment schemes on the Lux EVM:
//   - Hash commitments (Blake3 0x3202, Poseidon2 0x3201): binding via
//     collision resistance, hiding via random salt — both Grover-bounded.
//   - For homomorphic / vector / range proofs, use STARK gadgets on
//     Z-chain rather than DLOG-based commitments.
package pedersen

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the (reserved) address of the retired Pedersen
	// precompile. Calls to this address return ErrClassicalForbiddenInPQ.
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000006")

	// PedersenPrecompile is the retired-stub singleton.
	PedersenPrecompile = &pedersenPrecompile{}

	_ contract.StatefulPrecompiledContract = &pedersenPrecompile{}
)

// MinCallGas is charged on every call so that the retired precompile
// cannot be probed for free.
const MinCallGas uint64 = 21_000

type pedersenPrecompile struct{}

// RequiredGas always returns MinCallGas; the precompile is retired.
func (p *pedersenPrecompile) RequiredGas(input []byte) uint64 {
	return MinCallGas
}

// Run refuses all calls with ErrClassicalForbiddenInPQ.
func (p *pedersenPrecompile) Run(
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
