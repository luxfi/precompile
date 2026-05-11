// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package poseidon implements the Poseidon/Poseidon2 ZK-friendly hash precompile.
// Address: 0x0500000000000000000000000000000000000005 (Hashing range)
//
// Poseidon is algebraic over prime fields, making it ideal for ZK circuits.
// Supports width 2-16 field elements over BN254 scalar field.
//
// Operations:
//   - 0x01: Hash (arbitrary width 1-16 elements) -> 32 bytes
//   - 0x02: HashPair (exactly 2 elements) -> 32 bytes (Merkle tree optimized)
//   - 0x03: Sponge (absorb arbitrary data, squeeze arbitrary output)
//
// Used by: zkRollups, Polygon zkEVM, Scroll, StarkNet, privacy pools.
package poseidon

import (
	"encoding/binary"
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000005")

	PoseidonPrecompile = &poseidonPrecompile{}

	_ contract.StatefulPrecompiledContract = &poseidonPrecompile{}

	ErrInvalidInput  = contract.ErrInvalidInput
	ErrTooManyInputs = errors.New("too many inputs: max 16 field elements")
	ErrInvalidOp     = errors.New("invalid operation selector")
)

const (
	OpHash     = 0x01
	OpHashPair = 0x02
	OpSponge   = 0x03

	GasHashBase    = 500
	GasPerElement  = 100
	GasHashPair    = 700
	GasSpongeBase  = 600
	GasSpongePerIn = 100
)

type poseidonPrecompile struct{}

func (p *poseidonPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpHash:
		n := (len(input) - 1) / 32
		if n == 0 {
			return 0
		}
		return GasHashBase + uint64(n)*GasPerElement
	case OpHashPair:
		return GasHashPair
	case OpSponge:
		if len(input) < 5 {
			return 0
		}
		n := (len(input) - 5) / 32
		return GasSpongeBase + uint64(n)*GasSpongePerIn
	default:
		return 0
	}
}

func (p *poseidonPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, gas, err
	}
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	switch input[0] {
	case OpHash:
		return p.hash(input[1:], gas)
	case OpHashPair:
		return p.hashPair(input[1:], gas)
	case OpSponge:
		return p.sponge(input[1:], gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

func (p *poseidonPrecompile) hash(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) == 0 || len(data)%32 != 0 {
		return nil, gas, ErrInvalidInput
	}
	n := len(data) / 32
	if n > 16 {
		return nil, gas, ErrTooManyInputs
	}

	hasher := poseidon2.NewMerkleDamgardHasher()
	for i := range n {
		var elem fr.Element
		elem.SetBytes(data[i*32 : (i+1)*32])
		b := elem.Bytes()
		hasher.Write(b[:])
	}
	h := hasher.Sum(nil)
	result := make([]byte, 32)
	copy(result, h)
	return result, gas, nil
}

func (p *poseidonPrecompile) hashPair(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	var left, right fr.Element
	left.SetBytes(data[:32])
	right.SetBytes(data[32:64])

	hasher := poseidon2.NewMerkleDamgardHasher()
	lb := left.Bytes()
	rb := right.Bytes()
	hasher.Write(lb[:])
	hasher.Write(rb[:])
	h := hasher.Sum(nil)
	result := make([]byte, 32)
	copy(result, h)
	return result, gas, nil
}

func (p *poseidonPrecompile) sponge(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 4 {
		return nil, gas, ErrInvalidInput
	}
	outLen := binary.BigEndian.Uint32(data[:4])
	if outLen > 1024 || outLen == 0 {
		return nil, gas, ErrInvalidInput
	}
	payload := data[4:]
	if len(payload)%32 != 0 {
		return nil, gas, ErrInvalidInput
	}
	n := len(payload) / 32
	if n > 16 {
		return nil, gas, ErrTooManyInputs
	}

	// Sponge construction over Poseidon2 permutation (width=3, rate=1).
	//
	// Absorb: for each input element, add it to state[0] and permute.
	// Squeeze: extract state[0] (one rate element = 32 bytes), permute,
	// repeat until we have enough output bytes.
	//
	// Width 3 is the standard sponge width for Poseidon2 over BN254:
	// rate=1 element (32 bytes), capacity=2 elements (64 bytes, >= 128-bit
	// security against generic sponge attacks).
	const (
		spongeWidth = 3
		rateBytes   = fr.Bytes // 32
	)

	perm := poseidon2.NewPermutation(spongeWidth, 6, 50)
	state := make([]fr.Element, spongeWidth) // zero-initialized (capacity domain sep)

	// Absorb phase: XOR each input element into state[0], then permute.
	for i := range n {
		var elem fr.Element
		elem.SetBytes(payload[i*32 : (i+1)*32])
		state[0].Add(&state[0], &elem)
		perm.Permutation(state)
	}

	// Squeeze phase: extract rate element, permute for more output.
	result := make([]byte, 0, outLen)
	for uint32(len(result)) < outLen {
		b := state[0].Bytes()
		result = append(result, b[:]...)
		if uint32(len(result)) < outLen {
			perm.Permutation(state)
		}
	}

	return result[:outLen], gas, nil
}
