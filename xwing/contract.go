// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package xwing implements the X-Wing hybrid KEM precompile (X25519 + ML-KEM-768).
// Address: 0x0000000000000000000000000000000000002221 (PQ Hybrid KEM, LP-2221)
//
// X-Wing combines classical X25519 with post-quantum ML-KEM-768 for hybrid
// key encapsulation, as specified in IETF draft-connolly-cfrg-xwing-kem.
//
// Operations:
//   - 0x02: Encapsulate -> pk -> (ct, ss) ciphertext + shared secret
//
// KeyGen and Decapsulate are intentionally excluded: KeyGen returns secret
// key material in EVM return data (visible to all validators), and
// Decapsulate requires the secret key in calldata (public on-chain).
// Both operations MUST be performed off-chain.
package xwing

import (
	"errors"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/xwing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// Ensure circl KEM interface is satisfied (compile-time check)
var _ kem.Scheme = xwing.Scheme()

var (
	// LP-2221: C-Chain hybrid KEM (X25519+ML-KEM)
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000002221")

	XWingPrecompile = &xwingPrecompile{}

	_ contract.StatefulPrecompiledContract = &xwingPrecompile{}

	ErrInvalidInput = errors.New("invalid xwing input")
	ErrInvalidOp    = errors.New("invalid xwing operation")
)

const (
	OpEncapsulate = 0x02

	GasEncapsulate = 40000
)

type xwingPrecompile struct{}

func (p *xwingPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpEncapsulate:
		return GasEncapsulate
	default:
		return 0
	}
}

func (p *xwingPrecompile) Run(
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
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	scheme := xwing.Scheme()

	switch input[0] {
	case OpEncapsulate:
		pkSize := scheme.PublicKeySize()
		if len(input) < 1+pkSize {
			return nil, gas, ErrInvalidInput
		}
		pk, err := scheme.UnmarshalBinaryPublicKey(input[1 : 1+pkSize])
		if err != nil {
			return nil, gas, err
		}
		ct, ss, err := scheme.Encapsulate(pk)
		if err != nil {
			return nil, gas, err
		}
		// Output: [2 bytes ct_len][ct][ss]
		result := make([]byte, 2+len(ct)+len(ss))
		result[0] = byte(len(ct) >> 8)
		result[1] = byte(len(ct))
		copy(result[2:], ct)
		copy(result[2+len(ct):], ss)
		return result, gas, nil

	default:
		return nil, gas, ErrInvalidOp
	}
}
