// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package xwing implements the X-Wing hybrid KEM precompile (X25519 + ML-KEM-768).
// Address: 0x0000000000000000000000000000000000002221 (PQ Hybrid KEM, LP-2221)
//
// X-Wing combines classical X25519 with post-quantum ML-KEM-768 for hybrid
// key encapsulation, as specified in IETF draft-connolly-cfrg-xwing-kem.
//
// Operations:
//   - 0x01: KeyGen      -> (pk, sk) public/secret keypair
//   - 0x02: Encapsulate -> pk -> (ct, ss) ciphertext + shared secret
//   - 0x03: Decapsulate -> sk + ct -> ss shared secret
//
// Used by: post-quantum TLS, next-gen key exchange, PQ upgrade path.
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
	ErrDecapFailed  = errors.New("xwing decapsulation failed")
)

const (
	OpKeyGen      = 0x01
	OpEncapsulate = 0x02
	OpDecapsulate = 0x03

	GasKeyGen      = 50000
	GasEncapsulate = 40000
	GasDecapsulate = 40000
)

type xwingPrecompile struct{}

func (p *xwingPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpKeyGen:
		return GasKeyGen
	case OpEncapsulate:
		return GasEncapsulate
	case OpDecapsulate:
		return GasDecapsulate
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
	case OpKeyGen:
		pk, sk, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, gas, err
		}
		pkBytes, _ := pk.MarshalBinary()
		skBytes, _ := sk.MarshalBinary()
		// Output: [2 bytes pk_len][pk][sk]
		result := make([]byte, 2+len(pkBytes)+len(skBytes))
		result[0] = byte(len(pkBytes) >> 8)
		result[1] = byte(len(pkBytes))
		copy(result[2:], pkBytes)
		copy(result[2+len(pkBytes):], skBytes)
		return result, gas, nil

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

	case OpDecapsulate:
		skSize := scheme.PrivateKeySize()
		ctSize := scheme.CiphertextSize()
		if len(input) < 1+skSize+ctSize {
			return nil, gas, ErrInvalidInput
		}
		sk, err := scheme.UnmarshalBinaryPrivateKey(input[1 : 1+skSize])
		if err != nil {
			return nil, gas, err
		}
		ct := input[1+skSize : 1+skSize+ctSize]
		ss, err := scheme.Decapsulate(sk, ct)
		if err != nil {
			return nil, gas, ErrDecapFailed
		}
		return ss, gas, nil

	default:
		return nil, gas, ErrInvalidOp
	}
}
