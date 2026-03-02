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
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/xwing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// SeedSize is the caller-provided seed length. X-Wing's internal
// EncapsulationSeedSize is 64; we accept 32 from the caller and expand
// via SHA-256("XWING_ENCAP_v1" || caller || raw_seed) to 64 bytes.
// Consensus safety: identical caller + raw seed + pk = identical output
// on every validator, eliminating the crypto/rand chain split.
const SeedSize = 32

// Ensure circl KEM interface is satisfied (compile-time check)
var _ kem.Scheme = xwing.Scheme()

var (
	// LP-2221: C-Chain hybrid KEM (X25519+ML-KEM)
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000002221")

	XWingPrecompile = &xwingPrecompile{}

	_ contract.StatefulPrecompiledContract = &xwingPrecompile{}

	ErrInvalidInput = contract.ErrInvalidInput
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
		// Input: [op(1)][seed(32)][pk(pkSize)]
		if len(input) < 1+SeedSize+pkSize {
			return nil, gas, ErrInvalidInput
		}
		rawSeed := input[1 : 1+SeedSize]
		pkBytes := input[1+SeedSize : 1+SeedSize+pkSize]

		pk, err := scheme.UnmarshalBinaryPublicKey(pkBytes)
		if err != nil {
			return nil, gas, err
		}

		// Domain-separate by caller + expand 32-byte raw seed to X-Wing's
		// required 64-byte seed via iterated SHA-256.
		seed := expandSeed(caller, rawSeed)
		ct, ss, err := scheme.EncapsulateDeterministically(pk, seed)
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

// expandSeed combines a caller-provided 32-byte seed with the caller
// address into a 64-byte seed suitable for X-Wing's
// EncapsulateDeterministically. Identical inputs on every validator
// produce identical output (consensus-safe). Two different callers
// cannot collide on the derived seed even if they pick the same raw
// seed bytes.
func expandSeed(caller common.Address, raw []byte) []byte {
	// First half: H("XWING_ENCAP_v1" || caller || raw || 0x00)
	// Second half: H("XWING_ENCAP_v1" || caller || raw || 0x01)
	// This is the standard HKDF-lite extract technique for a 64-byte output.
	out := make([]byte, 64)
	for i, tag := range []byte{0x00, 0x01} {
		h := sha256.New()
		h.Write([]byte("XWING_ENCAP_v1"))
		h.Write(caller.Bytes())
		h.Write(raw)
		h.Write([]byte{tag})
		copy(out[i*32:(i+1)*32], h.Sum(nil))
	}
	return out
}
