// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package sr25519 implements an EVM precompile for sr25519 (Schnorrkel)
// signature verification. This enables on-chain verification of Substrate
// wallet signatures, primarily for Substrate → EVM account migration.
//
// The signing context is fixed to "substrate" (the default for all Substrate
// runtimes and polkadot-js). This matches the sr25519-donna C library.
//
// Precompile address: 0x3212000000000000000000000000000000000000 (LP-3212)
package sr25519

import (
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the precompile address (Curves range 0x0A00, slot 1).
	ContractAddress = common.HexToAddress("0x0A00000000000000000000000000000000000001")

	// SR25519VerifyPrecompile is the singleton instance.
	SR25519VerifyPrecompile = &sr25519VerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = SR25519VerifyPrecompile

	// Success return value (32 bytes, value 1).
	successResult = common.LeftPadBytes([]byte{1}, 32)

	// Failure return value (32 bytes, value 0).
	failResult = make([]byte, 32)
)

const (
	// Gas costs. sr25519 verification involves Ristretto255 point decompression,
	// Merlin transcript construction (Keccak), and Schnorr equation check.
	// Roughly 3x ed25519 due to Ristretto decoding + Merlin overhead.
	SR25519VerifyBaseGas    uint64 = 9_000
	SR25519VerifyPerByteGas uint64 = 3

	// Field sizes.
	PublicKeySize = 32
	SignatureSize = 64

	// MinInputSize = pubkey(32) + signature(64) + message(>=1)
	MinInputSize = PublicKeySize + SignatureSize + 1
)

var (
	ErrInputTooShort = errors.New("sr25519: input too short")
	ErrEmptyMessage  = errors.New("sr25519: empty message")
)

type sr25519VerifyPrecompile struct{}

// Address returns the precompile address.
func (p *sr25519VerifyPrecompile) Address() common.Address {
	return ContractAddress
}

// RequiredGas calculates gas cost: base + per-byte for message.
func (p *sr25519VerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) <= PublicKeySize+SignatureSize {
		return SR25519VerifyBaseGas
	}
	msgLen := uint64(len(input) - PublicKeySize - SignatureSize)
	return SR25519VerifyBaseGas + msgLen*SR25519VerifyPerByteGas
}

// Run implements sr25519 signature verification.
//
// Input format (variable length, minimum 97 bytes):
//
//	[0:32]   = public key (32 bytes, Ristretto255 compressed)
//	[32:96]  = signature  (64 bytes, R || s Schnorrkel format)
//	[96:]    = message    (variable length, raw bytes that were signed)
//
// Signing context is fixed to "substrate" (Substrate runtime default).
//
// Output: 32-byte word, value 1 if valid, 0 if invalid.
func (p *sr25519VerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, remainingGas, err
	}

	if len(input) < MinInputSize {
		return failResult, remainingGas, fmt.Errorf(
			"%w: expected >= %d bytes, got %d", ErrInputTooShort, MinInputSize, len(input))
	}

	publicKey := input[0:PublicKeySize]
	signature := input[PublicKeySize : PublicKeySize+SignatureSize]
	message := input[PublicKeySize+SignatureSize:]

	if len(message) == 0 {
		return failResult, remainingGas, ErrEmptyMessage
	}

	// sr25519 is Schnorrkel over Ristretto255 with a Merlin ("substrate")
	// transcript. There is NO GPU/accel kernel for it: luxfi/accel only
	// exposes an Ed25519 (Edwards) verify, which is a DIFFERENT scheme on a
	// DIFFERENT encoding. Routing sr25519 through the Ed25519 kernel accepted
	// any well-formed Ed25519 signature as a valid sr25519 signature
	// (wrong-curve forgery) AND diverged from this CPU verifier across the
	// validator set (consensus split). The constant-only CPU verifier below
	// (sr25519-donna under cgo, go-schnorrkel otherwise) is the single source
	// of truth. Re-introducing accel here requires a real Ristretto255 +
	// Merlin Schnorrkel kernel proven byte-identical to this path.
	if verifySR25519(publicKey, signature, message) {
		return successResult, remainingGas, nil
	}
	return failResult, remainingGas, nil
}
