// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ed25519 implements an EVM precompile for Ed25519 signature verification.
// This enables native verification of Solana, TON, XRP (Ed25519 mode), and other
// Ed25519-based wallet signatures directly on the EVM.
//
// Precompile address: 0x3211000000000000000000000000000000000000 (LP-3211)
package ed25519

import (
	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

const (
	// GasEd25519Verify is the gas cost for signature verification
	// Ed25519 is ~2x faster than secp256k1 ECDSA in practice
	GasEd25519Verify = 3_000

	// InputLength is the required input length (128 bytes)
	// 32 (message hash) + 64 (signature) + 32 (public key)
	InputLength = 128

	// PublicKeySize is 32 bytes for Ed25519
	PublicKeySize = 32

	// SignatureSize is 64 bytes for Ed25519
	SignatureSize = 64

	// MessageHashSize is 32 bytes (SHA-256 hash)
	MessageHashSize = 32
)

var (
	// ContractAddress is the precompile address
	ContractAddress = common.HexToAddress("0x3211000000000000000000000000000000000000")

	// Ed25519VerifyPrecompile is the singleton instance
	Ed25519VerifyPrecompile = &ed25519VerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &ed25519VerifyPrecompile{}

	// Success return value (32 bytes, value 1)
	successResult = common.LeftPadBytes([]byte{1}, 32)

	// Errors
	ErrInvalidInputLength = contract.ErrInvalidInput
)

// ed25519VerifyPrecompile implements StatefulPrecompiledContract for Ed25519 verification.
type ed25519VerifyPrecompile struct{}

// RequiredGas returns the gas required to execute the precompile
func (c *ed25519VerifyPrecompile) RequiredGas(input []byte) uint64 {
	return GasEd25519Verify
}

// Run executes the Ed25519 signature verification.
//
// Input format (128 bytes):
//   - bytes  0-31:  message hash (32 bytes)
//   - bytes 32-95:  signature (64 bytes)
//   - bytes 96-127: public key (32 bytes)
//
// Output:
//   - Success: 32 bytes with value 1
//   - Failure: empty bytes (invalid signature or key)
func (c *ed25519VerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := c.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	if len(input) != InputLength {
		return nil, remainingGas, nil
	}

	// Extract components
	message := input[0:MessageHashSize]
	signature := input[MessageHashSize : MessageHashSize+SignatureSize]
	publicKey := input[MessageHashSize+SignatureSize : MessageHashSize+SignatureSize+PublicKeySize]

	// Validate public key length
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, remainingGas, nil
	}

	// CPU is the single source of truth, via the canonical luxfi/crypto/ed25519
	// verifier. Ed25519 verification disagreement across implementations is a
	// well-known hazard (cofactored vs cofactorless checks, non-canonical S>=L,
	// small-order A/R): the luxfi/accel Ed25519 GPU kernel is not proven
	// byte-identical to this verifier on those adversarial edge cases, so
	// trusting its verdict risked a CPU/GPU consensus split on exactly the
	// inputs an attacker controls. Re-introducing accel requires a kernel
	// proven byte-identical to ed25519.Verify over the full edge-case corpus.
	if ed25519.Verify(publicKey, message, signature) {
		return successResult, remainingGas, nil
	}

	return nil, remainingGas, nil
}

// Verify is a convenience function for direct Ed25519 verification.
// Returns true if the signature is valid for the given message and public key.
func Verify(message, signature, publicKey []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// VerifyRaw verifies an Ed25519 signature on raw (unhashed) data.
// Solana's signMessage signs the raw bytes, not a hash.
func VerifyRaw(rawMessage, signature, publicKey []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, rawMessage, signature)
}
