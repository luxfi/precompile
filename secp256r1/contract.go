// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package secp256r1

import (
	"crypto/elliptic"
	"math/big"

	luxsecp256r1 "github.com/luxfi/crypto/secp256r1"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

const (
	// P256VerifyAddress is the precompile address for secp256r1 verification
	// Matches RIP-7212/EIP-7212 for cross-ecosystem compatibility
	P256VerifyAddress = "0x0000000000000000000000000000000000000100"

	// GasP256Verify is the gas cost for signature verification
	// Based on EIP-7212 benchmarking - 100x cheaper than Solidity
	GasP256Verify = 3450

	// InputLength is the required input length (160 bytes)
	// 32 (hash) + 32 (r) + 32 (s) + 32 (x) + 32 (y)
	InputLength = 160
)

var (
	// Address is the precompile address as common.Address
	Address = common.HexToAddress(P256VerifyAddress)

	// Success return value (32 bytes, value 1)
	successResult = common.LeftPadBytes([]byte{1}, 32)

	// Errors
	ErrInvalidInputLength = contract.ErrInvalidInput
)

// Contract implements the secp256r1 signature verification precompile
type Contract struct{}

// Address returns the precompile address
func (c *Contract) Address() common.Address {
	return Address
}

// RequiredGas returns the gas required to execute the precompile
func (c *Contract) RequiredGas(input []byte) uint64 {
	return GasP256Verify
}

// Run executes the secp256r1 signature verification
//
// Input format (160 bytes):
//   - bytes  0-31: message hash
//   - bytes 32-63: r (signature component)
//   - bytes 64-95: s (signature component)
//   - bytes 96-127: x (public key x-coordinate)
//   - bytes 128-159: y (public key y-coordinate)
//
// Output:
//   - Success: 32 bytes with value 1
//   - Failure: empty bytes (invalid signature or point not on curve)
func (c *Contract) Run(input []byte) ([]byte, error) {
	if len(input) != InputLength {
		// Invalid input length returns empty (not error)
		return nil, nil
	}

	// Extract components
	hash := input[0:32]
	r := new(big.Int).SetBytes(input[32:64])
	s := new(big.Int).SetBytes(input[64:96])
	x := new(big.Int).SetBytes(input[96:128])
	y := new(big.Int).SetBytes(input[128:160])

	// Get P-256 curve
	curve := elliptic.P256()

	// Validate point is on curve
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}

	// Validate r and s are in valid range [1, n-1]
	n := curve.Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return nil, nil
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return nil, nil
	}

	// CPU is the single source of truth, via the canonical luxfi/crypto/
	// secp256r1 (NIST P-256) verifier. The luxfi/accel ECDSAVerifyBatch kernel
	// is fixed to secp256k1 (it has no curve selector); feeding it P-256 points
	// makes it evaluate the verify equation under the WRONG curve parameters,
	// so its verdict was unrelated to this P-256 verifier -- a CPU/GPU
	// consensus split. Re-introducing accel requires a P-256 kernel proven
	// byte-identical to luxsecp256r1.Verify.
	if luxsecp256r1.Verify(hash, r, s, x, y) {
		return successResult, nil
	}

	return nil, nil
}

// Name returns the precompile name
func (c *Contract) Name() string {
	return "P256VERIFY"
}

// Verify is a convenience function for direct verification.
// Delegates to canonical luxfi/crypto/secp256r1, which performs
// curve membership and (r,s) range validation internally.
func Verify(hash []byte, r, s, x, y *big.Int) bool {
	return luxsecp256r1.Verify(hash, r, s, x, y)
}
