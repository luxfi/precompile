// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/luxfi/accel"
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

	// Construct public key
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Try GPU-accelerated verification first
	if gpuValid, gpuUsed := verifyGPU(hash, r, s, x, y); gpuUsed {
		if gpuValid {
			return successResult, nil
		}
		return nil, nil
	}

	// CPU fallback: verify signature
	if ecdsa.Verify(pubKey, hash, r, s) {
		return successResult, nil
	}

	return nil, nil
}

// verifyGPU attempts GPU-accelerated ECDSA P-256 signature verification.
// Returns (valid, true) if GPU was used, (false, false) if GPU unavailable.
func verifyGPU(hash []byte, r, s, x, y *big.Int) (valid bool, gpuUsed bool) {
	if !accel.Available() {
		return false, false
	}

	sess, err := accel.NewSession()
	if err != nil {
		return false, false
	}
	defer sess.Close()

	crypto := sess.Crypto()

	// ECDSAVerifyBatch expects:
	//   messages: [N, 32] bytes (message hashes)
	//   signatures: [N, 64] bytes (r || s)
	//   pubkeys: [N, 65] bytes (uncompressed 0x04 || x || y)
	//   results: [N] uint8

	// Build signature: r || s (64 bytes)
	sig := make([]byte, 64)
	copy(sig[0:32], common.LeftPadBytes(r.Bytes(), 32))
	copy(sig[32:64], common.LeftPadBytes(s.Bytes(), 32))

	// Build uncompressed public key: 0x04 || x || y (65 bytes)
	pk := make([]byte, 65)
	pk[0] = 0x04
	copy(pk[1:33], common.LeftPadBytes(x.Bytes(), 32))
	copy(pk[33:65], common.LeftPadBytes(y.Bytes(), 32))

	msgTensor, err := accel.NewTensorWithData[byte](sess, []int{1, 32}, hash)
	if err != nil {
		return false, false
	}
	defer msgTensor.Close()

	sigTensor, err := accel.NewTensorWithData[byte](sess, []int{1, 64}, sig)
	if err != nil {
		return false, false
	}
	defer sigTensor.Close()

	pkTensor, err := accel.NewTensorWithData[byte](sess, []int{1, 65}, pk)
	if err != nil {
		return false, false
	}
	defer pkTensor.Close()

	resultTensor, err := accel.NewTensor[byte](sess, []int{1})
	if err != nil {
		return false, false
	}
	defer resultTensor.Close()

	if err := crypto.ECDSAVerifyBatch(msgTensor.Untyped(), sigTensor.Untyped(), pkTensor.Untyped(), resultTensor.Untyped()); err != nil {
		return false, false
	}

	results, err := resultTensor.ToSlice()
	if err != nil {
		return false, false
	}

	return results[0] == 1, true
}

// Name returns the precompile name
func (c *Contract) Name() string {
	return "P256VERIFY"
}

// Verify is a convenience function for direct verification
func Verify(hash []byte, r, s, x, y *big.Int) bool {
	curve := elliptic.P256()

	// Validate point is on curve
	if !curve.IsOnCurve(x, y) {
		return false
	}

	// Validate r and s
	n := curve.Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return false
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return false
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return ecdsa.Verify(pubKey, hash, r, s)
}
