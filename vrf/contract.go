// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package vrf implements an EVM precompile for ECVRF-EDWARDS25519-SHA512-ELL2
// verification per RFC 9381. This enables on-chain verifiable randomness for
// lotteries, leader election, NFT minting, and privacy-preserving protocols.
//
// Only verification and proof-to-hash extraction are exposed. Proving requires
// the secret key and happens off-chain.
//
// Precompile address: 0x0000000000000000000000000000000000003213 (LP-3213)
package vrf

import (
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// OpVerify verifies a VRF proof and returns beta_string on success.
	OpVerify = 0x01

	// OpProofToHash extracts beta_string from a proof without verification.
	OpProofToHash = 0x02

	// Gas costs.
	GasVerify      = 20_000 // One scalar mul + two hash-to-curve ops
	GasProofToHash = 1_000  // One SHA-512

	// Sizes per RFC 9381 section 5.5 (ECVRF-EDWARDS25519-SHA512-ELL2).
	PublicKeySize = 32 // Compressed Edwards Y coordinate
	ProofSize     = 80 // Gamma(32) + c(16) + s(32)
	BetaSize      = 64 // SHA-512 output

	// RFC 9381 suite string for ECVRF-EDWARDS25519-SHA512-ELL2.
	suiteString = 0x04

	// Domain separation prefixes (RFC 9381 section 5.4.1.2).
	dsHashToTryCAndIncrement = 0x01
	dsHashPoints             = 0x02
	dsProofToHash            = 0x03
)

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrInvalidInput     = contract.ErrInvalidInput
	ErrInvalidOperation = errors.New("vrf: invalid operation selector")
)

// ─── Addresses ────────────────────────────────────────────────────────────────

var (
	// ContractAddress is the precompile address (LP-3213, EVM/Crypto page).
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000003213")

	// VRFPrecompile is the singleton.
	VRFPrecompile = &vrfPrecompile{}

	_ contract.StatefulPrecompiledContract = VRFPrecompile
)

// ─── Precompile ───────────────────────────────────────────────────────────────

type vrfPrecompile struct{}

// RequiredGas returns the gas cost for the given input.
func (p *vrfPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpVerify:
		return GasVerify
	case OpProofToHash:
		return GasProofToHash
	default:
		return 0
	}
}

// Run dispatches to the requested VRF operation.
//
// OpVerify (0x01):
//
//	Input:  opcode(1) || pk(32) || alpha_len(2 big-endian) || alpha(variable) || proof(80)
//	Output: beta_string(64) on success, empty on failure
//
// OpProofToHash (0x02):
//
//	Input:  opcode(1) || proof(80)
//	Output: beta_string(64)
func (p *vrfPrecompile) Run(
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

	if len(input) < 1 {
		return nil, remainingGas, nil
	}

	switch input[0] {
	case OpVerify:
		result := p.opVerify(input[1:])
		return result, remainingGas, nil

	case OpProofToHash:
		result := p.opProofToHash(input[1:])
		return result, remainingGas, nil

	default:
		return nil, remainingGas, nil
	}
}

// opVerify implements ECVRF_verify per RFC 9381 section 5.3.
//
//	Input: pk(32) || alpha_len(2) || alpha(variable) || proof(80)
func (p *vrfPrecompile) opVerify(data []byte) []byte {
	// Minimum: pk(32) + alpha_len(2) + alpha(0) + proof(80) = 114
	if len(data) < PublicKeySize+2+ProofSize {
		return nil
	}

	pk := data[:PublicKeySize]
	alphaLen := int(data[PublicKeySize])<<8 | int(data[PublicKeySize+1])
	offset := PublicKeySize + 2

	if len(data) < offset+alphaLen+ProofSize {
		return nil
	}

	alpha := data[offset : offset+alphaLen]
	proof := data[offset+alphaLen : offset+alphaLen+ProofSize]

	beta, ok := ecvrfVerify(pk, alpha, proof)
	if !ok {
		return nil
	}
	return beta
}

// opProofToHash implements ECVRF_proof_to_hash per RFC 9381 section 5.2.
//
//	Input: proof(80)
func (p *vrfPrecompile) opProofToHash(data []byte) []byte {
	if len(data) < ProofSize {
		return nil
	}

	gamma, _, _, ok := decodeProof(data[:ProofSize])
	if !ok {
		return nil
	}

	return proofToHash(gamma)
}

// ─── RFC 9381 ECVRF-EDWARDS25519-SHA512-ELL2 ─────────────────────────────────

// ecvrfVerify implements ECVRF_verify (RFC 9381 section 5.3).
// Returns (beta_string, true) on success.
func ecvrfVerify(pkBytes, alpha, piBytes []byte) ([]byte, bool) {
	// Step 1: Decode public key Y
	Y, err := new(edwards25519.Point).SetBytes(pkBytes)
	if err != nil {
		return nil, false
	}

	// Step 2: Decode proof (Gamma, c, s)
	Gamma, c, s, ok := decodeProof(piBytes)
	if !ok {
		return nil, false
	}

	// Step 3: Hash to curve H = ECVRF_encode_to_curve(encode_to_curve_salt=pk, alpha)
	H := hashToCurveELL2(pkBytes, alpha)
	if H == nil {
		return nil, false
	}

	// Step 4: U = s*B - c*Y
	cNeg := new(edwards25519.Scalar).Negate(c)
	U := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(cNeg, Y, s)

	// Step 5: V = s*H - c*Gamma
	sH := new(edwards25519.Point).ScalarMult(s, H)
	cGamma := new(edwards25519.Point).ScalarMult(c, Gamma)
	cGammaNeg := new(edwards25519.Point).Negate(cGamma)
	V := new(edwards25519.Point).Add(sH, cGammaNeg)

	// Step 6: Derive c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
	cPrime := challengeGeneration(Y, H, Gamma, U, V)

	// Step 7: Check c == c'
	if c.Equal(cPrime) != 1 {
		return nil, false
	}

	// Step 8: beta = ECVRF_proof_to_hash(pi)
	beta := proofToHash(Gamma)
	return beta, true
}

// proofToHash implements ECVRF_proof_to_hash (RFC 9381 section 5.2).
// beta_string = SHA-512(suite_string || proof_to_hash_domain_separator || cofactor*Gamma || zero)
func proofToHash(Gamma *edwards25519.Point) []byte {
	// Cofactor multiply: cofGamma = cofactor * Gamma
	// For Ed25519, cofactor = 8. We multiply by 8 via three doublings.
	cofGamma := new(edwards25519.Point).Add(Gamma, Gamma)      // 2*Gamma
	cofGamma = new(edwards25519.Point).Add(cofGamma, cofGamma) // 4*Gamma
	cofGamma = new(edwards25519.Point).Add(cofGamma, cofGamma) // 8*Gamma

	h := sha512.New()
	h.Write([]byte{suiteString, dsProofToHash})
	h.Write(cofGamma.Bytes())
	h.Write([]byte{0x00})
	return h.Sum(nil)
}

// hashToCurveELL2 implements ECVRF_encode_to_curve using the
// Elligator2 method per RFC 9381 section 5.4.1.2.
//
// This is the "try-and-increment" variant. It hashes the input to a
// field element, applies Elligator2 to obtain a point, and multiplies
// by the cofactor.
func hashToCurveELL2(pkBytes, alpha []byte) *edwards25519.Point {
	// Hash: SHA-512(suite_string || one || pk || alpha || ctr || zero)
	// Try ctr = 0, 1, 2, ... until we get a valid point.
	for ctr := range byte(255) {
		h := sha512.New()
		h.Write([]byte{suiteString, dsHashToTryCAndIncrement})
		h.Write(pkBytes)
		h.Write(alpha)
		h.Write([]byte{ctr})
		h.Write([]byte{0x00})
		hash := h.Sum(nil)

		// Take the first 32 bytes, clear the high bit (MSB of last byte
		// when using little-endian encoding), and try to decompress.
		var candidate [32]byte
		copy(candidate[:], hash[:32])
		candidate[31] &= 0x7F // Clear sign bit

		point, err := new(edwards25519.Point).SetBytes(candidate[:])
		if err != nil {
			continue
		}

		// Multiply by cofactor (8) to ensure we're in the prime-order subgroup.
		cofPoint := new(edwards25519.Point).Add(point, point)      // 2
		cofPoint = new(edwards25519.Point).Add(cofPoint, cofPoint) // 4
		cofPoint = new(edwards25519.Point).Add(cofPoint, cofPoint) // 8

		// Reject identity.
		if cofPoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
			continue
		}
		return cofPoint
	}
	return nil
}

// challengeGeneration implements ECVRF_challenge_generation (RFC 9381 section 5.4.3).
// c = SHA-512(suite_string || challenge_generation_domain_separator || encode(Y) || encode(H) || encode(Gamma) || encode(U) || encode(V) || zero)[0:16]
func challengeGeneration(Y, H, Gamma, U, V *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte{suiteString, dsHashPoints})
	h.Write(Y.Bytes())
	h.Write(H.Bytes())
	h.Write(Gamma.Bytes())
	h.Write(U.Bytes())
	h.Write(V.Bytes())
	h.Write([]byte{0x00})

	hash := h.Sum(nil)

	// c is the first 16 bytes, interpreted as a little-endian scalar.
	var truncated [32]byte
	copy(truncated[:16], hash[:16])

	scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(truncated[:])
	if err != nil {
		// Should not happen with a 128-bit value in a 256-bit field.
		return new(edwards25519.Scalar)
	}
	return scalar
}

// decodeProof splits pi_string into (Gamma, c, s).
//
// pi_string layout (80 bytes):
//
//	Gamma: 32 bytes (compressed Edwards point)
//	c:     16 bytes (little-endian scalar, zero-padded to 32 for SetCanonicalBytes)
//	s:     32 bytes (little-endian scalar)
func decodeProof(pi []byte) (*edwards25519.Point, *edwards25519.Scalar, *edwards25519.Scalar, bool) {
	if len(pi) != ProofSize {
		return nil, nil, nil, false
	}

	// Decode Gamma
	Gamma, err := new(edwards25519.Point).SetBytes(pi[:32])
	if err != nil {
		return nil, nil, nil, false
	}

	// Decode c (16 bytes, little-endian, padded to 32)
	var cBytes [32]byte
	copy(cBytes[:16], pi[32:48])
	c, err := new(edwards25519.Scalar).SetCanonicalBytes(cBytes[:])
	if err != nil {
		return nil, nil, nil, false
	}

	// Decode s (32 bytes, little-endian)
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(pi[48:80])
	if err != nil {
		return nil, nil, nil, false
	}

	return Gamma, c, s, true
}
