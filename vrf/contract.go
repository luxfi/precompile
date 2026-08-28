// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package vrf implements an EVM precompile for ECVRF-EDWARDS25519-SHA512-TAI
// verification per RFC 9381. This enables on-chain verifiable randomness for
// lotteries, leader election, NFT minting, and privacy-preserving protocols.
//
// Only verification and proof-to-hash extraction are exposed. Proving requires
// the secret key and happens off-chain.
//
// The public key is supplied by the caller and is therefore never trusted:
// ECVRF_verify runs with validate_key = TRUE (RFC 9381, Section 5.4.5), which
// is what buys "full collision resistance" and "unpredictability under
// malicious key generation" (RFC 9381, Sections 7.1.1 and 7.1.3) -- the two
// properties an on-chain lottery is actually paying for.
//
// Precompile address: 0x0000000000000000000000000000000000003213 (LP-3213)
package vrf

import (
	"bytes"
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

	// MinCallGas is charged for any call that performs no work -- empty input
	// or an unrecognised selector -- so that no call is ever free.
	MinCallGas = 21_000

	// GasVerify covers the size-independent work: one double-scalar base
	// multiplication and two scalar multiplications.
	GasVerify = 20_000

	// GasVerifyPerWord prices the size-dependent work. ECVRF_encode_to_curve
	// hashes the whole alpha string once per counter, and the counter loop
	// advances only when a candidate fails to decode -- probability 1/2 each --
	// so forcing n passes over alpha costs an offline search of 2^n. This is
	// eight times the EVM's own SHA3 word price (6), which covers a grind of
	// that scale given SHA-512's throughput advantage over Keccak.
	GasVerifyPerWord = 48

	// GasProofToHash covers one point decompression and one SHA-512 of a
	// fixed-size input.
	GasProofToHash = 1_000

	// Sizes per RFC 9381 Section 5.5 (ECVRF-EDWARDS25519-SHA512-TAI).
	PublicKeySize = 32 // Compressed Edwards Y coordinate
	ProofSize     = 80 // Gamma(32) + c(16) + s(32)
	BetaSize      = 64 // SHA-512 output

	// AlphaLenSize is the width of the big-endian alpha_string length prefix.
	AlphaLenSize = 2

	// RFC 9381 suite string for ECVRF-EDWARDS25519-SHA512-TAI.
	suiteString = 0x03

	// Domain separators (RFC 9381 Sections 5.4.1.1, 5.4.3 and 5.2). Each
	// hashed string opens with suite_string || front and closes with back.
	dsEncodeToCurve = 0x01
	dsChallenge     = 0x02
	dsProofToHash   = 0x03
	dsBack          = 0x00

	// maxCounter bounds the encode_to_curve counter to the one octet RFC 9381
	// gives it.
	maxCounter = 256
)

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrInvalidInput     = contract.ErrInvalidInput
	ErrInvalidOperation = contract.ErrInvalidOp

	errNonCanonicalPoint = errors.New("vrf: non-canonical point encoding")
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

// words returns the number of 32-byte words spanned by n bytes.
func words(n int) uint64 {
	return (uint64(n) + 31) / 32
}

// RequiredGas returns the gas cost for the given input.
func (p *vrfPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return MinCallGas
	}
	switch input[0] {
	case OpVerify:
		// alpha_string is variable length and is hashed, so the fee grows
		// with it. len(input) bounds alpha from above and is available here,
		// before the input has been parsed.
		return GasVerify + words(len(input)-1)*GasVerifyPerWord
	case OpProofToHash:
		return GasProofToHash
	default:
		return MinCallGas
	}
}

// Run dispatches to the requested VRF operation.
//
// OpVerify (0x01):
//
//	Input:  opcode(1) || pk(32) || alpha_len(2 big-endian) || alpha(alpha_len) || proof(80)
//	Output: beta_string(64) if the proof is valid, empty if it is not
//
// OpProofToHash (0x02):
//
//	Input:  opcode(1) || proof(80)
//	Output: beta_string(64), empty if the proof does not decode
//
// Both operations require an exact-length input; an unrecognised selector or
// an empty input is an error, never an empty success.
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

	if len(input) < 1 {
		return nil, remainingGas, ErrInvalidInput
	}

	switch input[0] {
	case OpVerify:
		return p.opVerify(input[1:]), remainingGas, nil

	case OpProofToHash:
		return p.opProofToHash(input[1:]), remainingGas, nil

	default:
		return nil, remainingGas, ErrInvalidOperation
	}
}

// opVerify implements ECVRF_verify per RFC 9381 Section 5.3.
//
//	Input: pk(32) || alpha_len(2) || alpha(alpha_len) || proof(80)
func (p *vrfPrecompile) opVerify(data []byte) []byte {
	// The header carries the length that describes the rest.
	if len(data) < PublicKeySize+AlphaLenSize {
		return nil
	}

	pk := data[:PublicKeySize]
	alphaLen := int(data[PublicKeySize])<<8 | int(data[PublicKeySize+1])
	offset := PublicKeySize + AlphaLenSize

	// alpha_len must place the proof exactly at the end of the body: further
	// overruns the buffer, nearer leaves trailing bytes, and either way one
	// query would have more than one encoding.
	if len(data) != offset+alphaLen+ProofSize {
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

// opProofToHash implements ECVRF_proof_to_hash per RFC 9381 Section 5.2.
// decodeProof owns the length of pi_string, so there is nothing to check here.
//
//	Input: proof(80)
func (p *vrfPrecompile) opProofToHash(data []byte) []byte {
	gamma, _, _, ok := decodeProof(data)
	if !ok {
		return nil
	}

	return proofToHash(gamma)
}

// ─── RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI ──────────────────────────────────

// ecvrfVerify implements ECVRF_verify (RFC 9381 Section 5.3) with
// validate_key = TRUE. Returns (beta_string, true) on success.
func ecvrfVerify(pkBytes, alpha, piBytes []byte) ([]byte, bool) {
	// Step 1-2: Y = string_to_point(PK_string)
	Y, err := decodePoint(pkBytes)
	if err != nil {
		return nil, false
	}

	// Step 3: ECVRF_validate_key(Y)
	if !validateKey(Y) {
		return nil, false
	}

	// Step 4-6: (Gamma, c, s) = ECVRF_decode_proof(pi_string)
	Gamma, c, s, ok := decodeProof(piBytes)
	if !ok {
		return nil, false
	}

	// Step 7: H = ECVRF_encode_to_curve(encode_to_curve_salt = PK_string, alpha)
	H := encodeToCurve(pkBytes, alpha)
	if H == nil {
		return nil, false
	}

	// Step 8: U = s*B - c*Y
	cNeg := new(edwards25519.Scalar).Negate(c)
	U := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(cNeg, Y, s)

	// Step 9: V = s*H - c*Gamma
	sH := new(edwards25519.Point).ScalarMult(s, H)
	cGamma := new(edwards25519.Point).ScalarMult(c, Gamma)
	V := new(edwards25519.Point).Subtract(sH, cGamma)

	// Step 10: c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
	cPrime := challengeGeneration(Y, H, Gamma, U, V)

	// Step 11: c == c' ?
	if c.Equal(cPrime) != 1 {
		return nil, false
	}

	return proofToHash(Gamma), true
}

// decodePoint implements string_to_point (RFC 8032 Section 5.1.3), which
// RFC 9381 Section 5.5 names for this suite and which MUST reject an octet
// string that is not the encoding of a point.
//
// edwards25519.Point.SetBytes deliberately does not: it accepts an unreduced y
// and accepts a set sign bit where x is zero, matching the wider ecosystem
// rather than RFC 8032. Under those rules a Gamma has more than one pi_string
// and a public key has more than one address. Re-encoding and comparing is the
// canonicality test, and it covers both cases at once.
func decodePoint(b []byte) (*edwards25519.Point, error) {
	P, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(P.Bytes(), b) {
		return nil, errNonCanonicalPoint
	}
	return P, nil
}

// validateKey implements ECVRF_validate_key (RFC 9381 Section 5.4.5): the key
// is valid iff cofactor*Y is not the identity.
//
// Y arrives in calldata, so a caller is free to pick it. Without this check a
// caller who picks the identity produces a proof that verifies for every
// alpha_string and whose beta_string is a fixed value known in advance, which
// is exactly the outcome a verifiable random function exists to prevent.
func validateKey(Y *edwards25519.Point) bool {
	cofY := new(edwards25519.Point).MultByCofactor(Y)
	return cofY.Equal(edwards25519.NewIdentityPoint()) == 0
}

// proofToHash implements ECVRF_proof_to_hash (RFC 9381 Section 5.2).
//
//	beta_string = Hash(suite_string || 0x03 || point_to_string(cofactor*Gamma) || 0x00)
func proofToHash(Gamma *edwards25519.Point) []byte {
	cofGamma := new(edwards25519.Point).MultByCofactor(Gamma)

	h := sha512.New()
	h.Write([]byte{suiteString, dsProofToHash})
	h.Write(cofGamma.Bytes())
	h.Write([]byte{dsBack})
	return h.Sum(nil)
}

// encodeToCurve implements ECVRF_encode_to_curve_try_and_increment (RFC 9381
// Section 5.4.1.1) with interpret_hash_value_as_a_point(s) =
// string_to_point(s[0]...s[31]), as fixed for this suite by Section 5.5.
//
// The counter advances while the candidate fails to decode to a point or
// decodes to the identity; the hash input is the full string every time, which
// is why the verify fee is charged per word of input.
func encodeToCurve(salt, alpha []byte) *edwards25519.Point {
	for ctr := range maxCounter {
		h := sha512.New()
		h.Write([]byte{suiteString, dsEncodeToCurve})
		h.Write(salt)
		h.Write(alpha)
		h.Write([]byte{byte(ctr), dsBack})

		if H := interpretHashAsPoint(h.Sum(nil)); H != nil {
			return H
		}
	}
	return nil
}

// interpretHashAsPoint is interpret_hash_value_as_a_point as RFC 9381
// Section 5.5 fixes it for this suite: string_to_point over the first 32
// octets, then multiplication by the cofactor.
//
// It returns nil where the counter must advance: the octets are not a point
// encoding, or the cofactor kills them. The high bit of the last octet is the
// sign of x (RFC 8032 Section 5.1.3), not padding, and is carried through.
func interpretHashAsPoint(hash []byte) *edwards25519.Point {
	point, err := decodePoint(hash[:32])
	if err != nil {
		return nil
	}

	cofPoint := new(edwards25519.Point).MultByCofactor(point)
	if cofPoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil
	}
	return cofPoint
}

// challengeGeneration implements ECVRF_challenge_generation (RFC 9381
// Section 5.4.3) over the five points ECVRF_verify passes it.
//
//	c = Hash(suite_string || 0x02 || point_to_string(P1) || ... || 0x00)[0..cLen-1]
func challengeGeneration(Y, H, Gamma, U, V *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte{suiteString, dsChallenge})
	for _, P := range []*edwards25519.Point{Y, H, Gamma, U, V} {
		h.Write(P.Bytes())
	}
	h.Write([]byte{dsBack})
	hash := h.Sum(nil)

	// c = string_to_int(hash[0..cLen-1]), little-endian, cLen = 16. A 128-bit
	// value is below the group order for every input, so the canonical-encoding
	// check cannot reject it and there is nothing to branch on.
	var truncated [32]byte
	copy(truncated[:16], hash[:16])
	c, _ := new(edwards25519.Scalar).SetCanonicalBytes(truncated[:])
	return c
}

// decodeProof implements ECVRF_decode_proof (RFC 9381 Section 5.4.4), splitting
// pi_string into (Gamma, c, s).
//
// pi_string layout (80 bytes):
//
//	Gamma: 32 bytes (compressed Edwards point)
//	c:     16 bytes (little-endian integer)
//	s:     32 bytes (little-endian integer, rejected if >= the group order)
func decodeProof(pi []byte) (*edwards25519.Point, *edwards25519.Scalar, *edwards25519.Scalar, bool) {
	if len(pi) != ProofSize {
		return nil, nil, nil, false
	}

	Gamma, err := decodePoint(pi[:32])
	if err != nil {
		return nil, nil, nil, false
	}

	var cBytes [32]byte
	copy(cBytes[:16], pi[32:48])
	c, _ := new(edwards25519.Scalar).SetCanonicalBytes(cBytes[:])

	// s >= q is rejected here; without it a proof would have a second encoding.
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(pi[48:80])
	if err != nil {
		return nil, nil, nil, false
	}

	return Gamma, c, s, true
}
