// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package p3q implements the EVM precompile entry for the P3Q strict
// post-quantum STARK verifier, the Lux family canonical proof system.
//
// P3Q is a fork of Plonky3 with the classical-curve surface stripped
// out: cSHAKE256 (FIPS 202 / SP 800-185) Merkle hashes over the
// Goldilocks 64-bit prime field, no KZG, no pairings. The wire-byte
// proof-backend ID is `ProofBackendP3QSTARKFRISHA3 = 0x22`, pinned in
// `consensus/config/pq_mode.go`; this precompile is the on-chain
// dispatch point for that backend.
//
// LP-4200 unified PQCrypto block:
//
//	0x012201 = ML-KEM          (Module-LWE KEM, FIPS 203)
//	0x012202 = ML-DSA          (Module-LWE single-party signature, FIPS 204)
//	0x012203 = SLH-DSA         (hash-based signature, FIPS 205)
//	0x012204 = Pulsar          (Module-LWE threshold FIPS 204, byte-equal)
//	0x012205 = P3Q             ← this precompile (strict-PQ STARK)
//	0x012206 = Corona         
//
// Wire format (single dispatch, version byte differentiates future
// proof formats; first deployment is v0x01):
//
//	[1 byte  version]
//	[4 bytes proof_len (big-endian)]
//	[proof_len bytes proof]   // must begin with MagicHeader "P3Q1"
//	[4 bytes pub_len (big-endian)]
//	[pub_len bytes public_inputs]
//
// The Rust prover / verifier in `~/work/lux/p3q` runs out-of-band; at
// startup the node calls `p3q.RegisterVerifier` to wire the Go-side
// callback that actually invokes the FFI verifier. Without a
// registered verifier the precompile returns ErrVerifierNotRegistered.
// Structural validation (length checks + MagicHeader) runs in the
// precompile itself and is constant-time-friendly: no secret-dependent
// branches, public inputs and the proof are non-secret by construction.
package p3q

import (
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ContractP3QVerifyAddress is the canonical LP-4200 slot for P3Q.
var ContractP3QVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000012205")

// P3QVerifyPrecompile is the singleton instance.
var P3QVerifyPrecompile = &p3qVerifyPrecompile{}

var _ contract.StatefulPrecompiledContract = &p3qVerifyPrecompile{}

// MagicHeader is the 4-byte prefix every P3Q proof MUST begin with.
// Ties the wire to the Plonky3 fork's cSHAKE256/Goldilocks profile.
const MagicHeader = "P3Q1"

// Wire layout constants.
const (
	versionByte = 1
	proofLenByte = 4
	pubLenByte   = 4

	// MinInputLength is the smallest valid input: 1 version + 4 proof_len
	// + 4 magic header + 4 pub_len. Proof must contain at least the
	// MagicHeader to clear structural validation.
	MinInputLength = versionByte + proofLenByte + len(MagicHeader) + pubLenByte

	// VersionV1 is the first wire-format version.
	VersionV1 byte = 0x01
)

// Gas schedule. STARK verification scales roughly with log²(circuit
// size), but on-chain we only see the serialized proof; charge a flat
// base plus a per-byte cost so callers pay for bandwidth and decode.
const (
	BaseVerifyGas   uint64 = 200_000
	PerByteGas      uint64 = 10
)

// Error sentinels returned by this precompile.
var (
	ErrInvalidInputLength    = errors.New("p3q: invalid input length")
	ErrInvalidVersion        = errors.New("p3q: invalid version byte")
	ErrVerifierNotRegistered = errors.New("p3q: verifier not registered")
	ErrInvalidProof          = errors.New("p3q: proof verification failed")
)

// VerifierFn is the Go-side callback that bridges to the out-of-band
// P3Q (Plonky3 fork) Rust verifier. Returns (ok, err). A non-nil err
// indicates an internal verifier failure (FFI, decode); ok=false with
// nil err indicates a well-formed proof that did not verify.
type VerifierFn func(version byte, proof, pubInputs []byte) (bool, error)

// verifier is the registered callback. Atomic.Value so RegisterVerifier
// is safe to call once at node startup without locking the hot path.
var verifier atomic.Value // VerifierFn

// RegisterVerifier wires the actual P3Q verifier. Called once at node
// startup. Passing nil clears the registration (useful for tests).
func RegisterVerifier(fn VerifierFn) {
	if fn == nil {
		verifier.Store(VerifierFn(nil))
		return
	}
	verifier.Store(fn)
}

// loadVerifier returns the currently-registered verifier, or nil.
func loadVerifier() VerifierFn {
	v, _ := verifier.Load().(VerifierFn)
	return v
}

type p3qVerifyPrecompile struct{}

// RequiredGas returns BaseVerifyGas + PerByteGas * len(input). STARK
// verifier cost is dominated by FRI query rounds (logarithmic in
// circuit size); per-byte covers serialization / hashing overhead.
func (p *p3qVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return BaseVerifyGas + uint64(len(input))*PerByteGas
}

// Run verifies a P3Q STARK proof.
//
// Returns:
//   - empty bytes, nil error on successful verification.
//   - empty bytes, typed error on any failure.
func (p *p3qVerifyPrecompile) Run(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	gas := p.RequiredGas(input)
	if suppliedGas < gas {
		return nil, 0, contract.ErrOutOfGas
	}
	remaining := suppliedGas - gas

	if len(input) < MinInputLength {
		return nil, remaining, ErrInvalidInputLength
	}

	version := input[0]
	if version != VersionV1 {
		return nil, remaining, ErrInvalidVersion
	}

	off := versionByte
	proofLen := binary.BigEndian.Uint32(input[off : off+proofLenByte])
	off += proofLenByte
	if uint64(len(input))-uint64(off) < uint64(proofLen)+uint64(pubLenByte) {
		return nil, remaining, ErrInvalidInputLength
	}
	proof := input[off : off+int(proofLen)]
	off += int(proofLen)

	pubLen := binary.BigEndian.Uint32(input[off : off+pubLenByte])
	off += pubLenByte
	if uint64(len(input))-uint64(off) < uint64(pubLen) {
		return nil, remaining, ErrInvalidInputLength
	}
	pub := input[off : off+int(pubLen)]

	// Structural check: proof must begin with the MagicHeader. P3Q
	// proofs are non-secret, so byte-equality is fine.
	if len(proof) < len(MagicHeader) || string(proof[:len(MagicHeader)]) != MagicHeader {
		return nil, remaining, ErrInvalidProof
	}

	fn := loadVerifier()
	if fn == nil {
		return nil, remaining, ErrVerifierNotRegistered
	}
	ok, err := fn(version, proof, pub)
	if err != nil {
		return nil, remaining, err
	}
	if !ok {
		return nil, remaining, ErrInvalidProof
	}
	return nil, remaining, nil
}
