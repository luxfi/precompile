// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package starkfri implements the EVM precompile entry for the
// strict-PQ STARK verifier (a Plonky3 fork with the classical-curve
// surface stripped out: cSHAKE256 (FIPS 202 / SP 800-185) Merkle
// hashes over the Goldilocks 64-bit prime field, no KZG, no
// pairings).
//
// History. This dispatch was previously misnamed "P3Q" and registered
// at slot 0x012205. Per HANZO-CRYPTO-SUITE §5.2, ROADMAP-CRYPTO-STACK
// §B.11, and LP-218, slot 0x012205 is reserved for "P3Q — Post-Quantum
// Pulsar Proof", the on-chain Pulsar / FIPS 204 ML-DSA verifier. The
// STARK dispatch lives here under its actual algorithmic identity
// (STARK / FRI / SHAKE) at a separate slot. The previous P3Q-as-STARK
// label was an aliasing error; this rename closes it.
//
// LP-4200 unified PQCrypto block (post-fix):
//
//	0x012201 = ML-KEM          (Module-LWE KEM, FIPS 203)
//	0x012202 = ML-DSA          (Module-LWE single-party signature, FIPS 204)
//	0x012203 = SLH-DSA         (hash-based signature, FIPS 205)
//	0x012204 = Pulsar          (Module-LWE threshold FIPS 204, byte-equal)
//	0x012205 = P3Q             (Post-Quantum Pulsar Proof — see precompile/p3q)
//	0x012206 = Corona          (Module-LWE threshold)
//	0x012207 = Magnetar        (SLH-DSA threshold, FIPS 205 byte-equal)
//	0x012208 = HQC             (code-based KEM, family-disjoint backup)
//	0x012220 = STARK-FRI       ← this precompile (strict-PQ STARK / FRI / SHAKE)
//
// The 0x012220 slot is a placeholder pending dedicated LP allocation
// (the prior 0x012205 claim is reverted to its canonical owner). The
// 0x012220 base is one nibble above the dense PQ-signature block,
// chosen so the strict-PQ STARK family can grow its own sub-range
// (0x012220..0x01222F) without recolliding with the 0x012201..0x01220F
// PQ-signature block.
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
// The MagicHeader value "P3Q1" is preserved verbatim from the pre-
// rename era to keep cryptographer sign-off and EasyCrypt / Lean /
// Jasmin proof artifacts byte-identical against on-chain calldata.
// Renaming the header would invalidate the wire-format proofs; the
// header is a wire-bytes tag, not a name claim. A future v2 wire
// format may rename it to "SFR1" or similar once the proof artifacts
// are refreshed.
//
// The Rust prover / verifier runs out-of-band; at startup the node
// calls `starkfri.RegisterVerifier` to wire the Go-side callback that
// actually invokes the FFI verifier. Without a registered verifier
// the precompile returns ErrVerifierNotRegistered. Structural
// validation (length checks, MagicHeader, and the soundness floor in
// soundness.go) runs in the precompile itself and is
// constant-time-friendly: no secret-dependent branches, public inputs
// and the proof are non-secret by construction.
package starkfri

import (
	"errors"
	"sync/atomic"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// ContractStarkFRIVerifyAddress is the canonical slot for the
// strict-PQ STARK verifier dispatch. Placeholder slot pending
// dedicated LP allocation; see the package doc comment for rationale.
var ContractStarkFRIVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000012220")

// StarkFRIVerifyPrecompile is the singleton instance.
var StarkFRIVerifyPrecompile = &starkFRIVerifyPrecompile{}

var _ contract.StatefulPrecompiledContract = &starkFRIVerifyPrecompile{}

// MagicHeader is the 4-byte prefix every STARK-FRI proof MUST begin
// with. Ties the wire to the Plonky3 fork's cSHAKE256/Goldilocks
// profile. Value preserved verbatim from the pre-rename era so
// EasyCrypt / Lean / Jasmin / dudect proof artifacts continue to
// reference the byte-identical wire tag.
const MagicHeader = "P3Q1"

// magic is MagicHeader as bytes, built once so the prefix test on the hot
// path allocates nothing. Both entry points ask the same question of the
// same value, so "begins with the header" has one definition.
var magic = []byte(MagicHeader)

// Wire layout constants.
const (
	versionByte  = 1
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
	BaseVerifyGas uint64 = 200_000
	PerByteGas    uint64 = 10
)

// Error sentinels returned by this precompile.
var (
	ErrInvalidInputLength    = errors.New("starkfri: invalid input length")
	ErrInvalidVersion        = errors.New("starkfri: invalid version byte")
	ErrVerifierNotRegistered = errors.New("starkfri: verifier not registered")
	ErrInvalidProof          = errors.New("starkfri: proof verification failed")
	ErrInsufficientSoundness = errors.New("starkfri: proof parameters below the soundness floor")
)

// VerifierFn is the Go-side callback that bridges to the out-of-band
// STARK-FRI (Plonky3 fork) Rust verifier. Returns (ok, err). A non-nil
// err indicates an internal verifier failure (FFI, decode); ok=false
// with nil err indicates a well-formed proof that did not verify.
type VerifierFn func(version byte, proof, pubInputs []byte) (bool, error)

// verifier is the registered callback. An atomic.Pointer so the hot
// path is lock-free AND so RegisterDefaultVerifier can compare-and-swap
// against "no verifier yet" without racing RegisterVerifier (the two
// must not clobber each other across package-init order — see
// RegisterDefaultVerifier).
var verifier atomic.Pointer[VerifierFn]

// RegisterVerifier wires the actual STARK-FRI verifier. This is the
// authoritative seam: it FORCES the given verifier, overriding any
// previously-registered one (including a safe-refuse default). The real
// cgo binding (verify_cgo.go) and tests use this. Passing nil clears the
// registration (so loadVerifier returns nil ⇒ ErrVerifierNotRegistered).
func RegisterVerifier(fn VerifierFn) {
	if fn == nil {
		verifier.Store(nil)
		return
	}
	verifier.Store(&fn)
}

// RegisterDefaultVerifier installs fn ONLY IF no verifier is currently
// registered. It is the safe-refuse / fallback seam: a node-init path
// (e.g. the geth precompile registry) calls this to guarantee the
// precompile never silently no-ops, WITHOUT clobbering a real verifier
// that a package init() may have already installed via RegisterVerifier.
//
// Decomplected policy vs. binding: RegisterVerifier is "this IS the
// verifier"; RegisterDefaultVerifier is "be the verifier iff nobody
// better volunteered". Because Go runs an imported package's init()
// before the importer's, the real cgo binding (in this package) wins the
// CAS first, and a downstream refuse-default no-ops harmlessly —
// independent of which init runs last. Returns true iff it installed fn.
func RegisterDefaultVerifier(fn VerifierFn) bool {
	if fn == nil {
		return false
	}
	return verifier.CompareAndSwap(nil, &fn)
}

// loadVerifier returns the currently-registered verifier, or nil.
func loadVerifier() VerifierFn {
	p := verifier.Load()
	if p == nil {
		return nil
	}
	return *p
}

// Verify is the in-process verification entry-point for callers outside
// the EVM precompile path (chains/zkvm STARK dispatch, off-chain
// verification, tests). It bypasses gas accounting and AccessibleState
// because those concerns belong to the precompile wrapper, not to the
// verifier primitive itself.
//
// Wire-format compatibility: proof must begin with MagicHeader "P3Q1"
// (the same structural check the on-chain precompile applies). version
// is fixed to VersionV1 — there is currently only one STARK-FRI wire
// version.
//
// Returns (true, nil) on a verified proof; (false, nil) on a well-formed
// but invalid proof; (false, ErrVerifierNotRegistered) when no FFI
// callback is wired (binding pending, not "unimplemented"); (false, err)
// on FFI / decode failures.
func Verify(proof, pubInputs []byte) (bool, error) {
	if err := admit(proof); err != nil {
		return false, err
	}
	fn := loadVerifier()
	if fn == nil {
		return false, ErrVerifierNotRegistered
	}
	return fn(VersionV1, proof, pubInputs)
}

type starkFRIVerifyPrecompile struct{}

// RequiredGas returns BaseVerifyGas + PerByteGas * len(input). STARK
// verifier cost is dominated by FRI query rounds (logarithmic in
// circuit size); per-byte covers serialization / hashing overhead.
func (p *starkFRIVerifyPrecompile) RequiredGas(input []byte) uint64 {
	return BaseVerifyGas + uint64(len(input))*PerByteGas
}

// Run verifies a STARK-FRI proof.
//
// Returns:
//   - empty bytes, nil error on successful verification.
//   - empty bytes, typed error on any failure.
func (p *starkFRIVerifyPrecompile) Run(
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

	// input is a window into EVM memory, not a buffer of its own: len is
	// what the caller declared and paid for, cap is the rest of that
	// memory, which the same caller filled with MSTORE. A slice expression
	// reaching past len therefore does not panic, it returns bytes the
	// caller chose — so every field below is taken through the cursor,
	// which bounds each read against the declared length. Each refusal is
	// mapped back to this package's own sentinel, so errors.Is answers
	// exactly what it answered before.
	in := contract.Read(input)

	version, err := in.Byte()
	if err != nil {
		return nil, remaining, ErrInvalidInputLength
	}
	proofLen, err := in.Uint32()
	if err != nil {
		return nil, remaining, ErrInvalidInputLength
	}

	// Length is settled before version, as it always has been: a frame too
	// short to hold the smallest valid call is a length failure, never a
	// version failure. The two reads above lie inside MinInputLength and
	// refuse with the same sentinel, so an input shorter than the frame is
	// refused identically whichever of the three fires.
	if len(input) < MinInputLength {
		return nil, remaining, ErrInvalidInputLength
	}
	if version != VersionV1 {
		return nil, remaining, ErrInvalidVersion
	}

	proof, err := in.Bytes(uint64(proofLen))
	if err != nil {
		return nil, remaining, ErrInvalidInputLength
	}

	pubLen, err := in.Uint32()
	if err != nil {
		return nil, remaining, ErrInvalidInputLength
	}
	pub, err := in.Bytes(uint64(pubLen))
	if err != nil {
		return nil, remaining, ErrInvalidInputLength
	}

	// Bytes past the public inputs are accepted. That is this format's
	// documented behaviour, matching the sibling P3Q precompile, which is
	// why in.End() is not called here.

	// Envelope tag, then the soundness floor — both decided on the
	// proof's own bytes, before a verifier is consulted and before any
	// cryptographic work. STARK-FRI proofs are non-secret, so
	// byte-equality is fine.
	if err := admit(proof); err != nil {
		return nil, remaining, err
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
