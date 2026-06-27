// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && starkfri_p3q

// verify_cgo.go — the REAL strict-PQ STARK/FRI verifier binding.
//
// This file wires the precompile's `RegisterVerifier` seam to the
// audited Rust verifier crate `p3q-verifier` (a post-quantum-only fork
// of Plonky3: FRI low-degree test over the Goldilocks 64-bit prime
// field, cSHAKE256 / KMAC256 / TupleHash256 Merkle commitments, no KZG,
// no pairings) through its C ABI shim `p3q-c-abi` (single entry point
// `p3q_verify`). Source: ~/work/lux/p3q.
//
// Build
// -----
//
//	# 1. build the staticlib (from the p3q workspace root):
//	make -C ../../p3q staticlib      # -> target/release/libp3q_c_abi.a
//	# 2. build any consumer of this package with the tag:
//	go build -tags starkfri_p3q ./...
//	go test  -tags starkfri_p3q ./...
//
// Without the `starkfri_p3q` build tag this file is excluded and the
// node falls back to the safe-refuse registration (verify_nocgo.go in
// this package, and the geth-side init in core/vm/lux_precompiles.go).
// Safe-refuse means: no verifier registered ⇒ the precompile returns
// ErrVerifierNotRegistered ⇒ no forgery oracle. The verifier is opt-in
// at build time because it pulls a native Rust staticlib into the link.
//
// Wire-format bridge (the load-bearing decision)
// ----------------------------------------------
//
// Two distinct envelopes meet here:
//
//   - EVM/precompile wire (contract.go): the `proof` argument handed to
//     a VerifierFn begins with the 4-byte MagicHeader "P3Q1"
//     (= 0x50 0x33 0x51 0x31). This tag is preserved verbatim so the
//     EasyCrypt / Jasmin / Lean proof artifacts in proofs/ and jasmin/
//     reference byte-identical on-chain calldata.
//
//   - p3q-native wire (p3q_verify): the proof begins with a
//     ProofSystemId byte (0x10 = P3Q-SHA3 strict-PQ, 0x11 = P3Q-Keccak),
//     followed by the 10-byte header (see p3q-verifier/src/wire.rs).
//
// The bridge: "P3Q1" is the on-chain ENVELOPE tag; the bytes AFTER it
// are the p3q-native proof. So this adapter strips the 4-byte magic and
// forwards proof[4:] to p3q_verify. This is exactly the
// `backend_verifier_axiom` hand-off point in
// proofs/easycrypt/P3Q_Verifier.ec (the precompile checks the magic and
// structural envelope; the backend does the cryptographic work). This
// binding is the concrete discharge of that axiom.
//
// Constant-time / soundness
// -------------------------
//
// The proof and public inputs are PUBLIC by EVM-precompile ABI — there
// is no confidentiality obligation. The verifier's secret-independent
// arithmetic (Goldilocks field ops, cSHAKE256 sponge) is constant-time
// by construction in the Rust crate; the CT property we care about is
// soundness (no timing oracle over the structural pre-filter), which is
// discharged by the Jasmin gate in jasmin/verify.jazz and measured by
// the dudect harness in ~/work/lux/crypto/p3q/ct/dudect.
package starkfri

/*
#cgo CFLAGS: -I${SRCDIR}/../../p3q/crates/p3q-c-abi/include
#cgo LDFLAGS: ${SRCDIR}/../../p3q/target/release/libp3q_c_abi.a -lm
#include <stddef.h>
#include <stdint.h>
#include "lux/p3q.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// p3qStatus mirrors the P3Q_* status codes exported by p3q-c-abi's
// generated header. Kept as typed constants so the switch in the
// adapter is exhaustive and self-documenting.
const (
	p3qOK                 = C.P3Q_OK                      // 1  — accepted
	p3qRejected           = C.P3Q_REJECTED                // 0  — ran, rejected
	p3qErrNullPtr         = C.P3Q_ERR_NULL_PTR            // -1
	p3qErrParse           = C.P3Q_ERR_PARSE               // -2
	p3qErrUnsupportedProf = C.P3Q_ERR_UNSUPPORTED_PROFILE // -3
	p3qErrMerkle          = C.P3Q_ERR_MERKLE              // -4
	p3qErrFRI             = C.P3Q_ERR_FRI                 // -5
	p3qErrStark           = C.P3Q_ERR_STARK               // -6
	p3qErrTranscript      = C.P3Q_ERR_TRANSCRIPT          // -7
	p3qErrField           = C.P3Q_ERR_FIELD               // -8
	p3qErrCircuit         = C.P3Q_ERR_CIRCUIT             // -9
	p3qErrPanic           = C.P3Q_ERR_PANIC               // -99
)

// Backend error sentinels. These are INTERNAL failures (decode, FFI,
// panic) surfaced as non-nil err — distinct from a well-formed proof
// that simply did not verify, which is (false, nil). Run() in
// contract.go propagates a non-nil err verbatim and maps (false, nil)
// to ErrInvalidProof, matching the EasyCrypt model
// (P3Q_Verifier.ec::reject_iff_backend_reject vs the VFailed path).
var (
	errBackendNullPtr     = errors.New("starkfri/p3q: backend received null pointer")
	errBackendParse       = errors.New("starkfri/p3q: proof failed to decode")
	errBackendUnsupported = errors.New("starkfri/p3q: unsupported proof-system profile byte")
	errBackendPanic       = errors.New("starkfri/p3q: backend panicked (caught at FFI boundary)")
)

// p3qVerify is the cgo bridge to `p3q_verify`. It performs the genuine
// FRI low-degree test (Merkle-cap authentication + per-query
// colinearity folds + final-polynomial check) under a Fiat-Shamir
// transcript bound to `publicInput`.
//
// Returns:
//   - (true,  nil)   on a verified proof              (P3Q_OK)
//   - (false, nil)   on a well-formed but invalid proof
//     (P3Q_REJECTED, and every cryptographic-rejection code:
//     Merkle / FRI / STARK / transcript / field / circuit — these mean
//     "this proof does not verify", which the precompile must treat as
//     ErrInvalidProof, NOT an internal error)
//   - (false, err)   on a STRUCTURAL/internal failure (null ptr, parse,
//     unsupported profile, panic) — surfaced verbatim by the precompile
func p3qVerify(p3qProof, publicInput []byte) (bool, error) {
	// p3q_verify accepts a null pointer iff len == 0; mirror that so an
	// empty public input (legal) doesn't trip the null-ptr guard.
	var piPtr *C.uint8_t
	if len(publicInput) > 0 {
		piPtr = (*C.uint8_t)(unsafe.Pointer(&publicInput[0]))
	}
	var prPtr *C.uint8_t
	if len(p3qProof) > 0 {
		prPtr = (*C.uint8_t)(unsafe.Pointer(&p3qProof[0]))
	}

	rc := C.p3q_verify(
		piPtr, C.uintptr_t(len(publicInput)),
		prPtr, C.uintptr_t(len(p3qProof)),
	)

	switch rc {
	case p3qOK:
		return true, nil
	case p3qRejected,
		p3qErrMerkle, p3qErrFRI, p3qErrStark,
		p3qErrTranscript, p3qErrField, p3qErrCircuit:
		// All cryptographic rejection paths: the proof is well-formed
		// but does not verify. The precompile maps (false, nil) to
		// ErrInvalidProof.
		return false, nil
	case p3qErrNullPtr:
		return false, errBackendNullPtr
	case p3qErrParse:
		return false, errBackendParse
	case p3qErrUnsupportedProf:
		return false, errBackendUnsupported
	case p3qErrPanic:
		return false, errBackendPanic
	default:
		// Unknown code — fail closed as an internal error. Never accept
		// on an unrecognised status.
		return false, errors.New("starkfri/p3q: unknown backend status code")
	}
}

// p3qVerifierFn is the VerifierFn adapter for the real strict-PQ
// STARK/FRI backend. It strips the 4-byte "P3Q1" envelope tag (already
// validated by the precompile's structural gate before this callback
// runs) and hands the p3q-native proof body to p3qVerify.
//
// Exposed as a named func (not an inline closure in init) so tests can
// re-register it after a RegisterVerifier(nil) — the registration is
// process-global mutable state, and other tests in the same binary may
// clear it.
//
// version is fixed to VersionV1 by the precompile; it is not part of the
// p3q-native proof (the p3q wire carries its own version inside the
// 10-byte header), so it is intentionally unused beyond the
// envelope-level check the precompile already performed.
func p3qVerifierFn(_ byte, proof, pubInputs []byte) (bool, error) {
	// Defensive: the precompile guarantees proof[:4] == "P3Q1" and
	// len(proof) >= 4 before dispatching, but re-check rather than index
	// blindly — a caller of the in-process Verify() path must not be able
	// to slice past the bounds.
	if len(proof) < len(MagicHeader) || string(proof[:len(MagicHeader)]) != MagicHeader {
		return false, ErrInvalidProof
	}
	return p3qVerify(proof[len(MagicHeader):], pubInputs)
}

// init wires the real verifier as the authoritative RegisterVerifier
// seam. Because Go runs this imported package's init() before any
// importer's init(), this beats the geth-side RegisterDefaultVerifier
// (which compare-and-swaps against nil and therefore no-ops once this
// has registered).
func init() {
	RegisterVerifier(p3qVerifierFn)
}
