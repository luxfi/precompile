// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package starkfri

import "bytes"

// The soundness floor: what the chain demands of a proof's parameters
// before it will spend a verification on it.
//
// A STARK/FRI proof carries its own security parameters. The verifier
// repeats an independent query check `num_queries` times against a
// codeword of rate 2^-log_blowup, so the two together decide how hard
// the proof is to forge — and both arrive off calldata, chosen by
// whoever submitted the proof. Without a floor the submitter picks the
// difficulty of the test applied to their own proof, which at the
// weakest settings the wire admits is about one bit: two attempts.
//
// This is a consensus rule. It is enforced here as well as inside the
// verifier so it is legible in the chain's own code rather than only
// in a linked staticlib, and so the node does no cryptographic work,
// and crosses no FFI boundary, for a proof it was never going to
// accept. The gas charge is unchanged either way — it is a function of
// calldata length alone (see RequiredGas) — so the saving is the
// node's, not the caller's.
const (
	// MinSoundnessBits is log_blowup * num_queries, the bits of
	// query-phase soundness a proof must claim.
	//
	// Under the capacity bound one query buys log_blowup bits, which
	// makes the predicate an exact integer product — no floating
	// point and no table, which is what a rule every node must agree
	// on needs. Under the provable Johnson bound (Ben-Sasson, Carmon,
	// Ishai, Kopparty, Saraf, "Proximity Gaps for Reed-Solomon
	// Codes", FOCS 2020) the same parameters deliver roughly half as
	// much. 128 is reachable at every blowup but rate-1/2, which
	// cannot reach it under any bound within the wire's 64-query
	// ceiling.
	//
	// The verifier is the source of this number; under the
	// starkfri_p3q build tag a test asserts the two agree by reading
	// p3q_min_soundness_bits() out of the linked library.
	MinSoundnessBits = 128

	// Offsets into the proof argument. The precompile envelope is the
	// 4-byte MagicHeader; the p3q-native proof follows, beginning with
	// a ProofSystemId byte and then a 10-byte header whose third and
	// fifth bytes are the two parameters (see p3q-verifier/src/wire.rs).
	offsetBlowup  = len(MagicHeader) + 1 + 2
	offsetQueries = len(MagicHeader) + 1 + 4

	// MinProofLength is the shortest proof that can carry parameters
	// at all: envelope + profile byte + the full 10-byte header.
	MinProofLength = len(MagicHeader) + 1 + 10
)

// admit reports whether proof is a frame this chain will verify: it
// carries the envelope tag, it is long enough to state its parameters,
// and those parameters meet MinSoundnessBits.
//
// One predicate, asked identically by both entry points, so the two
// cannot answer differently.
func admit(proof []byte) error {
	if !bytes.HasPrefix(proof, magic) || len(proof) < MinProofLength {
		return ErrInvalidProof
	}
	if uint32(proof[offsetBlowup])*uint32(proof[offsetQueries]) < MinSoundnessBits {
		return ErrInsufficientSoundness
	}
	return nil
}
