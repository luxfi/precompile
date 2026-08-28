// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// A precompile's input is a window into EVM memory. opCall builds it with
// Memory.GetPtr, which returns the two-index slice m.store[off : off+size],
// and nothing on the path to Run copies it — so len is the size the caller
// declared and paid gas for, while cap is the rest of EVM memory, filled by
// that same caller with MSTORE.
//
// A slice expression reaching past len therefore does not panic and does not
// halt a validator. It succeeds, returning bytes the attacker chose, and the
// verifier answers over material nobody declared. Every input below is built
// with contract.Poisoned so an over-read shows up as 0xA5 rather than as a
// harmless run of zeros — which is what an append-built fixture would give,
// and why an append-built fixture passes whether or not the bound exists.

// hostile is the whole calldata as the EVM would hand it over.
func hostile(b []byte) []byte { return contract.Poisoned(b, 4096) }

func run(t *testing.T, input []byte) ([]byte, error) {
	t.Helper()
	in := hostile(input)
	var out []byte
	var err error
	require.NotPanics(t, func() {
		out, _, err = ZKVerifyPrecompile.Run(nil, common.Address{}, ZKVerifyContractAddress,
			in, ZKVerifyPrecompile.RequiredGas(in)+1_000_000, false)
	}, "a %d-byte input must be refused, never panic", len(in))
	return out, err
}

// dispatchedOps is every selector Run routes, with a body long enough to
// reach each verifier's own parsing.
var dispatchedOps = []byte{
	OpVerifyGroth16, OpVerifyPLONK, OpVerifyFflonk, OpVerifyHalo2,
	OpVerifyKZG, OpVerifyIPA, OpVerifyRangeProof, OpVerifyNullifier,
	OpVerifyCommitment, OpVerifyBatch,
}

// TestNoPrefixEscapesAnyVerifier sweeps every truncation of a plausible call
// to every dispatched op. Each must produce a verdict or an error, never a
// panic, and never a positive verdict.
//
// The boundaries between fields are where an off-by-one lives and there is no
// reason to guess which, so this walks all of them.
func TestNoPrefixEscapesAnyVerifier(t *testing.T) {
	for _, op := range dispatchedOps {
		body := make([]byte, 1024)
		body[0] = op
		for n := 0; n <= 300; n++ {
			out, err := run(t, body[:n])
			if err == nil && len(out) == 32 {
				require.Equal(t, byte(0), out[31],
					"op 0x%02x: a %d-byte prefix must never verify", op, n)
			}
		}
	}
}

// TestDeclaredCountsCannotOverrun is the core of the class. Every op below
// carries a count or length read straight off the wire; each must be bounded
// against what the calldata holds before it selects any bytes or sizes any
// allocation.
//
// The claims include values whose product with the element width overflows,
// which is how a wrapped product comes to compare as small against any
// length.
func TestDeclaredCountsCannotOverrun(t *testing.T) {
	claims := []uint32{1, 2, 1 << 16, 1 << 24, 1 << 30, ^uint32(0) - 1, ^uint32(0)}

	// The [op][vkID:32][numInputs:4] frame, shared by ops 0x01-0x04.
	for _, op := range []byte{OpVerifyGroth16, OpVerifyPLONK, OpVerifyFflonk, OpVerifyHalo2} {
		for _, claim := range claims {
			in := make([]byte, inputsOff+64)
			in[0] = op
			binary.BigEndian.PutUint32(in[numInputsOff:inputsOff], claim)
			out, err := run(t, in)
			if err == nil && len(out) == 32 {
				require.Equal(t, byte(0), out[31],
					"op 0x%02x: %d declared public inputs in %d bytes must not verify", op, claim, len(in))
			}
		}
	}

	// op 0x12: numRounds at [96:100] of the payload, sizing two vectors of
	// 64-byte fold points.
	for _, claim := range claims {
		in := make([]byte, 1+100)
		in[0] = OpVerifyIPA
		binary.BigEndian.PutUint32(in[1+96:1+100], claim)
		out, err := run(t, in)
		if err == nil && len(out) == 32 {
			require.Equal(t, byte(0), out[31], "ipa: %d declared rounds must not verify", claim)
		}
	}

	// op 0x22 Merkle sub-mode: proofLen at [72:76] of the payload.
	for _, claim := range claims {
		in := make([]byte, 1+1+76)
		in[0] = OpVerifyCommitment
		in[1] = 0x01 // Merkle discriminator
		binary.BigEndian.PutUint32(in[1+1+72:1+1+76], claim)
		out, err := run(t, in)
		if err == nil && len(out) == 32 {
			require.Equal(t, byte(0), out[31], "merkle: %d declared siblings must not verify", claim)
		}
	}

	// op 0x30: numProofs, then a per-entry declared length.
	for _, claim := range claims {
		in := make([]byte, 1+4)
		in[0] = OpVerifyBatch
		binary.BigEndian.PutUint32(in[1:5], claim)
		out, err := run(t, in)
		if err == nil && len(out) == 32 {
			require.Equal(t, byte(0), out[31], "batch: %d declared proofs must not verify", claim)
		}

		entry := make([]byte, 1+4+5)
		entry[0] = OpVerifyBatch
		binary.BigEndian.PutUint32(entry[1:5], 1)
		entry[5] = OpVerifyKZG
		binary.BigEndian.PutUint32(entry[6:10], claim)
		out, err = run(t, entry)
		if err == nil && len(out) == 32 {
			require.Equal(t, byte(0), out[31], "batch: a %d-byte declared entry must not verify", claim)
		}
	}
}

// TestHalo2CountsCannotOverrun walks the four counts the Halo2 frame carries
// in sequence. Each sits behind the ones before it, so a bound missing on the
// third is only reachable once the first two are satisfied.
func TestHalo2CountsCannotOverrun(t *testing.T) {
	// [vkID:32][nInputs:4][nAdvice:4][nInstance:4][nRounds:4]
	build := func(nInputs, nAdvice, nInstance, nRounds uint32) []byte {
		b := []byte{OpVerifyHalo2}
		b = append(b, make([]byte, 32)...)
		for _, n := range []uint32{nInputs, nAdvice, nInstance, nRounds} {
			var w [4]byte
			binary.BigEndian.PutUint32(w[:], n)
			b = append(b, w[:]...)
		}
		return b
	}
	for _, claim := range []uint32{1, 1 << 20, 1 << 30, ^uint32(0)} {
		for i, in := range [][]byte{
			build(claim, 0, 0, 1),
			build(0, claim, 0, 1),
			build(0, 0, claim, 1),
			build(0, 0, 0, claim),
		} {
			_, err := run(t, in)
			require.Error(t, err, "halo2 count %d at position %d must be refused", claim, i)
		}
	}
}

// TestSTARKPublicInputCountDoesNotSizeTheAllocation is the regression for a
// declared count that sized a slice before anything bounded it.
//
// STARKVerifyPrecompile read a uint32 count and immediately did
// make([]uint64, n) — up to 34 GB for an attacker-chosen count — and only
// then checked, on the first loop iteration, whether the bytes were there.
// The refusal arrived after the allocation it existed to prevent.
func TestSTARKPublicInputCountDoesNotSizeTheAllocation(t *testing.T) {
	for _, claim := range []uint32{1 << 20, 1 << 28, 1 << 30, ^uint32(0)} {
		in := hostile(func() []byte {
			b := make([]byte, 36)
			binary.BigEndian.PutUint32(b[32:36], claim)
			return b
		}())
		require.NotPanics(t, func() {
			_, err := STARKVerifyPrecompile(in)
			require.Error(t, err, "a declared count of %d must be refused", claim)
		})
	}
}

// TestUnknownOpIsRefused pins the dispatch default.
func TestUnknownOpIsRefused(t *testing.T) {
	dispatched := map[byte]bool{}
	for _, op := range dispatchedOps {
		dispatched[op] = true
	}
	for b := 0; b < 256; b++ {
		if dispatched[byte(b)] {
			continue
		}
		_, err := run(t, []byte{byte(b)})
		require.ErrorIs(t, err, ErrInvalidOperation, "op 0x%02x names no verifier", b)
	}
	_, err := run(t, nil)
	require.ErrorIs(t, err, ErrInvalidInput, "an empty input names no verifier")
}

// The parsers below are not reachable through Run today — op 0x03 is refused
// at dispatch (ErrFflonkDisabled) and the Merkle sub-mode's header reads sit
// behind verifyCommitment's own 96-byte floor. They are still parsers with
// their own contract: given bytes, yield a structure or refuse. Exercising
// them directly is what keeps that contract from drifting while the dispatch
// is closed, and what would catch a bound going missing on the day 0x03 is
// re-enabled.

func TestFflonkParserRefusesEveryTruncation(t *testing.T) {
	p := &zkVerifyPrecompile{}

	// The whole frame: vkID(32) + numInputs(4) + 4 commitments + 8 evals.
	full := make([]byte, inputsOff-1+fflonkMinProofSize)
	require.True(t, len(full) > fflonkMinProofSize)

	for n := 0; n <= len(full); n++ {
		in := hostile(full[:n])
		require.NotPanics(t, func() {
			ok, err := p.verifyFflonk(in)
			require.False(t, ok, "a %d-byte prefix must not verify", n)
			if n < len(full) {
				require.Error(t, err, "a %d-byte prefix must be refused", n)
			}
		}, "prefix of length %d panicked", n)
	}

	// A declared public-input count the calldata cannot back must be refused
	// before the proof body is reached.
	for _, claim := range []uint32{1, 1 << 20, ^uint32(0)} {
		in := make([]byte, len(full))
		binary.BigEndian.PutUint32(in[fieldLen:fieldLen+4], claim)
		ok, err := p.verifyFflonk(hostile(in))
		require.False(t, ok)
		require.ErrorIs(t, err, ErrInvalidProofLength, "claim %d", claim)
	}

	// parseFflonkProof's own boundaries: the four commitments, then the
	// evaluation floor.
	body := make([]byte, fflonkMinProofSize)
	for n := 0; n < fflonkMinProofSize; n++ {
		fp, err := parseFflonkProof(hostile(body[:n]))
		require.Nil(t, fp, "a %d-byte body is not an fflonk proof", n)
		require.ErrorIs(t, err, ErrInvalidProofLength)
	}
	fp, err := parseFflonkProof(hostile(body))
	require.NoError(t, err)
	require.Len(t, fp.Evaluations, fflonkNumEvaluations)
}

func TestMerkleParserRefusesEveryTruncation(t *testing.T) {
	p := &zkVerifyPrecompile{}
	const merkleHeader = 2*fieldLen + 8 + 4 // poolID + commitmentID + leafIndex + proofLen

	for n := 0; n < merkleHeader; n++ {
		ok, err := p.verifyCommitmentMerkle(hostile(make([]byte, n)))
		require.False(t, ok, "a %d-byte header must not verify", n)
		require.ErrorIs(t, err, ErrInvalidInput, "a %d-byte header must be refused", n)
	}

	// A declared sibling count past the calldata is refused before the proof
	// slice is built.
	for _, claim := range []uint32{1, 1 << 20, 1 << 30, ^uint32(0)} {
		h := make([]byte, merkleHeader)
		binary.BigEndian.PutUint32(h[merkleHeader-4:], claim)
		ok, err := p.verifyCommitmentMerkle(hostile(h))
		require.False(t, ok)
		require.ErrorIs(t, err, ErrInvalidInput, "%d declared siblings", claim)
	}
}

// TestBatchCountReadsTheOpByte pins that the batch gas count skips the
// selector before reading its number, and answers zero when there is no
// selector to skip.
func TestBatchCountReadsTheOpByte(t *testing.T) {
	require.Equal(t, 0, countBatchProofs(nil))
	require.Equal(t, 0, countBatchProofs(hostile([]byte{OpVerifyBatch})))

	in := make([]byte, 1+4+40)
	in[0] = OpVerifyBatch
	binary.BigEndian.PutUint32(in[1:5], 3)
	require.Equal(t, 3, countBatchProofs(hostile(in)))

	// A claim past what the remaining bytes could hold is capped, never
	// billed in full.
	binary.BigEndian.PutUint32(in[1:5], ^uint32(0))
	require.Equal(t, 8, countBatchProofs(hostile(in)), "40 bytes hold 8 five-byte entries")
}
