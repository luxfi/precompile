// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// Gas metering is a consensus rule: the price a caller pays must be a
// function of the work the verifier performs. These tests assert that
// relationship as a property — "changing X changes the price, changing Y
// does not" — rather than pinning magic numbers, which would pass just as
// happily against a schedule that reads the wrong field.

// headerOps are the four ops that share the
// [op][vkID:32][numInputs:4][inputs...] header. All four verifiers read
// numInputs at [32:36] of input[1:], so all four must be priced on it.
var headerOps = []struct {
	op   byte
	base uint64
}{
	{OpVerifyGroth16, GasGroth16Base},
	{OpVerifyPLONK, GasPLONKBase},
	{OpVerifyFflonk, GasFflonkBase},
	{OpVerifyHalo2, GasHalo2Base},
}

// header builds a well-formed op header declaring numInputs public inputs,
// with vkID[0:4] set to vkPrefix, and enough trailing bytes that the
// declared inputs actually fit (so the length cap never binds).
func header(op byte, vkPrefix uint32, numInputs uint32, tail int) []byte {
	buf := make([]byte, inputsOff+int(numInputs)*fieldLen+tail)
	buf[0] = op
	binary.BigEndian.PutUint32(buf[1:5], vkPrefix)
	binary.BigEndian.PutUint32(buf[numInputsOff:inputsOff], numInputs)
	return buf
}

// TestGas_PriceIgnoresVerifyingKeyID is the regression test for the
// confirmed defect: RequiredGas read the public-input count from
// input[1:5] — the first four bytes of the 32-byte vkID — while every
// verifier reads it from input[33:37]. Price and work were driven by two
// unrelated, independently attacker-chosen fields.
//
// The property: the vkID names WHICH statement is being proved. It has no
// bearing on how much work verification is, so it must have no bearing on
// the price. Before the fix this failed on the very first prefix.
func TestGas_PriceIgnoresVerifyingKeyID(t *testing.T) {
	// Prefixes spanning the uint32 range, including the two the defect
	// report calls out: all-zero (flat base, undercharge) and near-max
	// (4.29e12 gas, a valid proof priced out of every block).
	prefixes := []uint32{0, 1, 0x0000_2710, 0x0001_0000, 0x7fff_ffff, 0xffff_ffff}

	for _, o := range headerOps {
		want := ZKVerifyPrecompile.RequiredGas(header(o.op, prefixes[0], 3, 256))
		for _, pfx := range prefixes[1:] {
			got := ZKVerifyPrecompile.RequiredGas(header(o.op, pfx, 3, 256))
			require.Equalf(t, want, got,
				"op 0x%02x: vkID prefix 0x%08x changed the price from %d to %d; "+
					"gas must not depend on the verification-key ID",
				o.op, pfx, want, got)
		}
	}
}

// TestGas_PriceTracksPublicInputCount is the other half: the field the
// verifier actually reads MUST move the price. A schedule that ignores
// numInputs would charge a flat base for unbounded parsing work.
func TestGas_PriceTracksPublicInputCount(t *testing.T) {
	for _, o := range headerOps {
		prev := ZKVerifyPrecompile.RequiredGas(header(o.op, 0xffff_ffff, 0, 256))
		for n := uint32(1); n <= 8; n++ {
			// Hold the vkID at its most misleading value throughout: if the
			// schedule were reading the vkID, every price here would be equal.
			got := ZKVerifyPrecompile.RequiredGas(header(o.op, 0xffff_ffff, n, 256))
			require.Greaterf(t, got, prev,
				"op 0x%02x: price did not rise from %d inputs to %d", o.op, n-1, n)
			require.Equalf(t, prev+GasPerPublicInput, got,
				"op 0x%02x: each public input must add GasPerPublicInput", o.op)
			prev = got
		}
	}
}

// TestGas_MatchesWhatTheVerifierParses closes the loop between the two
// halves above: the count RequiredGas prices is the same count the
// verifier accepts. An input sized to exactly the declared numInputs must
// clear the verifier's own length check — if the two functions disagreed
// about where the count lives, one of them would reject.
func TestGas_MatchesWhatTheVerifierParses(t *testing.T) {
	p := &zkVerifyPrecompile{}
	for _, n := range []uint32{0, 1, 5} {
		// Groth16 expectedLen = vkID(32) + numInputs(4) + n*32 + proof(256).
		in := header(OpVerifyGroth16, 0xdead_beef, n, 256)

		require.Equal(t, GasGroth16Base+uint64(n)*GasPerPublicInput,
			ZKVerifyPrecompile.RequiredGas(in),
			"gas must price the declared count")

		_, err := p.verifyGroth16(in[1:])
		require.NotErrorIs(t, err, ErrInvalidProofLength,
			"verifier rejected the length that gas just priced as sufficient: "+
				"the two are reading different fields")
	}
}

// TestGas_BoundedByInputLength pins the cap. A caller may declare any
// uint32 count, but the verifier refuses in constant time once the
// declared inputs cannot fit, so the price must not run away either. Gas
// stays a function of calldata the caller actually paid to supply.
func TestGas_BoundedByInputLength(t *testing.T) {
	for _, o := range headerOps {
		for _, size := range []int{inputsOff, inputsOff + 32, 1024, 4096} {
			in := make([]byte, size)
			in[0] = o.op
			// Declare the largest count expressible on the wire.
			binary.BigEndian.PutUint32(in[numInputsOff:inputsOff], math.MaxUint32)

			got := ZKVerifyPrecompile.RequiredGas(in)
			ceiling := o.base + uint64((size-inputsOff)/fieldLen)*GasPerPublicInput

			require.LessOrEqualf(t, got, ceiling,
				"op 0x%02x at %d bytes: charged %d for at most %d parseable inputs",
				o.op, size, got, (size-inputsOff)/fieldLen)
		}
	}
}

// TestGas_ValidProofIsPayable is the overcharge direction stated as user
// impact. Verification-key IDs are hashes, so their leading bytes are
// uniform; under the defect a key was usable only if its first four bytes
// happened to encode a number below ~29,850 — about one key in 143,000.
// Every key must now price the same modest amount.
func TestGas_ValidProofIsPayable(t *testing.T) {
	const blockGasLimit = 30_000_000

	for _, o := range headerOps {
		// A realistic hash-derived key ID, high bytes set.
		in := header(o.op, 0xa3f1_09c7, 4, 256)
		got := ZKVerifyPrecompile.RequiredGas(in)
		require.Lessf(t, got, uint64(blockGasLimit),
			"op 0x%02x: a 4-input proof costs %d gas, more than a whole block",
			o.op, got)
	}
}

// TestGas_BatchIsNeverFree pins defect (a): numProofs == 0 made
// numProofs*GasPerBatchProof evaluate to zero, so op 0x30 dispatched into
// verifyBatch for nothing — bypassing MinCallGas, which exists precisely
// to stop zero-cost calls.
func TestGas_BatchIsNeverFree(t *testing.T) {
	zero := []byte{OpVerifyBatch, 0, 0, 0, 0}
	require.GreaterOrEqual(t, ZKVerifyPrecompile.RequiredGas(zero), MinCallGas,
		"a zero-proof batch must still cost at least MinCallGas")

	// And it really does reach the verifier, so the charge is not academic.
	_, _, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, zero, 10_000_000, true)
	require.Error(t, err)

	// The floor holds for every input length, including a bare selector.
	for size := 0; size <= 64; size++ {
		in := make([]byte, size)
		if size > 0 {
			in[0] = OpVerifyBatch
		}
		require.GreaterOrEqualf(t, ZKVerifyPrecompile.RequiredGas(in), MinCallGas,
			"batch of %d bytes priced below MinCallGas", size)
	}
}

// TestGas_BatchDoesNotOverflow checks the multiplication cannot wrap. The
// count is a uint32, so even uncapped the product is bounded by
// 2^32 * GasPerBatchProof ~ 2.1e14, comfortably inside uint64 — this test
// pins that reasoning against a future rise in GasPerBatchProof, and pins
// that a larger declared count never prices LOWER (the wrap signature).
func TestGas_BatchDoesNotOverflow(t *testing.T) {
	require.Less(t, uint64(math.MaxUint32),
		uint64(math.MaxUint64)/GasPerBatchProof,
		"GasPerBatchProof has grown large enough for uint32*GasPerBatchProof to wrap")

	// Monotonicity over a fully-populated batch: more declared entries in
	// the same calldata must never cost less.
	body := make([]byte, 5+5*40)
	body[0] = OpVerifyBatch
	var prev uint64
	for n := uint32(0); n <= 40; n++ {
		binary.BigEndian.PutUint32(body[1:5], n)
		got := ZKVerifyPrecompile.RequiredGas(body)
		require.GreaterOrEqualf(t, got, prev, "price fell when count rose to %d", n)
		prev = got
	}

	// A wrapped product would land far below the floor.
	huge := make([]byte, 5+5*8)
	huge[0] = OpVerifyBatch
	binary.BigEndian.PutUint32(huge[1:5], math.MaxUint32)
	require.GreaterOrEqual(t, ZKVerifyPrecompile.RequiredGas(huge), MinCallGas)
}

// TestGas_EveryReachableCallCharges sweeps every op selector, valid and
// invalid, at a range of lengths: no input may reach Run for free.
func TestGas_EveryReachableCallCharges(t *testing.T) {
	for op := 0; op <= 0xff; op++ {
		for _, size := range []int{0, 1, 5, 37, 100, 512} {
			in := make([]byte, size)
			if size > 0 {
				in[0] = byte(op)
			}
			require.GreaterOrEqualf(t, ZKVerifyPrecompile.RequiredGas(in), MinCallGas,
				"op 0x%02x at %d bytes costs less than MinCallGas", op, size)
		}
	}
}

// TestGas_DeductedBeforeWork proves the charge is enforced, not merely
// computed: one gas short of the requirement must fail for every op, and
// must fail before any verifier runs.
func TestGas_DeductedBeforeWork(t *testing.T) {
	ops := []byte{
		OpVerifyGroth16, OpVerifyPLONK, OpVerifyFflonk, OpVerifyHalo2,
		OpVerifyKZG, OpVerifyIPA, OpVerifyRangeProof, OpVerifyNullifier,
		OpVerifyCommitment, OpVerifyBatch, 0xff,
	}
	for _, op := range ops {
		in := make([]byte, 512)
		in[0] = op
		need := ZKVerifyPrecompile.RequiredGas(in)
		require.Positive(t, need)

		_, rem, err := ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, need-1, true)
		require.Errorf(t, err, "op 0x%02x ran on insufficient gas", op)
		require.Zerof(t, rem, "op 0x%02x left gas after an out-of-gas failure", op)

		// Exactly enough must get past the charge (it may still fail on the
		// proof itself, but not for want of gas).
		_, rem, err = ZKVerifyPrecompile.Run(nil, addr0, ZKVerifyContractAddress, in, need, true)
		if err != nil {
			require.NotContainsf(t, err.Error(), "gas",
				"op 0x%02x refused an exactly-sufficient payment", op)
		}
		require.Zerof(t, rem, "op 0x%02x: exact payment should leave nothing", op)
	}
}
