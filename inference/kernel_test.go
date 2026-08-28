// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// kernel_test.go — the integer kernels' edges: the two guards that stop a degenerate
// input from dividing by zero (which on the consensus path panics a validator), the
// causal mask itself, and the saturation that keeps requantisation from wrapping.

package inference

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaxu32(t *testing.T) {
	for _, c := range [][2]uint32{{0, 0}, {3, 7}, {7, 3}, {5, 5}, {0, math.MaxUint32}, {math.MaxUint32, 0}} {
		a, b := c[0], c[1]
		got := maxu32(a, b)
		require.GreaterOrEqual(t, got, a)
		require.GreaterOrEqual(t, got, b)
		require.True(t, got == a || got == b, "must return one of its arguments")
		require.Equal(t, got, maxu32(b, a), "must be symmetric")
	}
}

// TestRmsnormZeroRow: with eps 0 an all-zero activation row drives the RMS denominator
// to zero. The kernel must clamp it — an integer divide by zero panics, and a panic
// inside a precompile takes the validator down.
func TestRmsnormZeroRow(t *testing.T) {
	const d = 4
	out := make([]int8, d)
	require.NotPanics(t, func() {
		rmsnormI8(make([]int8, d), []int8{1, 1, 1, 1}, out, d, 5, 0)
	})
	require.Equal(t, make([]int8, d), out, "a zero row normalises to zeros")
}

// TestRmsnormDividesByTheRootMeanSquare pins the arithmetic itself: ss = 4·80² = 25600
// and isqrt(25600) = 160, so each output is (x·w·mult)/160.
func TestRmsnormDividesByTheRootMeanSquare(t *testing.T) {
	const d = 4
	x := []int8{80, 80, 80, 80}
	out := make([]int8, d)

	rmsnormI8(x, []int8{1, 1, 1, 1}, out, d, 8, 0)
	require.Equal(t, []int8{4, 4, 4, 4}, out, "80·1·8/160")

	rmsnormI8(x, []int8{2, 2, 2, 2}, out, d, 8, 0)
	require.Equal(t, []int8{8, 8, 8, 8}, out, "doubling the weight doubles the output; the divisor is unchanged")

	rmsnormI8(x, []int8{127, 127, 127, 127}, out, d, 8, 0)
	require.Equal(t, []int8{127, 127, 127, 127}, out, "an over-range result saturates, it must never wrap")

	// eps only enlarges the divisor, so raising it can only shrink the result.
	prev := int8(math.MaxInt8)
	for _, eps := range []int32{0, 39936, 1_000_000} {
		rmsnormI8(x, []int8{1, 1, 1, 1}, out, d, 8, eps)
		require.LessOrEqual(t, out[0], prev, "a larger eps must not enlarge the result")
		prev = out[0]
	}
	require.Zero(t, prev, "a large enough eps drives the row to zero")
}

// TestAttentionAtLengthOne: with a single token there is exactly one key, so the
// softmax weight is 1 whatever the scores are. The output must therefore depend on v
// alone, and the causal flag must make no difference.
func TestAttentionAtLengthOne(t *testing.T) {
	const seq, d = 1, 2
	v := []int8{100, -100}

	zeroScores := make([]int8, d)
	loudScores := []int8{120, -7}

	a := make([]int8, d)
	b := make([]int8, d)
	attentionI8(zeroScores, zeroScores, v, aivmExpLUT[:], a, seq, d, 9, 7, true)
	attentionI8(loudScores, []int8{-60, 33}, v, aivmExpLUT[:], b, seq, d, 9, 7, true)
	require.Equal(t, a, b, "at length one the scores cannot matter")

	open := make([]int8, d)
	attentionI8(zeroScores, zeroScores, v, aivmExpLUT[:], open, seq, d, 9, 7, false)
	require.Equal(t, a, open, "at length one the mask has nothing to mask")

	require.NotEqual(t, make([]int8, d), a, "the value vector must actually reach the output")
}

// TestAttentionMaskHidesTheFuture: under the causal mask row 0 is computed from token 0
// alone, so rewriting token 1's value must leave it untouched — and must not, with the
// mask off. Scores are all equal (q and k are zero) so any leak shows up in the output.
func TestAttentionMaskHidesTheFuture(t *testing.T) {
	const seq, d = 2, 2
	q := make([]int8, seq*d)
	k := make([]int8, seq*d)
	v := []int8{100, 100, -100, -100}
	vFuture := []int8{100, 100, 7, 55} // same first row, different second

	masked := make([]int8, seq*d)
	maskedFuture := make([]int8, seq*d)
	attentionI8(q, k, v, aivmExpLUT[:], masked, seq, d, 9, 7, true)
	attentionI8(q, k, vFuture, aivmExpLUT[:], maskedFuture, seq, d, 9, 7, true)
	require.Equal(t, masked[:d], maskedFuture[:d], "row 0 must not see row 1")
	require.NotEqual(t, masked[d:], maskedFuture[d:], "row 1 must see row 1")

	open := make([]int8, seq*d)
	attentionI8(q, k, v, aivmExpLUT[:], open, seq, d, 9, 7, false)
	require.NotEqual(t, masked[:d], open[:d], "with the mask off row 0 must see row 1")
}

// TestAttentionZeroTable: a probability table of all zeros drives the softmax
// denominator to zero. The kernel must clamp it rather than divide by zero.
func TestAttentionZeroTable(t *testing.T) {
	const seq, d = 2, 2
	out := make([]int8, seq*d)
	require.NotPanics(t, func() {
		attentionI8(make([]int8, seq*d), make([]int8, seq*d), []int8{100, 100, -100, -100},
			make([]int32, 256), out, seq, d, 9, 7, true)
	})
	require.Equal(t, make([]int8, seq*d), out, "no probability mass, no output")
}
