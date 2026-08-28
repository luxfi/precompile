// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// gasFrame builds a frame whose headers are well formed for mode but whose
// body is filler: enough to price, not enough to verify. The public key is
// filled with 0xFF so that reading the message-length header at a shifted
// offset -- which is exactly what dropping the declared-size check would do --
// yields a conspicuously different length rather than another zero.
func gasFrame(t *testing.T, mode uint8, declaredPubKeyLen uint16, msg []byte) []byte {
	t.Helper()
	pkSize, sigSize, _, _, err := getModeParams(mode)
	require.NoError(t, err)

	out := make([]byte, 0, ModeByte+PubKeyLenSize+pkSize+MessageLenSize+len(msg)+sigSize)
	out = append(out, mode)
	out = binary.BigEndian.AppendUint16(out, declaredPubKeyLen)
	for i := 0; i < pkSize; i++ {
		out = append(out, 0xFF)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(msg)))
	out = append(out, msg...)
	return append(out, make([]byte, sigSize)...)
}

// TestRequiredGas_MalformedNeverFree pins what an input the precompile cannot
// even parse costs. An unreadable mode byte and an unknown parameter set both
// bill the flat default; everything else bills at least its mode's base. No
// input is free, including nil -- a zero-cost path would be a way to make a
// validator do work for nothing.
func TestRequiredGas_MalformedNeverFree(t *testing.T) {
	require.Positive(t, MagnetarDefaultGas, "the flat default must cost something")
	require.Positive(t, MagnetarVerifyPerByteGas, "message bytes must cost something")
	require.Positive(t, MagnetarVerifyPrecompile.RequiredGas(nil))
	require.Equal(t, MagnetarDefaultGas, MagnetarVerifyPrecompile.RequiredGas(nil))
	require.Equal(t, MagnetarDefaultGas, MagnetarVerifyPrecompile.RequiredGas([]byte{}))

	known := map[uint8]bool{}
	for _, m := range allModes {
		known[m] = true
	}
	for b := 0; b < 256; b++ {
		if known[uint8(b)] {
			continue
		}
		require.Equal(t, MagnetarDefaultGas,
			MagnetarVerifyPrecompile.RequiredGas([]byte{uint8(b), 0x00, 0x00}),
			"unknown mode 0x%02x must bill the flat default", b)
	}

	// Every malformed shape of a *known* mode still bills at least that
	// mode's base, and never nothing.
	for _, mode := range allModes {
		_, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)
		for n := 1; n <= 80; n++ {
			in := make([]byte, n)
			in[0] = mode
			got := MagnetarVerifyPrecompile.RequiredGas(in)
			require.Positive(t, got, "mode=0x%02x len=%d", mode, n)
			require.GreaterOrEqual(t, got, baseGas, "mode=0x%02x len=%d", mode, n)
		}
	}
}

// TestRequiredGas_BaseTierOrdering pins the shape of the schedule rather than
// its magic numbers: cost rises with the security level, the fast variant of a
// level costs more than the small one because its signature is larger, and the
// two hash families at the same level cost the same because they do the same
// amount of work.
func TestRequiredGas_BaseTierOrdering(t *testing.T) {
	base := func(mode uint8) uint64 {
		_, _, g, _, err := getModeParams(mode)
		require.NoError(t, err)
		require.Equal(t, g, MagnetarVerifyPrecompile.RequiredGas([]byte{mode}),
			"a bare mode byte must bill exactly the mode's base")
		return g
	}

	ladder := []uint8{
		ModeSHA2_128s, ModeSHA2_128f,
		ModeSHA2_192s, ModeSHA2_192f,
		ModeSHA2_256s, ModeSHA2_256f,
	}
	for i := 1; i < len(ladder); i++ {
		require.Less(t, base(ladder[i-1]), base(ladder[i]),
			"%s must cost less than %s", ModeName(ladder[i-1]), ModeName(ladder[i]))
	}

	for _, pair := range [][2]uint8{
		{ModeSHA2_128s, ModeSHAKE_128s}, {ModeSHA2_128f, ModeSHAKE_128f},
		{ModeSHA2_192s, ModeSHAKE_192s}, {ModeSHA2_192f, ModeSHAKE_192f},
		{ModeSHA2_256s, ModeSHAKE_256s}, {ModeSHA2_256f, ModeSHAKE_256f},
	} {
		require.Equal(t, base(pair[0]), base(pair[1]),
			"%s and %s do the same work and must bill the same base",
			ModeName(pair[0]), ModeName(pair[1]))
	}
}

// TestRequiredGas_MonotoneInMessageLength pins the per-byte term: price rises
// strictly with the declared message length, by exactly the per-byte rate, for
// every parameter set. The declared length is what is billed -- gas is metered
// before the frame is validated -- so an over-declared length costs more, never
// less, which is the safe direction.
func TestRequiredGas_MonotoneInMessageLength(t *testing.T) {
	for _, mode := range allModes {
		_, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)

		prev := uint64(0)
		for _, n := range []int{0, 1, 2, 31, 32, 33, 1000} {
			in := gasFrame(t, mode, uint16(mustPubKeySize(t, mode)), make([]byte, n))
			got := MagnetarVerifyPrecompile.RequiredGas(in)
			require.Equal(t, baseGas+uint64(n)*MagnetarVerifyPerByteGas, got,
				"mode=%s msgLen=%d", ModeName(mode), n)
			if n > 0 {
				require.Greater(t, got, prev, "mode=%s msgLen=%d", ModeName(mode), n)
			}
			prev = got
		}

		// The largest length the uint16 header can name, priced without wrapping.
		in := gasFrame(t, mode, uint16(mustPubKeySize(t, mode)), nil)
		binary.BigEndian.PutUint16(in[ModeByte+PubKeyLenSize+mustPubKeySize(t, mode):], math.MaxUint16)
		require.Equal(t, baseGas+uint64(math.MaxUint16)*MagnetarVerifyPerByteGas,
			MagnetarVerifyPrecompile.RequiredGas(in), "mode=%s", ModeName(mode))
	}
}

// TestRequiredGas_DeclaredPubKeyLenGate pins that pricing stops at the base
// when the declared public key length is not the mode's. Without that check the
// message-length header would be read at a shifted offset, so a caller could
// steer the per-byte charge by lying about the key size -- here the 0xFF filler
// makes the shifted read a very large length, and the assertion is that it does
// not reach the meter.
func TestRequiredGas_DeclaredPubKeyLenGate(t *testing.T) {
	for _, mode := range allModes {
		pkSize, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)

		for _, declared := range []uint16{0, 1, uint16(pkSize - 1), uint16(pkSize + 1), 0xFFFF} {
			in := gasFrame(t, mode, declared, make([]byte, 64))
			require.Equal(t, baseGas, MagnetarVerifyPrecompile.RequiredGas(in),
				"mode=%s declared=%d must bill exactly the base", ModeName(mode), declared)
		}

		// The true size is the only one that unlocks the per-byte term.
		in := gasFrame(t, mode, uint16(pkSize), make([]byte, 64))
		require.Equal(t, baseGas+64*MagnetarVerifyPerByteGas,
			MagnetarVerifyPrecompile.RequiredGas(in), "mode=%s", ModeName(mode))
	}
}

// TestRequiredGas_ShortOfMessageHeader pins the last unpriced boundary: a frame
// that stops before the message-length header is readable bills the bare base,
// and the byte that completes the header is what unlocks the per-byte term.
func TestRequiredGas_ShortOfMessageHeader(t *testing.T) {
	for _, mode := range allModes {
		pkSize, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)

		full := gasFrame(t, mode, uint16(pkSize), make([]byte, 7))
		headerEnd := ModeByte + PubKeyLenSize + pkSize + MessageLenSize

		for _, n := range []int{ModeByte, ModeByte + 1, headerEnd - MessageLenSize, headerEnd - 1} {
			require.Equal(t, baseGas, MagnetarVerifyPrecompile.RequiredGas(full[:n]),
				"mode=%s len=%d", ModeName(mode), n)
		}
		require.Equal(t, baseGas+7*MagnetarVerifyPerByteGas,
			MagnetarVerifyPrecompile.RequiredGas(full[:headerEnd]),
			"mode=%s: the byte completing the header unlocks the per-byte term", ModeName(mode))
	}
}

// TestRequiredGas_MatchesFrozenFrame ties the schedule to the known-answer
// vector, so the accepting path has one pinned absolute price alongside all the
// relational assertions.
func TestRequiredGas_MatchesFrozenFrame(t *testing.T) {
	require.Equal(t,
		SLH128sVerifyBaseGas+32*MagnetarVerifyPerByteGas,
		MagnetarVerifyPrecompile.RequiredGas(katFrame(t)))
}

func mustPubKeySize(t *testing.T, mode uint8) int {
	t.Helper()
	pkSize, _, _, _, err := getModeParams(mode)
	require.NoError(t, err)
	return pkSize
}
