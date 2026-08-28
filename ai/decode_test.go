// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestBlobs_LengthOverflowIsRefusedNotPanicked is the chain-halt regression.
//
// The two verification handlers used to bound-check their length prefixes in uint32:
//
//	pubkeyLen := binary.BigEndian.Uint32(input[0:4])
//	if uint32(len(input)) < 4+pubkeyLen+4 { ... }
//	pubkey := input[4 : 4+pubkeyLen]
//
// For pubkeyLen near 2^32 the sum wraps, the check passes, and the slice expression that
// follows panics with "slice bounds out of range". Nothing recovers a panic on the
// precompile execution path, so it halts every validator that processed the transaction —
// 96 bytes of calldata for the ML-DSA handler, 8 for the TEE handler.
//
// The whole wrap band is swept, not one sample: the value that shipped past review
// (0xFFFF) is below it and never wrapped.
func TestBlobs_LengthOverflowIsRefusedNotPanicked(t *testing.T) {
	c := &AIMiningContract{}

	lengths := []uint32{
		math.MaxUint32, math.MaxUint32 - 1, math.MaxUint32 - 3, math.MaxUint32 - 4,
		math.MaxUint32 - 7, math.MaxUint32 - 8, math.MaxUint32 - 11,
		1 << 31, 1<<31 + 4, 1 << 24, 0xFFFF, 97, 96, 1,
	}

	for _, n := range lengths {
		for _, size := range []int{8, 12, 96, 200} {
			t.Run("", func(t *testing.T) {
				// Position 0: the first length prefix.
				in := make([]byte, size)
				binary.BigEndian.PutUint32(in[0:4], n)
				requireRefusedNotPanicked(t, c, in)

				// Position 1: a well-formed first blob followed by an overflowing one.
				if size >= 12 {
					in2 := make([]byte, size)
					binary.BigEndian.PutUint32(in2[0:4], 0)
					binary.BigEndian.PutUint32(in2[4:8], n)
					requireRefusedNotPanicked(t, c, in2)

					// Position 2.
					in3 := make([]byte, size)
					binary.BigEndian.PutUint32(in3[0:4], 0)
					binary.BigEndian.PutUint32(in3[4:8], 0)
					binary.BigEndian.PutUint32(in3[8:12], n)
					requireRefusedNotPanicked(t, c, in3)
				}
			})
		}
	}
}

// requireRefusedNotPanicked drives every handler that decodes length-prefixed blobs, both
// directly and through the registered dispatch path.
//
// The invariant asserted is the one that holds for ALL framing, well-formed or not: the
// decode never panics, and it never hands back a blob the calldata did not contain. A
// declared length that overruns must be refused; a declared length that fits may be
// accepted, but only for exactly the bytes present.
func requireRefusedNotPanicked(t *testing.T, c *AIMiningContract, body []byte) {
	t.Helper()

	for _, count := range []int{1, 2, 3} {
		require.NotPanics(t, func() {
			parts, off, err := blobs(body, count)
			if err != nil {
				return
			}
			require.LessOrEqual(t, off, len(body), "decode ran past the end of the input")
			total := 4 * count
			for _, p := range parts {
				total += len(p)
				require.LessOrEqual(t, len(p), len(body), "decoded a blob longer than the input")
			}
			require.Equal(t, off, total, "offset must account for every header and blob")
		}, "blobs(%d) panicked on %x", count, body[:min(len(body), 16)])
	}

	require.NotPanics(t, func() {
		_, _, err := c.runVerifyMLDSA(nil, body, 1_000_000, false)
		_ = err
	})
	require.NotPanics(t, func() {
		_, _, err := c.runVerifyTEE(nil, body, 1_000_000)
		_ = err
	})
	require.NotPanics(t, func() {
		_, _, _, _, err := parseTriple(body)
		_ = err
	})

	for _, sel := range []uint32{
		SelectorVerifyMLDSA, SelectorVerifyTEE,
		SelectorVerifyAndMintWork, SelectorVerifyAndMintData,
	} {
		input := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(input[:4], sel)
		copy(input[4:], body)
		require.NotPanics(t, func() {
			_, _, err := c.Run(newTestAS(), common.Address{}, ContractAddress, input, 1_000_000, false)
			require.Error(t, err, "selector %#x accepted degenerate framing", sel)
		}, "selector %#x panicked", sel)
	}
}

// TestBlobs_WellFormedFramingRoundTrips proves the decoder is not simply refusing
// everything: correct framing decodes to exactly the blobs that were encoded, including
// empty ones, and the reported offset lands just past the last blob.
func TestBlobs_WellFormedFramingRoundTrips(t *testing.T) {
	cases := [][][]byte{
		{},
		{nil},
		{[]byte("a")},
		{nil, nil, nil},
		{[]byte("pubkey"), nil, []byte("sig")},
		{[]byte("pubkey"), []byte("message"), []byte("signature")},
	}
	for _, want := range cases {
		var enc []byte
		for _, b := range want {
			hdr := make([]byte, 4)
			binary.BigEndian.PutUint32(hdr, uint32(len(b)))
			enc = append(append(enc, hdr...), b...)
		}

		got, off, err := blobs(enc, len(want))
		require.NoError(t, err)
		require.Equal(t, len(enc), off, "offset must land just past the last blob")
		require.Len(t, got, len(want))
		for i := range want {
			require.Equal(t, len(want[i]), len(got[i]))
			if len(want[i]) > 0 {
				require.Equal(t, want[i], got[i])
			}
		}

		// Trailing bytes are permitted and are not consumed.
		got2, off2, err := blobs(append(enc, 0xde, 0xad), len(want))
		require.NoError(t, err)
		require.Equal(t, off, off2)
		require.Len(t, got2, len(want))

		// Every proper prefix is refused: truncation is never read as a shorter list.
		for n := 0; n < len(enc); n++ {
			if _, _, err := blobs(enc[:n], len(want)); err == nil {
				// A prefix may legitimately still contain all the blobs only when the
				// encoding is empty.
				require.Empty(t, want)
			}
		}

		// Asking for one more blob than was encoded is refused.
		_, _, err = blobs(enc, len(want)+1)
		require.ErrorIs(t, err, ErrInputTooShort)
	}
}

// TestParseTriple_ChainIDTailRequired proves the trailing chainId is mandatory: a triple
// with a short or missing tail is refused rather than read out of adjacent memory.
func TestParseTriple_ChainIDTailRequired(t *testing.T) {
	body := make([]byte, 12) // three zero-length blobs

	_, _, _, _, err := parseTriple(body)
	require.ErrorIs(t, err, ErrInputTooShort)

	for n := 1; n < 8; n++ {
		_, _, _, _, err := parseTriple(append(body, make([]byte, n)...))
		require.ErrorIs(t, err, ErrInputTooShort, "tail of %d bytes must be refused", n)
	}

	full := append(body, make([]byte, 8)...)
	binary.BigEndian.PutUint64(full[12:], 96369)
	a, b, cc, chainID, err := parseTriple(full)
	require.NoError(t, err)
	require.Empty(t, a)
	require.Empty(t, b)
	require.Empty(t, cc)
	require.Equal(t, uint64(96369), chainID)
}
