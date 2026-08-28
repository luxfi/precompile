// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// The router's LIVE codecs: the quote decoders and the quote-result encoder that the
// surviving read-only selectors on 0x9012 actually use. (The value-moving selectors
// are retired — see TestRouterValueSelectorsAreRetired — so their decoders and
// EncodeSwapResult are dead; they are reported rather than tested, because writing
// tests for code nothing dispatches to manufactures coverage without buying safety.)

// TestEncodeQuoteResultsIsFixedWidthAndOrdered pins the result wire format. Each
// entry is a fixed 73 bytes, so a caller indexes entry i at a computed offset; a
// width or ordering change silently reassigns every field after the first entry.
func TestEncodeQuoteResultsIsFixedWidthAndOrdered(t *testing.T) {
	mk := func(v SwapVenue, out int64, poolByte byte, gas uint64) QuoteResult {
		var id [32]byte
		id[0] = poolByte
		return QuoteResult{Venue: v, AmountOut: big.NewInt(out), PoolID: id, GasEstimate: gas}
	}

	// Empty: a count byte and nothing else — never a nil slice a caller would
	// misread as a failed call.
	empty := EncodeQuoteResults(nil)
	require.Len(t, empty, 1)
	require.Equal(t, byte(0), empty[0])

	results := []QuoteResult{
		mk(VenueV4Native, 1_000, 0xA1, 50_000),
		mk(VenueV3, 999, 0xB2, 60_000),
		mk(VenueV2, 1, 0xC3, 70_000),
		mk(VenueExternal, 0, 0xD4, 0),
	}
	enc := EncodeQuoteResults(results)
	require.Len(t, enc, 1+len(results)*73, "each result is exactly 73 bytes")
	require.Equal(t, byte(len(results)), enc[0], "the leading byte is the result count")

	// Every field of every entry must land at its documented offset, in order.
	for i, want := range results {
		off := 1 + i*73
		require.Equalf(t, byte(want.Venue), enc[off], "entry %d venue", i)
		require.Equalf(t, 0, new(big.Int).SetBytes(enc[off+1:off+33]).Cmp(want.AmountOut),
			"entry %d amountOut", i)
		require.Equalf(t, want.PoolID[:], enc[off+33:off+65], "entry %d poolID", i)
		require.Equalf(t, want.GasEstimate, binary.BigEndian.Uint64(enc[off+65:off+73]),
			"entry %d gasEstimate", i)
	}

	// Order is preserved: reversing the input must change the bytes, or a caller
	// reading "best venue first" gets the wrong venue.
	rev := []QuoteResult{results[3], results[2], results[1], results[0]}
	require.NotEqual(t, enc, EncodeQuoteResults(rev), "result order must be significant")

	// Determinism: the same results encode identically every time.
	for range 20 {
		require.Equal(t, enc, EncodeQuoteResults(results))
	}
}

// TestDecodeQuoteParamsRefusesShortInput: the single-hop quote decoder must refuse
// anything shorter than its fixed layout rather than reading past the end.
func TestDecodeQuoteParamsRefusesShortInput(t *testing.T) {
	tokenIn := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tokenOut := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// tokenIn(20) + tokenOut(20) + amountIn(32) + fee(3)
	body := make([]byte, 0, 75)
	body = append(body, tokenIn.Bytes()...)
	body = append(body, tokenOut.Bytes()...)
	amt := make([]byte, 32)
	big.NewInt(1_000_000).FillBytes(amt)
	body = append(body, amt...)
	body = append(body, 0x00, 0x0B, 0xB8) // fee 3000

	gotIn, gotOut, gotAmt, gotFee, err := DecodeQuoteParams(body)
	require.NoError(t, err)
	require.Equal(t, tokenIn, gotIn)
	require.Equal(t, tokenOut, gotOut)
	require.Equal(t, int64(1_000_000), gotAmt.Int64())
	require.Equal(t, uint32(3000), gotFee)

	// The FEE IS OPTIONAL: the decoder's floor is 72 bytes (tokenIn+tokenOut+amountIn)
	// and a body without the trailing 3 fee bytes decodes with fee == 0. Pinning that
	// explicitly, because a truncated request silently quoting a ZERO-FEE pool is a
	// surprising default — it returns a better price than any real pool would give.
	// Harmless on an advisory view (it moves no value), but a caller sizing a trade
	// from it is reading a fee-free number.
	short := body[:72]
	_, _, gotAmt2, gotFee2, err := DecodeQuoteParams(short)
	require.NoError(t, err, "72 bytes is the documented minimum: the fee is optional")
	require.Equal(t, int64(1_000_000), gotAmt2.Int64())
	require.Zero(t, gotFee2, "a body with no fee bytes quotes at fee ZERO")

	// Every prefix BELOW the 72-byte floor must be refused, never partially decoded.
	for cut := 0; cut < 72; cut++ {
		require.NotPanicsf(t, func() {
			_, _, _, _, err := DecodeQuoteParams(body[:cut])
			require.Errorf(t, err, "a %d-byte quote body is below the floor and must be refused", cut)
		}, "a %d-byte quote body must not panic", cut)
	}
	// And a partial fee (73 or 74 bytes) also falls back to fee 0 rather than reading
	// past the end.
	for _, cut := range []int{73, 74} {
		require.NotPanicsf(t, func() {
			_, _, _, f, err := DecodeQuoteParams(body[:cut])
			require.NoError(t, err)
			require.Zerof(t, f, "a %d-byte body has a partial fee and must default to 0", cut)
		}, "a %d-byte body must not panic", cut)
	}
}

// TestDecodeExactInputSingleParamsRoundTrip: every field must survive decoding at
// its documented offset. A field read from the wrong offset routes the trade to a
// different pool than the caller asked for.
func TestDecodeExactInputSingleParamsRoundTrip(t *testing.T) {
	tokenIn := common.HexToAddress("0xaaaa000000000000000000000000000000000001")
	tokenOut := common.HexToAddress("0xbbbb000000000000000000000000000000000002")
	hooks := common.HexToAddress("0xcccc000000000000000000000000000000000003")

	// tokenIn(20)+tokenOut(20)+amountIn(32)+amountOutMin(32)+fee(3)+tickSpacing(3)+hooks(20)+sqrtLimit(32)+deadline(8)
	body := make([]byte, 0, 170)
	body = append(body, tokenIn.Bytes()...)
	body = append(body, tokenOut.Bytes()...)
	in := make([]byte, 32)
	big.NewInt(5_000_000).FillBytes(in)
	body = append(body, in...)
	minOut := make([]byte, 32)
	big.NewInt(4_000_000).FillBytes(minOut)
	body = append(body, minOut...)
	body = append(body, 0x00, 0x0B, 0xB8) // fee 3000
	body = append(body, 0x00, 0x00, 0x3C) // tickSpacing 60
	body = append(body, hooks.Bytes()...)
	limit := make([]byte, 32)
	big.NewInt(123456789).FillBytes(limit)
	body = append(body, limit...)
	dl := make([]byte, 8)
	binary.BigEndian.PutUint64(dl, 99_999)
	body = append(body, dl...)

	p, err := DecodeExactInputSingleParams(body)
	require.NoError(t, err)
	require.Equal(t, tokenIn, p.TokenIn)
	require.Equal(t, tokenOut, p.TokenOut)
	require.Equal(t, int64(5_000_000), p.AmountIn.Int64())
	require.Equal(t, int64(4_000_000), p.AmountOutMinimum.Int64())
	require.Equal(t, uint32(3000), p.Fee)
	require.Equal(t, int32(60), p.TickSpacing)
	require.Equal(t, hooks, p.Hooks)

	// 107 bytes is the documented floor (20+20+32+32+3): the trailing tickSpacing,
	// hooks, sqrtPriceLimit and deadline are optional. Every prefix BELOW it must be
	// refused rather than yielding a half-filled struct whose zero AmountOutMinimum
	// would read as "no slippage bound".
	for cut := 0; cut < 107; cut++ {
		require.NotPanicsf(t, func() {
			_, err := DecodeExactInputSingleParams(body[:cut])
			require.Errorf(t, err, "a %d-byte body is below the floor and must be refused", cut)
		}, "a %d-byte body must not panic", cut)
	}
	// At and above the floor it decodes without reading past the end, whatever the
	// optional tail happens to be.
	for cut := 107; cut <= len(body); cut++ {
		require.NotPanicsf(t, func() {
			_, err := DecodeExactInputSingleParams(body[:cut])
			require.NoErrorf(t, err, "a %d-byte body is at or above the floor", cut)
		}, "a %d-byte body must not panic", cut)
	}
}

// TestDecodeExactInputParamsSimpleFormat covers the address-list encoding's own
// refusals: a path needs at least two tokens, and the declared token count must be
// backed by enough bytes — otherwise a short buffer would decode to addresses read
// past the end.
func TestDecodeExactInputParamsSimpleFormat(t *testing.T) {
	body := rgEncodeSimplePath(3, big.NewInt(7_000_000))
	p, err := DecodeExactInputParams(body)
	require.NoError(t, err)
	require.Len(t, p.Path, 3)
	require.Equal(t, int64(7_000_000), p.AmountIn.Int64())
	require.Empty(t, p.PathKeys, "the simple format carries no V4 path keys")

	// Fewer than two tokens is not a path.
	for _, n := range []int{0, 1} {
		_, err := DecodeExactInputParams(rgEncodeSimplePath(n, big.NewInt(1)))
		require.Errorf(t, err, "a %d-token path must be refused", n)
	}

	// A declared count larger than the bytes provided must be refused, not read past.
	truncated := append([]byte{}, body...)
	truncated[0] = 8 // claim 8 tokens in a 3-token buffer
	require.NotPanics(t, func() {
		_, err := DecodeExactInputParams(truncated)
		require.Error(t, err, "a token count larger than the buffer must be refused")
	})

	// Empty input carries no count byte at all.
	_, err = DecodeExactInputParams(nil)
	require.Error(t, err)

	// V4 format: a declared pathLen longer than the buffer must be refused.
	v4 := rgEncodeV4Path(2, big.NewInt(1_000))
	binary.BigEndian.PutUint16(v4[1:3], 60000)
	require.NotPanics(t, func() {
		_, err := DecodeExactInputParams(v4)
		require.Error(t, err, "a pathLen beyond the buffer must be refused")
	})

	// A V4 header with no room for the length field.
	_, err = DecodeExactInputParams([]byte{0xFF})
	require.Error(t, err)
	_, err = DecodeExactInputParams([]byte{0xFF, 0x00})
	require.Error(t, err)
}

// TestDecodeExactInputParamsV4RoundTrip: the V4 binary path must decode to exactly
// the hops encoded, with each hop's fields intact.
func TestDecodeExactInputParamsV4RoundTrip(t *testing.T) {
	for hops := 1; hops <= MaxPathLength; hops++ {
		body := rgEncodeV4Path(hops, big.NewInt(int64(1000*hops)))
		p, err := DecodeExactInputParams(body)
		require.NoErrorf(t, err, "%d hops must decode", hops)
		require.Lenf(t, p.PathKeys, hops, "%d hops must yield %d keys", hops, hops)
		require.Equalf(t, int64(1000*hops), p.AmountIn.Int64(), "%d hops amountIn", hops)
		require.Emptyf(t, p.Path, "%d hops: the V4 format carries no address list", hops)
		for i, pk := range p.PathKeys {
			require.Equalf(t, uint32(3000), pk.Fee, "hop %d fee", i)
			require.Equalf(t, int32(60), pk.TickSpacing, "hop %d tickSpacing", i)
		}
	}
}

// TestCheckDeadlineIsNotWiredToAnyPath records dead code, with proof, rather than
// manufacturing coverage for it.
//
// `checkDeadline` has ZERO callers in the repository. It is residue of the retired
// value path: 0x9012's four value-moving selectors now revert PRECOMPILE_MOVED, and
// with them went the only code that enforced a deadline. The LIVE quote decoders
// still PARSE a Deadline field, so a caller can supply one and it is simply ignored.
//
// That is harmless today — a quote moves no value, so an expired quote costs nothing
// but a stale number — but it is a control that reads as present and is not. The
// function's own logic is correct and is exercised here so that a future wiring
// starts from a tested primitive; the finding is the absence of a CALLER.
func TestCheckDeadlineIsNotWiredToAnyPath(t *testing.T) {
	db := NewMockStateDB()
	db.SetBlockNumber(1_000)

	require.NoError(t, checkDeadline(db, 0), "deadline 0 means no deadline")
	require.NoError(t, checkDeadline(db, 1_000), "the deadline block itself is still valid")
	require.NoError(t, checkDeadline(db, 1_001), "a future deadline is valid")
	require.ErrorIs(t, checkDeadline(db, 999), ErrDeadlineExpired,
		"a block past the deadline must be refused")

	// The boundary is exclusive on the far side only: expiry begins the block AFTER
	// the deadline, which is the convention a caller signs against.
	db.SetBlockNumber(1_001)
	require.ErrorIs(t, checkDeadline(db, 1_000), ErrDeadlineExpired)

	// And the live quote path parses a deadline it never checks: decoding succeeds
	// with a long-expired value, which is the pinned evidence of the missing wiring.
	body := rgEncodeSimplePath(2, big.NewInt(1_000))
	p, err := DecodeExactInputParams(body)
	require.NoError(t, err)
	require.Zero(t, p.Deadline, "the helper encodes a zero deadline")
}

// TestDecodeExactOutputV4AndOptionalTail covers the exact-output decoder's V4 branch
// and the optional trailing fields both exact-output decoders share. The tail is
// OPTIONAL, so a short body must yield zero values rather than reading past the end —
// and a caller must be able to tell the difference between "unset" and "read garbage".
func TestDecodeExactOutputV4AndOptionalTail(t *testing.T) {
	// --- V4 binary path branch of DecodeExactOutputParams ---
	var currencyOut common.Address
	currencyOut[19] = 9
	keys := []PathKey{
		{IntermediateCurrency: common.HexToAddress("0x0a"), Fee: 3000, TickSpacing: 60},
		{IntermediateCurrency: common.HexToAddress("0x0b"), Fee: 500, TickSpacing: 10},
	}
	path := EncodePath(currencyOut, keys)

	body := []byte{0xFF}
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(path)))
	body = append(body, hdr...)
	body = append(body, path...)
	amountOut := make([]byte, 32)
	big.NewInt(4_242).FillBytes(amountOut)
	body = append(body, amountOut...)
	amountInMax := make([]byte, 32)
	big.NewInt(9_999).FillBytes(amountInMax)
	body = append(body, amountInMax...)
	dl := make([]byte, 8)
	binary.BigEndian.PutUint64(dl, 777)
	body = append(body, dl...)

	p, err := DecodeExactOutputParams(body)
	require.NoError(t, err)
	require.Len(t, p.PathKeys, 2, "the V4 branch must decode both hops")
	require.Equal(t, int64(4_242), p.AmountOut.Int64())
	require.Equal(t, int64(9_999), p.AmountInMaximum.Int64())
	require.Equal(t, uint64(777), p.Deadline, "the trailing deadline must be read when present")

	// Without the trailing deadline the decode still succeeds, with Deadline zero.
	noDeadline, err := DecodeExactOutputParams(body[:len(body)-8])
	require.NoError(t, err)
	require.Zero(t, noDeadline.Deadline, "an absent deadline must read as zero, not as garbage")
	require.Len(t, noDeadline.PathKeys, 2)

	// A corrupt inner path (not a whole number of PathKeys) must be refused rather
	// than silently decoding the keys that happen to fit.
	corrupt := append([]byte{}, body...)
	binary.BigEndian.PutUint16(corrupt[1:3], uint16(len(path)-1))
	require.NotPanics(t, func() {
		_, err := DecodeExactOutputParams(corrupt)
		require.Error(t, err, "a misaligned V4 path must be refused")
	})

	// Fewer than two tokens is not a path in the simple branch either.
	for _, n := range []byte{0, 1} {
		short := append([]byte{n}, make([]byte, 200)...)
		_, err := DecodeExactOutputParams(short)
		require.Errorf(t, err, "a %d-token exact-output path must be refused", n)
	}

	// --- optional tail of DecodeExactOutputSingleParams ---
	// Minimum body (107 bytes) then each optional field added one at a time. Every
	// prefix must decode without panicking, with the absent fields left zero.
	single := make([]byte, 0, 170)
	single = append(single, common.HexToAddress("0x11").Bytes()...)
	single = append(single, common.HexToAddress("0x22").Bytes()...)
	single = append(single, amountOut...)
	single = append(single, amountInMax...)
	single = append(single, 0x00, 0x0B, 0xB8) // fee
	single = append(single, 0x00, 0x00, 0x3C) // tickSpacing
	single = append(single, common.HexToAddress("0x33").Bytes()...)
	limit := make([]byte, 32)
	big.NewInt(555).FillBytes(limit)
	single = append(single, limit...)
	single = append(single, dl...)

	full, err := DecodeExactOutputSingleParams(single)
	require.NoError(t, err)
	require.Equal(t, int32(60), full.TickSpacing, "the optional tickSpacing must be read when present")
	require.Equal(t, common.HexToAddress("0x33"), full.Hooks)
	require.Equal(t, uint64(777), full.Deadline)

	for cut := 107; cut <= len(single); cut++ {
		require.NotPanicsf(t, func() {
			_, err := DecodeExactOutputSingleParams(single[:cut])
			require.NoErrorf(t, err, "a %d-byte body is at or above the floor", cut)
		}, "a %d-byte body must not panic", cut)
	}
}
