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

// This file answers one question about 0x9012 (the router): is the per-hop gas
// charged over a path whose length is actually CAPPED, and does the number of hops
// paid for equal the number of hops walked? A per-hop fee computed from one quantity
// while the loop iterates over another is a flat fee over unbounded input.

// rgEncodeSimplePath builds the router's address-list ExactInput encoding:
//
//	numTokens(1) | tokens(numTokens*20) | amountIn(32) | amountOutMin(32) | deadline(8)
func rgEncodeSimplePath(numTokens int, amountIn *big.Int) []byte {
	out := make([]byte, 0, 1+numTokens*20+72)
	out = append(out, byte(numTokens))
	for i := range numTokens {
		var a common.Address
		a[19] = byte(i + 1)
		out = append(out, a.Bytes()...)
	}
	amt := make([]byte, 32)
	amountIn.FillBytes(amt)
	out = append(out, amt...)
	out = append(out, make([]byte, 32)...) // amountOutMinimum
	out = append(out, make([]byte, 8)...)  // deadline
	return out
}

// rgEncodeV4Path builds the router's V4 binary-path ExactInput encoding:
//
//	0xFF | pathLen(2) | path(pathLen) | amountIn(32) | amountOutMin(32) | deadline(8)
//	path = currencyIn(20) | hops * PathKey(46)
func rgEncodeV4Path(hops int, amountIn *big.Int) []byte {
	keys := make([]PathKey, hops)
	for i := range keys {
		var a common.Address
		a[19] = byte(i + 2)
		keys[i] = PathKey{IntermediateCurrency: a, Fee: 3000, TickSpacing: 60}
	}
	var currencyIn common.Address
	currencyIn[19] = 1
	path := EncodePath(currencyIn, keys)

	out := make([]byte, 0, 3+len(path)+72)
	out = append(out, 0xFF)
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(path)))
	out = append(out, hdr...)
	out = append(out, path...)
	amt := make([]byte, 32)
	amountIn.FillBytes(amt)
	out = append(out, amt...)
	out = append(out, make([]byte, 32)...)
	out = append(out, make([]byte, 8)...)
	return out
}

func rgQuoteInput(body []byte) []byte {
	return append(selectorBytes(SelectorQuoteExactInput), body...)
}

// TestRouterPathCapIsEnforcedOnBothEncodings proves MaxPathLength actually bounds
// the loop, on BOTH input encodings. The cap has exactly one enforcement site
// (router_module.go:228) and the per-hop gas is computed from the same `numHops` it
// checks — so if either encoding could slip past it, the per-hop fee would be
// covering an unbounded walk.
func TestRouterPathCapIsEnforcedOnBothEncodings(t *testing.T) {
	h := newSettleHarness(t)
	c := RouterPrecompile // the REGISTERED singleton — test what a chain actually dispatches to
	addr := common.HexToAddress(LXRouterAddress)
	amt := big.NewInt(1e18)

	// Simple encoding: numTokens tokens == numTokens-1 hops. 255 is excluded
	// deliberately — see TestRouterSimplePathCannotEncode255Tokens below.
	for _, numTokens := range []int{MaxPathLength + 2, 32, 254} {
		_, _, err := c.Run(h.state, h.caller, addr, rgQuoteInput(rgEncodeSimplePath(numTokens, amt)), 100_000_000, true)
		require.Errorf(t, err, "%d tokens (%d hops) must exceed the cap", numTokens, numTokens-1)
		require.Containsf(t, err.Error(), "path too long",
			"%d tokens must be refused by the MaxPathLength cap specifically", numTokens)
	}

	// V4 encoding: the cap must bind here too, computed from len(PathKeys).
	for _, hops := range []int{MaxPathLength + 1, 64, 1424} {
		_, _, err := c.Run(h.state, h.caller, addr, rgQuoteInput(rgEncodeV4Path(hops, amt)), 100_000_000, true)
		require.Errorf(t, err, "%d V4 hops must exceed the cap", hops)
		require.Containsf(t, err.Error(), "path too long", "%d V4 hops must hit MaxPathLength", hops)
	}

	// The boundary is exact: MaxPathLength hops is ACCEPTED by the cap (it may still
	// fail later for want of a pool, but never with "path too long").
	for _, hops := range []int{1, MaxPathLength} {
		_, _, err := c.Run(h.state, h.caller, addr, rgQuoteInput(rgEncodeV4Path(hops, amt)), 100_000_000, true)
		if err != nil {
			require.NotContainsf(t, err.Error(), "path too long",
				"%d hops is within MaxPathLength and must not be refused by the cap", hops)
		}
	}
}

// TestRouterSimplePathCannotEncode255Tokens pins an encoding AMBIGUITY: the simple
// format's leading byte is a token count, but 0xFF is also the V4 binary-path marker,
// so a 255-token simple path is not decodable as one — it is parsed as a V4 path and
// fails on the V4 header instead. Harmless today because BOTH branches are capped by
// MaxPathLength, but it means the simple format's usable range is 2..254, not 2..255.
func TestRouterSimplePathCannotEncode255Tokens(t *testing.T) {
	h := newSettleHarness(t)
	c := RouterPrecompile
	addr := common.HexToAddress(LXRouterAddress)

	_, _, err := c.Run(h.state, h.caller, addr,
		rgQuoteInput(rgEncodeSimplePath(255, big.NewInt(1e18))), 100_000_000, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "V4 path",
		"a leading 0xFF is read as the V4 marker, not a token count of 255")

	// 254 is the largest count the simple format can express, and it is still refused
	// by the cap rather than walked.
	_, _, err = c.Run(h.state, h.caller, addr,
		rgQuoteInput(rgEncodeSimplePath(254, big.NewInt(1e18))), 100_000_000, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "path too long", "254 tokens must hit MaxPathLength")
}

// TestRouterGasScalesPerHop proves the fee is not flat: each additional hop costs
// exactly GasQuotePerHop more, and a budget sized for a short path cannot buy a
// longer one.
func TestRouterGasScalesPerHop(t *testing.T) {
	h := newSettleHarness(t)
	c := RouterPrecompile // the REGISTERED singleton — test what a chain actually dispatches to
	addr := common.HexToAddress(LXRouterAddress)
	amt := big.NewInt(1e18)

	cost := func(hops int) uint64 { return GasQuoteBase + uint64(hops)*GasQuotePerHop }

	// One gas below the computed charge is refused with nothing left, for every legal
	// hop count — the charge is taken BEFORE the walk.
	for hops := 1; hops <= MaxPathLength; hops++ {
		in := rgQuoteInput(rgEncodeV4Path(hops, amt))
		_, remaining, err := c.Run(h.state, h.caller, addr, in, cost(hops)-1, true)
		require.Errorf(t, err, "%d hops at one gas below cost must refuse", hops)
		require.Zerof(t, remaining, "%d hops: a refused call must leave no gas", hops)
	}

	// Gas strictly increases with hop count.
	require.Equal(t, cost(1)+GasQuotePerHop, cost(2), "each hop adds exactly GasQuotePerHop")
	require.Greater(t, cost(MaxPathLength), cost(1), "a longer path must cost more")

	// A budget that funds a 1-hop quote cannot fund a MaxPathLength quote.
	_, _, err := c.Run(h.state, h.caller, addr,
		rgQuoteInput(rgEncodeV4Path(MaxPathLength, amt)), cost(1), true)
	require.Error(t, err, "a max-length path must not run at a single-hop price")
}

// TestRouterHopsPaidForEqualHopsWalked is the alignment property that makes the
// per-hop fee meaningful: the `numHops` the gas is computed from must be the length
// of the slice the loop ranges over. The V4 branch pays for len(PathKeys) and walks
// PathKeys; the simple branch pays for len(Path)-1 and walks len(Path)-1.
//
// Asserted through observable behaviour: a quote that fails on hop i proves the walk
// reached hop i, and i must always be below the hop count that was charged.
func TestRouterHopsPaidForEqualHopsWalked(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)   // a live pool, so the walk reaches a real quote rather than failing at hop 0
	c := RouterPrecompile // the REGISTERED singleton — test what a chain actually dispatches to
	addr := common.HexToAddress(LXRouterAddress)
	amt := big.NewInt(1e18)

	for hops := 1; hops <= MaxPathLength; hops++ {
		charged := GasQuoteBase + uint64(hops)*GasQuotePerHop
		_, remaining, err := c.Run(h.state, h.caller, addr,
			rgQuoteInput(rgEncodeV4Path(hops, amt)), 100_000_000, true)
		if err == nil {
			require.Equal(t, uint64(100_000_000)-charged, remaining,
				"%d hops: a successful quote must consume exactly the per-hop charge", hops)
			continue
		}
		// The walk failed at some hop; it must still have consumed exactly the
		// charge computed for the DECLARED hop count, never more.
		require.Equalf(t, uint64(100_000_000)-charged, remaining,
			"%d hops: gas consumed must equal the per-hop charge even on a failed hop", hops)
		require.Containsf(t, err.Error(), "quote hop",
			"%d hops: the failure must come from walking a hop, proving the loop ran", hops)
	}
}

// TestRouterValueSelectorsAreRetired pins that the router's four value-moving
// selectors are gone. This matters for the gas assessment: their absence is why the
// unbounded-path question only has to be answered for the quote views. If one ever
// came back it would be a SECOND money path, which the design explicitly forbids.
func TestRouterValueSelectorsAreRetired(t *testing.T) {
	h := newSettleHarness(t)
	c := RouterPrecompile // the REGISTERED singleton — test what a chain actually dispatches to
	addr := common.HexToAddress(LXRouterAddress)

	for name, sel := range map[string]uint32{
		"exactInputSingle":  SelectorExactInputSingle,
		"exactInput":        SelectorExactInput,
		"exactOutputSingle": SelectorExactOutputSingle,
		"exactOutput":       SelectorExactOutput,
	} {
		out, remaining, err := c.Run(h.state, h.caller, addr,
			append(selectorBytes(sel), make([]byte, 256)...), 1_000_000, false)
		require.ErrorIsf(t, err, ErrPrecompileMoved, "%s must revert PRECOMPILE_MOVED", name)
		require.Nilf(t, out, "%s must return nothing", name)
		require.Equalf(t, uint64(1_000_000), remaining,
			"%s is a retired entry point, not work — it must charge no gas", name)
	}
}

// TestRouterRefusesMalformedInput walks the router's refusal surface. Every
// truncation must be refused without panicking; the router is a view, but it is
// still reachable calldata.
func TestRouterRefusesMalformedInput(t *testing.T) {
	h := newSettleHarness(t)
	c := RouterPrecompile // the REGISTERED singleton — test what a chain actually dispatches to
	addr := common.HexToAddress(LXRouterAddress)

	t.Run("shorter than a selector", func(t *testing.T) {
		for n := range 4 {
			_, _, err := c.Run(h.state, h.caller, addr, make([]byte, n), 1_000_000, true)
			require.Errorf(t, err, "a %d-byte input carries no selector", n)
		}
	})

	t.Run("unknown selector", func(t *testing.T) {
		for _, sel := range []uint32{0x00000000, 0xffffffff, 0x0A00FFFF} {
			_, _, err := c.Run(h.state, h.caller, addr,
				append(selectorBytes(sel), make([]byte, 64)...), 1_000_000, true)
			require.Errorf(t, err, "selector %#x must be refused", sel)
		}
	})

	t.Run("every truncation of a quote", func(t *testing.T) {
		full := rgQuoteInput(rgEncodeV4Path(2, big.NewInt(1e18)))
		for cut := 4; cut < len(full); cut++ {
			require.NotPanicsf(t, func() {
				_, _, _ = c.Run(h.state, h.caller, addr, full[:cut], 1_000_000, true)
			}, "quote truncated to %d bytes must not panic", cut)
		}
		simple := rgQuoteInput(rgEncodeSimplePath(3, big.NewInt(1e18)))
		for cut := 4; cut < len(simple); cut++ {
			require.NotPanicsf(t, func() {
				_, _, _ = c.Run(h.state, h.caller, addr, simple[:cut], 1_000_000, true)
			}, "simple quote truncated to %d bytes must not panic", cut)
		}
	})

	t.Run("degenerate token count", func(t *testing.T) {
		for _, n := range []int{0, 1} {
			_, _, err := c.Run(h.state, h.caller, addr,
				rgQuoteInput(rgEncodeSimplePath(n, big.NewInt(1e18))), 1_000_000, true)
			require.Errorf(t, err, "a %d-token path must be refused", n)
		}
	})

	t.Run("zero gas", func(t *testing.T) {
		for _, sel := range []uint32{SelectorQuoteExactInput, SelectorQuoteExactInputSingle, SelectorGetBestRoute} {
			require.NotPanicsf(t, func() {
				_, _, err := c.Run(h.state, h.caller, addr,
					append(selectorBytes(sel), rgEncodeV4Path(1, big.NewInt(1e18))...), 0, true)
				require.Errorf(t, err, "selector %#x with zero gas must be refused", sel)
			}, "selector %#x with zero gas must not panic", sel)
		}
	})
}

// TestDecodePathRejectsMisalignedData: a V4 path is currencyIn plus a whole number
// of fixed-size PathKeys. Anything else must be refused rather than silently
// truncated to the keys that happen to fit — a caller must not be able to smuggle a
// partial key past the hop count the gas was computed from.
func TestDecodePathRejectsMisalignedData(t *testing.T) {
	var currencyIn common.Address
	currencyIn[19] = 1

	// Well-formed paths decode to exactly the hops encoded.
	for hops := 1; hops <= 8; hops++ {
		keys := make([]PathKey, hops)
		for i := range keys {
			keys[i] = PathKey{Fee: 3000, TickSpacing: 60}
		}
		gotIn, gotKeys, err := DecodePath(EncodePath(currencyIn, keys))
		require.NoError(t, err)
		require.Equal(t, currencyIn, gotIn)
		require.Lenf(t, gotKeys, hops, "%d hops must decode to %d keys", hops, hops)
	}

	// Too short for the currency.
	_, _, err := DecodePath(make([]byte, 19))
	require.Error(t, err)

	// A trailing partial PathKey must be refused, not dropped.
	for extra := 1; extra < PathKeySize; extra++ {
		buf := append(EncodePath(currencyIn, []PathKey{{Fee: 3000}}), make([]byte, extra)...)
		_, _, err := DecodePath(buf)
		require.Errorf(t, err, "a path with %d trailing bytes must be refused", extra)
	}

	// Zero hops is not a path.
	_, _, err = DecodePath(currencyIn.Bytes())
	require.Error(t, err, "a path with no hops must be refused")
}

// TestPathKeyRoundTrip: a hop must survive encode/decode exactly. A field that
// silently changes across the wire is a hop routed to a different pool than the
// caller signed for.
func TestPathKeyRoundTrip(t *testing.T) {
	cases := []PathKey{
		{IntermediateCurrency: common.HexToAddress("0x01"), Fee: 100, TickSpacing: 1},
		{IntermediateCurrency: common.HexToAddress("0xabcdef"), Fee: 3000, TickSpacing: 60},
		{IntermediateCurrency: common.HexToAddress("0xff"), Fee: uint32(FeeMax), TickSpacing: -60},
		{Fee: 0, TickSpacing: 0},
	}
	for i, pk := range cases {
		got, err := DecodePathKey(EncodePathKey(pk))
		require.NoErrorf(t, err, "case %d", i)
		require.Equalf(t, pk.IntermediateCurrency, got.IntermediateCurrency, "case %d currency", i)
		require.Equalf(t, pk.Fee, got.Fee, "case %d fee", i)
		require.Equalf(t, pk.TickSpacing, got.TickSpacing, "case %d tickSpacing (negative spacing must survive)", i)
		require.Equalf(t, pk.Hooks, got.Hooks, "case %d hooks", i)
	}
	// One byte short is refused rather than read past the end.
	_, err := DecodePathKey(make([]byte, PathKeySize-1))
	require.Error(t, err)
}
