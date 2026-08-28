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

// TestRouterConfigureSetsProcessGlobals pins a design property worth being explicit
// about: the router's Configure does not write to state — it assigns four
// PACKAGE-LEVEL variables (v3QuoterAddr, v3FactoryAddr, v2RouterAddr, v2FactoryAddr).
//
// That is safe for a node serving one chain, which is the deployment model. It is
// worth pinning because the consequences are non-obvious: the values persist for the
// life of the PROCESS, a later Configure with zero addresses does NOT clear them (each
// assignment is guarded by a non-zero check), and anything sharing the process shares
// the values. The test restores the originals so it cannot leak into other tests —
// which is itself the demonstration that the state is global.
func TestRouterConfigureSetsProcessGlobals(t *testing.T) {
	origQuoter, origV3Factory := v3QuoterAddr, v3FactoryAddr
	origV2Router, origV2Factory := v2RouterAddr, v2FactoryAddr
	t.Cleanup(func() {
		v3QuoterAddr, v3FactoryAddr = origQuoter, origV3Factory
		v2RouterAddr, v2FactoryAddr = origV2Router, origV2Factory
	})

	cfgr := &routerConfigurator{}

	// A foreign config type is refused rather than silently configuring nothing.
	err := cfgr.Configure(nil, &QuoterConfig{}, nil, nil)
	require.Error(t, err, "Configure must refuse a config that is not a *RouterConfig")

	// An empty RouterConfig leaves every address untouched.
	require.NoError(t, cfgr.Configure(nil, &RouterConfig{}, nil, nil))
	require.Equal(t, origQuoter, v3QuoterAddr, "an unset address must not overwrite")
	require.Equal(t, origV3Factory, v3FactoryAddr)
	require.Equal(t, origV2Router, v2RouterAddr)
	require.Equal(t, origV2Factory, v2FactoryAddr)

	// Each address is applied independently.
	q := common.HexToAddress("0x00000000000000000000000000000000000000q1")
	f3 := common.HexToAddress("0x0000000000000000000000000000000000000f31")
	r2 := common.HexToAddress("0x0000000000000000000000000000000000000r21")
	f2 := common.HexToAddress("0x0000000000000000000000000000000000000f21")
	require.NoError(t, cfgr.Configure(nil, &RouterConfig{
		V3QuoterAddress:  q,
		V3FactoryAddress: f3,
		V2RouterAddress:  r2,
		V2FactoryAddress: f2,
	}, nil, nil))
	require.Equal(t, q, v3QuoterAddr)
	require.Equal(t, f3, v3FactoryAddr)
	require.Equal(t, r2, v2RouterAddr)
	require.Equal(t, f2, v2FactoryAddr)

	// A subsequent Configure carrying ZERO addresses does NOT clear them: the guard
	// is "set if non-zero", so a chain cannot un-configure a venue by blanking it.
	require.NoError(t, cfgr.Configure(nil, &RouterConfig{}, nil, nil))
	require.Equal(t, q, v3QuoterAddr, "a zero address does not clear a previously set one")
	require.Equal(t, f3, v3FactoryAddr)
	require.Equal(t, r2, v2RouterAddr)
	require.Equal(t, f2, v2FactoryAddr)
}

// TestRunQuoteExactInputSingleChargesAndRefuses covers the single-hop quote handler:
// it must charge its fee before any work and refuse a malformed body.
func TestRunQuoteExactInputSingleChargesAndRefuses(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	c := RouterPrecompile
	addr := common.HexToAddress(LXRouterAddress)

	body := make([]byte, 0, 75)
	body = append(body, h.key.Currency0.Address.Bytes()...)
	body = append(body, h.key.Currency1.Address.Bytes()...)
	amt := make([]byte, 32)
	big.NewInt(1_000_000).FillBytes(amt)
	body = append(body, amt...)
	body = append(body, 0x00, 0x0B, 0xB8) // fee 3000
	in := append(selectorBytes(SelectorQuoteExactInputSingle), body...)

	// Below the fee: refused with nothing left.
	_, remaining, err := c.Run(h.state, h.caller, addr, in, GasQuote-1, true)
	require.Error(t, err)
	require.Zero(t, remaining)

	// At or above the fee the handler runs and consumes exactly GasQuote.
	_, remaining, err = c.Run(h.state, h.caller, addr, in, 10_000_000, true)
	if err == nil {
		require.Equal(t, uint64(10_000_000)-GasQuote, remaining, "the quote fee is flat and exact")
	} else {
		require.Equal(t, uint64(10_000_000)-GasQuote, remaining,
			"a refusal after the charge must still consume exactly the fee")
	}

	// A body below the decoder's floor is refused without panicking.
	for cut := 0; cut < 72; cut++ {
		require.NotPanicsf(t, func() {
			_, _, err := c.Run(h.state, h.caller, addr,
				append(selectorBytes(SelectorQuoteExactInputSingle), body[:cut]...), 10_000_000, true)
			require.Errorf(t, err, "a %d-byte body must be refused", cut)
		}, "a %d-byte body must not panic", cut)
	}
}

// TestRunGetBestRouteChargesAndRefuses covers the route-discovery view on the same
// terms: a flat fee taken up front over a fixed-length input.
func TestRunGetBestRouteChargesAndRefuses(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	c := RouterPrecompile
	addr := common.HexToAddress(LXRouterAddress)

	body := make([]byte, 0, 75)
	body = append(body, h.key.Currency0.Address.Bytes()...)
	body = append(body, h.key.Currency1.Address.Bytes()...)
	amt := make([]byte, 32)
	big.NewInt(1_000_000).FillBytes(amt)
	body = append(body, amt...)
	body = append(body, 0x00, 0x0B, 0xB8)
	in := append(selectorBytes(SelectorGetBestRoute), body...)

	_, remaining, err := c.Run(h.state, h.caller, addr, in, GasRouteLookup-1, true)
	require.Error(t, err)
	require.Zero(t, remaining)

	out, remaining, err := c.Run(h.state, h.caller, addr, in, 10_000_000, true)
	require.Equal(t, uint64(10_000_000)-GasRouteLookup, remaining,
		"route lookup consumes exactly its flat fee, success or failure")
	if err == nil {
		require.NotEmpty(t, out)
		require.Equal(t, byte(1), out[0], "a best-route answer carries exactly one result")
		require.Len(t, out, 1+73, "one result is 73 bytes after the count byte")
	}

	for cut := 0; cut < 72; cut++ {
		require.NotPanicsf(t, func() {
			_, _, err := c.Run(h.state, h.caller, addr,
				append(selectorBytes(SelectorGetBestRoute), body[:cut]...), 10_000_000, true)
			require.Errorf(t, err, "a %d-byte body must be refused", cut)
		}, "a %d-byte body must not panic", cut)
	}
}

// TestTickSpacingForFeeIsTotal: every fee tier maps to a spacing, and an unknown
// tier falls back to the standard one rather than returning zero — a zero spacing
// would divide by zero in Compress.
func TestTickSpacingForFeeIsTotal(t *testing.T) {
	require.Equal(t, TickSpacing001, tickSpacingForFee(Fee001))
	require.Equal(t, TickSpacing005, tickSpacingForFee(Fee005))
	require.Equal(t, TickSpacing030, tickSpacingForFee(Fee030))
	require.Equal(t, TickSpacing100, tickSpacingForFee(Fee100))

	// Any unrecognised tier must still yield a NON-ZERO spacing: Compress and
	// FlipTick take `tick % tickSpacing`, so a zero here is a division-by-zero panic.
	for _, fee := range []uint24{0, 1, 7, 999, 2999, 3001, FeeMax, 1 << 20} {
		got := tickSpacingForFee(fee)
		require.Equalf(t, TickSpacing030, got, "fee %d must fall back to the standard spacing", fee)
		require.NotZerof(t, got, "fee %d must never map to a zero spacing (Compress divides by it)", fee)
	}
}

// TestAbsInt returns a magnitude without aliasing its argument. Returning the same
// pointer would let a caller mutate the original through the result.
func TestAbsInt(t *testing.T) {
	for _, v := range []int64{0, 1, -1, 1 << 40, -(1 << 40)} {
		in := big.NewInt(v)
		out := absInt(in)
		require.Equal(t, 0, out.CmpAbs(in), "absInt must preserve magnitude")
		require.GreaterOrEqual(t, out.Sign(), 0, "absInt must never be negative")

		// The result must be a COPY: mutating it must not disturb the input.
		before := new(big.Int).Set(in)
		out.Add(out, big.NewInt(1))
		require.Equal(t, 0, before.Cmp(in), "absInt must not alias its argument")
	}
}

// TestExactOutputDecodersAreBoundsSafe covers the two exact-output decoders. They
// are EXPORTED API with no internal caller today (the exact-output selectors revert
// PRECOMPILE_MOVED), so they are tested as a public contract: whatever a downstream
// client feeds them, they must refuse rather than read past the end.
func TestExactOutputDecodersAreBoundsSafe(t *testing.T) {
	// ExactOutputSingle: tokenIn(20)+tokenOut(20)+amountOut(32)+amountInMax(32)+fee(3) = 107
	single := make([]byte, 0, 170)
	single = append(single, common.HexToAddress("0x11").Bytes()...)
	single = append(single, common.HexToAddress("0x22").Bytes()...)
	out := make([]byte, 32)
	big.NewInt(1_000).FillBytes(out)
	single = append(single, out...)
	inMax := make([]byte, 32)
	big.NewInt(2_000).FillBytes(inMax)
	single = append(single, inMax...)
	single = append(single, 0x00, 0x0B, 0xB8)

	p, err := DecodeExactOutputSingleParams(single)
	require.NoError(t, err)
	require.Equal(t, int64(1_000), p.AmountOut.Int64())
	require.Equal(t, int64(2_000), p.AmountInMaximum.Int64())
	require.Equal(t, uint32(3000), p.Fee)

	for cut := 0; cut < 107; cut++ {
		require.NotPanicsf(t, func() {
			_, err := DecodeExactOutputSingleParams(single[:cut])
			require.Errorf(t, err, "a %d-byte body must be refused", cut)
		}, "a %d-byte body must not panic", cut)
	}

	// ExactOutput, simple format: a token list, amountOut, amountInMax.
	simple := []byte{3}
	for i := range 3 {
		var a common.Address
		a[19] = byte(i + 1)
		simple = append(simple, a.Bytes()...)
	}
	simple = append(simple, out...)
	simple = append(simple, inMax...)
	simple = append(simple, make([]byte, 8)...)

	mp, err := DecodeExactOutputParams(simple)
	require.NoError(t, err)
	require.Len(t, mp.Path, 3)

	for cut := 0; cut < len(simple)-8; cut++ {
		require.NotPanicsf(t, func() {
			_, err := DecodeExactOutputParams(simple[:cut])
			require.Errorf(t, err, "a %d-byte body must be refused", cut)
		}, "a %d-byte body must not panic", cut)
	}

	// V4 format with a pathLen beyond the buffer must be refused, not read past.
	v4 := []byte{0xFF, 0x00, 0x00}
	binary.BigEndian.PutUint16(v4[1:3], 60000)
	require.NotPanics(t, func() {
		_, err := DecodeExactOutputParams(v4)
		require.Error(t, err)
	})
	_, err = DecodeExactOutputParams(nil)
	require.Error(t, err)
	_, err = DecodeExactOutputParams([]byte{0xFF})
	require.Error(t, err)
}

// TestEncodeSwapResultIsFixedWidth: 33 bytes, amount then venue. Exported API with
// no internal caller today; pinned so a downstream decoder cannot silently drift.
func TestEncodeSwapResultIsFixedWidth(t *testing.T) {
	for _, v := range []SwapVenue{VenueV4Native, VenueV3, VenueV2, VenueExternal} {
		enc := EncodeSwapResult(big.NewInt(0x1234), v)
		require.Len(t, enc, 33)
		require.Equal(t, 0, new(big.Int).SetBytes(enc[0:32]).Cmp(big.NewInt(0x1234)))
		require.Equal(t, byte(v), enc[32], "the venue is the trailing byte")
	}
	// A zero amount still encodes a full word, never a short buffer.
	require.Equal(t, append(make([]byte, 32), byte(VenueV3)), EncodeSwapResult(big.NewInt(0), VenueV3))
}
