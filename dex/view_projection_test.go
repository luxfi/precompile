// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// The 0x9998 quote projections and the 0x9997 view encoders are advisory, but they
// are ALSO the numbers a router or a front-end sizes a real trade from. The two
// properties that matter are DETERMINISM (a view that probes a live per-node engine
// would diverge between validators) and HONESTY about what is being reported (a
// projected reference must never be dressed up as book depth).

func vpMarket(sqrtPrice *big.Int, fee uint24) MarketRecord {
	return MarketRecord{SqrtPriceX96: sqrtPrice, Fee: fee, Status: MarketStatusActive}
}

// TestSpotOutputIsDirectional: token0->token1 multiplies by the price, the reverse
// divides. Getting this backwards inverts every quote the router reads.
func TestSpotOutputIsDirectional(t *testing.T) {
	// sqrtP = 2*2^96 => price = 4.
	sqrtP := new(big.Int).Lsh(big.NewInt(2), 96)
	rec := vpMarket(sqrtP, 0)
	amount := big.NewInt(1_000_000)

	out01 := spotOutput(rec, amount, true)
	require.Equal(t, int64(4_000_000), out01.Int64(), "token0->token1 multiplies by the price")

	out10 := spotOutput(rec, amount, false)
	require.Equal(t, int64(250_000), out10.Int64(), "token1->token0 divides by the price")

	// The two directions are inverses up to flooring: round-tripping can never gain.
	back := spotOutput(rec, out01, false)
	require.LessOrEqual(t, back.Cmp(amount), 0,
		"a spot round trip must never return more than it started with")

	// An uninitialized or zero price projects nothing rather than dividing by zero.
	for _, bad := range []*big.Int{nil, big.NewInt(0)} {
		require.NotPanics(t, func() {
			require.Zero(t, spotOutput(vpMarket(bad, 0), amount, true).Sign())
			require.Zero(t, spotOutput(vpMarket(bad, 0), amount, false).Sign())
		}, "a market with no price must project zero, not divide by zero")
	}

	// A zero amount projects zero in both directions.
	require.Zero(t, spotOutput(rec, big.NewInt(0), true).Sign())
	require.Zero(t, spotOutput(rec, big.NewInt(0), false).Sign())
}

// TestFeeOnInputRoundsTowardTheLP: the LP fee is amount*feePips/1e6 floored, and the
// fee-adjusted projection must always be no better than the fee-free one. A quote
// that forgot the fee would over-promise the trader on every hop.
func TestFeeOnInputRoundsTowardTheLP(t *testing.T) {
	require.Zero(t, feeOnInput(big.NewInt(1_000_000), 0).Sign(), "a zero-fee pool charges nothing")
	require.Equal(t, int64(3_000), feeOnInput(big.NewInt(1_000_000), 3000).Int64(), "0.3% of 1e6")
	require.Equal(t, int64(0), feeOnInput(big.NewInt(1), 3000).Int64(),
		"a fee below one wei floors to zero — it must never round up into the trader's balance")

	// The fee is monotonic in the fee tier, and never exceeds the input.
	prev := big.NewInt(-1)
	for _, pips := range []uint24{0, 100, 500, 3000, 10000, FeeMax} {
		f := feeOnInput(big.NewInt(1_000_000_000), pips)
		require.GreaterOrEqual(t, f.Cmp(prev), 0, "fee must not decrease with the tier")
		require.LessOrEqual(t, f.Cmp(big.NewInt(1_000_000_000)), 0, "fee must never exceed the input")
		prev = f
	}

	// The fee-adjusted projection is never better than the fee-free one.
	sqrtP := new(big.Int).Lsh(big.NewInt(1), 96)
	amount := big.NewInt(1_000_000)
	for _, pips := range []uint24{0, 500, 3000, FeeMax} {
		rec := vpMarket(sqrtP, pips)
		gross := spotOutput(rec, amount, true)
		net := spotOutputFeeAdjusted(rec, amount, true)
		require.LessOrEqualf(t, net.Cmp(gross), 0,
			"fee tier %d: the fee-adjusted quote must not exceed the fee-free one", pips)
		if pips > 0 {
			require.Lessf(t, net.Cmp(gross), 0, "fee tier %d must actually cost the trader", pips)
		}
	}
}

// TestEngineProjectionsAreDeterministicAndHonest: these three helpers deliberately
// report a C-side reference rather than probing a live per-node engine, because a
// live probe would return different values on different validators and fork
// consensus. Determinism is the property; `fromBook=false` is the honesty flag that
// stops the reference being mistaken for real depth.
func TestEngineProjectionsAreDeterministicAndHonest(t *testing.T) {
	sqrtP := new(big.Int).Lsh(big.NewInt(2), 96)
	rec := vpMarket(sqrtP, 3000)

	require.Zero(t, engineLiquidity(rec).Sign(),
		"the C registry holds no AMM liquidity; reporting a number would be a fabrication")

	base, quote, fromBook := engineDepth(rec)
	require.Zero(t, base.Sign())
	require.Zero(t, quote.Sign())
	require.False(t, fromBook, "C-side depth is not book depth and must say so")

	bid, ask, fromBook := engineBestBidAsk(rec)
	require.False(t, fromBook, "a projected spot is not a book quote and must say so")
	require.Equal(t, 0, bid.Cmp(ask), "the projection is a single spot, not a real spread")
	require.Positive(t, bid.Sign(), "an initialized market must project a positive spot")

	// price = 4, scaled to 1e18.
	require.Equal(t, 0, bid.Cmp(new(big.Int).Mul(big.NewInt(4), big.NewInt(1e18))),
		"the spot must be (sqrtP/2^96)^2 scaled to 1e18")

	// A market with no price projects zeroes rather than dividing by zero.
	for _, bad := range []*big.Int{nil, big.NewInt(0)} {
		b, a, fb := engineBestBidAsk(vpMarket(bad, 3000))
		require.Zero(t, b.Sign())
		require.Zero(t, a.Sign())
		require.False(t, fb)
	}

	// DETERMINISM: repeated calls on the same record must be byte-identical. A live
	// engine probe here would be a consensus fork.
	for range 50 {
		b2, a2, f2 := engineBestBidAsk(rec)
		require.Equal(t, 0, b2.Cmp(bid))
		require.Equal(t, 0, a2.Cmp(ask))
		require.False(t, f2)
	}
}

// TestQuoteEncodersPackExactlyTwoWords: every multi-value quote result is two ABI
// words. A short or misaligned encoding would be decoded as a different number by
// the calling contract.
func TestQuoteEncodersPackExactlyTwoWords(t *testing.T) {
	a := big.NewInt(0x1234)
	b := big.NewInt(0x5678)

	two := encodeTwoWords(a, b)
	require.Len(t, two, 64)
	require.Equal(t, 0, new(big.Int).SetBytes(two[0:32]).Cmp(a))
	require.Equal(t, 0, new(big.Int).SetBytes(two[32:64]).Cmp(b))

	// nil and zero encode as a zero word, never as a short buffer.
	require.Equal(t, make([]byte, 64), encodeTwoWords(nil, nil))
	require.Equal(t, make([]byte, 64), encodeTwoWords(big.NewInt(0), big.NewInt(0)))

	wb := encodeWordAndBool(a, true)
	require.Len(t, wb, 64)
	require.Equal(t, 0, new(big.Int).SetBytes(wb[0:32]).Cmp(a))
	require.Equal(t, byte(1), wb[63], "a true flag is the last byte of the second word")

	wb = encodeWordAndBool(a, false)
	require.Equal(t, byte(0), wb[63], "a false flag must clear the byte")
	require.Equal(t, make([]byte, 32), wb[32:64], "the flag word must be zero apart from the flag")

	require.Equal(t, make([]byte, 64), encodeWordAndBool(nil, false))
	require.Equal(t, byte(1), encodeWordAndBool(nil, true)[63])
}

// TestQuoteModesAllAnswerAndAreDeterministic drives every quoter selector against a
// live registered market and asserts two things: each mode returns a well-formed
// result, and repeated calls return byte-identical bytes. A quote that varied
// between calls would vary between validators.
func TestQuoteModesAllAnswerAndAreDeterministic(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t) // a LIVE market, so each mode returns a real quote
	q := &QuoterContract{}
	addr := common.HexToAddress(DEXQuoterAddress)

	modes := map[string]uint32{
		"exactInput":       SelQExactInput,
		"exactInputSingle": SelQExactInputSingle,
		"exactOutput":      SelQExactOutput,
		"againstBook":      SelQAgainstBook,
		"withDepth":        SelQWithDepth,
		"withFees":         SelQWithFees,
		"withSlippage":     SelQWithSlippage,
	}
	for name, sel := range modes {
		t.Run(name, func(t *testing.T) {
			in := append(selectorBytes(sel), quoteBody(h.key, big.NewInt(1_000_000), true)...)
			first, gas1, err1 := q.Run(h.state, h.caller, addr, in, 10_000_000, true)
			if err1 != nil {
				// A mode may legitimately refuse (no market depth); it must do so
				// deterministically too.
				second, gas2, err2 := q.Run(h.state, h.caller, addr, in, 10_000_000, true)
				require.Equal(t, err1.Error(), err2.Error(), "a refusal must be deterministic")
				require.Equal(t, gas1, gas2)
				require.Equal(t, first, second)
				return
			}
			require.NotEmpty(t, first, "a successful quote must return a result")
			require.Zero(t, len(first)%32, "a quote result must be whole ABI words")

			for range 20 {
				again, gas2, err2 := q.Run(h.state, h.caller, addr, in, 10_000_000, true)
				require.NoError(t, err2)
				require.Equal(t, first, again, "a quote must be byte-identical across calls")
				require.Equal(t, gas1, gas2, "a quote must cost the same every time")
			}
		})
	}
}

// TestStateViewSelectorsAnswerOrRefuseDeterministically drives every 0x9997 view
// against a live market. Each must either answer with whole ABI words or refuse —
// and do the same thing every time, for the same consensus reason as above.
func TestStateViewSelectorsAnswerOrRefuseDeterministically(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t) // a LIVE market, so the success paths are exercised, not just the refusals
	v := &StateViewContract{}
	addr := common.HexToAddress(DEXStateViewAddress)
	poolID := h.key.ID()
	id32 := make([]byte, 32)
	copy(id32, poolID[:])

	byKey := map[string]uint32{"getPool": SelectorGetPool, "getPoolId": SelectorGetPoolId}
	byID := map[string]uint32{
		"getSlot0":         SelectorGetSlot0,
		"getLiquidity":     SelectorGetLiquidity,
		"getMarket":        SelectorGetMarket,
		"getBestBidAsk":    SelectorGetBestBidAsk,
		"getReceiptStatus": SelectorGetReceiptStatus,
		"getHaltStatus":    SelectorGetHaltStatus,
		"getPosition":      SelectorGetPosition,
	}

	check := func(t *testing.T, name string, in []byte) {
		t.Helper()
		first, gas1, err1 := v.Run(h.state, h.caller, addr, in, 10_000_000, true)
		for range 10 {
			again, gas2, err2 := v.Run(h.state, h.caller, addr, in, 10_000_000, true)
			require.Equalf(t, err1 == nil, err2 == nil, "%s: refusal must be deterministic", name)
			require.Equalf(t, first, again, "%s: result must be byte-identical across calls", name)
			require.Equalf(t, gas1, gas2, "%s: cost must be identical across calls", name)
		}
		if err1 == nil {
			require.Zerof(t, len(first)%32, "%s: a view result must be whole ABI words", name)
		}
	}

	for name, sel := range byKey {
		t.Run(name, func(t *testing.T) {
			check(t, name, append(selectorBytes(sel), EncodePoolKeyABI(h.key)...))
		})
	}
	for name, sel := range byID {
		t.Run(name, func(t *testing.T) {
			check(t, name, append(selectorBytes(sel), id32...))
		})
	}
	t.Run("getDepth", func(t *testing.T) {
		body := append(append([]byte{}, id32...), make([]byte, 32)...)
		check(t, "getDepth", append(selectorBytes(SelectorGetDepth), body...))
	})
	t.Run("getOpenOrders", func(t *testing.T) {
		owner := make([]byte, 32)
		copy(owner[12:], h.caller.Bytes())
		check(t, "getOpenOrders", append(selectorBytes(SelectorGetOpenOrders), owner...))
	})
}

// TestStateViewRefusesUnregisteredMarket: a view for a market that was never opened
// must refuse, not return an all-zero record that reads as a real empty pool.
func TestStateViewRefusesUnregisteredMarket(t *testing.T) {
	h := newSettleHarness(t)
	v := &StateViewContract{}
	addr := common.HexToAddress(DEXStateViewAddress)

	unknown := make([]byte, 32)
	unknown[0] = 0xde

	for name, sel := range map[string]uint32{
		"getMarket": SelectorGetMarket,
		"getSlot0":  SelectorGetSlot0,
	} {
		_, _, err := v.Run(h.state, h.caller, addr, append(selectorBytes(sel), unknown...), 10_000_000, true)
		require.Errorf(t, err, "%s for an unregistered market must be refused", name)
	}

	// A PoolKey that was never initialized is refused the same way.
	other := h.key
	other.Fee = 999
	_, _, err := v.Run(h.state, h.caller, addr,
		append(selectorBytes(SelectorGetPool), EncodePoolKeyABI(other)...), 10_000_000, true)
	require.Error(t, err, "getPool for an unregistered key must be refused")
}

// TestGetPoolIdMatchesTheKeyID: the id a caller reads back must be the id the
// settle path derives, or every subsequent by-id call addresses a different pool.
func TestGetPoolIdMatchesTheKeyID(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	v := &StateViewContract{}
	addr := common.HexToAddress(DEXStateViewAddress)

	out, _, err := v.Run(h.state, h.caller, addr,
		append(selectorBytes(SelectorGetPoolId), EncodePoolKeyABI(h.key)...), 10_000_000, true)
	require.NoError(t, err)
	require.Len(t, out, 32)

	want := h.key.ID()
	require.Equal(t, want[:], out, "getPoolId must return the canonical PoolKey.ID()")

	// Changing any one field of the key must change the id — otherwise two distinct
	// pools would share state.
	base := h.key
	variants := map[string]PoolKey{
		"currency0":   {Currency0: Currency{Address: common.HexToAddress("0xAA")}, Currency1: base.Currency1, Fee: base.Fee, TickSpacing: base.TickSpacing, Hooks: base.Hooks},
		"currency1":   {Currency0: base.Currency0, Currency1: Currency{Address: common.HexToAddress("0xBB")}, Fee: base.Fee, TickSpacing: base.TickSpacing, Hooks: base.Hooks},
		"fee":         {Currency0: base.Currency0, Currency1: base.Currency1, Fee: base.Fee + 1, TickSpacing: base.TickSpacing, Hooks: base.Hooks},
		"tickSpacing": {Currency0: base.Currency0, Currency1: base.Currency1, Fee: base.Fee, TickSpacing: base.TickSpacing + 1, Hooks: base.Hooks},
		"hooks":       {Currency0: base.Currency0, Currency1: base.Currency1, Fee: base.Fee, TickSpacing: base.TickSpacing, Hooks: common.HexToAddress("0xCC")},
	}
	for field, k := range variants {
		got := k.ID()
		require.NotEqualf(t, want, got,
			"changing %s must change the pool id: a field the id ignores is a pool-state collision", field)
	}
}

// TestPoolKeyIDIsStableAndCollisionFree sweeps the id derivation: the same key
// always yields the same id (determinism), and distinct keys never collide.
// Deterministic seed 31337 — fixed so a failure reproduces exactly.
func TestPoolKeyIDIsStableAndCollisionFree(t *testing.T) {
	const seed = 31337
	r := rand.New(rand.NewSource(seed))
	seen := map[[32]byte]PoolKey{}

	for range 4000 {
		var c0, c1, hooks common.Address
		r.Read(c0[:])
		r.Read(c1[:])
		r.Read(hooks[:])
		k := PoolKey{
			Currency0:   Currency{Address: c0},
			Currency1:   Currency{Address: c1},
			Fee:         uint24(r.Intn(int(FeeMax) + 1)),
			TickSpacing: int32(r.Intn(2000) - 1000),
			Hooks:       hooks,
		}
		id := k.ID()

		// Determinism: the same key must derive the same id every time.
		require.Equalf(t, id, k.ID(), "seed=%d PoolKey.ID must be deterministic", seed)

		if prev, dup := seen[id]; dup {
			require.Equalf(t, prev, k, "seed=%d two DIFFERENT keys derived the same id", seed)
		}
		seen[id] = k
	}
	require.Greater(t, len(seen), 3900, "the sweep must have produced mostly distinct ids")
}
