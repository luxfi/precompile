// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// quote_direction_test.go pins the direction of the 0x9998 projection. The eight
// quote selectors ask one of two questions — given an input, what output does it
// buy; given a desired output, what input does it cost — and the two answers are
// inverses of the same price-and-fee map, not the same number.
//
// The exact-output side rounds UP at every step. A quote of what a taker must
// supply may overstate by a unit; understating it is a quote the taker cannot
// fill.

// qdMarket is a market at price = sqrtP^2 / 2^192 with the given fee in pips.
func qdMarket(priceSqrtMultiple int64, fee uint24) MarketRecord {
	return vpMarket(new(big.Int).Lsh(big.NewInt(priceSqrtMultiple), 96), fee)
}

// TestExactOutputAsksTheOtherQuestion is the defect: at any price other than 1 the
// input needed to buy N is not the output that N buys, so a projection that ignores
// the direction answers the wrong question with a confident number.
func TestExactOutputAsksTheOtherQuestion(t *testing.T) {
	// sqrtP = 2*2^96 => price 4: one token0 buys four token1.
	rec := qdMarket(2, 0)
	want := big.NewInt(1_000)

	in := projectSingleTick(rec, want, true /*zeroForOne*/, false /*exactOut*/)
	if in.Int64() != 250 {
		t.Fatalf("input to buy 1000 token1 at price 4 = %s, want 250", in)
	}
	out := projectSingleTick(rec, want, true, true /*exactIn*/)
	if out.Int64() != 4_000 {
		t.Fatalf("output bought by 1000 token0 at price 4 = %s, want 4000", out)
	}
	if in.Cmp(out) == 0 {
		t.Fatal("the exact-output projection returned the exact-input answer")
	}

	// The other direction inverts: one token1 buys a quarter of a token0.
	in = projectSingleTick(rec, want, false /*oneForZero*/, false)
	if in.Int64() != 4_000 {
		t.Fatalf("input to buy 1000 token0 at price 4 = %s, want 4000", in)
	}
}

// TestExactOutputCoversTheOutputItQuotes is the property that matters: feeding the
// quoted input back through the exact-input projection must buy at least the output
// that was asked for. A round trip that comes up short is a quote that cannot fill.
func TestExactOutputCoversTheOutputItQuotes(t *testing.T) {
	for _, fee := range []uint24{0, 500, 3_000, 10_000, FeeMax} {
		for _, mult := range []int64{1, 2, 3, 7, 1_000} {
			rec := qdMarket(mult, fee)
			for _, zeroForOne := range []bool{true, false} {
				for _, want := range []int64{1, 2, 7, 999, 1_000, 1_000_001} {
					wantOut := big.NewInt(want)
					in := projectSingleTick(rec, wantOut, zeroForOne, false)
					got := projectSingleTick(rec, in, zeroForOne, true)
					if got.Cmp(wantOut) < 0 {
						t.Fatalf("fee=%d price=%d^2 zeroForOne=%v: quoted input %s buys %s, short of the %s asked for",
							fee, mult, zeroForOne, in, got, wantOut)
					}
					// And it must not be wasteful: one unit less must come up short,
					// which pins the rounding to the smallest covering input.
					if in.Sign() > 0 {
						less := new(big.Int).Sub(in, big.NewInt(1))
						if projectSingleTick(rec, less, zeroForOne, true).Cmp(wantOut) >= 0 {
							t.Fatalf("fee=%d price=%d^2 zeroForOne=%v: quoted input %s for %s is one above the smallest that covers it",
								fee, mult, zeroForOne, in, wantOut)
						}
					}
				}
			}
		}
	}
}

// TestExactInputProjectionIsUnchanged pins that adding the inverse did not move the
// exact-input answer. Every existing caller reads that number.
func TestExactInputProjectionIsUnchanged(t *testing.T) {
	for _, fee := range []uint24{0, 3_000, FeeMax} {
		for _, mult := range []int64{1, 2, 5} {
			rec := qdMarket(mult, fee)
			for _, zeroForOne := range []bool{true, false} {
				amount := big.NewInt(1_000_000)
				if got, want := projectSingleTick(rec, amount, zeroForOne, true), spotOutputFeeAdjusted(rec, amount, zeroForOne); got.Cmp(want) != 0 {
					t.Fatalf("fee=%d price=%d^2 zeroForOne=%v: exact-input projection = %s, want the unchanged %s",
						fee, mult, zeroForOne, got, want)
				}
			}
		}
	}
}

// TestPricelessMarketQuotesZeroInBothDirections pins the degenerate market: a record
// with no registered price cannot answer either question, and must answer 0 rather
// than divide by it.
func TestPricelessMarketQuotesZeroInBothDirections(t *testing.T) {
	for _, rec := range []MarketRecord{
		{SqrtPriceX96: nil, Fee: 3_000, Status: MarketStatusActive},
		{SqrtPriceX96: big.NewInt(0), Fee: 3_000, Status: MarketStatusActive},
	} {
		for _, zeroForOne := range []bool{true, false} {
			for _, exactIn := range []bool{true, false} {
				if got := projectSingleTick(rec, big.NewInt(1_000), zeroForOne, exactIn); got.Sign() != 0 {
					t.Fatalf("priceless market quoted %s (zeroForOne=%v exactIn=%v), want 0", got, zeroForOne, exactIn)
				}
			}
		}
	}
}

// TestQuoterDispatchesTheDirection pins the wiring: the exact-output selectors must
// reach the exact-output projection through the real Run, not just in isolation.
func TestQuoterDispatchesTheDirection(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	q := &QuoterContract{}
	addr := common.HexToAddress(DEXQuoterAddress)
	amount := big.NewInt(1_000_000)

	read := func(sel uint32) *big.Int {
		t.Helper()
		out, _, err := q.Run(h.state, h.caller, addr, quoteCalldata(sel, h.key, amount, true), 5_000_000, true)
		if err != nil {
			t.Fatalf("selector %#x: %v", sel, err)
		}
		return new(big.Int).SetBytes(out)
	}

	rec := loadMarket(readOnlyView{state: h.state}, h.key.ID())
	if got, want := read(SelQExactInput), projectSingleTick(rec, amount, true, true); got.Cmp(want) != 0 {
		t.Fatalf("exactInput selector = %s, want %s", got, want)
	}
	for _, sel := range []uint32{SelQExactOutput, SelQExactOutputSingle} {
		if got, want := read(sel), projectSingleTick(rec, amount, true, false); got.Cmp(want) != 0 {
			t.Fatalf("selector %#x = %s, want the exact-output projection %s", sel, got, want)
		}
	}
}
