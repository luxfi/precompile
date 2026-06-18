// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math"
	"math/big"
	"testing"
)

// =========================================================================
// RED (debit != credit): the C-Chain taker delta and the cross-chain proxy
// credit settle the SAME fill stream and so MUST round by the SAME rule.
//
// The proxy leg (chains/dexvm settleFromFills) rounds a quantity the taker
// RECEIVES DOWN (quantToCredit / floor) and a quantity the taker OWES UP
// (quantToCharge / ceil). Before the fix the precompile leg (fillsToDelta) used
// math.Round on BOTH legs, so a fractional notional that the proxy floored to 4
// the precompile rounded to 5 (and vice-versa) — a per-fill mint/burn the
// attacker steers by choosing fill sizes whose fractional notional rounds in
// their favor. These tests pin fillsToDelta to the proxy's exact policy.
// =========================================================================

// proxyCredit mirrors chains/dexvm atomic.go quantToCredit (FLOOR) EXACTLY: a
// quantity the taker RECEIVES. Kept inline (the two modules don't import each
// other) so this test is the byte-for-byte parity oracle for the proxy leg.
func proxyCredit(f float64) uint64 {
	r := math.Round(f)
	if math.Abs(f-r) <= 1e-9*math.Max(1, math.Abs(f)) {
		f = r
	} else {
		f = math.Floor(f)
	}
	return uint64(f)
}

// proxyCharge mirrors chains/dexvm atomic.go quantToCharge (CEIL) EXACTLY: a
// quantity the taker OWES against locked escrow.
func proxyCharge(f float64) uint64 {
	r := math.Round(f)
	if math.Abs(f-r) <= 1e-9*math.Max(1, math.Abs(f)) {
		f = r
	} else {
		f = math.Ceil(f)
	}
	return uint64(f)
}

// TestRoundingHelpersMatchProxyPolicy asserts the precompile's directional
// rounding helpers are byte-identical to the proxy's quantToCredit/quantToCharge
// across the integral, just-under, just-over, half, and epsilon-noisy cases. If
// these ever diverge, the two settlement legs diverge — which is the finding.
func TestRoundingHelpersMatchProxyPolicy(t *testing.T) {
	cases := []float64{
		0, 1, 4, 4.0, 4.4, 4.5, 4.6, 4.9, 5,
		0.99, 99.0, 100.5, 1234.4999, 1234.5001,
		12 + 1e-13, 12 - 1e-13, // mathematically-integral aggregate with FP noise
		3*1.5 + 3*2.5,          // == 12 exactly in spirit; FP may wobble
	}
	for _, f := range cases {
		// floorToBig == quantToCredit (received leg).
		if got, want := floorToBig(f), new(big.Int).SetUint64(proxyCredit(f)); got.Cmp(want) != 0 {
			t.Errorf("floorToBig(%v) = %s, proxy quantToCredit = %s (legs diverge on RECEIVED)", f, got, want)
		}
		// ceilToBig == quantToCharge (owed leg).
		if got, want := ceilToBig(f), new(big.Int).SetUint64(proxyCharge(f)); got.Cmp(want) != 0 {
			t.Errorf("ceilToBig(%v) = %s, proxy quantToCharge = %s (legs diverge on OWED)", f, got, want)
		}
	}
}

// TestFillsToDelta_PoC_NoMintNoBurn replays the finding's exact proof-of-concept
// fill streams through fillsToDelta and asserts the C-Chain taker delta now
// rounds in the SAME conservation-safe direction the proxy credits — so the two
// legs agree to the unit and the attacker can neither mint nor burn.
func TestFillsToDelta_PoC_NoMintNoBurn(t *testing.T) {
	// A BUY (!zeroForOne): taker RECEIVES base (floor), OWES quote (ceil).
	// PoC notional 4.5: pre-fix the precompile round(4.5)=5 while the proxy
	// floored received and ceiled owed. Post-fix both legs ceil the OWED quote.
	t.Run("buy notional 4.5 owes ceil(=5)", func(t *testing.T) {
		// price*size = 4.5; base = 1 (integral, floors to 1).
		fills := []fill{{price: 4.5, size: 1}}
		d, err := fillsToDelta(false, fills)
		if err != nil {
			t.Fatal(err)
		}
		// taker receives base: Amount0 = -floor(1) = -1.
		if d.Amount0.Cmp(big.NewInt(-1)) != 0 {
			t.Fatalf("Amount0 = %s, want -1 (received base floored)", d.Amount0)
		}
		// taker owes quote: Amount1 = +ceil(4.5) = +5 == proxy quantToCharge(4.5).
		if want := new(big.Int).SetUint64(proxyCharge(4.5)); d.Amount1.Cmp(want) != 0 {
			t.Fatalf("Amount1 = %s, want %s (owed quote MUST match proxy charge)", d.Amount1, want)
		}
	})

	// Reverse the fraction (<0.5): pre-fix round(4.4)=4 UNDER-charged the taker
	// while the proxy ceiled to 5 — the taker was MINTED 1 quote unit across the
	// two legs. Post-fix both ceil to 5: no mint.
	t.Run("buy notional 4.4 owes ceil(=5) not round(=4)", func(t *testing.T) {
		fills := []fill{{price: 4.4, size: 1}}
		d, err := fillsToDelta(false, fills)
		if err != nil {
			t.Fatal(err)
		}
		if d.Amount1.Cmp(big.NewInt(5)) != 0 {
			t.Fatalf("Amount1 = %s, want 5 (ceil); round-to-nearest would mint a unit", d.Amount1)
		}
		if want := new(big.Int).SetUint64(proxyCharge(4.4)); d.Amount1.Cmp(want) != 0 {
			t.Fatalf("Amount1 = %s != proxy charge %s — legs diverge", d.Amount1, want)
		}
	})

	// A SELL (zeroForOne): taker OWES base (ceil), RECEIVES quote (floor).
	// PoC received-quote 4.6: pre-fix round(4.6)=5 OVER-credited the taker while
	// the proxy floored to 4 — the taker was MINTED 1 quote unit. Post-fix both
	// floor to 4: no mint.
	t.Run("sell received quote 4.6 floors(=4) not round(=5)", func(t *testing.T) {
		// size=1 base, price=4.6 => received quote aggregate 4.6.
		fills := []fill{{price: 4.6, size: 1}}
		d, err := fillsToDelta(true, fills)
		if err != nil {
			t.Fatal(err)
		}
		// taker owes base: Amount0 = +ceil(1) = +1.
		if d.Amount0.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("Amount0 = %s, want +1 (owed base ceiled)", d.Amount0)
		}
		// taker receives quote: Amount1 = -floor(4.6) = -4 == -proxy quantToCredit.
		want := new(big.Int).Neg(new(big.Int).SetUint64(proxyCredit(4.6)))
		if d.Amount1.Cmp(want) != 0 {
			t.Fatalf("Amount1 = %s, want %s (received quote floored to match proxy credit)", d.Amount1, want)
		}
		if d.Amount1.Cmp(big.NewInt(-4)) != 0 {
			t.Fatalf("Amount1 = %s, want -4; round-to-nearest would mint a unit", d.Amount1)
		}
	})
}

// TestFillsToDelta_MultiFillSweep_NoAccumulatedDrift proves the per-fill leak the
// finding describes ("over a multi-fill sweep this accumulates") is gone: the
// engine sums the stream ONCE as exact floats then rounds ONCE at the asset
// boundary, so 100 fills of fractional notional round like their exact aggregate,
// not 100 independent roundings. Both legs (precompile here, proxy in dexvm) use
// this single-aggregate-then-round discipline, so they stay equal at any depth.
func TestFillsToDelta_MultiFillSweep_NoAccumulatedDrift(t *testing.T) {
	// 100 fills, each price 0.99 on size 1 => exact aggregate notional 99.0.
	// Pre-fix per-fill round(0.99)=1 each => 100 (and the proxy's pre-fix per-fill
	// truncate(0.99)=0 each => 0): a 100-unit divergence. Post-fix BOTH compute the
	// exact aggregate 99.0 and round once.
	fills := make([]fill, 100)
	for i := range fills {
		fills[i] = fill{price: 0.99, size: 1}
	}
	d, err := fillsToDelta(false, fills) // BUY: owes quote (ceil of aggregate)
	if err != nil {
		t.Fatal(err)
	}
	// aggregate quote = 99.0 (integral) => ceil = 99, matching proxy charge.
	if d.Amount1.Cmp(big.NewInt(99)) != 0 {
		t.Fatalf("aggregate owed quote = %s, want 99 (single-aggregate rounding)", d.Amount1)
	}
	if want := new(big.Int).SetUint64(proxyCharge(99.0)); d.Amount1.Cmp(want) != 0 {
		t.Fatalf("Amount1 = %s != proxy charge %s — sweep diverges", d.Amount1, want)
	}
	// base aggregate = 100 (integral) => floor = 100; taker receives base.
	if d.Amount0.Cmp(big.NewInt(-100)) != 0 {
		t.Fatalf("aggregate received base = %s, want -100", d.Amount0)
	}
}
