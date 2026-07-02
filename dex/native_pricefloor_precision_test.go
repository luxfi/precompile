// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// exactFloorRef is an INDEPENDENT exact-rational reference for the settlement price floor,
// computed straight from the definition with big.Rat (no float64 on the amounts). The
// priceLimit is a fixed-point ×priceScale integer, so limit = priceLimit / priceScale. The
// production enforceProceedsPriceFloor must agree with it for every amount, including the
// uint256 range above 2^53 where a float64 reconstruction would truncate.
func exactFloorRef(priceLimit uint64, limitIsUpper bool, spent, out uint64) bool /*reject*/ {
	if priceLimit == 0 {
		return false
	}
	if spent == 0 || out == 0 {
		return true
	}
	limitRat := new(big.Rat).SetFrac(
		new(big.Int).SetUint64(priceLimit),
		big.NewInt(priceScale),
	) // limit = priceLimit / priceScale
	if limitIsUpper {
		// BUY ceiling: realized quote/base = spent/out must be <= limit.
		realized := new(big.Rat).SetFrac(
			new(big.Int).SetUint64(spent),
			new(big.Int).SetUint64(out),
		)
		return realized.Cmp(limitRat) > 0 // reject if spent/out > limit
	}
	// SELL floor: realized out/spent must be >= limit.
	realized := new(big.Rat).SetFrac(
		new(big.Int).SetUint64(out),
		new(big.Int).SetUint64(spent),
	)
	return realized.Cmp(limitRat) < 0 // reject if out/spent < limit
}

// TestPriceFloor_Exact_Above2Pow53 is the regression for the consensus hazard: spent/out
// are uint256-domain token amounts, and the OLD float64 reconstruction (float64(spent),
// float64(out)) silently truncated their low bits above 2^53 — so a fill strictly BELOW
// the taker's floor compared EQUAL and was accepted (the precise MEV the floor refuses).
//
// limit == 1.0, SELL: floor demands out/spent >= 1, i.e. out >= spent. With spent = 2^53+1
// and out = 2^53 the realized price is BELOW the floor and MUST be rejected. float64 maps
// both 2^53 and 2^53+1 to the double 2^53, so the old code saw out == spent and PASSED.
func TestPriceFloor_Exact_Above2Pow53(t *testing.T) {
	one := uint64(priceScale) // limit 1.0 on the fixed-point grid
	const p53 = uint64(1) << 53

	// SELL floor: out just under spent past the float64 cliff -> must REJECT.
	require.ErrorIs(t,
		enforceProceedsPriceFloor(one, false, p53+1, p53),
		ErrSettlePriceLimit,
		"SELL: out(2^53) < spent(2^53+1) is below the floor and must be rejected exactly")

	// BUY ceiling: spent just over out past the float64 cliff -> must REJECT.
	require.ErrorIs(t,
		enforceProceedsPriceFloor(one, true, p53+1, p53),
		ErrSettlePriceLimit,
		"BUY: spent(2^53+1) > out(2^53) is above the ceiling and must be rejected exactly")

	// Exactly on the floor (out == spent, limit 1.0) is allowed on both sides.
	require.NoError(t, enforceProceedsPriceFloor(one, false, p53+1, p53+1))
	require.NoError(t, enforceProceedsPriceFloor(one, true, p53+1, p53+1))
}

// TestPriceFloor_MatchesExactReferenceSweep cross-checks the production verdict against the
// independent big.Rat reference across small values AND values straddling 2^53, proving the
// comparison is exact everywhere (and deterministic — pure integer arithmetic).
func TestPriceFloor_MatchesExactReferenceSweep(t *testing.T) {
	limits := []float64{0.5, 1.0, 2.0, 1.25, 3.333333333}
	const p53 = uint64(1) << 53
	amounts := []uint64{
		1, 2, 7, 1_000_000, 1e15,
		p53 - 1, p53, p53 + 1, p53 + 2, p53 + 3,
		2 * p53, 2*p53 + 1, math.MaxUint64 / 2, math.MaxUint64 - 1,
	}
	for _, lf := range limits {
		lb := uint64(lf * priceScale) // the fixed-point ×priceScale grid limit
		for _, upper := range []bool{false, true} {
			for _, spent := range amounts {
				for _, out := range amounts {
					wantReject := exactFloorRef(lb, upper, spent, out)
					got := enforceProceedsPriceFloor(lb, upper, spent, out)
					if wantReject {
						require.ErrorIsf(t, got, ErrSettlePriceLimit,
							"limit=%v upper=%v spent=%d out=%d: expected reject", lf, upper, spent, out)
					} else {
						require.NoErrorf(t, got,
							"limit=%v upper=%v spent=%d out=%d: expected pass", lf, upper, spent, out)
					}
				}
			}
		}
	}
}

// TestPriceFloor_EdgeCasesPreserved locks the fail-secure edges unchanged by the rewrite.
func TestPriceFloor_EdgeCasesPreserved(t *testing.T) {
	one := uint64(priceScale) // limit 1.0 on the fixed-point grid
	// No recorded limit -> no floor.
	require.NoError(t, enforceProceedsPriceFloor(0, false, 100, 50))
	// Limit set but an amount is zero -> price unprovable -> fail secure.
	require.ErrorIs(t, enforceProceedsPriceFloor(one, false, 0, 50), ErrSettlePriceLimit)
	require.ErrorIs(t, enforceProceedsPriceFloor(one, false, 50, 0), ErrSettlePriceLimit)
	// A large integer limit is a REAL floor (no float degeneracy): a SELL realized below it
	// is rejected, one at/above it passes — exact on the fixed-point grid.
	big5 := uint64(5 * priceScale)
	require.ErrorIs(t, enforceProceedsPriceFloor(big5, false, 100, 400), ErrSettlePriceLimit) // 4.0 < 5.0
	require.NoError(t, enforceProceedsPriceFloor(big5, false, 100, 500))                       // 5.0 == 5.0
}
