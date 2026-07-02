// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// pricelimitPoolKey is a minimal valid V4 pool: currency0 native, currency1 a token.
func pricelimitPoolKey() PoolKey {
	return PoolKey{
		Currency0:   Currency{Address: common.Address{}},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
}

// native_pricelimit_test.go proves the MEDIUM slippage-floor plumbing: the V4
// SqrtPriceLimitX96 is converted to the CLOB price domain (quote-per-base float64) and
// carried into the C->D intent with the correct DIRECTION, so the dexvm settle path can
// refuse a fill worse than the taker's limit (bounded sandwich/MEV). Pre-fix the native
// exact-input path DROPPED SqrtPriceLimitX96 entirely and carried no floor.

// sqrtX96For returns floor(sqrt(price) * 2^96) for a target quote-per-base price — the
// V4 SqrtPriceLimitX96 a client would pass to bound the swap at `price`.
func sqrtX96For(price float64) *big.Int {
	// sqrt(price) * 2^96, computed in big.Float for range.
	s := new(big.Float).Sqrt(big.NewFloat(price))
	s.Mul(s, new(big.Float).SetInt(new(big.Int).Lsh(big.NewInt(1), 96)))
	out, _ := s.Int(nil)
	return out
}

// TestPriceLimitToCLOB_ConvertsAndOrientsLimit pins the sqrt->CLOB conversion and the
// BUY-ceiling / SELL-floor direction.
func TestPriceLimitToCLOB_ConvertsAndOrientsLimit(t *testing.T) {
	// A !zeroForOne swap (BUY base with quote) at limit price 2.0 quote/base => an UPPER
	// bound (never pay more than 2 per base).
	buy := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-1000), SqrtPriceLimitX96: sqrtX96For(2.0)}
	units, isUpper := priceLimitToCLOB(buy)
	if !isUpper {
		t.Fatalf("a !zeroForOne (BUY) limit must be an UPPER bound (ceiling)")
	}
	// The limit is a fixed-point ×priceScale integer; recover the human price by /priceScale.
	if got := float64(units) / priceScale; math.Abs(got-2.0) > 1e-6 {
		t.Fatalf("BUY price limit = %g, want ~2.0 (from sqrtX96(2.0))", got)
	}

	// A zeroForOne swap (SELL base for quote) at limit price 2.0 => a LOWER bound (never
	// receive less than 2 per base).
	sell := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-1000), SqrtPriceLimitX96: sqrtX96For(2.0)}
	units2, isUpper2 := priceLimitToCLOB(sell)
	if isUpper2 {
		t.Fatalf("a zeroForOne (SELL) limit must be a LOWER bound (floor)")
	}
	if got := float64(units2) / priceScale; math.Abs(got-2.0) > 1e-6 {
		t.Fatalf("SELL price limit = %g, want ~2.0", got)
	}
}

// TestPriceLimitToCLOB_SentinelsAreUnbounded pins that the V4 "no limit" sentinels (and
// an unset limit) map to 0 = no floor, preserving the unbounded behavior.
func TestPriceLimitToCLOB_SentinelsAreUnbounded(t *testing.T) {
	// zeroForOne with the MinSqrtRatio sentinel => no limit.
	sell := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-1), SqrtPriceLimitX96: new(big.Int).Set(MinSqrtRatio)}
	if units, _ := priceLimitToCLOB(sell); units != 0 {
		t.Fatalf("zeroForOne MinSqrtRatio sentinel must mean no limit (0), got units=%d", units)
	}
	// !zeroForOne with the MaxSqrtRatio sentinel => no limit.
	buy := SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-1), SqrtPriceLimitX96: new(big.Int).Set(MaxSqrtRatio)}
	if units, _ := priceLimitToCLOB(buy); units != 0 {
		t.Fatalf("!zeroForOne MaxSqrtRatio sentinel must mean no limit (0), got units=%d", units)
	}
	// Unset (nil) => no limit.
	if units, _ := priceLimitToCLOB(SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-1)}); units != 0 {
		t.Fatalf("unset SqrtPriceLimitX96 must mean no limit (0), got units=%d", units)
	}
}

// TestBuildIntentRequest_CarriesPriceLimit proves the V4 swap's slippage floor flows
// into the C->D intent (previously DROPPED). A !zeroForOne exact-input swap at limit
// price 3.0 must produce an intent carrying the CLOB limit (~3.0) as an UPPER bound.
func TestBuildIntentRequest_CarriesPriceLimit(t *testing.T) {
	key := pricelimitPoolKey()
	params := SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-1000), // exact input
		SqrtPriceLimitX96: sqrtX96For(3.0),
	}
	caller := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	req, err := buildIntentRequest(key, params, caller, 0, 7)
	if err != nil {
		t.Fatalf("buildIntentRequest: %v", err)
	}
	if req.PriceLimit == 0 {
		t.Fatalf("MEDIUM NOT FIXED: buildIntentRequest dropped the slippage floor (PriceLimit=0) for a swap " +
			"carrying a real SqrtPriceLimitX96.")
	}
	if !req.LimitIsUpper {
		t.Fatalf("a !zeroForOne (BUY) intent must carry an UPPER price bound")
	}
	if got := float64(req.PriceLimit) / priceScale; math.Abs(got-3.0) > 1e-6 {
		t.Fatalf("intent price limit = %g, want ~3.0", got)
	}
	// The nonce flows through too (the watch-correlation binding).
	if req.Nonce != 7 {
		t.Fatalf("intent nonce = %d, want 7", req.Nonce)
	}
}
