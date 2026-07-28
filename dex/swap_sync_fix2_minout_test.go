// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	dexcore "github.com/luxfi/dex/pkg/dex"
	lx "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
)

// swap_sync_fix2_minout_test.go is the FIX-2 RED suite for the min-out / max-in slippage
// floor on the 0x9999 value path. It proves a user-provided floor is required on EVERY
// value route and is ENFORCED on the realized AGGREGATE (CLOB, AMM, split): exact-input
// amountOut >= minAmountOut, and a no-limit market SELL with no floor is refused outright.
// No value route may rely on a default-zero floor.
//
// Every test runs the REAL 0x9999 Run dispatch over the real EVM/vault/atomic harness with
// real ERC-20 balances and real registry admission (no stubs). Token layout: LETH =
// currency0 (base), LUSD = currency1 (quote); "sell LETH for LUSD" is zeroForOne.

// swapWithMinOut drives a real sync swap with an explicit DM01 min-out floor. It builds the
// calldata directly (the harness h.swap passes empty hookData) and drives it through the
// EVM atomicity boundary so a floor breach is observably atomic.
func swapWithMinOut(t *testing.T, h *e2eHarness, taker common.Address, zeroForOne bool, amountIn int64, minOut uint64) ([]byte, error) {
	t.Helper()
	params := SwapParams{ZeroForOne: zeroForOne, AmountSpecified: big.NewInt(-amountIn), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(minOut))
	out, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	return out, err
}

// Test9999SwapRequiresMinOut: a no-limit market SELL with NEITHER a price limit NOR a
// min-out floor is REFUSED on the value path (the unbounded-slippage SELL hazard). This is
// the SELL-side mirror of the BUY's ErrBuyRequiresLimit.
func Test9999SwapRequiresMinOut(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// A real maker bid exists (so liquidity is present — the refusal is the POLICY, not a
	// lack of depth).
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)

	h.mint(e2eLETH, taker, 80)
	takerLETHBefore := h.ercBal(e2eLETH, taker)

	// A market SELL with NO price limit (sqrtLimit 0) and NO min-out (TRULY empty hookData) ->
	// the value path refuses it. We build the calldata directly with empty hookData to
	// exercise the unprotected case (the h.swap helper auto-injects a minimal floor for its
	// conservation tests; here we deliberately omit ALL protection).
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, nil) // empty hookData -> no floor, no limit
	out, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, ErrSellRequiresProtection) {
		t.Fatalf("a no-limit market SELL with no min-out must revert ErrSellRequiresProtection, got: %v (out=%x)", err, out)
	}
	// Fail-closed: nothing moved.
	if got := h.ercBal(e2eLETH, taker); got != takerLETHBefore {
		t.Fatalf("a refused unprotected SELL must not move the taker's balance: %d -> %d", takerLETHBefore, got)
	}

	// A SELL WITH a price limit (and no min-out) IS protected — it must NOT be refused by the
	// policy (the limit floors the price). Prove the policy is precise, not over-broad: with a
	// price floor at 50 the swap clears the policy (it then fills or reverts on liquidity, not
	// on the protection policy).
	sqrtLimited := sqrtPriceForFloor(50)
	pLimited := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: sqrtLimited}
	cLimited := buildSwapCalldata(h.key, pLimited, nil)
	if _, _, e := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, cLimited), 5_000_000, false); errors.Is(e, ErrSellRequiresProtection) {
		t.Fatalf("a SELL WITH a price limit must NOT be refused by the SELL-protection policy, got: %v", e)
	}
}

// Test9999SwapRevertsBelowMinOut: a SELL whose realized proceeds are BELOW the declared
// min-out reverts (and rolls back atomically). The maker's price yields 4000 LUSD for 80
// LETH; a min-out of 5000 cannot be met, so the swap reverts.
func Test9999SwapRevertsBelowMinOut(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100) // BID 100 LETH @ 50

	h.mint(e2eLETH, taker, 80)
	takerLETHBefore := h.ercBal(e2eLETH, taker)
	makerLockedBefore := h.dcLocked(maker, e2eLUSD)

	// SELL 80 LETH with a min-out of 5000 LUSD. The fill at 50 yields only 4000 < 5000 -> revert.
	_, err := swapWithMinOut(t, h, taker, true, 80, 5000)
	if !errors.Is(err, dexcore.ErrPriceLimit) {
		t.Fatalf("a SELL whose proceeds (4000) are below the min-out (5000) must revert ErrPriceLimit, got: %v", err)
	}
	// ATOMIC ROLLBACK: neither the taker's LETH nor the maker's lock moved.
	if got := h.ercBal(e2eLETH, taker); got != takerLETHBefore {
		t.Fatalf("taker LETH moved on a min-out-breached swap: %d -> %d", takerLETHBefore, got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 0 {
		t.Fatalf("taker received LUSD on a min-out-breached swap: %d", got)
	}
	if got := h.dcLocked(maker, e2eLUSD); got != makerLockedBefore {
		t.Fatalf("maker lock changed on a min-out-breached swap: %d -> %d", makerLockedBefore, got)
	}
}

// Test9999BestExecCannotWorsenUserFloor: best-execution may improve the price but can NEVER
// settle below the user's floor. A min-out exactly equal to the best achievable proceeds
// succeeds; one unit higher (unachievable) reverts — the floor is the hard boundary the
// router cannot cross even while optimizing.
func Test9999BestExecCannotWorsenUserFloor(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100) // best proceeds for 80 LETH = 4000

	// (a) min-out exactly at the achievable proceeds (4000) -> succeeds.
	h.mint(e2eLETH, taker, 80)
	out, err := swapWithMinOut(t, h, taker, true, 80, 4000)
	if err != nil {
		t.Fatalf("a SELL with min-out exactly at the achievable proceeds (4000) must succeed: %v", err)
	}
	a0, a1 := UnpackBalanceDelta(out)
	if a0.Int64() != -80 || a1.Int64() != 4000 {
		t.Fatalf("realized legs = (%s,%s), want (-80,4000)", a0, a1)
	}

	// (b) a fresh swap with min-out ONE unit above the best achievable (4001) -> reverts. The
	// router cannot fabricate the extra unit even with best-exec.
	h2 := newE2EHarness(t)
	h2.mint(e2eLUSD, maker, 5000)
	h2.deposit(t, maker, e2eLUSD, 5000)
	h2.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h2.mint(e2eLETH, taker, 80)
	if _, err := swapWithMinOut(t, h2, taker, true, 80, 4001); !errors.Is(err, dexcore.ErrPriceLimit) {
		t.Fatalf("a SELL whose floor (4001) exceeds the best achievable (4000) must revert ErrPriceLimit, got: %v", err)
	}
}

// Test9999SplitRouteRespectsAggregateMinOut: when the input is split across two maker
// bids at different prices, the min-out is enforced on the AGGREGATE proceeds, not per-leg.
// A floor at the achievable aggregate succeeds; above it reverts.
func Test9999SplitRouteRespectsAggregateMinOut(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// Two bids: 40 LETH @ 50 (=2000 LUSD) and 40 LETH @ 48 (=1920 LUSD). Selling 80 LETH
	// sweeps both -> aggregate proceeds = 3920 LUSD across the split.
	h.mint(e2eLUSD, maker, 10000)
	h.deposit(t, maker, e2eLUSD, 10000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 40) // best bid first
	h.placeArgs(t, maker, true, 48*uint64(priceMultiplierConst), 40) // worse bid

	h.mint(e2eLETH, taker, 80)
	// Aggregate floor at 3920 (the true achievable across the split) -> succeeds.
	out, err := swapWithMinOut(t, h, taker, true, 80, 3920)
	if err != nil {
		t.Fatalf("a split SELL with min-out at the achievable aggregate (3920) must succeed: %v", err)
	}
	_, a1 := UnpackBalanceDelta(out)
	if a1.Int64() != 3920 {
		t.Fatalf("aggregate proceeds across the split = %s, want 3920", a1)
	}

	// A floor ABOVE the aggregate (3921) on a fresh swap -> reverts.
	h2 := newE2EHarness(t)
	h2.mint(e2eLUSD, maker, 10000)
	h2.deposit(t, maker, e2eLUSD, 10000)
	h2.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 40)
	h2.placeArgs(t, maker, true, 48*uint64(priceMultiplierConst), 40)
	h2.mint(e2eLETH, taker, 80)
	if _, err := swapWithMinOut(t, h2, taker, true, 80, 3921); !errors.Is(err, dexcore.ErrPriceLimit) {
		t.Fatalf("a split SELL whose floor (3921) exceeds the aggregate (3920) must revert ErrPriceLimit, got: %v", err)
	}
}

// Test9999AMMFallbackRespectsMinOut: when the CLOB has no depth and the swap falls through
// to the AMM, the min-out floor still bites on the AMM-realized proceeds. We seed a real,
// vault-backed AMM pool (the same setup the AMM e2e uses) and assert a floor ABOVE the AMM
// curve output reverts, while one exactly AT it succeeds.
func Test9999AMMFallbackRespectsMinOut(t *testing.T) {
	const baseR, quoteR = uint64(100_000), uint64(5_000_000)
	const amountIn = int64(100)
	ammOut := lx.ConstantProductOut(baseR, quoteR, uint64(amountIn)) // the deterministic curve output

	// (a) Floor exactly at the AMM output -> succeeds.
	h := newE2EHarness(t)
	taker := e2eTaker
	seedAMMReserves(t, h, h.key.ID(), baseR, quoteR)
	seedVaultReserve(t, h, e2eLUSD, int64(quoteR)) // back the AMM proceeds (no-mint conservation)
	h.mint(e2eLETH, taker, amountIn)
	out, err := swapWithMinOut(t, h, taker, true, amountIn, ammOut)
	if err != nil {
		t.Fatalf("an AMM-routed SELL with min-out exactly at the curve output (%d) must succeed: %v", ammOut, err)
	}
	_, a1 := UnpackBalanceDelta(out)
	if uint64(a1.Int64()) != ammOut {
		t.Fatalf("AMM realized proceeds = %s, want %d", a1, ammOut)
	}

	// (b) Floor ONE above the AMM output -> reverts (the floor bites the AMM leg).
	h2 := newE2EHarness(t)
	seedAMMReserves(t, h2, h2.key.ID(), baseR, quoteR)
	seedVaultReserve(t, h2, e2eLUSD, int64(quoteR))
	h2.mint(e2eLETH, taker, amountIn)
	if _, err := swapWithMinOut(t, h2, taker, true, amountIn, ammOut+1); !errors.Is(err, dexcore.ErrPriceLimit) {
		t.Fatalf("an AMM-routed SELL whose floor (%d) exceeds the curve output (%d) must revert ErrPriceLimit, got: %v", ammOut+1, ammOut, err)
	}
}

// Test9999SyncRouterRejectsExactOutput: the synchronous value router is exact-input only;
// an exact-output swap (positive amountSpecified) is REFUSED rather than silently routed as
// exact-input with no floor (which would be the unprotected case FIX-2 forbids).
func Test9999SyncRouterRejectsExactOutput(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
	h.mint(e2eLETH, taker, 80)

	// POSITIVE AmountSpecified = V4 exact-output. The sync router must refuse it.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(4000), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, ErrExactOutputNotSupported) {
		t.Fatalf("an exact-output swap on the sync router must revert ErrExactOutputNotSupported, got: %v", err)
	}
}

// Test9999CLOBRouteRespectsMinOut: the primary CLOB route enforces the min-out on its
// realized proceeds. A floor at the CLOB fill succeeds; above it reverts.
func Test9999CLOBRouteRespectsMinOut(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// A deep CLOB bid: 200 LETH @ 50. Selling 80 fills entirely on the CLOB -> 4000 LUSD.
	h.mint(e2eLUSD, maker, 10000)
	h.deposit(t, maker, e2eLUSD, 10000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 200)

	h.mint(e2eLETH, taker, 80)
	out, err := swapWithMinOut(t, h, taker, true, 80, 4000) // floor at the CLOB fill
	if err != nil {
		t.Fatalf("a CLOB SELL with min-out at the realized fill (4000) must succeed: %v", err)
	}
	_, a1 := UnpackBalanceDelta(out)
	if a1.Int64() != 4000 {
		t.Fatalf("CLOB proceeds = %s, want 4000", a1)
	}

	// Above the CLOB fill -> reverts.
	h2 := newE2EHarness(t)
	h2.mint(e2eLUSD, maker, 10000)
	h2.deposit(t, maker, e2eLUSD, 10000)
	h2.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 200)
	h2.mint(e2eLETH, taker, 80)
	if _, err := swapWithMinOut(t, h2, taker, true, 80, 4001); !errors.Is(err, dexcore.ErrPriceLimit) {
		t.Fatalf("a CLOB SELL whose floor (4001) exceeds the fill (4000) must revert ErrPriceLimit, got: %v", err)
	}
}
