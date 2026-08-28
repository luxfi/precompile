// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/precompile/contract"
)

// zznarrow_engine_test.go covers the narrowings that are NOT at a decode
// boundary: values computed inside the leverage, fee and repayment engines that
// were then squeezed into a machine integer.
//
// These differ from the decoder cases in one way that matters. A decoder
// narrowing substitutes a value; these narrow INSIDE the comparison that is
// supposed to bound the value, so the check does not merely miss — it inverts.
// A position at 2^64 times the leverage ceiling read as leverage zero, which is
// the safest number in the range.

// TestZznMarginCeilingHoldsAtFullWidth drives UpdatePositionMargin to a leverage
// past uint64 and confirms the removal is refused.
//
// notional = Size*MarkPrice/Q96, and leverage = notional/newMargin. With
// MarkPrice = Q96 the notional is the size, so a size of 2^64 against a margin
// of 1 is a leverage of exactly 2^64 — whose low word is zero, and zero is below
// every ceiling.
func TestZznMarginCeilingHoldsAtFullWidth(t *testing.T) {
	me, acct := zzlMarginEngine(t, IsolatedMargin, 1e18)

	size := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64
	pos := &MarginPosition{
		MarketID:   zzlMarket,
		Side:       Long,
		Size:       new(big.Int).Set(size),
		EntryPrice: new(big.Int).Set(Q96),
		MarkPrice:  new(big.Int).Set(Q96),
		// Start at 2 so removing 1 leaves 1, making the quotient exactly 2^64.
		Margin:        big.NewInt(2),
		UnrealizedPnL: big.NewInt(0),
		RealizedPnL:   big.NewInt(0),
		IsIsolated:    true,
		Leverage:      1,
	}
	acct.Positions[zzlMarket] = pos

	// The fixture is the whole point: the true leverage must be exactly the value
	// whose low word is zero, or the test proves nothing about the narrowing.
	notional := new(big.Int).Div(new(big.Int).Mul(size, Q96), Q96)
	trueLev := new(big.Int).Div(notional, big.NewInt(1))
	if trueLev.Cmp(new(big.Int).Lsh(big.NewInt(1), 64)) != 0 {
		t.Fatalf("fixture: true leverage is %s, want exactly 2^64", trueLev)
	}
	if trueLev.Uint64() != 0 {
		t.Fatalf("fixture: 2^64 narrows to %d, want 0", trueLev.Uint64())
	}
	if uint64(acct.MaxLeverage) == 0 {
		t.Fatal("fixture: MaxLeverage is zero, so the comparison is vacuous")
	}

	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, big.NewInt(-1)); !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("a margin removal to 2^64x leverage was admitted: %v", err)
	}
	if pos.Margin.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("a refused removal still moved the margin to %s", pos.Margin)
	}

	// The boundary in the other direction: a removal that lands exactly ON the
	// ceiling is admitted, so the guard is a bound and not a blanket refusal.
	pos.Size = new(big.Int).Mul(big.NewInt(int64(acct.MaxLeverage)), big.NewInt(2))
	pos.Margin = big.NewInt(3)
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, big.NewInt(-1)); err != nil {
		t.Fatalf("a removal to exactly the ceiling was refused: %v", err)
	}
	if pos.Margin.Cmp(big.NewInt(2)) != 0 {
		t.Fatalf("margin = %s, want 2", pos.Margin)
	}
}

// TestZznIncreasePositionLeverageFitsItsField covers the other margin site, where
// the quotient is not compared but ASSIGNED — to a uint32 field that then sets
// the liquidation price. A wrapped value there gives the position most in need
// of liquidating the liquidation price of a safe one.
func TestZznIncreasePositionLeverageFitsItsField(t *testing.T) {
	me, acct := zzlMarginEngine(t, IsolatedMargin, 1e18)

	// existing.Size + incoming.Size, times MarkPrice/Q96, over the summed margin.
	// 2^32 exactly, whose low 32 bits are zero.
	existing := &MarginPosition{
		MarketID:   zzlMarket,
		Side:       Long,
		Size:       new(big.Int).Lsh(big.NewInt(1), 32),
		EntryPrice: new(big.Int).Set(Q96),
		MarkPrice:  new(big.Int).Set(Q96),
		Margin:     big.NewInt(1),
		Leverage:   1,
	}
	incoming := &MarginPosition{
		MarketID:   zzlMarket,
		Side:       Long,
		Size:       big.NewInt(0),
		EntryPrice: new(big.Int).Set(Q96),
		MarkPrice:  new(big.Int).Set(Q96),
		Margin:     big.NewInt(0),
	}
	if got := uint32(new(big.Int).Lsh(big.NewInt(1), 32).Uint64()); got != 0 {
		t.Fatalf("fixture: uint32(2^32) = %d, want 0", got)
	}

	if _, err := me.increasePosition(acct, existing, incoming); !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("a leverage of 2^32 was written into a uint32 field: %v", err)
	}

	// One below the field's width is assigned faithfully.
	existing.Size = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 32), big.NewInt(1))
	existing.Margin = big.NewInt(1)
	got, err := me.increasePosition(acct, existing, incoming)
	if err != nil {
		t.Fatalf("the largest leverage the field can hold was refused: %v", err)
	}
	if got.Leverage != 1<<32-1 {
		t.Fatalf("Leverage = %d, want 2^32-1", got.Leverage)
	}
}

// TestZznRepaymentHorizonSaturates covers the third engine site. The horizon is
// read as "how long until this debt clears", so a wrap turns a debt that will
// never realistically clear into one clearing within a few blocks.
func TestZznRepaymentHorizonSaturates(t *testing.T) {
	// A yield rate of 1 against a collateral of 1e18 gives a yield of exactly one
	// unit per block, so the horizon in blocks IS the debt and the fixture can name
	// the boundary directly.
	horizon := func(t *testing.T, debt *big.Int) uint64 {
		t.Helper()
		q := zzcrNewVault(t, big.NewInt(1), zzcrCeiling())
		if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
			t.Fatalf("Deposit: %v", err)
		}
		acc := q.account(t, zzcrBorrower)
		if acc.Collateral.Cmp(zzcrE18()) != 0 {
			t.Fatalf("fixture: collateral is %s, want 1e18", acc.Collateral)
		}
		acc.Debt = new(big.Int).Set(debt)
		acc.AccruedYield = big.NewInt(0)
		return q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok)
	}

	// A debt of exactly 2^64 is 2^64 blocks — low word zero, and zero is the
	// answer this function gives for "already repaid".
	debt := new(big.Int).Lsh(big.NewInt(1), 64)
	if debt.Uint64() != 0 {
		t.Fatalf("fixture: (2^64).Uint64() = %d, want 0", debt.Uint64())
	}
	if got := horizon(t, debt); got != ^uint64(0) {
		t.Fatalf("horizon at 2^64 blocks = %d, want saturation at 2^64-1", got)
	}

	// The largest horizon that fits is reported exactly. It happens to equal the
	// saturation value, so it cannot tell the two paths apart on its own — the
	// ordinary case below is what does that, and without it this test would pass
	// against a function that answered 2^64-1 for everything.
	if got := horizon(t, new(big.Int).Sub(debt, big.NewInt(1))); got != ^uint64(0) {
		t.Fatalf("horizon at 2^64-1 blocks = %d, want 2^64-1", got)
	}
	if got := horizon(t, big.NewInt(500)); got != 500 {
		t.Fatalf("horizon at 500 blocks = %d, want 500", got)
	}
}

// TestZznModifyLiquidityTicksAreBoundedAtTheirWidth covers the V4 decoder that
// DecodeSwapInput's sibling uses. Same shape as decodePMLifecycle, separate
// function, and therefore a separate bound to keep honest.
func TestZznModifyLiquidityTicksAreBoundedAtTheirWidth(t *testing.T) {
	build := func(lower, upper *big.Int) []byte {
		data := make([]byte, 0, 288)
		data = append(data, zznKey(big.NewInt(3000), big.NewInt(60))[:160]...)
		data = append(data, zznWord(lower)...)
		data = append(data, zznWord(upper)...)
		data = append(data, zznWord(big.NewInt(1))...) // liquidityDelta
		data = append(data, zznWord(big.NewInt(0))...) // salt
		return contract.Poisoned(data, 1024)
	}

	key, params, _, err := DecodeModifyLiquidityInput(build(big.NewInt(-(1 << 23)), big.NewInt(1<<23-1)))
	if err != nil {
		t.Fatalf("the int24 extremes were refused: %v", err)
	}
	if params.TickLower != -(1<<23) || params.TickUpper != 1<<23-1 {
		t.Fatalf("ticks = (%d, %d), want the int24 extremes", params.TickLower, params.TickUpper)
	}
	if key.Fee != 3000 {
		t.Fatalf("Fee = %d, want 3000", key.Fee)
	}

	for _, wide := range []*big.Int{
		zznPow2(23),
		new(big.Int).Add(zznPow2(24), big.NewInt(6)),
		new(big.Int).Add(zznPow2(32), big.NewInt(6)), // used to arrive as 6
		new(big.Int).Neg(new(big.Int).Add(zznPow2(23), big.NewInt(1))),
		zznPow2(200),
	} {
		if _, got, _, err := DecodeModifyLiquidityInput(build(wide, big.NewInt(60))); !errors.Is(err, ErrInvalidTick) {
			t.Fatalf("tickLower %s admitted as %d: %v", wide, got.TickLower, err)
		}
		if _, got, _, err := DecodeModifyLiquidityInput(build(big.NewInt(-60), wide)); !errors.Is(err, ErrInvalidTick) {
			t.Fatalf("tickUpper %s admitted as %d: %v", wide, got.TickUpper, err)
		}
	}
}
