// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzlev_margin_test.go covers dex/margin.go — the cross/isolated/portfolio margin
// engine. margin.go is a pure in-memory engine: it takes no StateDB, so the mock
// StateDB harness (mock_snapshot_test.go, native_harness_test.go) does not apply
// here; those doubles exist for the SettleContract precompile surface.
//
// Every assertion below is stated against the DEFINITION of the quantity under
// test (equity = margin + pnl, required = notional * mm / MarginPrecision, …)
// recomputed independently in the test, never against a copied magic constant.
// Boundaries are located by bisection so the exact comparison operator is pinned.

// ---------------------------------------------------------------------------
// shared helpers (every package-scope name is zzl-prefixed)
// ---------------------------------------------------------------------------

var zzlOwner = common.HexToAddress("0x1111111111111111111111111111111111111111")
var zzlOther = common.HexToAddress("0x2222222222222222222222222222222222222222")
var zzlLiquidator = common.HexToAddress("0x3333333333333333333333333333333333333333")

var zzlAssetA = common.HexToAddress("0x00000000000000000000000000000000000000AA")
var zzlAssetB = common.HexToAddress("0x00000000000000000000000000000000000000BB")

var zzlMarket = [32]byte{0xDE, 0xAD}
var zzlMarket2 = [32]byte{0xBE, 0xEF}

// zzlPx converts a plain integer price into the Q96 fixed-point the engine uses.
func zzlPx(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), Q96) }

// zzlBig is shorthand for a plain big.Int.
func zzlBig(n int64) *big.Int { return big.NewInt(n) }

// zzlPanics reports whether fn panics, returning the recovered value.
func zzlPanics(fn func()) (panicked bool, recovered any) {
	defer func() {
		if r := recover(); r != nil {
			panicked, recovered = true, r
		}
	}()
	fn()
	return false, nil
}

// zzlMarginEngine builds an engine with one account whose CollateralValue (the
// only field calculateTotalEquity reads) is set directly. Nothing in margin.go
// writes CollateralValue — see TestZzlMarginDepositCollateralNeverRaisesEquity.
func zzlMarginEngine(t *testing.T, typ MarginAccountType, collateralValue int64) (*MarginEngine, *MarginAccount) {
	t.Helper()
	me := NewMarginEngine()
	acct, err := me.CreateAccount(zzlOwner, typ)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	acct.CollateralValue = big.NewInt(collateralValue)
	return me, acct
}

// zzlActiveCollateral registers asset as accepted collateral on me.
func zzlActiveCollateral(me *MarginEngine, asset common.Address, active bool) {
	me.CollateralRates[asset] = &CollateralRate{
		Asset:           asset,
		CollateralRatio: big.NewInt(1e18),
		BorrowRate:      big.NewInt(0),
		MaxBorrowable:   big.NewInt(1e18),
		IsActive:        active,
	}
}

// zzlMarginPos builds a MarginPosition directly, bypassing OpenPosition, so the
// pure predicates (isPositionLiquidatable, calculatePnL, …) can be driven to an
// exact boundary without OpenPosition's margin sizing getting in the way.
func zzlMarginPos(side PositionSide, size, entry, margin *big.Int) *MarginPosition {
	return &MarginPosition{
		MarketID:      zzlMarket,
		Side:          side,
		Size:          new(big.Int).Set(size),
		EntryPrice:    new(big.Int).Set(entry),
		MarkPrice:     new(big.Int).Set(entry),
		Margin:        new(big.Int).Set(margin),
		UnrealizedPnL: big.NewInt(0),
		RealizedPnL:   big.NewInt(0),
		Leverage:      10,
	}
}

// zzlEquityAndRequired recomputes, from the definitions in the doc comments of
// margin.go, the two sides of the liquidation comparison. The test never trusts
// the implementation to tell it what the answer is.
func zzlEquityAndRequired(pos *MarginPosition, price *big.Int, mm uint32) (equity, required *big.Int) {
	diff := new(big.Int).Sub(price, pos.EntryPrice)
	pnl := new(big.Int).Mul(pos.Size, diff)
	pnl.Div(pnl, Q96)
	if pos.Side == Short {
		pnl.Neg(pnl)
	}
	equity = new(big.Int).Add(pos.Margin, pnl)

	notional := new(big.Int).Mul(pos.Size, price)
	notional.Div(notional, Q96)
	required = new(big.Int).Mul(notional, big.NewInt(int64(mm)))
	required.Div(required, big.NewInt(MarginPrecision))
	return equity, required
}

// zzlBisect returns the smallest price in [lo,hi] for which pred is true,
// assuming pred is monotone false→true over the interval.
func zzlBisect(lo, hi *big.Int, pred func(*big.Int) bool) *big.Int {
	l, h := new(big.Int).Set(lo), new(big.Int).Set(hi)
	for l.Cmp(h) < 0 {
		mid := new(big.Int).Add(l, h)
		mid.Rsh(mid, 1)
		if pred(mid) {
			h = mid
		} else {
			l = new(big.Int).Add(mid, big.NewInt(1))
		}
	}
	return l
}

// ---------------------------------------------------------------------------
// account lifecycle
// ---------------------------------------------------------------------------

func TestZzlMarginCreateAccountLeverageCeilingPerType(t *testing.T) {
	// The max leverage an account may ever ask for is fixed by its type at
	// creation and is the ONLY ceiling OpenPosition enforces.
	for _, tc := range []struct {
		name string
		typ  MarginAccountType
		want uint32
	}{
		{"cross", CrossMargin, DefaultMaxLeverage},
		{"isolated", IsolatedMargin, IsolatedMaxLeverage},
		{"portfolio", PortfolioMargin, PortfolioMaxLeverage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			me := NewMarginEngine()
			acct, err := me.CreateAccount(zzlOwner, tc.typ)
			if err != nil {
				t.Fatalf("CreateAccount: %v", err)
			}
			if acct.MaxLeverage != tc.want {
				t.Fatalf("MaxLeverage = %d, want %d", acct.MaxLeverage, tc.want)
			}
			if acct.MaintenanceMargin != DefaultMaintenanceMargin || acct.InitialMargin != DefaultInitialMargin {
				t.Fatalf("margin ratios not defaulted: mm=%d im=%d", acct.MaintenanceMargin, acct.InitialMargin)
			}
			// Ordering invariant: an account may never be required to post less
			// margin to open than it must keep to stay open.
			if acct.InitialMargin < acct.MaintenanceMargin {
				t.Fatalf("initial margin %d < maintenance %d: a position would be liquidatable the instant it opens",
					acct.InitialMargin, acct.MaintenanceMargin)
			}
			// An unknown account type gets zero leverage, i.e. it can open nothing.
			if _, err := me.CreateAccount(zzlOther, MarginAccountType(9)); err != nil {
				t.Fatalf("CreateAccount(unknown type): %v", err)
			}
			if me.Accounts[zzlOther].MaxLeverage != 0 {
				t.Fatalf("unknown account type got leverage %d, want 0", me.Accounts[zzlOther].MaxLeverage)
			}
		})
	}
}

func TestZzlMarginCreateAccountRefusesDuplicate(t *testing.T) {
	me := NewMarginEngine()
	if _, err := me.CreateAccount(zzlOwner, CrossMargin); err != nil {
		t.Fatalf("first CreateAccount: %v", err)
	}
	first := me.Accounts[zzlOwner]
	got, err := me.CreateAccount(zzlOwner, PortfolioMargin)
	if !errors.Is(err, ErrAccountExists) {
		t.Fatalf("duplicate CreateAccount err = %v, want ErrAccountExists", err)
	}
	if got != nil {
		t.Fatal("duplicate CreateAccount returned a non-nil account")
	}
	// The refusal must not have upgraded the existing account's leverage.
	if me.Accounts[zzlOwner] != first || first.MaxLeverage != DefaultMaxLeverage {
		t.Fatal("duplicate CreateAccount mutated the existing account")
	}
}

// ---------------------------------------------------------------------------
// collateral
// ---------------------------------------------------------------------------

func TestZzlMarginDepositCollateralRefusals(t *testing.T) {
	me, _ := zzlMarginEngine(t, CrossMargin, 0)

	if err := me.DepositCollateral(zzlOther, zzlAssetA, zzlBig(100)); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	// Unregistered asset.
	if err := me.DepositCollateral(zzlOwner, zzlAssetA, zzlBig(100)); !errors.Is(err, ErrInvalidCollateral) {
		t.Fatalf("unregistered asset err = %v, want ErrInvalidCollateral", err)
	}
	// Registered but inactive asset.
	zzlActiveCollateral(me, zzlAssetA, false)
	if err := me.DepositCollateral(zzlOwner, zzlAssetA, zzlBig(100)); !errors.Is(err, ErrInvalidCollateral) {
		t.Fatalf("inactive asset err = %v, want ErrInvalidCollateral", err)
	}
	// Nothing was credited by any refusal.
	if me.Accounts[zzlOwner].Collateral[zzlAssetA] != nil {
		t.Fatal("a refused deposit credited collateral")
	}
	if me.TotalCollateral[zzlAssetA] != nil {
		t.Fatal("a refused deposit moved the engine total")
	}
}

func TestZzlMarginDepositAccumulatesAndConservesTotals(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 0)
	zzlActiveCollateral(me, zzlAssetA, true)
	zzlActiveCollateral(me, zzlAssetB, true)

	// Conservation: the engine-wide total for an asset must equal the sum of
	// every account's balance in that asset, after any sequence of deposits.
	deposits := []int64{100, 250, 1}
	for _, d := range deposits {
		if err := me.DepositCollateral(zzlOwner, zzlAssetA, zzlBig(d)); err != nil {
			t.Fatalf("DepositCollateral(%d): %v", d, err)
		}
	}
	want := big.NewInt(0)
	for _, d := range deposits {
		want.Add(want, big.NewInt(d))
	}
	if acct.Collateral[zzlAssetA].Cmp(want) != 0 {
		t.Fatalf("account balance = %s, want %s", acct.Collateral[zzlAssetA], want)
	}
	if me.TotalCollateral[zzlAssetA].Cmp(want) != 0 {
		t.Fatalf("engine total = %s, want %s", me.TotalCollateral[zzlAssetA], want)
	}
	// A second asset is tracked independently.
	if err := me.DepositCollateral(zzlOwner, zzlAssetB, zzlBig(7)); err != nil {
		t.Fatalf("DepositCollateral(B): %v", err)
	}
	if me.TotalCollateral[zzlAssetA].Cmp(want) != 0 {
		t.Fatal("depositing asset B disturbed asset A's total")
	}
	if me.TotalCollateral[zzlAssetB].Cmp(zzlBig(7)) != 0 {
		t.Fatalf("asset B total = %s, want 7", me.TotalCollateral[zzlAssetB])
	}
}

// DEFECT (reported): DepositCollateral credits account.Collateral but never
// account.CollateralValue, which is the ONLY term calculateTotalEquity reads.
// Consequence: depositing collateral does not raise equity, so free margin stays
// at zero and every cross-margin OpenPosition requiring margin > 0 is refused.
func TestZzlMarginDepositCollateralNeverRaisesEquity(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 0)
	zzlActiveCollateral(me, zzlAssetA, true)

	before := me.calculateTotalEquity(acct)
	if err := me.DepositCollateral(zzlOwner, zzlAssetA, zzlBig(1_000_000)); err != nil {
		t.Fatalf("DepositCollateral: %v", err)
	}
	after := me.calculateTotalEquity(acct)
	if after.Cmp(before) != 0 {
		t.Fatalf("equity moved from %s to %s: CollateralValue is now wired to deposits — "+
			"re-check the free-margin path this test pins", before, after)
	}
	if acct.CollateralValue.Sign() != 0 {
		t.Fatalf("CollateralValue = %s, expected the deposit to leave it at 0", acct.CollateralValue)
	}
	// And therefore a cross-margin open of any size is refused despite the deposit.
	_, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("open after depositing 1e6 collateral: err = %v, want ErrInsufficientMargin", err)
	}
}

func TestZzlMarginWithdrawCollateralRefusals(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 0)
	zzlActiveCollateral(me, zzlAssetA, true)
	if err := me.DepositCollateral(zzlOwner, zzlAssetA, zzlBig(100)); err != nil {
		t.Fatalf("DepositCollateral: %v", err)
	}

	if err := me.WithdrawCollateral(zzlOther, zzlAssetA, zzlBig(1)); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	// Asset never deposited: nil balance.
	if err := me.WithdrawCollateral(zzlOwner, zzlAssetB, zzlBig(1)); !errors.Is(err, ErrInsufficientCollateral) {
		t.Fatalf("never-deposited asset err = %v, want ErrInsufficientCollateral", err)
	}
	// One unit over balance is refused; exactly the balance is allowed. That is
	// the boundary that stops a withdrawal from creating collateral.
	if err := me.WithdrawCollateral(zzlOwner, zzlAssetA, zzlBig(101)); !errors.Is(err, ErrInsufficientCollateral) {
		t.Fatalf("over-withdraw err = %v, want ErrInsufficientCollateral", err)
	}
	if acct.Collateral[zzlAssetA].Cmp(zzlBig(100)) != 0 {
		t.Fatal("a refused withdrawal moved the balance")
	}
	if err := me.WithdrawCollateral(zzlOwner, zzlAssetA, zzlBig(100)); err != nil {
		t.Fatalf("exact-balance withdraw: %v", err)
	}
	if acct.Collateral[zzlAssetA].Sign() != 0 || me.TotalCollateral[zzlAssetA].Sign() != 0 {
		t.Fatalf("after full withdraw balance=%s total=%s, want 0/0",
			acct.Collateral[zzlAssetA], me.TotalCollateral[zzlAssetA])
	}
}

// DEFECT (reported): isAccountSafeWithCollateral is `newAmount.Sign() >= 0`, and
// the caller has already proven newAmount >= 0, so the health check is a no-op.
// An account holding open leveraged positions can withdraw ALL of its collateral.
func TestZzlMarginWithdrawIgnoresOpenPositions(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 1_000_000)
	zzlActiveCollateral(me, zzlAssetA, true)
	if err := me.DepositCollateral(zzlOwner, zzlAssetA, zzlBig(500_000)); err != nil {
		t.Fatalf("DepositCollateral: %v", err)
	}
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false); err != nil {
		t.Fatalf("OpenPosition: %v", err)
	}
	if len(acct.Positions) != 1 {
		t.Fatal("expected one open position")
	}
	// The whole collateral balance leaves while the leveraged position stands.
	if err := me.WithdrawCollateral(zzlOwner, zzlAssetA, zzlBig(500_000)); err != nil {
		t.Fatalf("withdraw-all against an open position: %v, want it to succeed "+
			"(this test pins the missing solvency check)", err)
	}
	if acct.Collateral[zzlAssetA].Sign() != 0 {
		t.Fatal("collateral not drained")
	}
	if len(acct.Positions) != 1 {
		t.Fatal("the position vanished; this test is no longer pinning what it claims")
	}
	// isAccountSafeWithCollateral is total over the reachable domain: it is true
	// for every non-negative amount, which is every amount its caller can pass.
	for _, v := range []int64{0, 1, 1 << 40} {
		if !me.isAccountSafeWithCollateral(acct, zzlAssetA, zzlBig(v)) {
			t.Fatalf("isAccountSafeWithCollateral(%d) = false", v)
		}
	}
	if me.isAccountSafeWithCollateral(acct, zzlAssetA, zzlBig(-1)) {
		t.Fatal("isAccountSafeWithCollateral(-1) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// PnL: sign correctness for both sides
// ---------------------------------------------------------------------------

func TestZzlMarginPnLSignIsCorrectForBothSides(t *testing.T) {
	size := zzlBig(1000)
	entry := zzlPx(100)
	me := NewMarginEngine()

	long := zzlMarginPos(Long, size, entry, zzlBig(10_000))
	short := zzlMarginPos(Short, size, entry, zzlBig(10_000))

	up, down := zzlPx(120), zzlPx(80)

	// A long gains when price rises and loses when it falls; a short is the
	// mirror image. Magnitudes must match exactly — the sides are symmetric.
	longUp := me.calculatePnL(long, up, size)
	shortUp := me.calculatePnL(short, up, size)
	longDown := me.calculatePnL(long, down, size)
	shortDown := me.calculatePnL(short, down, size)

	if longUp.Sign() <= 0 {
		t.Fatalf("long PnL on a price rise = %s, want > 0", longUp)
	}
	if shortUp.Sign() >= 0 {
		t.Fatalf("short PnL on a price rise = %s, want < 0", shortUp)
	}
	if longDown.Sign() >= 0 {
		t.Fatalf("long PnL on a price fall = %s, want < 0", longDown)
	}
	if shortDown.Sign() <= 0 {
		t.Fatalf("short PnL on a price fall = %s, want > 0", shortDown)
	}
	if new(big.Int).Add(longUp, shortUp).Sign() != 0 {
		t.Fatalf("long %s and short %s on the same move are not equal and opposite", longUp, shortUp)
	}
	if new(big.Int).Add(longDown, shortDown).Sign() != 0 {
		t.Fatalf("long %s and short %s on the same move are not equal and opposite", longDown, shortDown)
	}
	// At entry the PnL of either side is exactly zero.
	if me.calculatePnL(long, entry, size).Sign() != 0 || me.calculatePnL(short, entry, size).Sign() != 0 {
		t.Fatal("PnL at the entry price is not zero")
	}
	// PnL is linear in size: closing half twice equals closing all at once.
	half := new(big.Int).Div(size, big.NewInt(2))
	twoHalves := new(big.Int).Mul(me.calculatePnL(long, up, half), big.NewInt(2))
	if twoHalves.Cmp(longUp) != 0 {
		t.Fatalf("PnL is not linear in size: 2 * half = %s, whole = %s", twoHalves, longUp)
	}
	// PnL is monotone in price for a long and anti-monotone for a short.
	prev := me.calculatePnL(long, zzlPx(50), size)
	for p := int64(51); p <= 60; p++ {
		cur := me.calculatePnL(long, zzlPx(p), size)
		if cur.Cmp(prev) <= 0 {
			t.Fatalf("long PnL not increasing in price at %d", p)
		}
		if me.calculatePnL(short, zzlPx(p), size).Cmp(me.calculatePnL(short, zzlPx(p-1), size)) >= 0 {
			t.Fatalf("short PnL not decreasing in price at %d", p)
		}
		prev = cur
	}
}

// DEFECT (reported): calculatePnL floors the division and THEN negates for a
// short, which turns the floor into a ceiling on that side. A long's sub-unit
// PnL rounds against the holder in both directions, as it should; a short's
// rounds IN THE HOLDER'S FAVOUR in both directions. A one-wei price move that
// costs a long one unit pays a short one unit out of nowhere.
func TestZzlMarginPnLRoundingIsAsymmetricBetweenSides(t *testing.T) {
	me := NewMarginEngine()
	size := zzlBig(1)
	entry := zzlPx(100)
	long := zzlMarginPos(Long, size, entry, zzlBig(1))
	short := zzlMarginPos(Short, size, entry, zzlBig(1))

	up := new(big.Int).Add(entry, big.NewInt(1))   // +1 wei of Q96 price
	down := new(big.Int).Sub(entry, big.NewInt(1)) // -1 wei

	// The long side is correct: a fractional gain floors to zero, a fractional
	// loss floors away from zero. Both favour the protocol.
	if got := me.calculatePnL(long, up, size); got.Sign() != 0 {
		t.Fatalf("long 1-wei favourable move produced PnL %s, want 0 (floored down)", got)
	}
	if got := me.calculatePnL(long, down, size); got.Cmp(big.NewInt(-1)) != 0 {
		t.Fatalf("long 1-wei adverse move produced PnL %s, want -1 (floored away from zero)", got)
	}

	// The short side is not. Both directions round the short's way.
	favourable := me.calculatePnL(short, down, size)
	if favourable.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("short 1-wei favourable move produced PnL %s, want 1 — the floor-then-negate "+
			"asymmetry was fixed, update the reported finding", favourable)
	}
	adverse := me.calculatePnL(short, up, size)
	if adverse.Sign() != 0 {
		t.Fatalf("short 1-wei adverse move produced PnL %s, want 0", adverse)
	}

	// A matched long/short pair still nets to zero — both sides round the same
	// wei the same way — so this is not a leak in a balanced book.
	for _, p := range []*big.Int{up, down} {
		if sum := new(big.Int).Add(
			me.calculatePnL(long, p, size), me.calculatePnL(short, p, size)); sum.Sign() != 0 {
			t.Fatalf("a matched long/short pair did not net to zero at price %s: %s", p, sum)
		}
	}

	// What it does break is uniformity against the collateral pool, which is the
	// counterparty to every position independently. A book of N shorts each
	// settling a sub-unit favourable move draws N units out of the pool for an
	// obligation that truncates to nothing; N longs in the same situation draw 0.
	shortTake, longTake := big.NewInt(0), big.NewInt(0)
	for i := 0; i < 1000; i++ {
		shortTake.Add(shortTake, me.calculatePnL(short, down, size))
		longTake.Add(longTake, me.calculatePnL(long, up, size))
	}
	if longTake.Sign() != 0 {
		t.Fatalf("1000 sub-unit favourable long settlements paid out %s, want 0", longTake)
	}
	if shortTake.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("1000 sub-unit favourable short settlements paid out %s, want 1000 — the "+
			"floor-then-negate asymmetry was fixed, update the reported finding", shortTake)
	}
}

// ---------------------------------------------------------------------------
// liquidation predicate: exact boundary, one unit either side
// ---------------------------------------------------------------------------

func TestZzlMarginLiquidatableExactlyWhenEquityFallsBelowMaintenance(t *testing.T) {
	me := NewMarginEngine()
	const mm = DefaultMaintenanceMargin

	for _, side := range []PositionSide{Long, Short} {
		name := "long"
		if side == Short {
			name = "short"
		}
		t.Run(name, func(t *testing.T) {
			pos := zzlMarginPos(side, zzlBig(1000), zzlPx(100), zzlBig(5000))

			// A long becomes liquidatable as price FALLS; a short as it RISES. In
			// both cases bisect on the adverse direction, mapping the search
			// variable so the predicate is monotone false→true.
			adverse := func(k *big.Int) *big.Int {
				if side == Long {
					return new(big.Int).Sub(zzlPx(100), k) // k = how far price fell
				}
				return new(big.Int).Add(zzlPx(100), k) // k = how far price rose
			}
			pred := func(k *big.Int) bool {
				return me.isPositionLiquidatable(pos, adverse(k), mm)
			}
			if pred(big.NewInt(0)) {
				t.Fatal("position is liquidatable at its entry price with 5000 margin")
			}
			hi := zzlPx(90) // far enough that the position is certainly under water
			if !pred(hi) {
				t.Fatal("position never becomes liquidatable over the search range")
			}
			k := zzlBisect(big.NewInt(0), hi, pred)
			pBoundary := adverse(k)                               // first liquidatable price
			pSafe := adverse(new(big.Int).Sub(k, big.NewInt(1)))  // one wei better
			pWorse := adverse(new(big.Int).Add(k, big.NewInt(1))) // one wei worse

			// The engine and the independently recomputed definition must agree
			// on all three, and the flip must sit exactly where equity crosses
			// below required — a `<` not a `<=`.
			for _, tc := range []struct {
				label string
				price *big.Int
				want  bool
			}{
				{"one wei better than the boundary", pSafe, false},
				{"the boundary price", pBoundary, true},
				{"one wei worse", pWorse, true},
			} {
				got := me.isPositionLiquidatable(pos, tc.price, mm)
				if got != tc.want {
					t.Fatalf("%s: isPositionLiquidatable = %v, want %v", tc.label, got, tc.want)
				}
				eq, req := zzlEquityAndRequired(pos, tc.price, mm)
				if (eq.Cmp(req) < 0) != tc.want {
					t.Fatalf("%s: definition says equity %s vs required %s, engine says %v",
						tc.label, eq, req, got)
				}
			}
			// The safe side of the boundary must satisfy equity >= required, and
			// the first liquidatable price must be exactly one wei worse.
			eqSafe, reqSafe := zzlEquityAndRequired(pos, pSafe, mm)
			if eqSafe.Cmp(reqSafe) < 0 {
				t.Fatalf("safe boundary is not safe: equity %s < required %s", eqSafe, reqSafe)
			}
			// Adding margin must strictly move the boundary in the holder's favour.
			fatter := zzlMarginPos(side, pos.Size, pos.EntryPrice, new(big.Int).Add(pos.Margin, big.NewInt(1000)))
			if me.isPositionLiquidatable(fatter, pBoundary, mm) {
				t.Fatal("adding margin did not lift the position out of liquidation at the boundary price")
			}
			// Removing margin must strictly worsen it.
			thinner := zzlMarginPos(side, pos.Size, pos.EntryPrice, new(big.Int).Sub(pos.Margin, big.NewInt(1)))
			if !me.isPositionLiquidatable(thinner, pBoundary, mm) {
				t.Fatal("removing margin un-liquidated the position")
			}
			// Margin is monotone in the holder's favour: the liquidatable set
			// can only shrink as margin grows, never the other way round.
			for _, extra := range []int64{0, 1, 10, 1000} {
				fat := zzlMarginPos(side, pos.Size, pos.EntryPrice,
					new(big.Int).Add(pos.Margin, big.NewInt(extra)))
				if !me.isPositionLiquidatable(fat, pBoundary, mm) && extra == 0 {
					t.Fatal("the boundary price is not liquidatable at the base margin")
				}
				if me.isPositionLiquidatable(fat, pSafe, mm) {
					t.Fatalf("margin+%d is liquidatable at a price the base margin survives", extra)
				}
			}
		})
	}
}

func TestZzlMarginLiquidationIsMonotoneInMaintenanceRatio(t *testing.T) {
	// A stricter maintenance ratio can only make MORE positions liquidatable,
	// never fewer. If this ever inverts, the risk parameter is wired backwards.
	me := NewMarginEngine()
	pos := zzlMarginPos(Long, zzlBig(1000), zzlPx(100), zzlBig(5000))
	price := zzlPx(97)
	prev := false
	for _, mm := range []uint32{0, 100, 300, 400, 500, 700, 1000, 5000} {
		got := me.isPositionLiquidatable(pos, price, mm)
		if prev && !got {
			t.Fatalf("mm=%d un-liquidated a position that a laxer ratio liquidated", mm)
		}
		prev = prev || got
	}
	// With a zero maintenance ratio a solvent position is never liquidatable.
	if me.isPositionLiquidatable(pos, price, 0) {
		t.Fatal("a solvent position is liquidatable at a zero maintenance ratio")
	}
	// But an insolvent one (equity < 0) is, even at mm = 0.
	broke := zzlMarginPos(Long, zzlBig(1000), zzlPx(100), zzlBig(1))
	if !me.isPositionLiquidatable(broke, zzlPx(50), 0) {
		t.Fatal("an insolvent position is not liquidatable even at mm = 0")
	}
}

// ---------------------------------------------------------------------------
// liquidation price
// ---------------------------------------------------------------------------

func TestZzlMarginLiquidationPriceDirectionAndLeverageMonotonicity(t *testing.T) {
	me := NewMarginEngine()
	entry := zzlPx(100)
	const mm = DefaultMaintenanceMargin

	// A long must liquidate BELOW a short's level. The two multipliers are
	// (1 - 1/L + m) and (1 + 1/L - m), so that ordering holds exactly while
	// 1/L > m — and inverts once maintenance outgrows the inverse leverage.
	// DEFECT (reported): with mm = DefaultMaintenanceMargin the inversion is
	// reachable inside the account's own leverage ceiling, at which point the
	// engine reports a long liquidating above a short.
	inverted := uint32(0)
	for _, lev := range []uint32{1, 2, 5, 10, 20, 25, 50, 100} {
		lo := me.calculateLiquidationPrice(Long, entry, lev, mm)
		sh := me.calculateLiquidationPrice(Short, entry, lev, mm)
		invL := MarginPrecision / int64(lev)
		switch {
		case invL > int64(mm):
			if lo.Cmp(sh) >= 0 {
				t.Fatalf("lev=%d (1/L=%d > mm=%d): long liq %s >= short liq %s", lev, invL, mm, lo, sh)
			}
		case invL == int64(mm):
			if lo.Cmp(sh) != 0 || lo.Cmp(entry) != 0 {
				t.Fatalf("lev=%d (1/L == mm): expected both liq prices to sit on entry %s, got %s/%s",
					lev, entry, lo, sh)
			}
		default:
			if lo.Cmp(sh) <= 0 {
				t.Fatalf("lev=%d (1/L=%d < mm=%d): expected the inversion, got long %s <= short %s",
					lev, invL, mm, lo, sh)
			}
			if inverted == 0 {
				inverted = lev
			}
		}
		// Whatever the ordering, the two sides stay symmetric about entry: the
		// multipliers are equidistant from MarginPrecision, so they must sum to
		// exactly twice the entry price.
		sum := new(big.Int).Add(lo, sh)
		if sum.Cmp(new(big.Int).Mul(entry, big.NewInt(2))) != 0 {
			t.Fatalf("lev=%d: liq prices are not symmetric about entry: %s + %s != 2*%s",
				lev, lo, sh, entry)
		}
	}
	if inverted == 0 {
		t.Fatal("the long/short liquidation ordering never inverted; the maintenance constant " +
			"changed — re-check the reported finding")
	}
	if inverted > DefaultMaxLeverage {
		t.Fatalf("inversion first seen at %dx, outside the cross-margin ceiling %dx",
			inverted, DefaultMaxLeverage)
	}
	// Monotonicity: more leverage pulls a long's liquidation price UP toward
	// entry (a smaller adverse move kills it) and a short's DOWN toward entry.
	prevLong := me.calculateLiquidationPrice(Long, entry, 1, mm)
	prevShort := me.calculateLiquidationPrice(Short, entry, 1, mm)
	for _, lev := range []uint32{2, 4, 10, 25, 50, 100} {
		curLong := me.calculateLiquidationPrice(Long, entry, lev, mm)
		curShort := me.calculateLiquidationPrice(Short, entry, lev, mm)
		if curLong.Cmp(prevLong) < 0 {
			t.Fatalf("lev=%d: long liq price fell as leverage rose (%s -> %s)", lev, prevLong, curLong)
		}
		if curShort.Cmp(prevShort) > 0 {
			t.Fatalf("lev=%d: short liq price rose as leverage rose (%s -> %s)", lev, prevShort, curShort)
		}
		prevLong, prevShort = curLong, curShort
	}
	// A stricter maintenance ratio also pulls a long's liquidation price up.
	loose := me.calculateLiquidationPrice(Long, entry, 10, 100)
	tight := me.calculateLiquidationPrice(Long, entry, 10, 900)
	if tight.Cmp(loose) <= 0 {
		t.Fatalf("a stricter maintenance ratio did not raise the long liq price: %s vs %s", tight, loose)
	}
}

// DEFECT (reported): the maintenance ratio DefaultMaintenanceMargin = 500 is 500
// basis points = 5%, not the 0.5% its comment claims. Because 5% exceeds 1/L for
// every leverage above 20x, a long's computed liquidation price sits ABOVE its
// entry price — the position is nominally liquidatable the instant it opens.
func TestZzlMarginLongLiquidationPriceCrossesAboveEntryAtHighLeverage(t *testing.T) {
	me := NewMarginEngine()
	entry := zzlPx(100)
	const mm = DefaultMaintenanceMargin

	// 1/L in basis points is MarginPrecision/L; the long multiplier is
	// MarginPrecision - 1/L + mm, which exceeds MarginPrecision exactly when
	// mm > MarginPrecision/L.
	crossed := uint32(0)
	for lev := uint32(1); lev <= 200; lev++ {
		liq := me.calculateLiquidationPrice(Long, entry, lev, mm)
		invL := MarginPrecision / int64(lev)
		wantAbove := int64(mm) > invL
		if (liq.Cmp(entry) > 0) != wantAbove {
			t.Fatalf("lev=%d: liq %s vs entry %s disagrees with mm(%d) > 1/L(%d)",
				lev, liq, entry, mm, invL)
		}
		if wantAbove && crossed == 0 {
			crossed = lev
		}
	}
	if crossed == 0 {
		t.Fatal("no leverage put a long's liquidation price above its entry; the maintenance " +
			"constant changed — re-check the reported basis-point finding")
	}
	if crossed > DefaultMaxLeverage {
		t.Fatalf("crossover at %dx is beyond the cross-margin ceiling %dx", crossed, DefaultMaxLeverage)
	}
	t.Logf("long liquidation price exceeds entry from %dx leverage upward (mm=%d bps)", crossed, mm)
}

// DEFECT (reported, HIGH): calculateLiquidationPrice divides MarginPrecision by
// leverage with no zero check, and OpenPosition only rejects leverage ABOVE the
// account ceiling. leverage == 0 therefore panics — a chain halt if this engine
// is ever dispatched to from a precompile.
func TestZzlMarginZeroLeveragePanics(t *testing.T) {
	me := NewMarginEngine()
	panicked, rec := zzlPanics(func() {
		me.calculateLiquidationPrice(Long, zzlPx(100), 0, DefaultMaintenanceMargin)
	})
	if !panicked {
		t.Fatal("calculateLiquidationPrice(leverage=0) did not panic; the guard was added — " +
			"update the reported finding")
	}
	// An unrecovered runtime panic in a precompile halts the chain; it is not a
	// returned error a caller could handle.
	if fmt.Sprint(rec) != "division by zero" {
		t.Fatalf("panic value = %v, want the big.Int division-by-zero", rec)
	}

	// The same panic is reachable from the public OpenPosition entry point.
	me2, _ := zzlMarginEngine(t, CrossMargin, 1_000_000)
	panicked, _ = zzlPanics(func() {
		_, _ = me2.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 0, zzlPx(100), false)
	})
	if !panicked {
		t.Fatal("OpenPosition(leverage=0) did not panic; a zero-leverage guard was added")
	}
}

// ---------------------------------------------------------------------------
// equity / used margin / free margin / maintenance aggregates
// ---------------------------------------------------------------------------

func TestZzlMarginAggregatesMatchTheirDefinitions(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 10_000)

	// An account with no positions: equity is exactly the collateral value, used
	// margin and maintenance are zero, free margin is the whole equity.
	if me.calculateTotalEquity(acct).Cmp(zzlBig(10_000)) != 0 {
		t.Fatalf("equity with no positions = %s, want 10000", me.calculateTotalEquity(acct))
	}
	if me.calculateUsedMargin(acct).Sign() != 0 {
		t.Fatal("used margin with no positions is non-zero")
	}
	if me.calculateTotalMaintenanceMargin(acct).Sign() != 0 {
		t.Fatal("maintenance margin with no positions is non-zero")
	}
	if me.calculateFreeMargin(acct).Cmp(zzlBig(10_000)) != 0 {
		t.Fatalf("free margin with no positions = %s, want the whole equity", me.calculateFreeMargin(acct))
	}

	// Add two positions with known margin and unrealized PnL. Every aggregate is
	// a plain sum, so recompute each independently and compare.
	p1 := zzlMarginPos(Long, zzlBig(1000), zzlPx(100), zzlBig(4000))
	p1.UnrealizedPnL = zzlBig(700)
	p2 := zzlMarginPos(Short, zzlBig(500), zzlPx(200), zzlBig(2500))
	p2.MarkPrice = zzlPx(200)
	p2.UnrealizedPnL = zzlBig(-300)
	acct.Positions[zzlMarket] = p1
	acct.Positions[zzlMarket2] = p2

	wantEquity := big.NewInt(10_000 + 700 - 300)
	if got := me.calculateTotalEquity(acct); got.Cmp(wantEquity) != 0 {
		t.Fatalf("equity = %s, want %s (collateral + sum of unrealized PnL)", got, wantEquity)
	}
	wantUsed := big.NewInt(4000 + 2500)
	if got := me.calculateUsedMargin(acct); got.Cmp(wantUsed) != 0 {
		t.Fatalf("used margin = %s, want %s", got, wantUsed)
	}
	if got := me.calculateFreeMargin(acct); got.Cmp(new(big.Int).Sub(wantEquity, wantUsed)) != 0 {
		t.Fatalf("free margin = %s, want equity - used = %s", got, new(big.Int).Sub(wantEquity, wantUsed))
	}
	// Maintenance is sum over positions of notional * mm / MarginPrecision.
	wantMaint := big.NewInt(0)
	for _, p := range []*MarginPosition{p1, p2} {
		n := new(big.Int).Mul(p.Size, p.MarkPrice)
		n.Div(n, Q96)
		n.Mul(n, big.NewInt(int64(acct.MaintenanceMargin)))
		n.Div(n, big.NewInt(MarginPrecision))
		wantMaint.Add(wantMaint, n)
	}
	if got := me.calculateTotalMaintenanceMargin(acct); got.Cmp(wantMaint) != 0 {
		t.Fatalf("maintenance = %s, want %s", got, wantMaint)
	}
	// Maintenance is strictly positive for a non-trivial book and scales with
	// the mark price: doubling every mark doubles the requirement.
	if wantMaint.Sign() <= 0 {
		t.Fatal("maintenance requirement is zero for two live positions")
	}
	p1.MarkPrice = new(big.Int).Mul(p1.MarkPrice, big.NewInt(2))
	p2.MarkPrice = new(big.Int).Mul(p2.MarkPrice, big.NewInt(2))
	if got := me.calculateTotalMaintenanceMargin(acct); got.Cmp(new(big.Int).Mul(wantMaint, big.NewInt(2))) != 0 {
		t.Fatalf("maintenance did not scale with mark price: %s vs 2*%s", got, wantMaint)
	}
}

func TestZzlMarginAccountHealth(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 10_000)

	if _, err := me.GetAccountHealth(zzlOther); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	// No positions: maximal health, and in particular no division by zero.
	h, err := me.GetAccountHealth(zzlOwner)
	if err != nil {
		t.Fatalf("GetAccountHealth: %v", err)
	}
	if h.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("health with no positions = %s, want 1e18", h)
	}

	// With a position, health = equity * 1e18 / maintenance, and it must fall
	// as equity falls and rise as equity rises — strictly, in both directions.
	pos := zzlMarginPos(Long, zzlBig(1000), zzlPx(100), zzlBig(5000))
	pos.UnrealizedPnL = zzlBig(0)
	acct.Positions[zzlMarket] = pos

	base, err := me.GetAccountHealth(zzlOwner)
	if err != nil {
		t.Fatalf("GetAccountHealth: %v", err)
	}
	eq := me.calculateTotalEquity(acct)
	mm := me.calculateTotalMaintenanceMargin(acct)
	want := new(big.Int).Mul(eq, big.NewInt(1e18))
	want.Div(want, mm)
	if base.Cmp(want) != 0 {
		t.Fatalf("health = %s, want equity*1e18/maintenance = %s", base, want)
	}

	pos.UnrealizedPnL = zzlBig(1000)
	better, _ := me.GetAccountHealth(zzlOwner)
	if better.Cmp(base) <= 0 {
		t.Fatalf("health did not improve when unrealized PnL rose: %s -> %s", base, better)
	}
	pos.UnrealizedPnL = zzlBig(-1000)
	worse, _ := me.GetAccountHealth(zzlOwner)
	if worse.Cmp(base) >= 0 {
		t.Fatalf("health did not worsen when unrealized PnL fell: %s -> %s", base, worse)
	}
	// An account whose losses exceed its collateral reports negative health.
	pos.UnrealizedPnL = zzlBig(-100_000)
	neg, _ := me.GetAccountHealth(zzlOwner)
	if neg.Sign() >= 0 {
		t.Fatalf("health of an insolvent account = %s, want negative", neg)
	}
}

// ---------------------------------------------------------------------------
// OpenPosition
// ---------------------------------------------------------------------------

func TestZzlMarginOpenPositionRefusals(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 0)

	if _, err := me.OpenPosition(zzlOther, zzlMarket, Long, zzlBig(1), 1, zzlPx(100), false); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	// One notch above the account ceiling is refused; exactly the ceiling is not.
	over := acct.MaxLeverage + 1
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1), over, zzlPx(100), false); !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("leverage %d err = %v, want ErrExcessiveLeverage", over, err)
	}
	if len(acct.Positions) != 0 {
		t.Fatal("a refused open created a position")
	}
	// At the ceiling, the only remaining objection is margin.
	_, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), acct.MaxLeverage, zzlPx(100), false)
	if !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("ceiling leverage with no equity: err = %v, want ErrInsufficientMargin", err)
	}
	if len(acct.Positions) != 0 {
		t.Fatal("a margin-refused open created a position")
	}
}

func TestZzlMarginOpenPositionRefusedBelowInitialMarginAndAllowedAtIt(t *testing.T) {
	// The initial-margin requirement is notional * InitialMargin / MarginPrecision.
	// A position must be refused with one unit less free margin than that and
	// accepted with exactly that much — never openable below the requirement.
	size, price := zzlBig(1000), zzlPx(100)
	notional := new(big.Int).Mul(size, price)
	notional.Div(notional, Q96)
	required := new(big.Int).Mul(notional, big.NewInt(DefaultInitialMargin))
	required.Div(required, big.NewInt(MarginPrecision))
	if required.Sign() <= 0 {
		t.Fatal("test fixture produces a zero margin requirement")
	}

	// One unit short.
	short := new(big.Int).Sub(required, big.NewInt(1))
	me, acct := zzlMarginEngine(t, CrossMargin, 0)
	acct.CollateralValue = short
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, size, 10, price, false); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("free margin one unit below the requirement: err = %v, want ErrInsufficientMargin", err)
	}

	// Exactly enough.
	me2, acct2 := zzlMarginEngine(t, CrossMargin, 0)
	acct2.CollateralValue = new(big.Int).Set(required)
	pos, err := me2.OpenPosition(zzlOwner, zzlMarket, Long, size, 10, price, false)
	if err != nil {
		t.Fatalf("free margin exactly at the requirement: %v", err)
	}
	if pos.Margin.Cmp(required) != 0 {
		t.Fatalf("posted margin = %s, want the requirement %s", pos.Margin, required)
	}
	// Free margin is now exactly zero: the open consumed precisely what it needed.
	if got := me2.calculateFreeMargin(acct2); got.Sign() != 0 {
		t.Fatalf("free margin after the open = %s, want 0", got)
	}
	// A second identical position is therefore refused.
	if _, err := me2.OpenPosition(zzlOwner, zzlMarket2, Long, size, 10, price, false); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("second open with no free margin: err = %v, want ErrInsufficientMargin", err)
	}
}

func TestZzlMarginOpenPositionInitialState(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 1_000_000)
	size, price := zzlBig(1000), zzlPx(100)

	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, size, 10, price, false)
	if err != nil {
		t.Fatalf("OpenPosition: %v", err)
	}
	if pos.EntryPrice.Cmp(price) != 0 || pos.MarkPrice.Cmp(price) != 0 {
		t.Fatalf("entry/mark = %s/%s, want both %s", pos.EntryPrice, pos.MarkPrice, price)
	}
	if pos.UnrealizedPnL.Sign() != 0 || pos.RealizedPnL.Sign() != 0 {
		t.Fatal("a fresh position starts with non-zero PnL")
	}
	if pos.Size.Cmp(size) != 0 {
		t.Fatalf("size = %s, want %s", pos.Size, size)
	}
	// The position must not alias the caller's arguments: mutating the caller's
	// big.Ints afterwards must not move the book.
	size.SetInt64(999999)
	price.Set(zzlPx(1))
	if pos.Size.Cmp(zzlBig(1000)) != 0 || pos.EntryPrice.Cmp(zzlPx(100)) != 0 {
		t.Fatal("OpenPosition aliased its caller's big.Int arguments")
	}
	if acct.Positions[zzlMarket] != pos {
		t.Fatal("position not filed under its market id")
	}
	// A fresh position is not liquidatable at its own entry price.
	if me.isPositionLiquidatable(pos, pos.EntryPrice, acct.MaintenanceMargin) {
		t.Fatal("a newly opened position is immediately liquidatable at its entry price")
	}
}

func TestZzlMarginOpenPositionIsolatedSkipsFreeMarginCheck(t *testing.T) {
	// An isolated open does not consult free margin at all, so an account with
	// zero equity can open one. Both routes into that branch are exercised: the
	// explicit isIsolated flag and an IsolatedMargin account type.
	me, _ := zzlMarginEngine(t, CrossMargin, 0)
	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), true)
	if err != nil {
		t.Fatalf("isolated open with zero equity: %v", err)
	}
	if !pos.IsIsolated {
		t.Fatal("IsIsolated not recorded")
	}

	me2 := NewMarginEngine()
	acct2, err := me2.CreateAccount(zzlOther, IsolatedMargin)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	acct2.CollateralValue = big.NewInt(0)
	if _, err := me2.OpenPosition(zzlOther, zzlMarket, Short, zzlBig(1000), 10, zzlPx(100), false); err != nil {
		t.Fatalf("IsolatedMargin account open with zero equity: %v", err)
	}
}

func TestZzlMarginIncreasePositionAveragesEntryAndSumsMargin(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)

	first, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	m1 := new(big.Int).Set(first.Margin)

	second, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(200), false)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if second != first {
		t.Fatal("increasing a position returned a different object")
	}
	if len(acct.Positions) != 1 {
		t.Fatalf("same-side open created %d positions, want 1", len(acct.Positions))
	}
	if second.Size.Cmp(zzlBig(2000)) != 0 {
		t.Fatalf("size after increase = %s, want 2000", second.Size)
	}
	// Weighted-average entry: (1000*100 + 1000*200)/2000 = 150.
	if second.EntryPrice.Cmp(zzlPx(150)) != 0 {
		t.Fatalf("blended entry = %s, want %s", second.EntryPrice, zzlPx(150))
	}
	// The blended entry always lies between the two component prices.
	if second.EntryPrice.Cmp(zzlPx(100)) <= 0 || second.EntryPrice.Cmp(zzlPx(200)) >= 0 {
		t.Fatal("blended entry escaped the interval between the two fills")
	}
	// Margin is additive.
	if second.Margin.Cmp(new(big.Int).Add(m1, new(big.Int).Sub(second.Margin, m1))) != 0 {
		t.Fatal("margin arithmetic is not additive")
	}
	if second.Margin.Cmp(m1) <= 0 {
		t.Fatalf("margin did not grow with the position: %s -> %s", m1, second.Margin)
	}
	if second.LiquidationPrice == nil {
		t.Fatal("liquidation price not recomputed after an increase")
	}
}

// DEFECT (reported, HIGH): increasePosition divides the combined notional by the
// combined size with no zero guard. Two zero-size opens on the same market and
// side therefore panic — reachable straight from the public OpenPosition.
func TestZzlMarginZeroSizeIncreasePanics(t *testing.T) {
	me, _ := zzlMarginEngine(t, CrossMargin, 1_000_000)
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(0), 1, zzlPx(100), false); err != nil {
		t.Fatalf("first zero-size open: %v, expected it to be accepted (no size guard)", err)
	}
	panicked, rec := zzlPanics(func() {
		_, _ = me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(0), 1, zzlPx(100), false)
	})
	if !panicked {
		t.Fatal("a second zero-size open did not panic; a size guard was added — update the finding")
	}
	if fmt.Sprint(rec) != "division by zero" {
		t.Fatalf("panic value = %v, want the big.Int division-by-zero", rec)
	}
}

// DEFECT (reported): increasePosition recomputes leverage from the blended
// position but never re-checks it against the account ceiling, so repeated
// same-side opens walk leverage past MaxLeverage without a refusal.
func TestZzlMarginIncreaseCanExceedTheAccountLeverageCeiling(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 1_000_000_000)

	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Hand-set a tiny margin, then increase: the recomputed leverage is notional
	// over margin, which the code writes back without comparing to MaxLeverage.
	pos.Margin = big.NewInt(1)
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1), 1, zzlPx(100), false); err != nil {
		t.Fatalf("increase: %v", err)
	}
	if pos.Leverage <= acct.MaxLeverage {
		t.Fatalf("recomputed leverage %d did not exceed the ceiling %d; this test no longer "+
			"pins the missing re-check", pos.Leverage, acct.MaxLeverage)
	}
	// And the engine accepts a further increase on the over-levered position.
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1), 1, zzlPx(100), false); err != nil {
		t.Fatalf("increase on an over-levered position was refused: %v", err)
	}
}

func TestZzlMarginReducePositionRealizesPnLAndShrinksSize(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)

	long, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// An opposing open smaller than the position reduces it and books PnL.
	got, err := me.OpenPosition(zzlOwner, zzlMarket, Short, zzlBig(400), 10, zzlPx(120), false)
	if err != nil {
		t.Fatalf("opposing open: %v", err)
	}
	if got != long {
		t.Fatal("a partial reduce returned a different position object")
	}
	if long.Size.Cmp(zzlBig(600)) != 0 {
		t.Fatalf("size after reducing 400 of 1000 = %s, want 600", long.Size)
	}
	// The realized PnL is the closed size against the price move, sign-correct
	// for a long closed above its entry.
	wantPnL := me.calculatePnL(&MarginPosition{Side: Long, EntryPrice: zzlPx(100)}, zzlPx(120), zzlBig(400))
	if long.RealizedPnL.Cmp(wantPnL) != 0 {
		t.Fatalf("realized PnL = %s, want %s", long.RealizedPnL, wantPnL)
	}
	if long.RealizedPnL.Sign() <= 0 {
		t.Fatal("closing a long above its entry realized a loss")
	}
	if len(acct.Positions) != 1 {
		t.Fatal("a partial reduce removed the position")
	}
	// The entry price of the surviving remainder is untouched.
	if long.EntryPrice.Cmp(zzlPx(100)) != 0 {
		t.Fatalf("entry price moved on a reduce: %s", long.EntryPrice)
	}
}

func TestZzlMarginExactOppositeCloseRemovesPositionAndReturnsNilPair(t *testing.T) {
	// An opposing open of exactly the position size closes it. The engine then
	// returns (nil, nil) — no error and no position — which a caller that
	// dereferences the result would fault on. Pinned so the contract is explicit.
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Short, zzlBig(1000), 10, zzlPx(120), false)
	if err != nil {
		t.Fatalf("exact opposite open returned err = %v, want nil", err)
	}
	if pos != nil {
		t.Fatalf("exact opposite open returned position %+v, want nil", pos)
	}
	if len(acct.Positions) != 0 {
		t.Fatalf("position not removed: %d remain", len(acct.Positions))
	}
}

func TestZzlMarginFlipPositionKeepsTheResidualOnTheNewSide(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	flipped, err := me.OpenPosition(zzlOwner, zzlMarket, Short, zzlBig(1500), 10, zzlPx(120), false)
	if err != nil {
		t.Fatalf("flip: %v", err)
	}
	if flipped == nil {
		t.Fatal("flip returned nil")
	}
	if flipped.Side != Short {
		t.Fatal("flipped position kept the old side")
	}
	// The residual is the overshoot only: 1500 closed against 1000.
	if flipped.Size.Cmp(zzlBig(500)) != 0 {
		t.Fatalf("residual size = %s, want 500", flipped.Size)
	}
	if flipped.EntryPrice.Cmp(zzlPx(120)) != 0 {
		t.Fatalf("residual entry = %s, want the incoming price %s", flipped.EntryPrice, zzlPx(120))
	}
	// The PnL of the closed leg carries onto the new position.
	wantPnL := me.calculatePnL(&MarginPosition{Side: Long, EntryPrice: zzlPx(100)}, zzlPx(120), zzlBig(1000))
	if flipped.RealizedPnL.Cmp(wantPnL) != 0 {
		t.Fatalf("carried realized PnL = %s, want %s", flipped.RealizedPnL, wantPnL)
	}
	if flipped.UnrealizedPnL.Sign() != 0 {
		t.Fatal("the flipped position starts with non-zero unrealized PnL")
	}
	if flipped.LiquidationPrice == nil {
		t.Fatal("flipped position has no liquidation price")
	}
	if acct.Positions[zzlMarket] != flipped {
		t.Fatal("flipped position not filed under the market id")
	}
	if len(acct.Positions) != 1 {
		t.Fatalf("%d positions after a flip, want 1", len(acct.Positions))
	}
}

// ---------------------------------------------------------------------------
// ClosePosition
// ---------------------------------------------------------------------------

func TestZzlMarginClosePositionRefusals(t *testing.T) {
	me, _ := zzlMarginEngine(t, CrossMargin, 1_000_000)
	if _, err := me.ClosePosition(zzlOther, zzlMarket, zzlBig(1), zzlPx(100)); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	if _, err := me.ClosePosition(zzlOwner, zzlMarket, zzlBig(1), zzlPx(100)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPositionNotFound", err)
	}
}

func TestZzlMarginPartialCloseReducesMarginProportionally(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)
	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m0 := new(big.Int).Set(pos.Margin)

	pnl, err := me.ClosePosition(zzlOwner, zzlMarket, zzlBig(250), zzlPx(120))
	if err != nil {
		t.Fatalf("partial close: %v", err)
	}
	if pnl.Sign() <= 0 {
		t.Fatalf("closing a quarter of a winning long returned PnL %s, want > 0", pnl)
	}
	if pos.Size.Cmp(zzlBig(750)) != 0 {
		t.Fatalf("remaining size = %s, want 750", pos.Size)
	}
	// A quarter of the position left, so a quarter of the margin was released —
	// and the release can never exceed what was posted.
	released := new(big.Int).Sub(m0, pos.Margin)
	if released.Sign() <= 0 {
		t.Fatalf("a partial close released no margin (%s -> %s)", m0, pos.Margin)
	}
	if released.Cmp(m0) > 0 {
		t.Fatalf("released %s of a %s margin", released, m0)
	}
	wantReleased := new(big.Int).Div(m0, big.NewInt(4))
	if new(big.Int).Sub(released, wantReleased).CmpAbs(big.NewInt(1)) > 0 {
		t.Fatalf("released %s for a 25%% close of %s, want ~%s", released, m0, wantReleased)
	}
	if pos.RealizedPnL.Cmp(pnl) != 0 {
		t.Fatalf("realized PnL %s not booked onto the position (%s)", pnl, pos.RealizedPnL)
	}
	if len(acct.Positions) != 1 {
		t.Fatal("a partial close removed the position")
	}
	// Closing the exact remainder removes it.
	if _, err := me.ClosePosition(zzlOwner, zzlMarket, zzlBig(750), zzlPx(120)); err != nil {
		t.Fatalf("exact close: %v", err)
	}
	if len(acct.Positions) != 0 {
		t.Fatal("closing the exact remaining size left the position open")
	}
}

// DEFECT (reported, HIGH): ClosePosition computes PnL on the caller's requested
// size before clamping it to the position size, so a request to close more than
// is held pays PnL on size the account never had.
func TestZzlMarginOverCloseMintsPnLOnPhantomSize(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	honest := me.calculatePnL(&MarginPosition{Side: Long, EntryPrice: zzlPx(100)}, zzlPx(120), zzlBig(1000))

	pnl, err := me.ClosePosition(zzlOwner, zzlMarket, zzlBig(10_000), zzlPx(120))
	if err != nil {
		t.Fatalf("over-close: %v", err)
	}
	if pnl.Cmp(honest) <= 0 {
		t.Fatalf("over-closing 10x the position paid %s, not more than the honest %s; "+
			"a clamp was added — update the reported finding", pnl, honest)
	}
	if new(big.Int).Div(pnl, honest).Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("over-close paid %s, expected exactly 10x the honest %s", pnl, honest)
	}
	if len(acct.Positions) != 0 {
		t.Fatal("the over-close did not remove the position")
	}
}

// ---------------------------------------------------------------------------
// UpdatePositionMargin
// ---------------------------------------------------------------------------

func TestZzlMarginUpdatePositionMarginRefusals(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)

	if err := me.UpdatePositionMargin(zzlOther, zzlMarket, zzlBig(1)); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, zzlBig(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPositionNotFound", err)
	}
	// A cross-margin position refuses per-position margin edits outright.
	if _, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, zzlBig(1)); !errors.Is(err, ErrNotIsolatedPosition) {
		t.Fatalf("cross position err = %v, want ErrNotIsolatedPosition", err)
	}

	// Isolated: taking the margin to zero or below is refused, and the balance
	// is left exactly as it was.
	iso, err := me.OpenPosition(zzlOwner, zzlMarket2, Long, zzlBig(1000), 10, zzlPx(100), true)
	if err != nil {
		t.Fatalf("isolated open: %v", err)
	}
	m0 := new(big.Int).Set(iso.Margin)
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket2, new(big.Int).Neg(m0)); !errors.Is(err, ErrInsufficientMargin) {
		t.Fatalf("margin to exactly zero: err = %v, want ErrInsufficientMargin", err)
	}
	if iso.Margin.Cmp(m0) != 0 {
		t.Fatal("a refused margin update moved the balance")
	}
	// One unit above zero is allowed — that is the boundary.
	keepOne := new(big.Int).Neg(new(big.Int).Sub(m0, big.NewInt(1)))
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket2, keepOne); err != nil {
		// The leverage re-check may also object; assert that it is the reason.
		if !errors.Is(err, ErrExcessiveLeverage) {
			t.Fatalf("leaving 1 unit of margin: err = %v, want nil or ErrExcessiveLeverage", err)
		}
		if iso.Margin.Cmp(m0) != 0 {
			t.Fatal("a leverage-refused update still moved the margin")
		}
	}
	_ = acct
}

func TestZzlMarginRemovingMarginIsRefusedAboveTheLeverageCeiling(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)
	iso, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// The removal is refused once notional/newMargin exceeds MaxLeverage. Bisect
	// for the smallest margin the engine still accepts, then assert the flip sits
	// exactly on the definitional boundary and one unit below it.
	notional := new(big.Int).Mul(iso.Size, iso.MarkPrice)
	notional.Div(notional, Q96)
	m0 := new(big.Int).Set(iso.Margin)
	lev := big.NewInt(int64(acct.MaxLeverage))

	// accepts reports whether pulling margin down to newMargin is allowed. The
	// position's margin is restored before every probe so the probes are
	// independent, and restored again at the end.
	accepts := func(newMargin *big.Int) bool {
		iso.Margin = new(big.Int).Set(m0)
		err := me.UpdatePositionMargin(zzlOwner, zzlMarket, new(big.Int).Sub(newMargin, m0))
		iso.Margin = new(big.Int).Set(m0)
		return err == nil
	}
	if !accepts(m0) {
		t.Fatal("leaving the margin untouched was refused")
	}
	if accepts(big.NewInt(1)) {
		t.Fatal("pulling the margin down to 1 unit was allowed; there is no ceiling to find")
	}
	smallest := zzlBisect(big.NewInt(1), m0, accepts)

	// At the smallest accepted margin, leverage is at or under the ceiling.
	if got := new(big.Int).Div(notional, smallest); got.Cmp(lev) > 0 {
		t.Fatalf("smallest accepted margin %s gives leverage %s, above the ceiling %d",
			smallest, got, acct.MaxLeverage)
	}
	// One unit less is refused, and refused for the leverage reason specifically.
	over := new(big.Int).Sub(smallest, big.NewInt(1))
	if new(big.Int).Div(notional, over).Cmp(lev) <= 0 {
		t.Fatalf("one unit below the smallest accepted margin (%s) still yields leverage %s "+
			"within the ceiling %d: the refusal is not the leverage check",
			over, new(big.Int).Div(notional, over), acct.MaxLeverage)
	}
	iso.Margin = new(big.Int).Set(m0)
	err = me.UpdatePositionMargin(zzlOwner, zzlMarket, new(big.Int).Sub(over, m0))
	if !errors.Is(err, ErrExcessiveLeverage) {
		t.Fatalf("newMargin=%s gives leverage %s > ceiling %d: err = %v, want ErrExcessiveLeverage",
			over, new(big.Int).Div(notional, over), acct.MaxLeverage, err)
	}
	if iso.Margin.Cmp(m0) != 0 {
		t.Fatal("a leverage-refused removal still moved the margin")
	}
	// Adding margin is never subject to the leverage check: it can only help.
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, zzlBig(1)); err != nil {
		t.Fatalf("adding one unit of margin was refused: %v", err)
	}
	if iso.Margin.Cmp(new(big.Int).Add(m0, big.NewInt(1))) != 0 {
		t.Fatalf("margin = %s after adding 1 to %s", iso.Margin, m0)
	}
}

func TestZzlMarginAddingMarginImprovesHealthRemovingWorsensIt(t *testing.T) {
	me, acct := zzlMarginEngine(t, CrossMargin, 100_000_000)
	iso, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Pick the price at which the position sits exactly on the liquidation edge.
	edge := zzlBisect(big.NewInt(0), zzlPx(100), func(k *big.Int) bool {
		return me.isPositionLiquidatable(iso, new(big.Int).Sub(zzlPx(100), k), acct.MaintenanceMargin)
	})
	pEdge := new(big.Int).Sub(zzlPx(100), edge)
	if !me.isPositionLiquidatable(iso, pEdge, acct.MaintenanceMargin) {
		t.Fatal("bisection did not land on a liquidatable price")
	}

	// Adding margin must lift it out.
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, zzlBig(1_000_000)); err != nil {
		t.Fatalf("add margin: %v", err)
	}
	if me.isPositionLiquidatable(iso, pEdge, acct.MaintenanceMargin) {
		t.Fatal("adding a million units of margin left the position liquidatable")
	}
	// Removing it again must put it back.
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, zzlBig(-1_000_000)); err != nil {
		t.Fatalf("remove margin: %v", err)
	}
	if !me.isPositionLiquidatable(iso, pEdge, acct.MaintenanceMargin) {
		t.Fatal("removing the margin again did not restore liquidatability")
	}
}

// DEFECT (reported): UpdatePositionMargin recomputes the liquidation price from
// position.Leverage, which it never updates, so posting or pulling margin leaves
// the advertised liquidation price unchanged even though the real one moved.
func TestZzlMarginUpdateMarginLeavesLiquidationPriceStale(t *testing.T) {
	me, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
	iso, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	before := new(big.Int).Set(iso.LiquidationPrice)
	if err := me.UpdatePositionMargin(zzlOwner, zzlMarket, zzlBig(1_000_000)); err != nil {
		t.Fatalf("add margin: %v", err)
	}
	if iso.LiquidationPrice.Cmp(before) != 0 {
		t.Fatalf("liquidation price moved from %s to %s after posting margin; the stale-leverage "+
			"path was fixed — update the reported finding", before, iso.LiquidationPrice)
	}
	if iso.Leverage != 10 {
		t.Fatalf("leverage = %d, expected the original 10 to be left untouched", iso.Leverage)
	}
	// Meanwhile the real risk did change: the position is no longer liquidatable
	// at a price that would have killed it before.
	if !me.isPositionLiquidatable(&MarginPosition{
		Side: Long, Size: iso.Size, EntryPrice: iso.EntryPrice, Margin: big.NewInt(1),
	}, zzlPx(99), DefaultMaintenanceMargin) {
		t.Fatal("fixture: the reference thin position is not liquidatable at 99")
	}
	if me.isPositionLiquidatable(iso, zzlPx(99), DefaultMaintenanceMargin) {
		t.Fatal("the fattened position is still liquidatable at 99")
	}
}

// ---------------------------------------------------------------------------
// stop loss / take profit
// ---------------------------------------------------------------------------

func TestZzlMarginStopLossAndTakeProfit(t *testing.T) {
	me, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)

	for _, tc := range []struct {
		name string
		set  func(common.Address, [32]byte, *big.Int) error
		read func(*MarginPosition) *big.Int
	}{
		{"stop loss", me.SetStopLoss, func(p *MarginPosition) *big.Int { return p.StopLoss }},
		{"take profit", me.SetTakeProfit, func(p *MarginPosition) *big.Int { return p.TakeProfit }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.set(zzlOther, zzlMarket, zzlPx(90)); !errors.Is(err, ErrAccountNotFound) {
				t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
			}
			if err := tc.set(zzlOwner, zzlMarket2, zzlPx(90)); !errors.Is(err, ErrPositionNotFound) {
				t.Fatalf("unknown market err = %v, want ErrPositionNotFound", err)
			}
		})
	}

	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if pos.StopLoss != nil || pos.TakeProfit != nil {
		t.Fatal("a fresh position carries a stop or target")
	}
	arg := zzlPx(90)
	if err := me.SetStopLoss(zzlOwner, zzlMarket, arg); err != nil {
		t.Fatalf("SetStopLoss: %v", err)
	}
	if pos.StopLoss.Cmp(zzlPx(90)) != 0 {
		t.Fatalf("stop loss = %s, want %s", pos.StopLoss, zzlPx(90))
	}
	// Stored by value, not aliased to the caller's big.Int.
	arg.Set(zzlPx(1))
	if pos.StopLoss.Cmp(zzlPx(90)) != 0 {
		t.Fatal("SetStopLoss aliased the caller's argument")
	}
	arg2 := zzlPx(150)
	if err := me.SetTakeProfit(zzlOwner, zzlMarket, arg2); err != nil {
		t.Fatalf("SetTakeProfit: %v", err)
	}
	if pos.TakeProfit.Cmp(zzlPx(150)) != 0 {
		t.Fatalf("take profit = %s, want %s", pos.TakeProfit, zzlPx(150))
	}
	arg2.Set(zzlPx(1))
	if pos.TakeProfit.Cmp(zzlPx(150)) != 0 {
		t.Fatal("SetTakeProfit aliased the caller's argument")
	}
	// Setting one does not disturb the other, and both are overwritable.
	if err := me.SetStopLoss(zzlOwner, zzlMarket, zzlPx(80)); err != nil {
		t.Fatalf("re-SetStopLoss: %v", err)
	}
	if pos.StopLoss.Cmp(zzlPx(80)) != 0 || pos.TakeProfit.Cmp(zzlPx(150)) != 0 {
		t.Fatal("overwriting the stop disturbed the target")
	}
}

// ---------------------------------------------------------------------------
// LiquidatePosition
// ---------------------------------------------------------------------------

func TestZzlMarginLiquidateRefusals(t *testing.T) {
	me, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)

	if _, err := me.LiquidatePosition(zzlLiquidator, zzlOther, zzlMarket, zzlPx(1)); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown owner err = %v, want ErrAccountNotFound", err)
	}
	if _, err := me.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, zzlPx(1)); !errors.Is(err, ErrPositionNotFound) {
		t.Fatalf("unknown market err = %v, want ErrPositionNotFound", err)
	}
	pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pos.Margin = big.NewInt(5000)

	// A healthy position may not be liquidated, and the attempt leaves it intact.
	safeEdge := zzlBisect(big.NewInt(0), zzlPx(100), func(k *big.Int) bool {
		return me.isPositionLiquidatable(pos, new(big.Int).Sub(zzlPx(100), k), DefaultMaintenanceMargin)
	})
	pSafe := new(big.Int).Sub(zzlPx(100), new(big.Int).Sub(safeEdge, big.NewInt(1)))
	if _, err := me.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, pSafe); !errors.Is(err, ErrPositionNotLiquidatable) {
		t.Fatalf("one wei inside the maintenance threshold: err = %v, want ErrPositionNotLiquidatable", err)
	}
	if me.Accounts[zzlOwner].Positions[zzlMarket] == nil {
		t.Fatal("a refused liquidation removed the position")
	}
	// One wei past it, the same call succeeds. The threshold is exact.
	pKill := new(big.Int).Sub(zzlPx(100), safeEdge)
	if _, err := me.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, pKill); err != nil {
		t.Fatalf("one wei past the maintenance threshold: %v", err)
	}
	if me.Accounts[zzlOwner].Positions[zzlMarket] != nil {
		t.Fatal("a successful liquidation left the position open")
	}
}

func TestZzlMarginLiquidationNeverSeizesMoreThanThePositionHolds(t *testing.T) {
	// Across a sweep of margins and prices, the liquidator reward plus the
	// insurance take must never exceed the position's remaining equity, and the
	// reward must never be negative.
	for _, margin := range []int64{1, 100, 5000, 20_000, 100_000} {
		for _, price := range []int64{1, 10, 50, 80, 95, 99} {
			me, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
			pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			pos.Margin = big.NewInt(margin)
			p := zzlPx(price)
			if !me.isPositionLiquidatable(pos, p, DefaultMaintenanceMargin) {
				continue
			}
			fundBefore := new(big.Int).Set(me.InsuranceFund)
			pnl := me.calculatePnL(pos, p, pos.Size)
			remaining := new(big.Int).Add(pos.Margin, pnl)

			reward, err := me.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, p)
			if err != nil {
				t.Fatalf("margin=%d price=%d: %v", margin, price, err)
			}
			if reward.Sign() < 0 {
				t.Fatalf("margin=%d price=%d: negative liquidator reward %s", margin, price, reward)
			}
			insuranceTake := new(big.Int).Sub(me.InsuranceFund, fundBefore)
			seized := new(big.Int).Add(reward, insuranceTake)
			if remaining.Sign() > 0 && seized.Cmp(remaining) > 0 {
				t.Fatalf("margin=%d price=%d: seized %s from a position holding %s",
					margin, price, seized, remaining)
			}
			if remaining.Sign() <= 0 && reward.Sign() != 0 {
				t.Fatalf("margin=%d price=%d: paid %s out of an insolvent position", margin, price, reward)
			}
		}
	}
}

// DEFECT (reported): the liquidation fees total DefaultLiquidatorReward +
// DefaultLiquidationPenalty = 750 bps of notional, but liquidation is only
// permitted once equity has fallen below the maintenance requirement of
// DefaultMaintenanceMargin = 500 bps. Since 750 > 500, the remaining equity is
// ALWAYS smaller than the fees at the moment liquidation becomes legal: the
// full-fee branch of LiquidatePosition can never execute, and every liquidation
// is a socialized-loss event.
func TestZzlMarginLiquidationFeesAlwaysExceedWhatThePositionCanPay(t *testing.T) {
	if DefaultLiquidatorReward+DefaultLiquidationPenalty <= DefaultMaintenanceMargin {
		t.Fatalf("fees (%d bps) no longer exceed maintenance (%d bps); the full-fee branch is "+
			"now reachable — update the reported finding and cover it",
			DefaultLiquidatorReward+DefaultLiquidationPenalty, DefaultMaintenanceMargin)
	}

	// Demonstrated rather than merely argued: over a sweep of margins and prices,
	// every position that is liquidatable at all holds less than the fees ask.
	checked := 0
	for _, margin := range []int64{1, 500, 5_000, 20_000, 60_000, 99_000} {
		for _, price := range []int64{1, 5, 20, 50, 75, 90, 95, 99} {
			me, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
			pos, err := me.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			pos.Margin = big.NewInt(margin)
			p := zzlPx(price)
			if !me.isPositionLiquidatable(pos, p, DefaultMaintenanceMargin) {
				continue
			}
			checked++
			notional := new(big.Int).Mul(pos.Size, p)
			notional.Div(notional, Q96)
			fees := new(big.Int).Mul(notional,
				big.NewInt(DefaultLiquidatorReward+DefaultLiquidationPenalty))
			fees.Div(fees, big.NewInt(MarginPrecision))
			remaining := new(big.Int).Add(pos.Margin, me.calculatePnL(pos, p, pos.Size))
			if fees.Cmp(remaining) <= 0 {
				t.Fatalf("margin=%d price=%d: fees %s <= remaining %s, so the full-fee branch "+
					"IS reachable here", margin, price, fees, remaining)
			}

			// Solvent-but-liquidatable: the equity is split in half between the
			// liquidator and the fund, and the split conserves it exactly.
			if remaining.Sign() <= 0 {
				continue
			}
			got, err := me.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, p)
			if err != nil {
				t.Fatalf("margin=%d price=%d: %v", margin, price, err)
			}
			half := new(big.Int).Div(remaining, big.NewInt(2))
			if got.Cmp(half) != 0 {
				t.Fatalf("margin=%d price=%d: reward %s, want remaining/2 = %s",
					margin, price, got, half)
			}
			if sum := new(big.Int).Add(got, me.InsuranceFund); sum.Cmp(remaining) != 0 {
				t.Fatalf("margin=%d price=%d: split %s + %s != remaining %s",
					margin, price, got, me.InsuranceFund, sum)
			}
			// The liquidator never takes more than half, so the fund is never
			// starved by the split.
			if got.Cmp(me.InsuranceFund) > 0 {
				t.Fatalf("margin=%d price=%d: liquidator took %s, more than the fund's %s",
					margin, price, got, me.InsuranceFund)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the sweep produced no liquidatable position; the fixture is not exercising anything")
	}
}

func TestZzlMarginLiquidationInsuranceDeficitPaths(t *testing.T) {
	deep := zzlPx(1)

	// Case: the position is insolvent and the insurance fund covers the hole.
	me2, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
	pos2, err := me2.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pos2.Margin = big.NewInt(1)
	me2.InsuranceFund = big.NewInt(1_000_000)
	before := new(big.Int).Set(me2.InsuranceFund)
	pnl2 := me2.calculatePnL(pos2, deep, pos2.Size)
	rem2 := new(big.Int).Add(pos2.Margin, pnl2)
	if rem2.Sign() > 0 {
		t.Fatalf("fixture: position is still solvent (%s)", rem2)
	}
	reward2, err := me2.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, deep)
	if err != nil {
		t.Fatalf("liquidate insolvent: %v", err)
	}
	if reward2.Sign() != 0 {
		t.Fatalf("insolvent liquidation paid %s, want 0", reward2)
	}
	deficit := new(big.Int).Neg(rem2)
	if new(big.Int).Sub(before, me2.InsuranceFund).Cmp(deficit) != 0 {
		t.Fatalf("insurance fund moved by %s, want the deficit %s",
			new(big.Int).Sub(before, me2.InsuranceFund), deficit)
	}

	// Case: a fund holding EXACTLY the deficit must still be spent. This is the
	// inclusive edge of the solvency comparison — a fund that can just cover the
	// hole has to, or the loss is socialised while the money to absorb it sits
	// unused.
	meEq, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
	posEq, err := meEq.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	posEq.Margin = big.NewInt(1)
	remEq := new(big.Int).Add(posEq.Margin, meEq.calculatePnL(posEq, deep, posEq.Size))
	if remEq.Sign() >= 0 {
		t.Fatalf("fixture: the position is solvent (%s)", remEq)
	}
	exact := new(big.Int).Neg(remEq)
	meEq.InsuranceFund = new(big.Int).Set(exact)
	if _, err := meEq.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, deep); err != nil {
		t.Fatalf("liquidate against an exactly-sufficient fund: %v", err)
	}
	if meEq.InsuranceFund.Sign() != 0 {
		t.Fatalf("insurance fund = %s, want it drained to exactly 0 by a deficit of %s",
			meEq.InsuranceFund, exact)
	}
	// One unit short of the deficit is NOT enough, and the fund is left whole
	// rather than partially spent.
	meShort, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
	posShort, err := meShort.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	posShort.Margin = big.NewInt(1)
	oneShort := new(big.Int).Sub(exact, big.NewInt(1))
	meShort.InsuranceFund = new(big.Int).Set(oneShort)
	if _, err := meShort.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, deep); err != nil {
		t.Fatalf("liquidate against a one-unit-short fund: %v", err)
	}
	if meShort.InsuranceFund.Cmp(oneShort) != 0 {
		t.Fatalf("insurance fund = %s, want it left whole at %s", meShort.InsuranceFund, oneShort)
	}

	// Case: the same hole with a fund too small to cover it leaves the fund
	// untouched rather than driving it negative.
	me3, _ := zzlMarginEngine(t, CrossMargin, 100_000_000)
	pos3, err := me3.OpenPosition(zzlOwner, zzlMarket, Long, zzlBig(1000), 10, zzlPx(100), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pos3.Margin = big.NewInt(1)
	me3.InsuranceFund = big.NewInt(1)
	reward3, err := me3.LiquidatePosition(zzlLiquidator, zzlOwner, zzlMarket, deep)
	if err != nil {
		t.Fatalf("liquidate with an empty fund: %v", err)
	}
	if reward3.Sign() != 0 {
		t.Fatalf("reward = %s, want 0", reward3)
	}
	if me3.InsuranceFund.Sign() < 0 {
		t.Fatalf("insurance fund went negative: %s", me3.InsuranceFund)
	}
	if me3.InsuranceFund.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("insurance fund = %s, want it left at 1 when it cannot cover the deficit",
			me3.InsuranceFund)
	}
}

func TestZzlMarginLiquidationConservesTheInsuranceFundAcrossManyLiquidations(t *testing.T) {
	// The insurance fund only ever grows by what it takes and shrinks by what it
	// pays; it must never end negative, whatever sequence of liquidations runs.
	me, _ := zzlMarginEngine(t, CrossMargin, 1_000_000_000)
	me.InsuranceFund = big.NewInt(500_000)
	markets := [][32]byte{{1}, {2}, {3}, {4}, {5}, {6}}
	margins := []int64{1, 10, 500, 5000, 50_000, 500_000}

	for i, m := range markets {
		pos, err := me.OpenPosition(zzlOwner, m, Long, zzlBig(1000), 10, zzlPx(100), false)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		pos.Margin = big.NewInt(margins[i])
	}
	for i, m := range markets {
		p := zzlPx(int64(1 + i*3))
		pos := me.Accounts[zzlOwner].Positions[m]
		if pos == nil || !me.isPositionLiquidatable(pos, p, DefaultMaintenanceMargin) {
			continue
		}
		if _, err := me.LiquidatePosition(zzlLiquidator, zzlOwner, m, p); err != nil {
			t.Fatalf("liquidate %d: %v", i, err)
		}
		if me.InsuranceFund.Sign() < 0 {
			t.Fatalf("insurance fund went negative after liquidation %d: %s", i, me.InsuranceFund)
		}
	}
}
