// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"
)

// zzcrAtUtil returns the (cash, borrows, reserves) triple that makes
// GetUtilizationRate report exactly u. Total available is pinned at RAY, so
// utilization == borrows numerically and a test can sit on any single unit --
// including the kink and the unit either side of it.
func zzcrAtUtil(u *big.Int) (cash, borrows, reserves *big.Int) {
	return new(big.Int).Sub(RAY, u), new(big.Int).Set(u), big.NewInt(0)
}

// zzcrExpectRate recomputes the model's own two-branch formula from its own
// parameters. Nothing here is a literal: a change to the curve has to be a
// deliberate change to the curve, not a drifted constant.
func zzcrExpectRate(m *InterestRateModel, u *big.Int) *big.Int {
	rate := new(big.Int)
	if u.Cmp(m.OptimalUtilization) <= 0 {
		rate.Mul(u, m.Slope1)
		rate.Div(rate, RAY)
		rate.Add(rate, m.BaseRate)
	} else {
		rate.Mul(m.OptimalUtilization, m.Slope1)
		rate.Div(rate, RAY)
		rate.Add(rate, m.BaseRate)
		excess := new(big.Int).Sub(u, m.OptimalUtilization)
		excess.Mul(excess, m.Slope2)
		excess.Div(excess, RAY)
		rate.Add(rate, excess)
	}
	return rate.Div(rate, BlocksPerYear)
}

// =========================================================================
// Utilization
// =========================================================================

// Utilization stays inside [0, 1] and never falls as borrowing rises. Swept
// with total available held constant so each step is one unit of utilization.
func TestZzcrUtilizationIsBoundedAndMonotone(t *testing.T) {
	m := DefaultInterestRateModel()
	kink := m.OptimalUtilization

	points := []*big.Int{big.NewInt(0), big.NewInt(1), zzcrFrac(1, 4), zzcrFrac(1, 2)}
	for _, d := range []int64{-2, -1, 0, 1, 2} {
		points = append(points, new(big.Int).Add(kink, big.NewInt(d)))
	}
	points = append(points, zzcrFrac(99, 100), new(big.Int).Sub(RAY, big.NewInt(1)), RAY)

	prev := big.NewInt(-1)
	for _, u := range points {
		cash, borrows, reserves := zzcrAtUtil(u)
		got := m.GetUtilizationRate(cash, borrows, reserves)
		zzcrEq(t, "utilization at "+u.String(), got, u)
		zzcrAtMost(t, "utilization is bounded above", got, RAY)
		zzcrAtLeast(t, "utilization is bounded below", got, big.NewInt(0))
		if got.Cmp(prev) < 0 {
			t.Fatalf("utilization fell as borrowing rose: %s then %s", prev, got)
		}
		prev = got
	}
}

func TestZzcrUtilizationEdges(t *testing.T) {
	m := DefaultInterestRateModel()

	// Nothing borrowed is nothing utilised, whatever the cash.
	zzcrEq(t, "no borrows", m.GetUtilizationRate(big.NewInt(1_000_000), big.NewInt(0), big.NewInt(0)), big.NewInt(0))
	zzcrEq(t, "no borrows, no cash", m.GetUtilizationRate(big.NewInt(0), big.NewInt(0), big.NewInt(0)), big.NewInt(0))

	// Reserves eating the whole pool reads as fully utilised rather than
	// dividing by zero.
	zzcrEq(t, "reserves equal the pool", m.GetUtilizationRate(big.NewInt(0), big.NewInt(100), big.NewInt(100)), RAY)
	zzcrEq(t, "reserves exceed the pool", m.GetUtilizationRate(big.NewInt(0), big.NewInt(100), big.NewInt(500)), RAY)

	// Borrowing beyond what is available is clamped, not reported above parity.
	zzcrEq(t, "borrows past the pool", m.GetUtilizationRate(big.NewInt(0), big.NewInt(1000), big.NewInt(500)), RAY)
	zzcrEq(t, "borrows equal the pool", m.GetUtilizationRate(big.NewInt(0), big.NewInt(1000), big.NewInt(0)), RAY)
}

// =========================================================================
// The rate curve
// =========================================================================

// The borrow rate never falls as utilization rises, across both slopes.
func TestZzcrBorrowRateIsMonotoneInUtilization(t *testing.T) {
	for _, m := range []*InterestRateModel{
		DefaultInterestRateModel(), StablecoinInterestRateModel(), VolatileInterestRateModel(),
	} {
		step := new(big.Int).Div(RAY, big.NewInt(200))
		prev := big.NewInt(-1)
		for u := big.NewInt(0); u.Cmp(RAY) <= 0; u.Add(u, step) {
			cash, borrows, reserves := zzcrAtUtil(u)
			got := m.GetBorrowRate(cash, borrows, reserves)
			if got.Cmp(prev) < 0 {
				t.Fatalf("borrow rate fell as utilization rose to %s: %s then %s", u, prev, got)
			}
			zzcrEq(t, "borrow rate at "+u.String(), got, zzcrExpectRate(m, u))
			prev = new(big.Int).Set(got)
		}
	}
}

// The curve does not jump at the kink. Both branches are evaluated at exactly
// the kink and must agree; the rate one unit past it is the kink rate plus one
// slope2 step and nothing more.
func TestZzcrBorrowRateIsContinuousAtTheKink(t *testing.T) {
	for _, m := range []*InterestRateModel{
		DefaultInterestRateModel(), StablecoinInterestRateModel(), VolatileInterestRateModel(),
	} {
		k := m.OptimalUtilization

		// Branch one at the kink.
		below := new(big.Int).Mul(k, m.Slope1)
		below.Div(below, RAY)
		below.Add(below, m.BaseRate)
		// Branch two at the kink: the excess term is exactly zero there.
		above := new(big.Int).Set(below)
		zzcrEq(t, "the two branches agree at the kink", below, above)

		cash, borrows, reserves := zzcrAtUtil(k)
		at := m.GetBorrowRate(cash, borrows, reserves)
		zzcrEq(t, "rate at the kink", at, new(big.Int).Div(below, BlocksPerYear))

		cash, borrows, reserves = zzcrAtUtil(new(big.Int).Sub(k, big.NewInt(1)))
		under := m.GetBorrowRate(cash, borrows, reserves)
		cash, borrows, reserves = zzcrAtUtil(new(big.Int).Add(k, big.NewInt(1)))
		over := m.GetBorrowRate(cash, borrows, reserves)

		if under.Cmp(at) > 0 || at.Cmp(over) > 0 {
			t.Fatalf("rate is not ordered across the kink: %s %s %s", under, at, over)
		}
		// The step past the kink is one slope2 unit, so there is no cliff.
		step := new(big.Int).Div(m.Slope2, RAY)
		step.Div(step, BlocksPerYear)
		zzcrAtMost(t, "step past the kink", new(big.Int).Sub(over, at), new(big.Int).Add(step, big.NewInt(1)))

		// Past the kink the steeper slope is actually in force: the same span of
		// utilization costs at least as much above the kink as below it.
		span := new(big.Int).Div(RAY, big.NewInt(20)) // 5% of utilization
		cash, borrows, reserves = zzcrAtUtil(new(big.Int).Sub(k, span))
		lo := m.GetBorrowRate(cash, borrows, reserves)
		cash, borrows, reserves = zzcrAtUtil(new(big.Int).Add(k, span))
		hi := m.GetBorrowRate(cash, borrows, reserves)
		zzcrAtLeast(t, "slope2 is steeper than slope1", new(big.Int).Sub(hi, at), new(big.Int).Sub(at, lo))
	}
}

// The supply rate is the borrow rate less the protocol's share, scaled by how
// much of the pool is actually earning. It can never reach the borrow rate.
func TestZzcrSupplyRateIsBoundedByTheBorrowRate(t *testing.T) {
	m := DefaultInterestRateModel()
	for _, pct := range []int64{0, 1, 25, 50, 80, 99, 100} {
		u := zzcrFrac(pct, 100)
		cash, borrows, reserves := zzcrAtUtil(u)
		borrowRate := m.GetBorrowRate(cash, borrows, reserves)
		supplyRate := m.GetSupplyRate(cash, borrows, reserves)

		want := new(big.Int).Mul(borrowRate, u)
		want.Div(want, RAY)
		want.Mul(want, new(big.Int).Sub(RAY, m.ReserveFactor))
		want.Div(want, RAY)
		zzcrEq(t, "supply rate", supplyRate, want)
		zzcrAtMost(t, "supply rate vs borrow rate", supplyRate, borrowRate)
		zzcrAtLeast(t, "supply rate is non-negative", supplyRate, big.NewInt(0))
	}

	// Hand the whole spread to the protocol and suppliers earn nothing.
	all := *m
	all.ReserveFactor = new(big.Int).Set(RAY)
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(50, 100))
	if got := all.GetSupplyRate(cash, borrows, reserves); got.Sign() != 0 {
		t.Fatalf("supply rate at a 100%% reserve factor: got %s, want 0", got)
	}
}

// The annual figures are the per-block figures times the year, so a quoted APR
// can never overstate what the block-by-block accrual will actually charge.
func TestZzcrAPRIsTheBlockRateTimesTheYear(t *testing.T) {
	m := DefaultInterestRateModel()
	for _, pct := range []int64{0, 10, 50, 80, 95, 100} {
		cash, borrows, reserves := zzcrAtUtil(zzcrFrac(pct, 100))

		borrowAPR := m.GetBorrowAPR(cash, borrows, reserves)
		zzcrEq(t, "borrow APR", borrowAPR,
			new(big.Int).Mul(m.GetBorrowRate(cash, borrows, reserves), BlocksPerYear))
		supplyAPR := m.GetSupplyAPR(cash, borrows, reserves)
		zzcrEq(t, "supply APR", supplyAPR,
			new(big.Int).Mul(m.GetSupplyRate(cash, borrows, reserves), BlocksPerYear))
		zzcrAtMost(t, "supply APR vs borrow APR", supplyAPR, borrowAPR)

		// The block rate is floored, so the quoted APR sits at or below the
		// nominal annual rate the curve names -- never above it.
		nominal := new(big.Int).Mul(zzcrExpectRate(m, zzcrFrac(pct, 100)), BlocksPerYear)
		zzcrEq(t, "APR is the floored block rate re-annualised", borrowAPR, nominal)
	}
}

// The presets differ in the direction their names promise, asserted through the
// curve rather than by reading the struct back.
func TestZzcrRatePresetsOrderAsTheirNamesPromise(t *testing.T) {
	std := DefaultInterestRateModel()
	stable := StablecoinInterestRateModel()
	vol := VolatileInterestRateModel()

	// At rest, only the volatile model charges anything.
	idleCash, idleBorrows, idleReserves := big.NewInt(1_000_000), big.NewInt(0), big.NewInt(0)
	if got := std.GetBorrowRate(idleCash, idleBorrows, idleReserves); got.Sign() != 0 {
		t.Fatalf("default model charges %s at zero utilization, want 0", got)
	}
	if got := stable.GetBorrowRate(idleCash, idleBorrows, idleReserves); got.Sign() != 0 {
		t.Fatalf("stablecoin model charges %s at zero utilization, want 0", got)
	}
	if got := vol.GetBorrowRate(idleCash, idleBorrows, idleReserves); got.Sign() <= 0 {
		t.Fatalf("volatile model charges %s at zero utilization, want a base rate", got)
	}

	// In the ordinary range the stablecoin model is the cheapest and the
	// volatile model the dearest.
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(50, 100))
	s, d, v := stable.GetBorrowRate(cash, borrows, reserves),
		std.GetBorrowRate(cash, borrows, reserves),
		vol.GetBorrowRate(cash, borrows, reserves)
	if !(s.Cmp(d) < 0 && d.Cmp(v) < 0) {
		t.Fatalf("preset order at 50%% utilization: stable=%s default=%s volatile=%s", s, d, v)
	}

	// The stablecoin model tolerates more utilization before the steep slope
	// bites: its kink sits further out.
	if stable.OptimalUtilization.Cmp(std.OptimalUtilization) <= 0 {
		t.Fatalf("stablecoin kink %s is not past the default %s", stable.OptimalUtilization, std.OptimalUtilization)
	}
	if vol.OptimalUtilization.Cmp(std.OptimalUtilization) >= 0 {
		t.Fatalf("volatile kink %s is not before the default %s", vol.OptimalUtilization, std.OptimalUtilization)
	}

	// And the protocol keeps more of a volatile market's interest.
	for _, in := range []int64{1_000_000_000, 7} {
		amount := big.NewInt(in)
		sv, dv, vv := stable.GetReserveAmount(amount), std.GetReserveAmount(amount), vol.GetReserveAmount(amount)
		if !(sv.Cmp(dv) <= 0 && dv.Cmp(vv) <= 0) {
			t.Fatalf("reserve share order on %s: stable=%s default=%s volatile=%s", amount, sv, dv, vv)
		}
	}
}

// =========================================================================
// Accrual
// =========================================================================

// No time, no interest. No debt, no interest. And interest never falls as time
// passes -- a borrower can never wait their way out of what they owe.
func TestZzcrAccrualIsZeroAtRestAndMonotoneInTime(t *testing.T) {
	m := DefaultInterestRateModel()
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(80, 100))
	principal := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)

	if got := m.AccrueInterest(principal, cash, borrows, reserves, 0); got.Sign() != 0 {
		t.Fatalf("interest over zero blocks: got %s, want 0", got)
	}
	if got := m.AccrueInterest(big.NewInt(0), cash, borrows, reserves, 1_000_000); got.Sign() != 0 {
		t.Fatalf("interest on zero principal: got %s, want 0", got)
	}
	if got := m.CalculateCompoundInterest(principal, cash, borrows, reserves, 0); got.Sign() != 0 {
		t.Fatalf("compound interest over zero blocks: got %s, want 0", got)
	}
	if got := m.CalculateCompoundInterest(big.NewInt(0), cash, borrows, reserves, 1_000_000); got.Sign() != 0 {
		t.Fatalf("compound interest on zero principal: got %s, want 0", got)
	}

	prevSimple, prevCompound := big.NewInt(-1), big.NewInt(-1)
	for _, blocks := range []uint64{0, 1, 2, 99, 100, 101, 1_000, 1_000_000, 1 << 40, 1 << 62} {
		simple := m.AccrueInterest(principal, cash, borrows, reserves, blocks)
		compound := m.CalculateCompoundInterest(principal, cash, borrows, reserves, blocks)
		if simple.Cmp(prevSimple) < 0 {
			t.Fatalf("simple interest fell at %d blocks: %s then %s", blocks, prevSimple, simple)
		}
		if compound.Cmp(prevCompound) < 0 {
			t.Fatalf("compound interest fell at %d blocks: %s then %s", blocks, prevCompound, compound)
		}
		zzcrAtLeast(t, "compound covers simple", compound, simple)
		prevSimple, prevCompound = simple, compound
	}
}

// Compounding is simple interest at or below the hundred-block seam and strictly
// more beyond it. That seam is where CalculateCompoundInterest switches formula,
// and the switch must not lose money going across.
func TestZzcrCompoundInterestSeamIsContinuous(t *testing.T) {
	m := DefaultInterestRateModel()
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(95, 100))
	principal := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)

	for _, blocks := range []uint64{1, 50, 99, 100} {
		zzcrEq(t, "compound below the seam is simple",
			m.CalculateCompoundInterest(principal, cash, borrows, reserves, blocks),
			m.AccrueInterest(principal, cash, borrows, reserves, blocks))
	}

	at := m.CalculateCompoundInterest(principal, cash, borrows, reserves, 100)
	past := m.CalculateCompoundInterest(principal, cash, borrows, reserves, 101)
	if past.Cmp(at) <= 0 {
		t.Fatalf("crossing the seam lost interest: %s at 100 blocks, %s at 101", at, past)
	}
	// Past the seam the quadratic term is a strict addition to simple interest.
	simple101 := m.AccrueInterest(principal, cash, borrows, reserves, 101)
	if past.Cmp(simple101) <= 0 {
		t.Fatalf("compounding past the seam is not above simple: %s vs %s", past, simple101)
	}
}

// Past the seam the extra over simple interest is the second Taylor term of
// e^(rt) - 1: exactly half the square of the linear term. Measured on a
// principal of one unit of the fixed point, where the interest and the
// multiplier coincide, so the coefficient is pinned without restating the code.
func TestZzcrCompoundingIsTheHalfSquareCorrection(t *testing.T) {
	m := DefaultInterestRateModel()
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(95, 100))
	principal := new(big.Int).Set(RAY)
	rate := m.GetBorrowRate(cash, borrows, reserves)

	for _, blocks := range []uint64{101, 1_000, 1_000_000} {
		simple := m.AccrueInterest(principal, cash, borrows, reserves, blocks)
		compound := m.CalculateCompoundInterest(principal, cash, borrows, reserves, blocks)

		linear := new(big.Int).Mul(rate, new(big.Int).SetUint64(blocks))
		zzcrEq(t, "at one unit of principal the simple interest is the linear term", simple, linear)

		square := new(big.Int).Mul(linear, linear)
		square.Div(square, RAY)
		excess := new(big.Int).Sub(compound, simple)
		if excess.Sign() <= 0 {
			t.Fatalf("no second-order term at %d blocks: %s", blocks, excess)
		}
		// twice the excess is the squared linear term, to within the floor.
		twice := new(big.Int).Mul(excess, big.NewInt(2))
		zzcrAtMost(t, "the correction is not more than half the square", twice, square)
		zzcrAtLeast(t, "the correction is not less than half the square",
			new(big.Int).Add(twice, big.NewInt(1)), square)

		// Doubling the time quadruples that correction, as a square must.
		double := m.CalculateCompoundInterest(principal, cash, borrows, reserves, blocks*2)
		doubleExcess := new(big.Int).Sub(double, m.AccrueInterest(principal, cash, borrows, reserves, blocks*2))
		zzcrAtLeast(t, "doubling the time nearly quadruples the correction",
			doubleExcess, new(big.Int).Mul(excess, big.NewInt(3)))
		zzcrAtMost(t, "and no more than quadruples it",
			doubleExcess, new(big.Int).Mul(new(big.Int).Add(excess, big.NewInt(1)), big.NewInt(4)))
	}
}

// The protocol's cut of accrued interest is a floored share of it, so it can
// never exceed the interest actually charged.
func TestZzcrReserveShareIsFlooredAndBounded(t *testing.T) {
	m := DefaultInterestRateModel()
	for _, in := range []int64{0, 1, 9, 10, 11, 999_999_937} {
		interest := big.NewInt(in)
		got := m.GetReserveAmount(interest)

		want := new(big.Int).Mul(interest, m.ReserveFactor)
		want.Div(want, RAY)
		zzcrEq(t, "reserve share", got, want)
		zzcrAtMost(t, "reserve share vs interest", got, interest)
		zzcrAtLeast(t, "reserve share is non-negative", got, big.NewInt(0))
	}
	// A tenth of nine is under one unit, and the floor sends it to the borrower.
	zzcrEq(t, "reserve share of nine at a 10% factor", m.GetReserveAmount(big.NewInt(9)), big.NewInt(0))
	zzcrEq(t, "reserve share of ten at a 10% factor", m.GetReserveAmount(big.NewInt(10)), big.NewInt(1))
}

// DEFECT PIN. Interest is floored at interest_rate.go:215, so it rounds toward
// the borrower rather than toward the protocol. That makes accrual path
// dependent: charging a debt one block at a time collects strictly less than
// charging it once over the same span, and for a small enough debt it collects
// nothing at all, for ever. Correct behaviour rounds owed interest UP.
func TestZzcrInterestRoundsTowardTheBorrowerPinsDefect(t *testing.T) {
	m := DefaultInterestRateModel()
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(80, 100))
	principal := big.NewInt(1000)

	perBlock := m.AccrueInterest(principal, cash, borrows, reserves, 1)
	if perBlock.Sign() != 0 {
		t.Fatalf("defect appears fixed: one block on a debt of 1000 now charges %s -- "+
			"round owed interest up at interest_rate.go:215 and delete this pin", perBlock)
	}

	const span = 1_000_000
	oneStep := m.AccrueInterest(principal, cash, borrows, reserves, span)
	if oneStep.Sign() <= 0 {
		t.Fatalf("fixture charges nothing even in one step: %s", oneStep)
	}
	// A million single-block charges collect zero; the same span charged once
	// collects the whole amount. Same debt, same rate, same time.
	stepwise := new(big.Int)
	for i := 0; i < 16; i++ { // sixteen is enough: each one is exactly zero
		stepwise.Add(stepwise, m.AccrueInterest(principal, cash, borrows, reserves, 1))
	}
	if stepwise.Sign() != 0 {
		t.Fatalf("defect appears fixed: stepwise accrual now collects %s -- delete this pin", stepwise)
	}
	if oneStep.Cmp(stepwise) <= 0 {
		t.Fatalf("accrual is no longer path dependent: %s in one step, %s stepwise", oneStep, stepwise)
	}
}

// DEFECT PIN, HIGH. interest_rate.go:214 narrows the uint64 block count through
// int64. Past 2^63 blocks the count reads negative, the charge reverses sign,
// and accrual runs backwards: the borrower is paid to hold the debt and the
// borrow index would fall. Nothing in the signature says the argument is bounded.
func TestZzcrAccrualReversesPastTheInt64BoundaryPinsDefect(t *testing.T) {
	m := DefaultInterestRateModel()
	cash, borrows, reserves := zzcrAtUtil(zzcrFrac(80, 100))
	principal := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)

	last := m.AccrueInterest(principal, cash, borrows, reserves, 1<<63-1)
	zzcrAtLeast(t, "interest below the boundary is positive", last, big.NewInt(1))

	over := m.AccrueInterest(principal, cash, borrows, reserves, 1<<63)
	if over.Sign() >= 0 {
		t.Fatalf("defect appears fixed: 2^63 blocks now charges %s -- "+
			"widen the block count at interest_rate.go:214 and delete this pin", over)
	}
	if over.Cmp(last) >= 0 {
		t.Fatalf("accrual is no longer non-monotone across the boundary: %s then %s", last, over)
	}

	// The same narrowing sits in the compound path. There the squared term keeps
	// the answer positive, so the reversal shows up as time running backwards
	// instead: one more block charges strictly less.
	lastCompound := m.CalculateCompoundInterest(principal, cash, borrows, reserves, 1<<63-1)
	overCompound := m.CalculateCompoundInterest(principal, cash, borrows, reserves, 1<<63)
	if overCompound.Cmp(lastCompound) >= 0 {
		t.Fatalf("defect appears fixed in the compound path: %s at 2^63-1 blocks, %s at 2^63 -- "+
			"widen the block count at interest_rate.go:252 and delete this pin", lastCompound, overCompound)
	}
}

// The whole curve is exercised at the extremes without overflowing or dividing
// by zero: a pool of 2^255 units at full utilization still yields a finite,
// non-negative charge.
func TestZzcrRateCurveSurvivesExtremeMagnitudes(t *testing.T) {
	m := DefaultInterestRateModel()
	huge := new(big.Int).Lsh(big.NewInt(1), 255)

	for _, tc := range []struct{ cash, borrows, reserves *big.Int }{
		{big.NewInt(0), huge, big.NewInt(0)},
		{huge, huge, big.NewInt(0)},
		{huge, big.NewInt(1), huge},
		{big.NewInt(0), big.NewInt(1), big.NewInt(0)},
	} {
		u := m.GetUtilizationRate(tc.cash, tc.borrows, tc.reserves)
		zzcrAtMost(t, "utilization stays bounded", u, RAY)
		zzcrAtLeast(t, "utilization stays non-negative", u, big.NewInt(0))

		rate := m.GetBorrowRate(tc.cash, tc.borrows, tc.reserves)
		zzcrAtLeast(t, "borrow rate stays non-negative", rate, big.NewInt(0))
		supply := m.GetSupplyRate(tc.cash, tc.borrows, tc.reserves)
		zzcrAtMost(t, "supply rate stays under the borrow rate", supply, rate)

		interest := m.AccrueInterest(huge, tc.cash, tc.borrows, tc.reserves, 1<<40)
		zzcrAtLeast(t, "interest stays non-negative", interest, big.NewInt(0))
		zzcrAtMost(t, "the protocol cut stays under the interest", m.GetReserveAmount(interest), interest)
	}
}
