// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
)

// =========================================================================
// The liquidation boundary
// =========================================================================

// A position sitting at health factor exactly 1.0 is healthy. Every one of the
// three places that compares against the threshold has to agree on that, or a
// borrower who never broke a rule gets liquidated one unit early. Borrowing the
// maximum the collateral factor allows lands on exactly 1.0, so this is not a
// contrived state: it is what the Borrow guard produces at its own limit.
func TestZzcrLiquidationBoundaryIsInclusiveOfHealth(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 100_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 750) // 1000 * 0.75 == the exact maximum

	zzcrEq(t, "health at the borrow limit", m.health(zzcrBorrower), RAY)

	if m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
		t.Fatal("position at health factor exactly 1.0 reported liquidatable")
	}
	if got := m.liq.GetLiquidatableAmount(m.db, zzcrBorrower, m.asset); got.Sign() != 0 {
		t.Fatalf("liquidatable amount at health 1.0: got %s, want 0", got)
	}
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(100)); err != ErrPositionHealthy {
		t.Fatalf("liquidating a position at health 1.0: got %v, want ErrPositionHealthy", err)
	}

	// One unit of debt past the limit and all three agree it is liquidatable.
	m.zzcrPushDebt(t, zzcrBorrower, 751)
	if m.health(zzcrBorrower).Cmp(RAY) >= 0 {
		t.Fatalf("health one unit past the limit: got %s, want < %s", m.health(zzcrBorrower), RAY)
	}
	if !m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
		t.Fatal("position one unit past the limit reported healthy")
	}
	if got := m.liq.GetLiquidatableAmount(m.db, zzcrBorrower, m.asset); got.Sign() == 0 {
		t.Fatal("liquidatable amount one unit past the limit is zero")
	}
	debt, coll, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1000))
	if err != nil {
		t.Fatalf("Liquidate one unit past the limit: %v", err)
	}
	if debt.Sign() <= 0 || coll.Sign() <= 0 {
		t.Fatalf("liquidation moved nothing: debt=%s collateral=%s", debt, coll)
	}
}

// Everything the borrow guard admits must be outside the liquidator's reach. This
// is the load-bearing relationship between lending.go:384 and liquidation.go:155,
// swept rather than spot-checked: any pair of guards that disagree by one unit
// shows up here. Deterministic seed 0x5EEDC0DE, fixed for reproducibility.
func TestZzcrHealthyPositionsAreNeverLiquidatable(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EEDC0DE))
	lp := NewLendingPool(NewPoolManager())
	liq := NewLiquidator(lp)

	for i := 0; i < 20_000; i++ {
		collateral := new(big.Int).SetInt64(rng.Int63n(1_000_000_000) + 1)
		factor := zzcrFrac(rng.Int63n(100)+1, 100)
		res := &Reserve{CollateralFactor: factor}

		// The exact ceiling the Borrow guard enforces.
		maxBorrow := new(big.Int).Mul(collateral, factor)
		maxBorrow.Div(maxBorrow, RAY)
		if maxBorrow.Sign() == 0 {
			continue
		}
		debt := new(big.Int).Rand(rng, maxBorrow)
		debt.Add(debt, big.NewInt(1)) // 1..maxBorrow, i.e. every admissible debt

		health := lp.calculateHealthFactor(collateral, debt, res)
		if health.Cmp(liq.config.LiquidationThreshold) < 0 {
			t.Fatalf("borrowable position is liquidatable: collateral=%s factor=%s debt=%s health=%s",
				collateral, factor, debt, health)
		}

		// And one unit past the ceiling must always be liquidatable, so the guard
		// is not merely conservative but exact.
		over := new(big.Int).Add(maxBorrow, big.NewInt(1))
		if h := lp.calculateHealthFactor(collateral, over, res); h.Cmp(liq.config.LiquidationThreshold) >= 0 {
			t.Fatalf("position past the borrow ceiling is not liquidatable: collateral=%s factor=%s debt=%s health=%s",
				collateral, factor, over, h)
		}
	}
}

// The same relationship through the real API rather than the bare arithmetic:
// supply, borrow the maximum, confirm untouchable; add one unit, confirm exposed.
func TestZzcrBorrowLimitAndLiquidationAgreeEndToEnd(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EEDC0DE))
	for i := 0; i < 200; i++ {
		pct := rng.Int63n(99) + 1
		collateral := rng.Int63n(1_000_000) + 100
		m := zzcrNewMarket(t, zzcrFrac(pct, 100), zzcrFrac(5, 100))
		m.supply(t, zzcrLender, 10_000_000)
		m.supply(t, zzcrBorrower, collateral)

		maxBorrow := collateral * pct / 100
		if maxBorrow == 0 {
			continue
		}
		if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(maxBorrow+1)); err != ErrMaxLTVExceeded {
			t.Fatalf("borrowing one past the limit (%d/%d at %d%%): got %v, want ErrMaxLTVExceeded",
				maxBorrow+1, collateral, pct, err)
		}
		m.borrow(t, zzcrBorrower, maxBorrow)
		if m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
			t.Fatalf("liquidatable straight after a legal max borrow: collateral=%d pct=%d", collateral, pct)
		}
		m.zzcrPushDebt(t, zzcrBorrower, maxBorrow+1)
		if !m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
			t.Fatalf("not liquidatable one unit past the limit: collateral=%d pct=%d", collateral, pct)
		}
	}
}

// =========================================================================
// What a liquidator may take
// =========================================================================

// Seizure is debt plus exactly the reserve's bonus, and the bonus rounds down --
// toward the borrower. Swept across bonus rates so a change of divisor or of
// rounding direction is caught wherever it is made.
func TestZzcrSeizureIsDebtPlusBonusRoundedDown(t *testing.T) {
	for _, pct := range []int64{0, 1, 5, 13, 50, 100} {
		bonus := zzcrFrac(pct, 100)
		res := &Reserve{LiquidationBonus: bonus}
		liq := NewLiquidator(NewLendingPool(NewPoolManager()))

		for _, debt := range []int64{1, 7, 99, 1000, 999_999_937} {
			d := big.NewInt(debt)
			collateral, got := liq.calculateCollateralToSeize(d, res)

			want := new(big.Int).Mul(d, bonus)
			want.Div(want, RAY) // floor: the borrower keeps the remainder
			zzcrEq(t, "bonus", got, want)
			zzcrEq(t, "collateral", collateral, new(big.Int).Add(d, want))

			// The two framings of the cap must agree, and seizure never dips below
			// the debt actually repaid.
			ceiling := new(big.Int).Mul(d, new(big.Int).Add(RAY, bonus))
			ceiling.Div(ceiling, RAY)
			zzcrAtMost(t, "seizure vs debt*(1+bonus)", collateral, ceiling)
			zzcrAtLeast(t, "seizure vs debt repaid", collateral, d)
		}
	}
}

// End to end: what Liquidate actually moves must obey the same ceiling, and the
// borrower's ledger must fall by exactly what the liquidator took.
func TestZzcrLiquidationMovesExactlyWhatItSeizes(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 100_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 750)
	m.zzcrPushDebt(t, zzcrBorrower, 751)

	res := m.reserve(t)
	pos := m.position(t, zzcrBorrower)
	sharesBefore := new(big.Int).Set(pos.SupplyShares)
	debtBefore := new(big.Int).Set(pos.BorrowAmount)
	supplyBefore := new(big.Int).Set(res.TotalSupply)
	borrowsBefore := new(big.Int).Set(res.TotalBorrows)
	reservesBefore := new(big.Int).Set(res.TotalReserves)
	keeperBefore := m.bal(zzcrKeeper)
	poolBefore := m.bal(lendingPoolAddr)

	repaid, seized, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(10_000))
	if err != nil {
		t.Fatalf("Liquidate: %v", err)
	}

	// Ceiling: never more than debt repaid plus the configured bonus.
	ceiling := new(big.Int).Mul(repaid, new(big.Int).Add(RAY, res.LiquidationBonus))
	ceiling.Div(ceiling, RAY)
	zzcrAtMost(t, "seized vs debt+bonus", seized, ceiling)

	// Close factor: never more than the configured share of the debt.
	cap := new(big.Int).Mul(debtBefore, m.liq.GetConfig().CloseFactor)
	cap.Div(cap, RAY)
	zzcrAtMost(t, "repaid vs close factor", repaid, cap)

	// The borrower's books move by exactly those two numbers.
	zzcrEq(t, "borrower debt", pos.BorrowAmount, new(big.Int).Sub(debtBefore, repaid))
	shares := new(big.Int).Mul(seized, RAY)
	shares.Div(shares, res.ExchangeRate)
	zzcrEq(t, "borrower shares", pos.SupplyShares, new(big.Int).Sub(sharesBefore, shares))
	zzcrAtLeast(t, "borrower shares stay non-negative", pos.SupplyShares, big.NewInt(0))

	// And so do the reserve totals.
	zzcrEq(t, "reserve total supply", res.TotalSupply, new(big.Int).Sub(supplyBefore, seized))
	zzcrEq(t, "reserve total borrows", res.TotalBorrows, new(big.Int).Sub(borrowsBefore, repaid))

	// Cash: the keeper pays the debt and takes the seizure less the protocol cut.
	bonus := new(big.Int).Sub(seized, repaid)
	fee := new(big.Int).Mul(bonus, m.liq.GetConfig().ProtocolFee)
	fee.Div(fee, RAY)
	zzcrEq(t, "protocol reserves", res.TotalReserves, new(big.Int).Add(reservesBefore, fee))

	keeperNet := new(big.Int).Sub(seized, fee)
	keeperNet.Sub(keeperNet, repaid)
	zzcrEq(t, "keeper balance", m.bal(zzcrKeeper), new(big.Int).Add(keeperBefore, keeperNet))
	zzcrEq(t, "pool balance", m.bal(lendingPoolAddr), new(big.Int).Sub(poolBefore, keeperNet))
}

// The close factor is the whole point of partial liquidation: asking for the
// world gets you the configured fraction of the debt and not a unit more.
func TestZzcrCloseFactorCapsOneLiquidation(t *testing.T) {
	for _, pct := range []int64{1, 25, 50, 100} {
		m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
		if err := m.liq.SetCloseFactor(zzcrFrac(pct, 100)); err != nil {
			t.Fatalf("SetCloseFactor(%d%%): %v", pct, err)
		}
		m.supply(t, zzcrLender, 10_000_000)
		m.supply(t, zzcrBorrower, 100_000)
		m.borrow(t, zzcrBorrower, 75_000)
		m.zzcrPushDebt(t, zzcrBorrower, 80_000)

		want := 80_000 * pct / 100
		repaid, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1<<40))
		if err != nil {
			t.Fatalf("Liquidate at close factor %d%%: %v", pct, err)
		}
		zzcrEq(t, "repaid under close factor", repaid, big.NewInt(want))
	}
}

// Seizure can never exceed what the borrower actually posted, however extravagant
// the bonus. Without the cap at liquidation.go:181 a large bonus would drive the
// borrower's share balance negative.
func TestZzcrSeizureCannotExceedBorrowerCollateral(t *testing.T) {
	m := zzcrNewMarket(t, RAY, new(big.Int).Mul(RAY, big.NewInt(10))) // 1000% bonus
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 1000)
	m.zzcrPushDebt(t, zzcrBorrower, 2000)

	pos := m.position(t, zzcrBorrower)
	res := m.reserve(t)
	supplyValue := new(big.Int).Mul(pos.SupplyShares, res.ExchangeRate)
	supplyValue.Div(supplyValue, RAY)

	repaid, seized, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1<<40))
	if err != nil {
		t.Fatalf("Liquidate: %v", err)
	}
	zzcrAtMost(t, "seized vs posted collateral", seized, supplyValue)
	zzcrAtLeast(t, "borrower shares stay non-negative", pos.SupplyShares, big.NewInt(0))
	zzcrAtLeast(t, "borrower debt stays non-negative", pos.BorrowAmount, big.NewInt(0))
	zzcrAtLeast(t, "something was repaid", repaid, big.NewInt(1))
}

// DEFECT PIN. When the seizure is capped by the borrower's collateral,
// liquidation.go:184 recovers the debt as collateral*RAY/(RAY+bonus) with a
// floor. Flooring the DEBT while holding the COLLATERAL at the cap hands the
// liquidator collateral worth more than debt*(1+bonus): the division rounds the
// wrong way. Correct behaviour rounds that debt UP, toward the protocol. The
// numbers below record the leak so a fix has to come here and delete the pin.
func TestZzcrCappedSeizureRoundsDebtTowardLiquidatorPinsDefect(t *testing.T) {
	m := zzcrNewMarket(t, RAY, new(big.Int).Mul(RAY, big.NewInt(10)))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 1000)
	m.zzcrPushDebt(t, zzcrBorrower, 2000)

	repaid, seized, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1<<40))
	if err != nil {
		t.Fatalf("Liquidate: %v", err)
	}
	// 1000 collateral for 90 of debt at a 10x bonus. Justified: 90*11 == 990.
	zzcrEq(t, "debt repaid", repaid, big.NewInt(90))
	zzcrEq(t, "collateral seized", seized, big.NewInt(1000))

	justified := new(big.Int).Mul(repaid, new(big.Int).Add(RAY, big.NewInt(10).Mul(big.NewInt(10), RAY)))
	justified.Div(justified, RAY)
	if seized.Cmp(justified) <= 0 {
		t.Fatalf("defect appears fixed: seized %s no longer exceeds the justified %s -- "+
			"round the debt recovery at liquidation.go:184 UP and delete this pin", seized, justified)
	}
	zzcrEq(t, "excess handed to the liquidator", new(big.Int).Sub(seized, justified), big.NewInt(10))
}

// =========================================================================
// Refusals
// =========================================================================

func TestZzcrLiquidationRefusals(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 100_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 750)

	unknown := common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, unknown, big.NewInt(1)); err != ErrReserveNotFound {
		t.Fatalf("unknown market: got %v, want ErrReserveNotFound", err)
	}
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrThird, m.asset, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("unknown position: got %v, want ErrNoDebtToRepay", err)
	}
	// A supplier with collateral but no debt is not a liquidation target either.
	m.supply(t, zzcrThird, 500)
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrThird, m.asset, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("no debt: got %v, want ErrNoDebtToRepay", err)
	}
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrPositionHealthy {
		t.Fatalf("healthy: got %v, want ErrPositionHealthy", err)
	}

	// Below the minimum liquidation size the engine refuses outright.
	m.zzcrPushDebt(t, zzcrBorrower, 751)
	m.liq.config.MinLiquidation = big.NewInt(100)
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(99)); err != ErrLiquidationTooSmall {
		t.Fatalf("under the minimum: got %v, want ErrLiquidationTooSmall", err)
	}
	// A negative request is refused by the same comparison.
	if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(-1000)); err != ErrLiquidationTooSmall {
		t.Fatalf("negative request: got %v, want ErrLiquidationTooSmall", err)
	}
	m.liq.config.MinLiquidation = big.NewInt(0)

	// Views agree with the engine rather than answering separately.
	if got := m.liq.GetLiquidatableAmount(m.db, zzcrKeeper, unknown); got.Sign() != 0 {
		t.Fatalf("liquidatable amount on an unknown market: %s", got)
	}
	if got := m.liq.GetLiquidatableAmount(m.db, zzcrThird, m.asset); got.Sign() != 0 {
		t.Fatalf("liquidatable amount with no debt: %s", got)
	}
	if got := m.liq.GetLiquidationBonus(m.db, zzcrBorrower, unknown, big.NewInt(1000)); got.Sign() != 0 {
		t.Fatalf("bonus on an unknown market: %s", got)
	}
	bonus := m.liq.GetLiquidationBonus(m.db, zzcrBorrower, m.asset, big.NewInt(1000))
	zzcrEq(t, "quoted bonus", bonus, big.NewInt(50)) // 1000 at 5%
}

// DEFECT PIN. A zero-size liquidation is accepted: with the default minimum of
// zero, `0 < 0` is false, so Liquidate runs to completion, moves nothing, and
// still records a liquidation event against the borrower. Every other credit
// entry point refuses a zero amount (Supply and Borrow both return
// ErrInvalidAmount); this one does not. Correct behaviour refuses it.
func TestZzcrZeroSizeLiquidationIsAcceptedPinsDefect(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 100_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 750)
	m.zzcrPushDebt(t, zzcrBorrower, 751)

	events := len(m.liq.GetLiquidationHistory(0))
	repaid, seized, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(0))
	if err != nil {
		t.Fatalf("defect appears fixed: zero-size liquidation now returns %v -- "+
			"add the refusal assertion and delete this pin", err)
	}
	zzcrEq(t, "repaid on a zero-size liquidation", repaid, big.NewInt(0))
	zzcrEq(t, "seized on a zero-size liquidation", seized, big.NewInt(0))
	if got := len(m.liq.GetLiquidationHistory(0)); got != events+1 {
		t.Fatalf("event count: got %d, want %d", got, events+1)
	}
}

// DEFECT PIN. InitializeReserve validates the collateral factor against RAY but
// never looks at the liquidation bonus, so a 1000%% bonus is accepted and the
// quoted seizure is eleven times the debt. The only thing standing between that
// and the borrower is the collateral cap inside Liquidate. Correct behaviour
// bounds the bonus at admission.
func TestZzcrLiquidationBonusIsUnboundedAtAdmissionPinsDefect(t *testing.T) {
	lp := NewLendingPool(NewPoolManager())
	db := NewMockStateDB()
	huge := new(big.Int).Mul(RAY, big.NewInt(10))
	if err := lp.InitializeReserve(db, zzcrAsset, RAY, huge, DefaultInterestRateModel()); err != nil {
		t.Fatalf("defect appears fixed: a 1000%% bonus is now refused (%v) -- delete this pin", err)
	}
	liq := NewLiquidator(lp)
	quoted := liq.GetLiquidationBonus(db, zzcrBorrower, zzcrAsset, big.NewInt(1000))
	zzcrEq(t, "quoted bonus at a 1000% rate", quoted, big.NewInt(10_000))

	// A negative bonus is accepted too, and quotes a seizure below the debt repaid.
	db2 := NewMockStateDB()
	lp2 := NewLendingPool(NewPoolManager())
	if err := lp2.InitializeReserve(db2, zzcrAsset, RAY, new(big.Int).Neg(zzcrFrac(50, 100)), nil); err != nil {
		t.Fatalf("defect appears fixed: a negative bonus is now refused (%v) -- delete this pin", err)
	}
	liq2 := NewLiquidator(lp2)
	coll, _ := liq2.calculateCollateralToSeize(big.NewInt(1000), lp2.GetReserve(zzcrAsset))
	zzcrEq(t, "seizure at a negative bonus", coll, big.NewInt(500))
}

// =========================================================================
// Configuration
// =========================================================================

func TestZzcrLiquidatorConfigBounds(t *testing.T) {
	liq := NewLiquidator(NewLendingPool(NewPoolManager()))

	// Close factor: (0, RAY]. Zero and negative are meaningless, above RAY would
	// let one call wipe more than the whole debt.
	if err := liq.SetCloseFactor(big.NewInt(0)); err != ErrInvalidParameter {
		t.Fatalf("zero close factor: got %v, want ErrInvalidParameter", err)
	}
	if err := liq.SetCloseFactor(big.NewInt(-1)); err != ErrInvalidParameter {
		t.Fatalf("negative close factor: got %v, want ErrInvalidParameter", err)
	}
	if err := liq.SetCloseFactor(new(big.Int).Add(RAY, big.NewInt(1))); err != ErrInvalidParameter {
		t.Fatalf("close factor one past RAY: got %v, want ErrInvalidParameter", err)
	}
	if err := liq.SetCloseFactor(RAY); err != nil { // exactly RAY is legal
		t.Fatalf("close factor at RAY: %v", err)
	}
	zzcrEq(t, "close factor after set", liq.GetConfig().CloseFactor, RAY)
	if err := liq.SetCloseFactor(big.NewInt(1)); err != nil { // one wei is legal
		t.Fatalf("close factor of one: %v", err)
	}
	zzcrEq(t, "close factor after set", liq.GetConfig().CloseFactor, big.NewInt(1))

	// Protocol fee: [0, RAY]. Zero is legal (no protocol cut), negative is not.
	if err := liq.SetProtocolFee(big.NewInt(-1)); err != ErrInvalidParameter {
		t.Fatalf("negative protocol fee: got %v, want ErrInvalidParameter", err)
	}
	if err := liq.SetProtocolFee(new(big.Int).Add(RAY, big.NewInt(1))); err != ErrInvalidParameter {
		t.Fatalf("protocol fee one past RAY: got %v, want ErrInvalidParameter", err)
	}
	if err := liq.SetProtocolFee(big.NewInt(0)); err != nil {
		t.Fatalf("zero protocol fee: %v", err)
	}
	zzcrEq(t, "protocol fee after set", liq.GetConfig().ProtocolFee, big.NewInt(0))
	if err := liq.SetProtocolFee(RAY); err != nil {
		t.Fatalf("protocol fee at RAY: %v", err)
	}
	zzcrEq(t, "protocol fee after set", liq.GetConfig().ProtocolFee, RAY)

	// The setters copy rather than alias: mutating the caller's value afterwards
	// must not reach into the config.
	arg := new(big.Int).Set(RAY)
	if err := liq.SetCloseFactor(arg); err != nil {
		t.Fatalf("SetCloseFactor: %v", err)
	}
	arg.SetInt64(7)
	zzcrEq(t, "close factor is a copy", liq.GetConfig().CloseFactor, RAY)
}

// The whole protocol cut lands in reserves and the liquidator keeps the rest of
// the bonus: at a 100% protocol fee the liquidator breaks exactly even.
func TestZzcrProtocolFeeSplitsTheBonus(t *testing.T) {
	for _, feePct := range []int64{0, 10, 50, 100} {
		m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(20, 100))
		if err := m.liq.SetProtocolFee(zzcrFrac(feePct, 100)); err != nil {
			t.Fatalf("SetProtocolFee(%d%%): %v", feePct, err)
		}
		m.supply(t, zzcrLender, 10_000_000)
		m.supply(t, zzcrBorrower, 100_000)
		m.borrow(t, zzcrBorrower, 75_000)
		m.zzcrPushDebt(t, zzcrBorrower, 80_000)

		before := m.bal(zzcrKeeper)
		repaid, seized, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1<<40))
		if err != nil {
			t.Fatalf("Liquidate: %v", err)
		}
		bonus := new(big.Int).Sub(seized, repaid)
		fee := new(big.Int).Mul(bonus, zzcrFrac(feePct, 100))
		fee.Div(fee, RAY)

		gain := new(big.Int).Sub(m.bal(zzcrKeeper), before)
		zzcrEq(t, "keeper keeps the bonus less the protocol cut", gain, new(big.Int).Sub(bonus, fee))
		zzcrEq(t, "reserves take the protocol cut", m.reserve(t).TotalReserves, fee)
		if feePct == 100 && gain.Sign() != 0 {
			t.Fatalf("at a 100%% protocol fee the keeper should break even, gained %s", gain)
		}
	}
}

// =========================================================================
// Flash, batch and history
// =========================================================================

func TestZzcrFlashLiquidationHonoursItsSwitch(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 100_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 750)
	m.zzcrPushDebt(t, zzcrBorrower, 751)

	m.liq.config.FlashLiquidationEnabled = false
	if _, _, err := m.liq.LiquidateWithFlash(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(100)); err != ErrFlashLiquidationDisabled {
		t.Fatalf("flash disabled: got %v, want ErrFlashLiquidationDisabled", err)
	}

	m.liq.config.FlashLiquidationEnabled = true
	repaid, seized, err := m.liq.LiquidateWithFlash(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(100))
	if err != nil {
		t.Fatalf("flash enabled: %v", err)
	}
	// The flash path is the ordinary path: same ceiling, same bonus.
	zzcrEq(t, "flash repaid", repaid, big.NewInt(100))
	zzcrEq(t, "flash seized", seized, big.NewInt(105))

	// It refuses the same states the ordinary path refuses.
	if _, _, err := m.liq.LiquidateWithFlash(m.db, zzcrKeeper, zzcrThird, m.asset, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("flash on an unknown position: got %v, want ErrNoDebtToRepay", err)
	}
}

// A batch reports per-target outcomes and totals only what actually settled: one
// bad target must not poison the rest, and must not be counted.
func TestZzcrBatchLiquidateIsPerTarget(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 10_000_000)
	m.supply(t, zzcrBorrower, 100_000)
	m.borrow(t, zzcrBorrower, 75_000)
	m.zzcrPushDebt(t, zzcrBorrower, 80_000)
	m.supply(t, zzcrThird, 1000) // collateral, no debt: healthy

	unknown := common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")
	targets := []BatchLiquidationTarget{
		{Borrower: zzcrBorrower, Asset: m.asset, DebtToRepay: big.NewInt(10_000)},
		{Borrower: zzcrThird, Asset: m.asset, DebtToRepay: big.NewInt(10_000)},
		{Borrower: zzcrBorrower, Asset: unknown, DebtToRepay: big.NewInt(10_000)},
		{Borrower: zzcrBorrower, Asset: m.asset, DebtToRepay: big.NewInt(5_000)},
	}
	debt, coll, errs := m.liq.BatchLiquidate(m.db, zzcrKeeper, targets)

	if len(errs) != len(targets) {
		t.Fatalf("one error slot per target: got %d, want %d", len(errs), len(targets))
	}
	if errs[0] != nil || errs[3] != nil {
		t.Fatalf("healthy targets errored: %v %v", errs[0], errs[3])
	}
	if errs[1] != ErrNoDebtToRepay {
		t.Fatalf("borrower with collateral but no debt: got %v, want ErrNoDebtToRepay", errs[1])
	}
	if errs[2] != ErrReserveNotFound {
		t.Fatalf("unknown market: got %v, want ErrReserveNotFound", errs[2])
	}
	// Totals count the two that settled and nothing else.
	zzcrEq(t, "batch debt repaid", debt, big.NewInt(15_000))
	bonus := new(big.Int).Div(new(big.Int).Mul(debt, zzcrFrac(5, 100)), RAY)
	zzcrEq(t, "batch collateral seized", coll, new(big.Int).Add(debt, bonus))

	// An empty batch is a no-op, not a panic.
	d, c, e := m.liq.BatchLiquidate(m.db, zzcrKeeper, nil)
	if d.Sign() != 0 || c.Sign() != 0 || len(e) != 0 {
		t.Fatalf("empty batch: debt=%s coll=%s errs=%d", d, c, len(e))
	}
}

// History is a bounded window on the most recent events, newest kept.
func TestZzcrLiquidationHistoryWindow(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 10_000_000)
	m.supply(t, zzcrBorrower, 100_000)
	m.borrow(t, zzcrBorrower, 75_000)
	m.zzcrPushDebt(t, zzcrBorrower, 80_000)

	if got := len(m.liq.GetLiquidationHistory(5)); got != 0 {
		t.Fatalf("history before any liquidation: %d entries", got)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := m.liq.Liquidate(m.db, zzcrKeeper, zzcrBorrower, m.asset, big.NewInt(1000+int64(i))); err != nil {
			t.Fatalf("Liquidate %d: %v", i, err)
		}
	}
	if got := len(m.liq.GetLiquidationHistory(0)); got != 3 {
		t.Fatalf("limit 0 means everything: got %d, want 3", got)
	}
	if got := len(m.liq.GetLiquidationHistory(-1)); got != 3 {
		t.Fatalf("negative limit means everything: got %d, want 3", got)
	}
	if got := len(m.liq.GetLiquidationHistory(99)); got != 3 {
		t.Fatalf("limit past the end: got %d, want 3", got)
	}
	last := m.liq.GetLiquidationHistory(1)
	if len(last) != 1 {
		t.Fatalf("limit 1: got %d entries", len(last))
	}
	zzcrEq(t, "history keeps the newest", last[0].DebtRepaid, big.NewInt(1002))

	ev := m.liq.GetLiquidationHistory(3)[0]
	if ev.Liquidator != zzcrKeeper || ev.Borrower != zzcrBorrower || ev.Asset != m.asset {
		t.Fatalf("event parties wrong: %+v", ev)
	}
	if ev.Timestamp != m.db.GetBlockNumber() {
		t.Fatalf("event block: got %d, want %d", ev.Timestamp, m.db.GetBlockNumber())
	}
	zzcrEq(t, "event bonus", ev.Bonus, new(big.Int).Sub(ev.CollateralSeized, ev.DebtRepaid))
}

// =========================================================================
// The liquidation-bot view
// =========================================================================

// DEFECT PIN, two of them, in one function.
//
// First: liquidation.go:484 passes shares*exchangeRate as the collateral value
// without the /RAY that every other caller applies, so collateral reads 1e18
// times too large and a genuinely liquidatable position is reported healthy.
// The bot view therefore disagrees with the engine.
//
// Second: the inner loop walks every position in the pool for each asset without
// checking that the position belongs to that asset, so one unhealthy position is
// reported once per registered market.
func TestZzcrFindLiquidatablePositionsPinsDefects(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	if err := m.lp.InitializeReserve(m.db, zzcrAssetB, zzcrFrac(75, 100), zzcrFrac(5, 100), DefaultInterestRateModel()); err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	m.supply(t, zzcrLender, 10_000_000)
	m.supply(t, zzcrBorrower, 100_000)
	m.borrow(t, zzcrBorrower, 75_000)
	m.zzcrPushDebt(t, zzcrBorrower, 80_000)

	// The engine and the views agree this is liquidatable.
	if !m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
		t.Fatal("fixture is not liquidatable")
	}
	// The bot view does not.
	if got := m.liq.FindLiquidatablePositions(m.db, []common.Address{m.asset}); len(got) != 0 {
		t.Fatalf("defect appears fixed: the bot view now reports %d target(s) -- "+
			"restore the /RAY at liquidation.go:484 assertion and delete this pin", len(got))
	}

	// Scaling the debt by RAY defeats the missing division and reaches the branch
	// that appends a target. The same position then shows up once per market,
	// including the market it has no position in.
	m.zzcrPushDebt(t, zzcrBorrower, 1_000_000_000)
	huge := new(big.Int).Mul(big.NewInt(1_000_000_000), RAY)
	pos := m.position(t, zzcrBorrower)
	pos.BorrowAmount = huge

	found := m.liq.FindLiquidatablePositions(m.db, []common.Address{m.asset, zzcrAssetB})
	if len(found) != 2 {
		t.Fatalf("defect appears fixed: one position now yields %d target(s) across two markets, "+
			"want the 2 this pin records -- filter by position.Asset and delete this pin", len(found))
	}
	if found[0].Asset == found[1].Asset {
		t.Fatalf("both targets name the same market: %v", found[0].Asset)
	}
	for _, f := range found {
		if f.Borrower != zzcrBorrower {
			t.Fatalf("target names %s, want %s", f.Borrower.Hex(), zzcrBorrower.Hex())
		}
		want := new(big.Int).Mul(huge, m.liq.GetConfig().CloseFactor)
		want.Div(want, RAY)
		zzcrEq(t, "target size", f.DebtToRepay, want)
	}

	// Markets that do not exist are skipped rather than crashing the sweep.
	unknown := common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")
	if got := m.liq.FindLiquidatablePositions(m.db, []common.Address{unknown}); len(got) != 0 {
		t.Fatalf("unknown market yielded %d targets", len(got))
	}
	if got := m.liq.FindLiquidatablePositions(m.db, nil); len(got) != 0 {
		t.Fatalf("no markets yielded %d targets", len(got))
	}
}

// The sweep agrees with the engine on where the boundary is: a position at
// health exactly parity is left alone, and one unit of debt past it is reported.
func TestZzcrFindLiquidatablePositionsBoundaryIsInclusiveOfHealth(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 10_000_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 1000)

	// The sweep prices collateral at shares times the rate (see the pin above),
	// so parity for it sits at that figure rather than at the shares alone.
	pos := m.position(t, zzcrBorrower)
	res := m.reserve(t)
	parity := new(big.Int).Mul(pos.SupplyShares, res.ExchangeRate)

	pos.BorrowAmount = new(big.Int).Set(parity)
	if got := m.liq.FindLiquidatablePositions(m.db, []common.Address{m.asset}); len(got) != 0 {
		t.Fatalf("a position at exactly parity was reported: %d targets", len(got))
	}
	pos.BorrowAmount = new(big.Int).Add(parity, big.NewInt(1))
	if got := m.liq.FindLiquidatablePositions(m.db, []common.Address{m.asset}); len(got) != 1 {
		t.Fatalf("a position one unit past parity was not reported: %d targets", len(got))
	}
}

// A position carrying no debt is never a target, whatever its collateral and
// however the threshold is set. There is nothing to liquidate.
func TestZzcrFindLiquidatablePositionsSkipsDebtFreePositions(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrThird, 100_000)
	if got := m.liq.FindLiquidatablePositions(m.db, []common.Address{m.asset}); len(got) != 0 {
		t.Fatalf("debt-free position reported: %d targets", len(got))
	}
	// Even a threshold high enough to swallow the no-debt health factor leaves
	// it alone: no debt means no target, not an unliquidatably healthy one.
	m.liq.config.LiquidationThreshold = new(big.Int).Mul(RAY, big.NewInt(1_000_000))
	if got := m.liq.FindLiquidatablePositions(m.db, []common.Address{m.asset}); len(got) != 0 {
		t.Fatalf("debt-free position reported under a raised threshold: %d targets", len(got))
	}
	if got := m.liq.GetLiquidatableAmount(m.db, zzcrThird, m.asset); got.Sign() != 0 {
		t.Fatalf("debt-free position quoted %s as liquidatable under a raised threshold", got)
	}
}

// The settlement step clamps what it takes from the borrower. Driven directly,
// because Liquidate's own caps (close factor, then the borrower's collateral)
// mean these three guards cannot fire through the public path -- they are the
// last line of defence if either cap is ever loosened.
func TestZzcrLiquidationSettlementClampsTheBorrowersBooks(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	res := m.reserve(t)

	// Nothing behind the key: refused rather than editing books that are not
	// there. Note the payment has already moved by this point, so the refusal
	// leaves the liquidator out of pocket -- see the report.
	keeperBefore := m.bal(zzcrKeeper)
	err := m.liq.executeLiquidation(m.db, zzcrKeeper, zzcrBorrower, m.asset,
		big.NewInt(10), big.NewInt(10), res)
	if err != ErrPositionNotFound {
		t.Fatalf("settling against an absent position: got %v, want ErrPositionNotFound", err)
	}
	zzcrEq(t, "the payment moved before the refusal",
		m.bal(zzcrKeeper), new(big.Int).Sub(keeperBefore, big.NewInt(10)))

	// Asked for more than the borrower has: their books empty and stop, they
	// never go negative.
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 10)
	m.borrow(t, zzcrBorrower, 5)
	pos := m.position(t, zzcrBorrower)
	if err := m.liq.executeLiquidation(m.db, zzcrKeeper, zzcrBorrower, m.asset,
		big.NewInt(100), big.NewInt(1000), res); err != nil {
		t.Fatalf("executeLiquidation: %v", err)
	}
	zzcrEq(t, "shares are emptied, not overdrawn", pos.SupplyShares, big.NewInt(0))
	zzcrEq(t, "debt is cleared, not inverted", pos.BorrowAmount, big.NewInt(0))

	// The market's own totals carry no such clamp: they are kept honest only by
	// the caps upstream in Liquidate, which is why those caps are load-bearing.
	if res.TotalBorrows.Sign() >= 0 {
		t.Fatalf("the fixture did not drive the market total negative: %s", res.TotalBorrows)
	}
}

// calculateMaxLiquidatable rounds down, toward the borrower.
func TestZzcrMaxLiquidatableRoundsDown(t *testing.T) {
	liq := NewLiquidator(NewLendingPool(NewPoolManager()))
	if err := liq.SetCloseFactor(zzcrFrac(1, 3)); err != nil {
		t.Fatalf("SetCloseFactor: %v", err)
	}
	pos := &LendingPosition{BorrowAmount: big.NewInt(100)}
	got := liq.calculateMaxLiquidatable(pos, &Reserve{})

	want := new(big.Int).Mul(big.NewInt(100), zzcrFrac(1, 3))
	want.Div(want, RAY)
	zzcrEq(t, "max liquidatable", got, want)
	if got.Cmp(big.NewInt(34)) >= 0 {
		t.Fatalf("a third of 100 rounded up: got %s, want at most 33", got)
	}
}

// The default configuration is internally consistent: a close factor and a
// protocol fee inside their own bounds, and a threshold at parity.
func TestZzcrDefaultLiquidatorConfigIsWithinItsOwnBounds(t *testing.T) {
	c := DefaultLiquidatorConfig()
	liq := NewLiquidator(nil)
	if err := liq.SetCloseFactor(c.CloseFactor); err != nil {
		t.Fatalf("default close factor rejected by its own setter: %v", err)
	}
	if err := liq.SetProtocolFee(c.ProtocolFee); err != nil {
		t.Fatalf("default protocol fee rejected by its own setter: %v", err)
	}
	zzcrEq(t, "default threshold is parity", c.LiquidationThreshold, RAY)
	zzcrEq(t, "default minimum size", c.MinLiquidation, big.NewInt(0))
	if !c.FlashLiquidationEnabled {
		t.Fatal("flash liquidation defaults off")
	}
	// Two calls hand back independent values, not a shared pointer.
	other := DefaultLiquidatorConfig()
	other.CloseFactor.SetInt64(7)
	zzcrEq(t, "config is not shared", DefaultLiquidatorConfig().CloseFactor, zzcrFrac(50, 100))
}
