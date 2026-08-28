// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
)

var zzcrUnknownAsset = common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")

// zzcrE24 is 1e24, the scale at which one block of interest is a whole number of
// units rather than nothing (see the rounding pin in zzcredit_rate_test.go).
func zzcrE24() *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil) }

// =========================================================================
// Admission
// =========================================================================

func TestZzcrReserveAdmission(t *testing.T) {
	lp := NewLendingPool(NewPoolManager())
	db := NewMockStateDB()
	db.SetBlockNumber(77)

	// A collateral factor above parity would let a borrower take out more than
	// they posted, so it is refused; parity itself is the last legal value.
	if err := lp.InitializeReserve(db, zzcrAsset, new(big.Int).Add(RAY, big.NewInt(1)), zzcrFrac(5, 100), nil); err != ErrInvalidCollateralFactor {
		t.Fatalf("collateral factor one past parity: got %v, want ErrInvalidCollateralFactor", err)
	}
	if lp.GetReserve(zzcrAsset) != nil {
		t.Fatal("a refused reserve was still registered")
	}
	if err := lp.InitializeReserve(db, zzcrAsset, RAY, zzcrFrac(5, 100), DefaultInterestRateModel()); err != nil {
		t.Fatalf("collateral factor at parity: %v", err)
	}
	if err := lp.InitializeReserve(db, zzcrAsset, RAY, zzcrFrac(5, 100), nil); err != ErrReserveAlreadyExists {
		t.Fatalf("re-admitting a market: got %v, want ErrReserveAlreadyExists", err)
	}

	// A fresh market starts empty, at parity, open for business.
	r := lp.GetReserve(zzcrAsset)
	zzcrEq(t, "opening supply", r.TotalSupply, big.NewInt(0))
	zzcrEq(t, "opening borrows", r.TotalBorrows, big.NewInt(0))
	zzcrEq(t, "opening reserves", r.TotalReserves, big.NewInt(0))
	zzcrEq(t, "opening exchange rate", r.ExchangeRate, RAY)
	zzcrEq(t, "opening borrow index", r.BorrowIndex, RAY)
	zzcrEq(t, "opening supply index", r.SupplyIndex, RAY)
	if !r.IsActive || r.IsFrozen || !r.IsBorrowEnabled {
		t.Fatalf("a fresh market is not open: active=%v frozen=%v borrowable=%v", r.IsActive, r.IsFrozen, r.IsBorrowEnabled)
	}
	if r.LastUpdateBlock != 77 {
		t.Fatalf("opening block: got %d, want 77", r.LastUpdateBlock)
	}
	if lp.GetReserve(zzcrUnknownAsset) != nil {
		t.Fatal("an unregistered market resolved")
	}
}

func TestZzcrReserveAdminGuards(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))

	if err := m.lp.SetReserveActive(m.db, zzcrUnknownAsset, false); err != ErrReserveNotFound {
		t.Fatalf("deactivating an unknown market: got %v, want ErrReserveNotFound", err)
	}
	if err := m.lp.SetBorrowCap(m.db, zzcrUnknownAsset, big.NewInt(1)); err != ErrReserveNotFound {
		t.Fatalf("capping an unknown market: got %v, want ErrReserveNotFound", err)
	}

	m.supply(t, zzcrLender, 10_000)
	m.supply(t, zzcrBorrower, 1000)

	// Deactivation closes supply, withdrawal and borrowing together.
	if err := m.lp.SetReserveActive(m.db, m.asset, false); err != nil {
		t.Fatalf("SetReserveActive: %v", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrReserveFrozen {
		t.Fatalf("supply into a closed market: got %v, want ErrReserveFrozen", err)
	}
	if _, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrReserveFrozen {
		t.Fatalf("withdraw from a closed market: got %v, want ErrReserveFrozen", err)
	}
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrBorrowDisabled {
		t.Fatalf("borrow from a closed market: got %v, want ErrBorrowDisabled", err)
	}
	if err := m.lp.SetReserveActive(m.db, m.asset, true); err != nil {
		t.Fatalf("SetReserveActive: %v", err)
	}
	m.borrow(t, zzcrBorrower, 1)

	// The cap is a ceiling on the total, and it copies rather than aliases.
	arg := big.NewInt(700)
	if err := m.lp.SetBorrowCap(m.db, m.asset, arg); err != nil {
		t.Fatalf("SetBorrowCap: %v", err)
	}
	arg.SetInt64(1)
	zzcrEq(t, "borrow cap is a copy", m.reserve(t).BorrowCap, big.NewInt(700))
	m.borrow(t, zzcrBorrower, 699) // total 700, exactly the cap
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrBorrowCapExceeded {
		t.Fatalf("one past the borrow cap: got %v, want ErrBorrowCapExceeded", err)
	}
	// A cap of zero means no cap, not a closed market.
	if err := m.lp.SetBorrowCap(m.db, m.asset, big.NewInt(0)); err != nil {
		t.Fatalf("SetBorrowCap(0): %v", err)
	}
	m.borrow(t, zzcrBorrower, 1)

	// Freezing stops new supply while leaving the market otherwise alive.
	m.reserve(t).IsFrozen = true
	if _, err := m.lp.Supply(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrReserveFrozen {
		t.Fatalf("supply into a frozen market: got %v, want ErrReserveFrozen", err)
	}
}

// =========================================================================
// Supply
// =========================================================================

func TestZzcrSupplyRefusals(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))

	if _, err := m.lp.Supply(m.db, zzcrLender, zzcrUnknownAsset, big.NewInt(1)); err != ErrReserveNotFound {
		t.Fatalf("unknown market: got %v, want ErrReserveNotFound", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrLender, m.asset, big.NewInt(0)); err != ErrInvalidAmount {
		t.Fatalf("zero supply: got %v, want ErrInvalidAmount", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrLender, m.asset, big.NewInt(-1)); err != ErrInvalidAmount {
		t.Fatalf("negative supply: got %v, want ErrInvalidAmount", err)
	}

	// The supply cap is a ceiling on the total, inclusive.
	m.reserve(t).SupplyCap = big.NewInt(1000)
	m.supply(t, zzcrLender, 1000)
	if _, err := m.lp.Supply(m.db, zzcrLender, m.asset, big.NewInt(1)); err != ErrSupplyCapExceeded {
		t.Fatalf("one past the supply cap: got %v, want ErrSupplyCapExceeded", err)
	}
	m.reserve(t).SupplyCap = big.NewInt(0) // zero means no cap
	m.supply(t, zzcrLender, 1)
}

func TestZzcrSupplyMintsSharesAtTheExchangeRate(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	before := m.bal(zzcrLender)
	poolBefore := m.bal(lendingPoolAddr)

	shares := m.supply(t, zzcrLender, 1000)
	zzcrEq(t, "shares at parity", shares, big.NewInt(1000))
	zzcrEq(t, "supplier paid", m.bal(zzcrLender), new(big.Int).Sub(before, big.NewInt(1000)))
	zzcrEq(t, "pool received", m.bal(lendingPoolAddr), new(big.Int).Add(poolBefore, big.NewInt(1000)))
	zzcrEq(t, "market total", m.reserve(t).TotalSupply, big.NewInt(1000))

	// A second deposit adds to the same position rather than replacing it.
	m.supply(t, zzcrLender, 500)
	zzcrEq(t, "shares accumulate", m.position(t, zzcrLender).SupplyShares, big.NewInt(1500))
	zzcrEq(t, "market total accumulates", m.reserve(t).TotalSupply, big.NewInt(1500))

	// Shares are minted at the rate, so a richer rate mints fewer of them.
	m.reserve(t).ExchangeRate = new(big.Int).Mul(RAY, big.NewInt(2))
	got := m.supply(t, zzcrThird, 1000)
	zzcrEq(t, "shares at twice parity", got, big.NewInt(500))
	// Rounding is down: a deposit that does not buy a whole share buys none, and
	// the shortfall stays with the pool rather than being conjured for the user.
	m.reserve(t).ExchangeRate = new(big.Int).Mul(RAY, big.NewInt(3))
	zzcrEq(t, "shares round down", m.supply(t, zzcrThird, 2), big.NewInt(0))
}

// =========================================================================
// Borrow
// =========================================================================

func TestZzcrBorrowRefusals(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)

	if err := m.lp.Borrow(m.db, zzcrBorrower, zzcrUnknownAsset, big.NewInt(1)); err != ErrReserveNotFound {
		t.Fatalf("unknown market: got %v, want ErrReserveNotFound", err)
	}
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(0)); err != ErrInvalidAmount {
		t.Fatalf("zero borrow: got %v, want ErrInvalidAmount", err)
	}
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(-1)); err != ErrInvalidAmount {
		t.Fatalf("negative borrow: got %v, want ErrInvalidAmount", err)
	}
	// Nothing posted means nothing to borrow against.
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrInsufficientCollateral {
		t.Fatalf("borrow with no position: got %v, want ErrInsufficientCollateral", err)
	}
	// Collateral posted but the market's borrow side switched off.
	m.supply(t, zzcrBorrower, 1000)
	m.reserve(t).IsBorrowEnabled = false
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrBorrowDisabled {
		t.Fatalf("borrowing disabled: got %v, want ErrBorrowDisabled", err)
	}
	m.reserve(t).IsBorrowEnabled = true

	// A position with collateral but zero shares is still refused at the limit.
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(751)); err != ErrMaxLTVExceeded {
		t.Fatalf("one past the limit: got %v, want ErrMaxLTVExceeded", err)
	}
}

// The pool cannot lend cash it does not hold, even to a borrower who is well
// within their collateral limit.
func TestZzcrBorrowRefusesBeyondAvailableCash(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	unit := zzcrE24()
	setBalance(m.db, zzcrBorrower, new(big.Int).Mul(unit, big.NewInt(100)))
	setBalance(m.db, zzcrThird, new(big.Int).Mul(unit, big.NewInt(100)))

	if _, err := m.lp.Supply(m.db, zzcrBorrower, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Borrow: %v", err) // drains the market's spare cash
	}

	// One block of interest grows what is owed without growing what is held, so
	// the remaining supplier's own deposit is no longer fully lendable.
	m.db.SetBlockNumber(m.db.GetBlockNumber() + 1)
	if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, unit); err != ErrInsufficientLiquidity {
		t.Fatalf("borrowing past available cash: got %v, want ErrInsufficientLiquidity", err)
	}
}

// =========================================================================
// Withdraw
// =========================================================================

func TestZzcrWithdrawRefusals(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)

	if _, err := m.lp.Withdraw(m.db, zzcrLender, zzcrUnknownAsset, big.NewInt(1)); err != ErrReserveNotFound {
		t.Fatalf("unknown market: got %v, want ErrReserveNotFound", err)
	}
	if _, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrInsufficientBalance {
		t.Fatalf("withdraw with no position: got %v, want ErrInsufficientBalance", err)
	}
	// A position drained to nothing is the same as no position.
	m.supply(t, zzcrBorrower, 100)
	if _, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(100)); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if _, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrInsufficientBalance {
		t.Fatalf("withdraw from an emptied position: got %v, want ErrInsufficientBalance", err)
	}
}

// Withdrawal stops exactly where the position would stop being safe: the last
// share that keeps health at parity comes out, the next one does not.
func TestZzcrWithdrawStopsAtTheHealthBoundary(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 375) // half the limit, so half the collateral is free

	// 500 shares left backs 375 of debt at exactly parity.
	if _, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(501)); err != ErrHealthFactorTooLow {
		t.Fatalf("withdrawing one share too many: got %v, want ErrHealthFactorTooLow", err)
	}
	got, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(500))
	if err != nil {
		t.Fatalf("withdrawing to exactly parity: %v", err)
	}
	zzcrEq(t, "underlying returned", got, big.NewInt(500))
	zzcrEq(t, "health after", m.health(zzcrBorrower), RAY)
	if m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
		t.Fatal("a legal withdrawal left the position liquidatable")
	}
	if _, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrHealthFactorTooLow {
		t.Fatalf("withdrawing past parity: got %v, want ErrHealthFactorTooLow", err)
	}
}

// Asking for more shares than you hold returns what you hold, at the rate, and
// the underlying rounds down -- the pool keeps the remainder.
func TestZzcrWithdrawIsCappedAndRoundsDown(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)

	before := m.bal(zzcrBorrower)
	got, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(1<<40))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	zzcrEq(t, "capped to the holding", got, big.NewInt(1000))
	zzcrEq(t, "balance rose by exactly that", m.bal(zzcrBorrower), new(big.Int).Add(before, big.NewInt(1000)))
	zzcrEq(t, "shares are gone", m.position(t, zzcrBorrower).SupplyShares, big.NewInt(0))

	// At a rate that is not a whole multiple, the underlying rounds toward the
	// pool: three shares at a rate of 1/3 above parity return three, not four.
	m.supply(t, zzcrThird, 3)
	m.reserve(t).ExchangeRate = new(big.Int).Add(RAY, big.NewInt(1))
	out, err := m.lp.Withdraw(m.db, zzcrThird, m.asset, big.NewInt(3))
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	zzcrEq(t, "underlying rounds down", out, big.NewInt(3))
}

// The last unit of cash in the market is withdrawable: the liquidity check is a
// ceiling, not a strict one, so a sole supplier can always get everything back.
func TestZzcrWithdrawTakesExactlyTheAvailableCash(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrBorrower, 1000)

	r := m.reserve(t)
	available := new(big.Int).Sub(r.TotalSupply, r.TotalBorrows)
	zzcrEq(t, "the fixture sits exactly on the boundary", available, big.NewInt(1000))

	got, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(1000))
	if err != nil {
		t.Fatalf("withdrawing exactly the available cash: %v", err)
	}
	zzcrEq(t, "the last unit comes out", got, big.NewInt(1000))
	zzcrEq(t, "the market is empty", m.reserve(t).TotalSupply, big.NewInt(0))
	zzcrEq(t, "the position is empty", m.position(t, zzcrBorrower).SupplyShares, big.NewInt(0))
}

// The same on the borrow side: a borrower may take the market's last unit of
// cash, provided their collateral covers it.
func TestZzcrBorrowTakesExactlyTheAvailableCash(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	m.supply(t, zzcrBorrower, 1000)

	r := m.reserve(t)
	available := new(big.Int).Sub(r.TotalSupply, r.TotalBorrows)
	zzcrEq(t, "the fixture sits exactly on the boundary", available, big.NewInt(1000))

	m.borrow(t, zzcrBorrower, 1000)
	zzcrEq(t, "the market's cash is gone",
		new(big.Int).Sub(m.reserve(t).TotalSupply, m.reserve(t).TotalBorrows), big.NewInt(0))
	zzcrEq(t, "health lands exactly at parity", m.health(zzcrBorrower), RAY)
}

// A supplier with no debt can still be locked out when accrual has eaten the
// market's spare cash.
func TestZzcrWithdrawRefusesWhenCashIsShort(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	unit := zzcrE24()
	setBalance(m.db, zzcrLender, new(big.Int).Mul(unit, big.NewInt(100)))
	setBalance(m.db, zzcrThird, new(big.Int).Mul(unit, big.NewInt(100)))

	if _, err := m.lp.Supply(m.db, zzcrLender, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Borrow: %v", err)
	}
	m.db.SetBlockNumber(m.db.GetBlockNumber() + 1)

	if _, err := m.lp.Withdraw(m.db, zzcrLender, m.asset, unit); err != ErrInsufficientLiquidity {
		t.Fatalf("withdrawing past available cash: got %v, want ErrInsufficientLiquidity", err)
	}
}

// =========================================================================
// Repay
// =========================================================================

func TestZzcrRepayRefusals(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)

	if _, err := m.lp.Repay(m.db, zzcrBorrower, zzcrUnknownAsset, big.NewInt(1)); err != ErrReserveNotFound {
		t.Fatalf("unknown market: got %v, want ErrReserveNotFound", err)
	}
	if _, err := m.lp.Repay(m.db, zzcrThird, m.asset, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("repay with no position: got %v, want ErrNoDebtToRepay", err)
	}
	if _, err := m.lp.Repay(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("repay with no debt: got %v, want ErrNoDebtToRepay", err)
	}
	// Clearing the debt closes the door again.
	m.borrow(t, zzcrBorrower, 100)
	if _, err := m.lp.Repay(m.db, zzcrBorrower, m.asset, big.NewInt(100)); err != nil {
		t.Fatalf("Repay: %v", err)
	}
	if _, err := m.lp.Repay(m.db, zzcrBorrower, m.asset, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("repay after clearing: got %v, want ErrNoDebtToRepay", err)
	}
}

// Overpaying is capped at the debt: the borrower is charged what they owed and
// not a unit more, and the surplus is never credited back to them.
func TestZzcrOverpaymentIsNotCredited(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 750)

	before := m.bal(zzcrBorrower)
	poolBefore := m.bal(lendingPoolAddr)
	repaid, err := m.lp.Repay(m.db, zzcrBorrower, m.asset, big.NewInt(1_000_000))
	if err != nil {
		t.Fatalf("Repay: %v", err)
	}
	zzcrEq(t, "repaid", repaid, big.NewInt(750))
	zzcrEq(t, "borrower charged exactly the debt", m.bal(zzcrBorrower), new(big.Int).Sub(before, big.NewInt(750)))
	zzcrEq(t, "pool received exactly the debt", m.bal(lendingPoolAddr), new(big.Int).Add(poolBefore, big.NewInt(750)))
	zzcrEq(t, "debt cleared", m.position(t, zzcrBorrower).BorrowAmount, big.NewInt(0))
	zzcrAtLeast(t, "debt never goes negative", m.position(t, zzcrBorrower).BorrowAmount, big.NewInt(0))
	zzcrEq(t, "market borrows cleared", m.reserve(t).TotalBorrows, big.NewInt(0))
}

// Borrowing and repaying in a loop can never leave the borrower holding more
// than they started with, at any number of turns.
func TestZzcrBorrowRepayRoundTripNeverProfits(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 10_000_000)
	m.supply(t, zzcrBorrower, 100_000)

	start := m.bal(zzcrBorrower)
	startShares := new(big.Int).Set(m.position(t, zzcrBorrower).SupplyShares)

	rng := rand.New(rand.NewSource(0x5EEDC0DE)) // fixed seed, reproducible
	for i := 0; i < 500; i++ {
		amount := rng.Int63n(75_000) + 1
		if err := m.lp.Borrow(m.db, zzcrBorrower, m.asset, big.NewInt(amount)); err != nil {
			continue
		}
		if _, err := m.lp.Repay(m.db, zzcrBorrower, m.asset, big.NewInt(amount+rng.Int63n(1000))); err != nil {
			t.Fatalf("Repay after Borrow: %v", err)
		}
		zzcrAtMost(t, "round trip never enriches the borrower", m.bal(zzcrBorrower), start)
		zzcrEq(t, "round trip leaves the debt clear", m.position(t, zzcrBorrower).BorrowAmount, big.NewInt(0))
		zzcrEq(t, "round trip leaves the collateral alone", m.position(t, zzcrBorrower).SupplyShares, startShares)
	}
	zzcrEq(t, "the borrower ends where they began", m.bal(zzcrBorrower), start)
}

// =========================================================================
// Accrual inside the pool
// =========================================================================

// Accrual does nothing without time, without debt, or without a rate model, and
// it never rewinds the clock.
func TestZzcrPoolAccrualIsInertAtRest(t *testing.T) {
	// No time passed.
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	setBalance(m.db, zzcrThird, new(big.Int).Mul(zzcrE24(), big.NewInt(100)))
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, zzcrE24()); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, zzcrE24()); err != nil {
		t.Fatalf("Borrow: %v", err)
	}
	r := m.reserve(t)
	index, borrows, rate := new(big.Int).Set(r.BorrowIndex), new(big.Int).Set(r.TotalBorrows), new(big.Int).Set(r.ExchangeRate)
	m.lp.accrueInterest(m.db, r)
	zzcrEq(t, "index without time", r.BorrowIndex, index)
	zzcrEq(t, "borrows without time", r.TotalBorrows, borrows)
	zzcrEq(t, "rate without time", r.ExchangeRate, rate)

	// Clock behind the reserve: still inert, and the stamp is not pulled back.
	m.db.SetBlockNumber(0)
	m.lp.accrueInterest(m.db, r)
	if r.LastUpdateBlock == 0 {
		t.Fatal("accrual rewound the reserve's stamp")
	}
	zzcrEq(t, "index with the clock behind", r.BorrowIndex, index)

	// No debt: the stamp moves, nothing else does.
	m2 := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	m2.supply(t, zzcrLender, 1_000_000)
	r2 := m2.reserve(t)
	m2.db.SetBlockNumber(500)
	m2.lp.accrueInterest(m2.db, r2)
	if r2.LastUpdateBlock != 500 {
		t.Fatalf("stamp with no debt: got %d, want 500", r2.LastUpdateBlock)
	}
	zzcrEq(t, "index with no debt", r2.BorrowIndex, RAY)
	zzcrEq(t, "rate with no debt", r2.ExchangeRate, RAY)

	// No rate model: same, the market simply charges nothing.
	lp3 := NewLendingPool(NewPoolManager())
	db3 := NewMockStateDB()
	if err := lp3.InitializeReserve(db3, zzcrAsset, RAY, zzcrFrac(5, 100), nil); err != nil {
		t.Fatalf("InitializeReserve: %v", err)
	}
	r3 := lp3.GetReserve(zzcrAsset)
	r3.TotalSupply = zzcrE24()
	r3.TotalBorrows = zzcrE24()
	db3.SetBlockNumber(500)
	lp3.accrueInterest(db3, r3)
	if r3.LastUpdateBlock != 500 {
		t.Fatalf("stamp with no model: got %d, want 500", r3.LastUpdateBlock)
	}
	zzcrEq(t, "index with no model", r3.BorrowIndex, RAY)
	zzcrEq(t, "borrows with no model", r3.TotalBorrows, zzcrE24())
}

// Interest only ever moves one way. Swept over increasing block stamps: the
// borrow index, what is owed, the protocol's reserves and the exchange rate all
// rise or hold, never fall.
func TestZzcrPoolAccrualOnlyMovesForward(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	unit := zzcrE24()
	setBalance(m.db, zzcrThird, new(big.Int).Mul(unit, big.NewInt(1000)))
	setBalance(m.db, zzcrLender, new(big.Int).Mul(unit, big.NewInt(1000)))
	if _, err := m.lp.Supply(m.db, zzcrLender, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	r := m.reserve(t)
	index := new(big.Int).Set(r.BorrowIndex)
	borrows := new(big.Int).Set(r.TotalBorrows)
	reserves := new(big.Int).Set(r.TotalReserves)
	rate := new(big.Int).Set(r.ExchangeRate)

	block := m.db.GetBlockNumber()
	for i := 0; i < 40; i++ {
		block += uint64(1 << i)
		m.db.SetBlockNumber(block)
		m.lp.accrueInterest(m.db, r)

		zzcrAtLeast(t, "borrow index never falls", r.BorrowIndex, index)
		zzcrAtLeast(t, "debt never falls", r.TotalBorrows, borrows)
		zzcrAtLeast(t, "protocol reserves never fall", r.TotalReserves, reserves)
		zzcrAtLeast(t, "exchange rate never falls", r.ExchangeRate, rate)
		if r.LastUpdateBlock != block {
			t.Fatalf("stamp: got %d, want %d", r.LastUpdateBlock, block)
		}
		// The protocol's cut is a share of the new interest, never all of it.
		grew := new(big.Int).Sub(r.TotalBorrows, borrows)
		took := new(big.Int).Sub(r.TotalReserves, reserves)
		zzcrAtMost(t, "the protocol cut is part of the interest", took, grew)

		index.Set(r.BorrowIndex)
		borrows.Set(r.TotalBorrows)
		reserves.Set(r.TotalReserves)
		rate.Set(r.ExchangeRate)
	}
	if index.Cmp(RAY) <= 0 {
		t.Fatalf("the borrow index never moved: %s", index)
	}
}

// A market with debt but no recorded supply accrues on the borrow side only:
// there is no supply base to raise the exchange rate against.
func TestZzcrAccrualWithoutASupplyBaseLeavesTheRateAlone(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	r := m.reserve(t)
	r.TotalBorrows = zzcrE24()
	r.TotalSupply = big.NewInt(0)
	m.db.SetBlockNumber(1000)

	m.lp.accrueInterest(m.db, r)
	zzcrEq(t, "exchange rate without a supply base", r.ExchangeRate, RAY)
	zzcrAtLeast(t, "debt still accrued", r.TotalBorrows, zzcrE24())
	if r.BorrowIndex.Cmp(RAY) <= 0 {
		t.Fatalf("the borrow index did not move: %s", r.BorrowIndex)
	}
}

// DEFECT PIN. Accrual adds the new interest to TotalBorrows but never to
// TotalSupply, while raising the exchange rate that prices every supplier's
// shares. The suppliers' aggregate claim therefore exceeds the supply the
// market has recorded the moment any interest accrues, and the shortfall grows
// with time. The market is insolvent on its own books.
func TestZzcrAccrualLeavesClaimsAboveRecordedSupplyPinsDefect(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	unit := zzcrE24()
	setBalance(m.db, zzcrLender, new(big.Int).Mul(unit, big.NewInt(1000)))
	setBalance(m.db, zzcrThird, new(big.Int).Mul(unit, big.NewInt(1000)))
	if _, err := m.lp.Supply(m.db, zzcrLender, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	r := m.reserve(t)
	shares := new(big.Int).Add(
		m.position(t, zzcrLender).SupplyShares,
		m.position(t, zzcrThird).SupplyShares,
	)
	zzcrEq(t, "claims match supply before accrual",
		new(big.Int).Div(new(big.Int).Mul(shares, r.ExchangeRate), RAY), r.TotalSupply)
	cashBefore := new(big.Int).Sub(r.TotalSupply, r.TotalBorrows)

	m.db.SetBlockNumber(m.db.GetBlockNumber() + 1000)
	m.lp.accrueInterest(m.db, r)

	claims := new(big.Int).Div(new(big.Int).Mul(shares, r.ExchangeRate), RAY)
	if claims.Cmp(r.TotalSupply) <= 0 {
		t.Fatalf("defect appears fixed: claims %s no longer exceed recorded supply %s -- "+
			"credit accrued interest to TotalSupply at lending.go:633 and delete this pin", claims, r.TotalSupply)
	}
	// And the same omission drains the market's spare cash with no one taking any.
	cashAfter := new(big.Int).Sub(r.TotalSupply, r.TotalBorrows)
	if cashAfter.Cmp(cashBefore) >= 0 {
		t.Fatalf("defect appears fixed: spare cash went from %s to %s -- delete this pin", cashBefore, cashAfter)
	}
}

// A borrower's debt is restated by the ratio of the market index to their own.
func TestZzcrUserBorrowFollowsTheIndex(t *testing.T) {
	lp := NewLendingPool(NewPoolManager())
	res := &Reserve{BorrowIndex: new(big.Int).Mul(RAY, big.NewInt(2))}

	// Nothing owed: nothing to restate, and the stamp is left alone.
	free := &LendingPosition{BorrowAmount: big.NewInt(0), BorrowIndex: RAY}
	lp.updateUserBorrow(free, res)
	zzcrEq(t, "no debt stays no debt", free.BorrowAmount, big.NewInt(0))
	zzcrEq(t, "no debt leaves the stamp", free.BorrowIndex, RAY)

	// An unstamped position is left alone rather than divided by zero.
	unstamped := &LendingPosition{BorrowAmount: big.NewInt(1000), BorrowIndex: big.NewInt(0)}
	lp.updateUserBorrow(unstamped, res)
	zzcrEq(t, "an unstamped debt is untouched", unstamped.BorrowAmount, big.NewInt(1000))

	// Already current: no restatement.
	current := &LendingPosition{BorrowAmount: big.NewInt(1000), BorrowIndex: new(big.Int).Set(res.BorrowIndex)}
	lp.updateUserBorrow(current, res)
	zzcrEq(t, "a current debt is untouched", current.BorrowAmount, big.NewInt(1000))

	// Behind: restated by the ratio, and re-stamped so it is not charged twice.
	behind := &LendingPosition{BorrowAmount: big.NewInt(1000), BorrowIndex: new(big.Int).Set(RAY)}
	lp.updateUserBorrow(behind, res)
	zzcrEq(t, "debt restated at twice the index", behind.BorrowAmount, big.NewInt(2000))
	zzcrEq(t, "the stamp caught up", behind.BorrowIndex, res.BorrowIndex)
	lp.updateUserBorrow(behind, res)
	zzcrEq(t, "restating twice charges once", behind.BorrowAmount, big.NewInt(2000))

	// Restatement rounds down, toward the borrower.
	odd := &LendingPosition{BorrowAmount: big.NewInt(3), BorrowIndex: new(big.Int).Mul(RAY, big.NewInt(2))}
	lp.updateUserBorrow(odd, &Reserve{BorrowIndex: new(big.Int).Mul(RAY, big.NewInt(3))})
	zzcrEq(t, "restatement rounds down", odd.BorrowAmount, big.NewInt(4)) // 3 * 3/2 == 4.5
}

// DEFECT PIN. updateUserBorrow guards a zero stamp and an equal stamp but not a
// stamp ahead of the market's, so a position carrying a higher index has its
// debt written DOWN. Correct behaviour refuses to restate backwards.
func TestZzcrUserBorrowShrinksOnAStaleMarketIndexPinsDefect(t *testing.T) {
	lp := NewLendingPool(NewPoolManager())
	ahead := &LendingPosition{
		BorrowAmount: big.NewInt(1000),
		BorrowIndex:  new(big.Int).Mul(RAY, big.NewInt(4)),
	}
	lp.updateUserBorrow(ahead, &Reserve{BorrowIndex: new(big.Int).Mul(RAY, big.NewInt(2))})
	if ahead.BorrowAmount.Cmp(big.NewInt(1000)) >= 0 {
		t.Fatalf("defect appears fixed: debt is now %s -- guard the backwards case at "+
			"lending.go:661 and delete this pin", ahead.BorrowAmount)
	}
	zzcrEq(t, "debt halved by a stale market index", ahead.BorrowAmount, big.NewInt(500))
}

// =========================================================================
// Views
// =========================================================================

func TestZzcrHealthAndAccountViews(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))

	// A market that does not exist reads as maximally healthy and empty.
	zzcrEq(t, "health on an unknown market", m.lp.GetHealthFactor(m.db, zzcrBorrower, zzcrUnknownAsset), RAY)
	s, b, a, h := m.lp.GetUserAccountData(m.db, zzcrBorrower, zzcrUnknownAsset)
	zzcrEq(t, "supply on an unknown market", s, big.NewInt(0))
	zzcrEq(t, "debt on an unknown market", b, big.NewInt(0))
	zzcrEq(t, "headroom on an unknown market", a, big.NewInt(0))
	zzcrEq(t, "health on an unknown market", h, RAY)

	// A user with no position reads the same way.
	zzcrEq(t, "health with no position", m.lp.GetHealthFactor(m.db, zzcrBorrower, m.asset), RAY)
	s, b, a, h = m.lp.GetUserAccountData(m.db, zzcrBorrower, m.asset)
	zzcrEq(t, "supply with no position", s, big.NewInt(0))
	zzcrEq(t, "headroom with no position", a, big.NewInt(0))
	zzcrEq(t, "health with no position", h, RAY)
	if m.lp.GetPosition(m.db, zzcrBorrower, m.asset) != nil {
		t.Fatal("a position materialised out of nothing")
	}

	// Collateral with no debt: full headroom, and health well above parity.
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)
	zzcrEq(t, "health with no debt", m.lp.GetHealthFactor(m.db, zzcrBorrower, m.asset), RAY)
	s, b, a, h = m.lp.GetUserAccountData(m.db, zzcrBorrower, m.asset)
	zzcrEq(t, "supply", s, big.NewInt(1000))
	zzcrEq(t, "debt", b, big.NewInt(0))
	zzcrEq(t, "headroom", a, big.NewInt(750))
	zzcrAtLeast(t, "health with no debt", h, RAY)

	// Borrowing consumes headroom one for one, down to none at the limit.
	m.borrow(t, zzcrBorrower, 300)
	s, b, a, h = m.lp.GetUserAccountData(m.db, zzcrBorrower, m.asset)
	zzcrEq(t, "debt after borrowing", b, big.NewInt(300))
	zzcrEq(t, "headroom after borrowing", a, big.NewInt(450))
	zzcrAtLeast(t, "still healthy", h, RAY)
	m.borrow(t, zzcrBorrower, 450)
	_, _, a, h = m.lp.GetUserAccountData(m.db, zzcrBorrower, m.asset)
	zzcrEq(t, "headroom at the limit", a, big.NewInt(0))
	zzcrEq(t, "health at the limit", h, RAY)

	// Past the limit headroom stays clamped at zero rather than going negative.
	m.zzcrPushDebt(t, zzcrBorrower, 2000)
	_, b, a, h = m.lp.GetUserAccountData(m.db, zzcrBorrower, m.asset)
	zzcrEq(t, "debt past the limit", b, big.NewInt(2000))
	zzcrEq(t, "headroom past the limit", a, big.NewInt(0))
	if h.Cmp(RAY) >= 0 {
		t.Fatalf("health past the limit: got %s, want under %s", h, RAY)
	}
}

// The account view restates a stale debt at the current index, so it reports
// what is owed now rather than what was owed at the last touch.
func TestZzcrAccountViewRestatesStaleDebt(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))
	unit := zzcrE24()
	setBalance(m.db, zzcrThird, new(big.Int).Mul(unit, big.NewInt(1000)))
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, new(big.Int).Mul(unit, big.NewInt(10))); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	_, before, headroomBefore, healthBefore := m.lp.GetUserAccountData(m.db, zzcrThird, m.asset)
	m.db.SetBlockNumber(m.db.GetBlockNumber() + 100_000)
	m.lp.accrueInterest(m.db, m.reserve(t))

	_, after, headroomAfter, healthAfter := m.lp.GetUserAccountData(m.db, zzcrThird, m.asset)
	if after.Cmp(before) <= 0 {
		t.Fatalf("the view did not restate the debt: %s then %s", before, after)
	}
	zzcrEq(t, "the stored figure is still stale", m.position(t, zzcrThird).BorrowAmount, before)
	// Health and headroom are computed from the restated figure, so both move
	// against the borrower as interest runs.
	if healthAfter.Cmp(healthBefore) >= 0 {
		t.Fatalf("health did not fall as interest ran: %s then %s", healthBefore, healthAfter)
	}
	if headroomAfter.Cmp(headroomBefore) >= 0 {
		t.Fatalf("headroom did not fall as interest ran: %s then %s", headroomBefore, headroomAfter)
	}
}

func TestZzcrAPYViews(t *testing.T) {
	m := zzcrNewMarket(t, RAY, zzcrFrac(5, 100))

	// An unknown market quotes nothing rather than guessing.
	zzcrEq(t, "supply APY on an unknown market", m.lp.GetSupplyAPY(zzcrUnknownAsset), big.NewInt(0))
	zzcrEq(t, "borrow APY on an unknown market", m.lp.GetBorrowAPY(zzcrUnknownAsset), big.NewInt(0))

	// An idle market quotes nothing on either side.
	zzcrEq(t, "supply APY when idle", m.lp.GetSupplyAPY(m.asset), big.NewInt(0))
	zzcrEq(t, "borrow APY when idle", m.lp.GetBorrowAPY(m.asset), big.NewInt(0))

	unit := zzcrE24()
	setBalance(m.db, zzcrThird, new(big.Int).Mul(unit, big.NewInt(1000)))
	if _, err := m.lp.Supply(m.db, zzcrThird, m.asset, new(big.Int).Mul(unit, big.NewInt(2))); err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if err := m.lp.Borrow(m.db, zzcrThird, m.asset, unit); err != nil {
		t.Fatalf("Borrow: %v", err)
	}

	r := m.reserve(t)
	model := DefaultInterestRateModel()
	cash := new(big.Int).Sub(r.TotalSupply, r.TotalBorrows)
	zzcrEq(t, "borrow APY", m.lp.GetBorrowAPY(m.asset), model.GetBorrowAPR(cash, r.TotalBorrows, r.TotalReserves))
	zzcrEq(t, "supply APY", m.lp.GetSupplyAPY(m.asset), model.GetSupplyAPR(cash, r.TotalBorrows, r.TotalReserves))
	zzcrAtMost(t, "suppliers never out-earn borrowers", m.lp.GetSupplyAPY(m.asset), m.lp.GetBorrowAPY(m.asset))

	// A market admitted without a rate model quotes nothing at all.
	lp2 := NewLendingPool(NewPoolManager())
	db2 := NewMockStateDB()
	if err := lp2.InitializeReserve(db2, zzcrAsset, RAY, zzcrFrac(5, 100), nil); err != nil {
		t.Fatalf("InitializeReserve: %v", err)
	}
	lp2.GetReserve(zzcrAsset).TotalBorrows = unit
	zzcrEq(t, "supply APY with no model", lp2.GetSupplyAPY(zzcrAsset), big.NewInt(0))
	zzcrEq(t, "borrow APY with no model", lp2.GetBorrowAPY(zzcrAsset), big.NewInt(0))
}

// =========================================================================
// Keys and storage
// =========================================================================

// One key per (user, market) pair, and no two pairs share one.
func TestZzcrPositionKeyIsInjective(t *testing.T) {
	seen := map[[32]byte][2]common.Address{}
	users := []common.Address{zzcrBorrower, zzcrKeeper, zzcrLender, zzcrThird, {}}
	assets := []common.Address{zzcrAsset, zzcrAssetB, zzcrUnknownAsset, {}}
	for _, u := range users {
		for _, a := range assets {
			k := positionKey(u, a)
			if prev, dup := seen[k]; dup {
				t.Fatalf("key collision: (%s,%s) and (%s,%s)", u.Hex(), a.Hex(), prev[0].Hex(), prev[1].Hex())
			}
			seen[k] = [2]common.Address{u, a}
			if k != positionKey(u, a) {
				t.Fatal("the key is not stable across calls")
			}
		}
	}
	// The pair is ordered: a user and a market cannot be swapped for each other.
	if positionKey(zzcrBorrower, zzcrAsset) == positionKey(zzcrAsset, zzcrBorrower) {
		t.Fatal("the key ignores which half is the user")
	}
}

// DEFECT PIN, HIGH. savePosition writes each figure LEFT-aligned into its
// sixteen-byte half (lending.go:721) and getPosition reads the half back as a
// big-endian integer (lending.go:706). The round trip is therefore not the
// identity: a stored figure comes back multiplied by 2^112, and worse, the
// encoding is not injective -- 1 and 256 persist to the same bytes. Owner,
// asset, stamp and borrow index are not written at all, so a position rebuilt
// from storage belongs to the zero address. Correct behaviour right-aligns.
func TestZzcrPositionStorageRoundTripIsNotTheIdentityPinsDefect(t *testing.T) {
	lp := NewLendingPool(NewPoolManager())
	db := NewMockStateDB()
	db.SetBlockNumber(99)
	key := positionKey(zzcrBorrower, zzcrAsset)

	lp.savePosition(db, key, &LendingPosition{
		Owner: zzcrBorrower, Asset: zzcrAsset,
		SupplyShares: big.NewInt(1000), BorrowAmount: big.NewInt(750),
		BorrowIndex: new(big.Int).Mul(RAY, big.NewInt(2)), LastUpdateBlock: 99,
	})
	delete(lp.positions, key) // force the read to come off storage

	got := lp.getPosition(db, key)
	if got == nil {
		t.Fatal("a saved position did not come back")
	}
	shift := new(big.Int).Lsh(big.NewInt(1), 112)
	if got.SupplyShares.Cmp(big.NewInt(1000)) == 0 {
		t.Fatal("defect appears fixed: shares round-trip intact -- " +
			"right-align the copy at lending.go:721 and delete this pin")
	}
	zzcrEq(t, "shares come back scaled by 2^112", got.SupplyShares, new(big.Int).Mul(big.NewInt(1000), shift))
	zzcrEq(t, "debt comes back scaled by 2^112", got.BorrowAmount, new(big.Int).Mul(big.NewInt(750), shift))
	if got.Owner != (common.Address{}) || got.Asset != (common.Address{}) {
		t.Fatalf("defect appears fixed: identity survived storage (%s,%s) -- delete this pin",
			got.Owner.Hex(), got.Asset.Hex())
	}
	if got.LastUpdateBlock != 0 {
		t.Fatalf("defect appears fixed: the stamp survived storage (%d) -- delete this pin", got.LastUpdateBlock)
	}
	zzcrEq(t, "the borrow stamp is reset to parity", got.BorrowIndex, RAY)

	// Not injective: two different holdings persist to the same bytes.
	kA, kB := positionKey(zzcrKeeper, zzcrAsset), positionKey(zzcrThird, zzcrAsset)
	lp.savePosition(db, kA, &LendingPosition{SupplyShares: big.NewInt(1), BorrowAmount: big.NewInt(0)})
	lp.savePosition(db, kB, &LendingPosition{SupplyShares: big.NewInt(256), BorrowAmount: big.NewInt(0)})
	delete(lp.positions, kA)
	delete(lp.positions, kB)
	a, b := lp.getPosition(db, kA), lp.getPosition(db, kB)
	if a.SupplyShares.Cmp(b.SupplyShares) != 0 {
		t.Fatalf("defect appears fixed: 1 and 256 now persist apart (%s vs %s) -- delete this pin",
			a.SupplyShares, b.SupplyShares)
	}
}

// A key with nothing behind it reads as no position rather than an empty one.
func TestZzcrUnknownPositionReadsAsAbsent(t *testing.T) {
	lp := NewLendingPool(NewPoolManager())
	db := NewMockStateDB()
	if got := lp.getPosition(db, positionKey(zzcrBorrower, zzcrAsset)); got != nil {
		t.Fatalf("an unwritten key produced a position: %+v", got)
	}
	if len(lp.positions) != 0 {
		t.Fatalf("an unwritten key was cached: %d entries", len(lp.positions))
	}
}

// =========================================================================
// Unchecked signs
// =========================================================================

// DEFECT PIN, HIGH. Supply and Borrow both refuse a non-positive amount; Repay
// does not. A negative repayment runs the transfer backwards -- the pool pays
// the caller -- and adds the same figure to their debt, with no collateral
// check anywhere on the path. It is an unsecured withdrawal of the market's
// cash by anyone holding one unit of debt. Correct behaviour refuses it.
func TestZzcrNegativeRepayIsAnUncheckedWithdrawalPinsDefect(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)
	m.borrow(t, zzcrBorrower, 1) // one unit of debt is the whole entry fee

	before := m.bal(zzcrBorrower)
	poolBefore := m.bal(lendingPoolAddr)
	debtBefore := new(big.Int).Set(m.position(t, zzcrBorrower).BorrowAmount)
	const steal = 900_000

	got, err := m.lp.Repay(m.db, zzcrBorrower, m.asset, big.NewInt(-steal))
	if err != nil {
		t.Fatalf("defect appears fixed: a negative repayment now returns %v -- "+
			"refuse a non-positive amount at lending.go:440 and delete this pin", err)
	}
	zzcrEq(t, "the call reports the negative figure back", got, big.NewInt(-steal))
	zzcrEq(t, "the caller was paid", m.bal(zzcrBorrower), new(big.Int).Add(before, big.NewInt(steal)))
	zzcrEq(t, "the pool paid", m.bal(lendingPoolAddr), new(big.Int).Sub(poolBefore, big.NewInt(steal)))
	zzcrEq(t, "the debt grew by the same figure",
		m.position(t, zzcrBorrower).BorrowAmount, new(big.Int).Add(debtBefore, big.NewInt(steal)))

	// The collateral behind it is a thousandth of what walked out.
	if !m.liq.IsLiquidatable(m.db, zzcrBorrower, m.asset) {
		t.Fatal("the position is not even liquidatable afterwards")
	}
	pos := m.position(t, zzcrBorrower)
	if pos.BorrowAmount.Cmp(pos.SupplyShares) <= 0 {
		t.Fatalf("debt %s did not exceed collateral %s", pos.BorrowAmount, pos.SupplyShares)
	}
}

// DEFECT PIN. Withdraw does not check the sign either. A negative withdrawal is
// a deposit that skips the frozen flag, the supply cap and the zero-amount
// refusal that Supply enforces. Correct behaviour refuses it.
func TestZzcrNegativeWithdrawIsADepositThroughTheBackPinsDefect(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	m.supply(t, zzcrLender, 1_000_000)
	m.supply(t, zzcrBorrower, 1000)

	// Close the front door: frozen, and capped at what is already there.
	r := m.reserve(t)
	r.IsFrozen = true
	r.SupplyCap = new(big.Int).Set(r.TotalSupply)
	if _, err := m.lp.Supply(m.db, zzcrBorrower, m.asset, big.NewInt(500)); err != ErrReserveFrozen {
		t.Fatalf("the front door is not shut: %v", err)
	}

	sharesBefore := new(big.Int).Set(m.position(t, zzcrBorrower).SupplyShares)
	supplyBefore := new(big.Int).Set(r.TotalSupply)
	got, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(-500))
	if err != nil {
		t.Fatalf("defect appears fixed: a negative withdrawal now returns %v -- "+
			"refuse a non-positive amount at lending.go:285 and delete this pin", err)
	}
	zzcrEq(t, "the call reports the negative figure back", got, big.NewInt(-500))
	zzcrEq(t, "shares grew", m.position(t, zzcrBorrower).SupplyShares, new(big.Int).Add(sharesBefore, big.NewInt(500)))
	zzcrEq(t, "recorded supply grew past its cap", r.TotalSupply, new(big.Int).Add(supplyBefore, big.NewInt(500)))
	if r.TotalSupply.Cmp(r.SupplyCap) <= 0 {
		t.Fatalf("supply %s did not pass the cap %s", r.TotalSupply, r.SupplyCap)
	}
	// A zero withdrawal is accepted too, where Supply would refuse it.
	zero, err := m.lp.Withdraw(m.db, zzcrBorrower, m.asset, big.NewInt(0))
	if err != nil {
		t.Fatalf("defect appears fixed: a zero withdrawal now returns %v -- delete this pin", err)
	}
	zzcrEq(t, "a zero withdrawal returns zero", zero, big.NewInt(0))
}

// DEFECT PIN. transferAsset moves value without checking that the payer holds
// it, so a market accepts a deposit from an account with nothing in it and the
// payer's balance wraps instead of the call being refused. Correct behaviour
// checks the balance before the subtraction.
func TestZzcrTransferDoesNotCheckThePayerPinsDefect(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	pauper := common.HexToAddress("0x0000000000000000000000000000000000ba1d00")
	setBalance(m.db, pauper, big.NewInt(0))

	if _, err := m.lp.Supply(m.db, pauper, m.asset, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("defect appears fixed: a deposit from an empty account now returns %v -- "+
			"check the payer at lending.go:739 and delete this pin", err)
	}
	zzcrEq(t, "the deposit was credited in full", m.position(t, pauper).SupplyShares, big.NewInt(1_000_000))
	// The payer's balance underflowed rather than the call being refused.
	want := new(big.Int).Sub(zzcrTwo256(), big.NewInt(1_000_000))
	zzcrEq(t, "the payer's balance wrapped", m.bal(pauper), want)
}

// =========================================================================
// Solvency across a workload
// =========================================================================

// Every legal sequence of operations leaves the market's books balanced and
// every position solvent. Deterministic seed 0x5EEDC0DE, fixed for
// reproducibility; the clock is held still so accrual cannot mask a mistake.
func TestZzcrMarketStaysSolventAcrossAWorkload(t *testing.T) {
	m := zzcrNewMarket(t, zzcrFrac(75, 100), zzcrFrac(5, 100))
	users := []common.Address{zzcrBorrower, zzcrKeeper, zzcrLender, zzcrThird}
	for _, u := range users {
		m.supply(t, u, 100_000)
	}
	rng := rand.New(rand.NewSource(0x5EEDC0DE))

	for step := 0; step < 4000; step++ {
		u := users[rng.Intn(len(users))]
		amount := big.NewInt(rng.Int63n(50_000) + 1)
		switch rng.Intn(4) {
		case 0:
			_, _ = m.lp.Supply(m.db, u, m.asset, amount)
		case 1:
			_ = m.lp.Borrow(m.db, u, m.asset, amount)
		case 2:
			_, _ = m.lp.Repay(m.db, u, m.asset, amount)
		case 3:
			_, _ = m.lp.Withdraw(m.db, u, m.asset, amount)
		}

		r := m.reserve(t)
		shares, debts := big.NewInt(0), big.NewInt(0)
		for _, v := range users {
			p := m.lp.GetPosition(m.db, v, m.asset)
			if p == nil {
				continue
			}
			zzcrAtLeast(t, "shares never go negative", p.SupplyShares, big.NewInt(0))
			zzcrAtLeast(t, "debt never goes negative", p.BorrowAmount, big.NewInt(0))

			// Solvency: what is owed never exceeds what the collateral factor
			// admits, so no position is ever liquidatable off a legal step.
			ceiling := new(big.Int).Mul(p.SupplyShares, r.CollateralFactor)
			ceiling.Div(ceiling, RAY)
			zzcrAtMost(t, "debt within the collateral factor", p.BorrowAmount, ceiling)
			if p.BorrowAmount.Sign() > 0 && m.liq.IsLiquidatable(m.db, v, m.asset) {
				t.Fatalf("step %d: a position built only from legal calls is liquidatable", step)
			}
			shares.Add(shares, p.SupplyShares)
			debts.Add(debts, p.BorrowAmount)
		}
		// The market's books equal the sum of the positions on them.
		zzcrEq(t, "recorded supply equals the shares held", r.TotalSupply, shares)
		zzcrEq(t, "recorded debt equals the debts owed", r.TotalBorrows, debts)
		zzcrAtMost(t, "the market never lends more than it holds", r.TotalBorrows, r.TotalSupply)
	}
}
