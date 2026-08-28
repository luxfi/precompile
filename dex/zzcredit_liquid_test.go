// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
)

var zzcrUnknownToken = common.HexToAddress("0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")

// zzcrE18 is the vault's fixed point: yield is collateral times the per-block
// rate divided by this.
func zzcrE18() *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) }

// zzcrCeiling is a debt ceiling far above anything these fixtures mint.
func zzcrCeiling() *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil) }

// =========================================================================
// Registration
// =========================================================================

func TestZzcrVaultRegistration(t *testing.T) {
	v := NewLiquid(NewPoolManager())
	db := NewMockStateDB()

	if err := v.AddYieldToken(db, zzcrYieldTok, zzcrUnder, big.NewInt(0)); err != nil {
		t.Fatalf("AddYieldToken: %v", err)
	}
	if err := v.AddYieldToken(db, zzcrYieldTok, zzcrUnder, big.NewInt(0)); err != ErrInvalidYieldToken {
		t.Fatalf("re-registering collateral: got %v, want ErrInvalidYieldToken", err)
	}
	if err := v.AddLiquidToken(db, zzcrSynthTok, zzcrUnder, zzcrCeiling()); err != nil {
		t.Fatalf("AddLiquidToken: %v", err)
	}
	// Re-registering a synthetic is refused, though under a name that reads as
	// the opposite of what happened (see the report on liquid.go:113).
	if err := v.AddLiquidToken(db, zzcrSynthTok, zzcrUnder, zzcrCeiling()); err != ErrLiquidTokenNotRegistered {
		t.Fatalf("re-registering a synthetic: got %v, want ErrLiquidTokenNotRegistered", err)
	}

	// Registration copies its arguments rather than aliasing the caller's.
	rate := big.NewInt(5)
	ceiling := big.NewInt(500)
	if err := v.AddYieldToken(db, zzcrUnknownToken, zzcrUnder, rate); err != nil {
		t.Fatalf("AddYieldToken: %v", err)
	}
	if err := v.AddLiquidToken(db, zzcrUnknownToken, zzcrUnder, ceiling); err != nil {
		t.Fatalf("AddLiquidToken: %v", err)
	}
	rate.SetInt64(999)
	ceiling.SetInt64(999)
	zzcrEq(t, "yield rate is a copy", v.yieldTokens[zzcrUnknownToken].YieldPerBlock, big.NewInt(5))
	zzcrEq(t, "debt ceiling is a copy", v.liquidTokens[zzcrUnknownToken].DebtCeiling, big.NewInt(500))

	yt := v.yieldTokens[zzcrYieldTok]
	if !yt.IsActive || yt.TotalDeposited.Sign() != 0 {
		t.Fatalf("fresh collateral token: active=%v deposited=%s", yt.IsActive, yt.TotalDeposited)
	}
	st := v.liquidTokens[zzcrSynthTok]
	if st.TotalMinted.Sign() != 0 {
		t.Fatalf("fresh synthetic has %s already minted", st.TotalMinted)
	}
}

// =========================================================================
// Deposit and withdraw
// =========================================================================

func TestZzcrVaultDepositRefusals(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())

	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrUnknownToken, big.NewInt(1)); err != ErrInvalidYieldToken {
		t.Fatalf("unknown collateral: got %v, want ErrInvalidYieldToken", err)
	}
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(0)); err != ErrInsufficientCollateral {
		t.Fatalf("zero deposit: got %v, want ErrInsufficientCollateral", err)
	}
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(-1)); err != ErrInsufficientCollateral {
		t.Fatalf("negative deposit: got %v, want ErrInsufficientCollateral", err)
	}
	// A delisted collateral token stops accepting deposits.
	q.v.yieldTokens[zzcrYieldTok].IsActive = false
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(1)); err != ErrInvalidYieldToken {
		t.Fatalf("delisted collateral: got %v, want ErrInvalidYieldToken", err)
	}
}

func TestZzcrVaultDepositAccumulates(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	before := q.bal(zzcrBorrower)
	vaultBefore := q.bal(liquidAddr)

	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	zzcrEq(t, "collateral", acc.Collateral, zzcrE18())
	zzcrEq(t, "debt", acc.Debt, big.NewInt(0))
	zzcrEq(t, "depositor paid", q.bal(zzcrBorrower), new(big.Int).Sub(before, zzcrE18()))
	zzcrEq(t, "vault received", q.bal(liquidAddr), new(big.Int).Add(vaultBefore, zzcrE18()))
	zzcrEq(t, "token total", q.v.yieldTokens[zzcrYieldTok].TotalDeposited, zzcrE18())

	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	zzcrEq(t, "collateral accumulates", q.account(t, zzcrBorrower).Collateral, new(big.Int).Mul(zzcrE18(), big.NewInt(2)))
	zzcrEq(t, "token total accumulates", q.v.yieldTokens[zzcrYieldTok].TotalDeposited, new(big.Int).Mul(zzcrE18(), big.NewInt(2)))

	// Two depositors keep separate books.
	if err := q.v.Deposit(q.db, zzcrThird, zzcrYieldTok, big.NewInt(7)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	zzcrEq(t, "the second account is its own", q.account(t, zzcrThird).Collateral, big.NewInt(7))
	zzcrEq(t, "the first account is untouched", q.account(t, zzcrBorrower).Collateral, new(big.Int).Mul(zzcrE18(), big.NewInt(2)))
}

func TestZzcrVaultWithdrawRefusals(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())

	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrUnknownToken, big.NewInt(1)); err != ErrInvalidYieldToken {
		t.Fatalf("unknown collateral: got %v, want ErrInvalidYieldToken", err)
	}
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(1)); err != ErrInsufficientCollateral {
		t.Fatalf("withdraw with no account: got %v, want ErrInsufficientCollateral", err)
	}
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	over := new(big.Int).Add(zzcrE18(), big.NewInt(1))
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, over); err != ErrInsufficientCollateral {
		t.Fatalf("withdraw past the deposit: got %v, want ErrInsufficientCollateral", err)
	}
	// Emptying the account closes it to further withdrawal.
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(1)); err != ErrInsufficientCollateral {
		t.Fatalf("withdraw from an empty account: got %v, want ErrInsufficientCollateral", err)
	}
	// An emptied account is refused for any amount, including nothing.
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(0)); err != ErrInsufficientCollateral {
		t.Fatalf("zero withdrawal from an empty account: got %v, want ErrInsufficientCollateral", err)
	}
	// And so is minting against it: nothing behind the debt is refused as
	// missing collateral rather than as a ratio the position cannot support.
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrInsufficientCollateral {
		t.Fatalf("mint against an emptied account: got %v, want ErrInsufficientCollateral", err)
	}
}

// Withdrawal stops exactly where the loan-to-value limit stops it: the last unit
// that keeps the debt covered comes out, the next one does not.
func TestZzcrVaultWithdrawStopsAtTheLimit(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	half := new(big.Int).Div(unit, big.NewInt(2))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, half); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// A debt of a half needs five ninths of a unit behind it, so four ninths is
	// free. The collateral that must stay is the smallest amount whose limit
	// still covers the debt -- a ceiling, because the limit itself floors.
	keep, rem := new(big.Int).DivMod(
		new(big.Int).Mul(half, big.NewInt(LTVPrecision)), big.NewInt(MaxLTV), new(big.Int))
	if rem.Sign() != 0 {
		keep.Add(keep, big.NewInt(1))
	}
	zzcrAtLeast(t, "the retained collateral covers the debt", q.v.calculateMaxDebt(keep), half)
	if q.v.calculateMaxDebt(new(big.Int).Sub(keep, big.NewInt(1))).Cmp(half) >= 0 {
		t.Fatal("the retained collateral is not the smallest that covers the debt")
	}
	free := new(big.Int).Sub(unit, keep)

	tooMuch := new(big.Int).Add(free, big.NewInt(1))
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, tooMuch); err != ErrMaxLTVExceeded {
		t.Fatalf("withdrawing one past the limit: got %v, want ErrMaxLTVExceeded", err)
	}
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, free); err != nil {
		t.Fatalf("withdrawing to exactly the limit: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	zzcrEq(t, "collateral left", acc.Collateral, keep)
	zzcrAtMost(t, "debt still covered", acc.Debt, q.v.calculateMaxDebt(acc.Collateral))
	zzcrAtMost(t, "ratio within the limit", q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(MaxLTV))

	// And nothing more comes out.
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(1)); err != ErrMaxLTVExceeded {
		t.Fatalf("withdrawing past the limit: got %v, want ErrMaxLTVExceeded", err)
	}
}

// =========================================================================
// Mint and burn
// =========================================================================

func TestZzcrVaultMintRefusals(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()

	if err := q.v.Mint(q.db, zzcrBorrower, zzcrUnknownToken, zzcrSynthTok, big.NewInt(1)); err != ErrInvalidYieldToken {
		t.Fatalf("unknown collateral: got %v, want ErrInvalidYieldToken", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrUnknownToken, big.NewInt(1)); err != ErrLiquidTokenNotRegistered {
		t.Fatalf("unknown synthetic: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrInsufficientCollateral {
		t.Fatalf("mint with no collateral: got %v, want ErrInsufficientCollateral", err)
	}
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	q.v.yieldTokens[zzcrYieldTok].IsActive = false
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrInvalidYieldToken {
		t.Fatalf("delisted collateral: got %v, want ErrInvalidYieldToken", err)
	}
	q.v.yieldTokens[zzcrYieldTok].IsActive = true

	// The ceiling is a ceiling on the total, inclusive.
	q.v.liquidTokens[zzcrSynthTok].DebtCeiling = big.NewInt(1000)
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1001)); err != ErrDebtCeiling {
		t.Fatalf("one past the ceiling: got %v, want ErrDebtCeiling", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1000)); err != nil {
		t.Fatalf("minting exactly to the ceiling: %v", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrDebtCeiling {
		t.Fatalf("minting past a full ceiling: got %v, want ErrDebtCeiling", err)
	}
}

// Minting stops at the loan-to-value limit and not a unit later, and what comes
// out is the amount less the mint fee -- the borrower owes more than they hold.
func TestZzcrVaultMintStopsAtTheLimit(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	limit := q.v.calculateMaxDebt(unit)
	zzcrEq(t, "the limit is the advertised share of the collateral", limit,
		new(big.Int).Div(new(big.Int).Mul(unit, big.NewInt(MaxLTV)), big.NewInt(LTVPrecision)))
	zzcrEq(t, "the view agrees", q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok), limit)

	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, new(big.Int).Add(limit, big.NewInt(1))); err != ErrMaxLTVExceeded {
		t.Fatalf("one past the limit: got %v, want ErrMaxLTVExceeded", err)
	}

	before := q.bal(zzcrBorrower)
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, limit); err != nil {
		t.Fatalf("minting to exactly the limit: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	zzcrEq(t, "debt is the full amount", acc.Debt, limit)
	zzcrEq(t, "collateral is untouched", acc.Collateral, unit)
	zzcrEq(t, "ratio sits exactly on the limit", q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(MaxLTV))

	// The fee is taken out of what is handed over, not out of what is owed.
	fee := q.v.calculateFee(limit, q.v.liquidTokens[zzcrSynthTok].MintFee)
	if fee.Sign() <= 0 {
		t.Fatalf("the fixture charges no fee: %s", fee)
	}
	zzcrEq(t, "the borrower receives the amount less the fee",
		q.bal(zzcrBorrower), new(big.Int).Add(before, new(big.Int).Sub(limit, fee)))
	zzcrEq(t, "the synthetic's total counts the gross", q.v.liquidTokens[zzcrSynthTok].TotalMinted, limit)

	// Nothing is left to mint, and the view says so.
	zzcrEq(t, "no headroom left", q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(0))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrMaxLTVExceeded {
		t.Fatalf("minting past a full position: got %v, want ErrMaxLTVExceeded", err)
	}
}

func TestZzcrVaultBurnRefusals(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())

	if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrUnknownToken, big.NewInt(1)); err != ErrLiquidTokenNotRegistered {
		t.Fatalf("unknown synthetic: got %v, want ErrLiquidTokenNotRegistered", err)
	}
	if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("burn with no account: got %v, want ErrNoDebtToRepay", err)
	}
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("burn with no debt: got %v, want ErrNoDebtToRepay", err)
	}
	// Burning against collateral that was never registered still works -- the
	// debt is what is being repaid, and the yield step is simply skipped.
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := q.v.Burn(q.db, zzcrBorrower, zzcrUnknownToken, zzcrSynthTok, big.NewInt(1)); err != ErrNoDebtToRepay {
		t.Fatalf("burn against unknown collateral: got %v, want ErrNoDebtToRepay", err)
	}
}

// Overpaying a burn is capped at the debt, and the burn fee means repaying the
// full debt still leaves the fee behind -- the borrower is never handed change.
func TestZzcrVaultBurnIsCappedAndCharged(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	debt := new(big.Int).Div(unit, big.NewInt(2))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, debt); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	before := q.bal(zzcrBorrower)
	mintedBefore := new(big.Int).Set(q.v.liquidTokens[zzcrSynthTok].TotalMinted)
	if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, new(big.Int).Mul(unit, big.NewInt(1000))); err != nil {
		t.Fatalf("Burn: %v", err)
	}

	fee := q.v.calculateFee(debt, q.v.liquidTokens[zzcrSynthTok].BurnFee)
	zzcrEq(t, "the borrower paid exactly the debt, not the request",
		q.bal(zzcrBorrower), new(big.Int).Sub(before, debt))
	zzcrEq(t, "the fee stays owed", q.account(t, zzcrBorrower).Debt, fee)
	zzcrAtLeast(t, "debt never goes negative", q.account(t, zzcrBorrower).Debt, big.NewInt(0))
	zzcrEq(t, "the synthetic's total falls by the gross",
		q.v.liquidTokens[zzcrSynthTok].TotalMinted, new(big.Int).Sub(mintedBefore, debt))
	zzcrEq(t, "collateral is untouched", q.account(t, zzcrBorrower).Collateral, unit)
}

// Minting and burning in a loop can never leave the borrower ahead: each turn
// costs both fees. Deterministic seed 0x5EEDC0DE, fixed for reproducibility.
func TestZzcrVaultMintBurnRoundTripNeverProfits(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := new(big.Int).Mul(zzcrE18(), big.NewInt(1000))
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	start := q.bal(zzcrBorrower)
	rng := rand.New(rand.NewSource(0x5EEDC0DE))
	for i := 0; i < 300; i++ {
		amount := new(big.Int).Rand(rng, new(big.Int).Div(unit, big.NewInt(4)))
		amount.Add(amount, big.NewInt(1))
		if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, amount); err != nil {
			continue
		}
		if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, new(big.Int).Mul(amount, big.NewInt(2))); err != nil {
			t.Fatalf("Burn after Mint: %v", err)
		}
		zzcrAtMost(t, "a round trip never enriches the borrower", q.bal(zzcrBorrower), start)
		zzcrEq(t, "a round trip leaves the collateral alone", q.account(t, zzcrBorrower).Collateral, unit)
		zzcrAtMost(t, "the ratio stays inside the limit",
			q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(MaxLTV))
	}
	if q.bal(zzcrBorrower).Cmp(start) >= 0 {
		t.Fatalf("three hundred round trips cost the borrower nothing: %s then %s", start, q.bal(zzcrBorrower))
	}
}

// Every legal deposit, mint, burn and withdraw leaves the position inside the
// advertised limit and its books non-negative. Seed 0x5EEDC0DE.
func TestZzcrVaultStaysInsideItsLimitAcrossAWorkload(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := new(big.Int).Mul(zzcrE18(), big.NewInt(1000))
	rng := rand.New(rand.NewSource(0x5EEDC0DE))

	for step := 0; step < 3000; step++ {
		amount := new(big.Int).Rand(rng, unit)
		amount.Add(amount, big.NewInt(1))
		switch rng.Intn(4) {
		case 0:
			_ = q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, amount)
		case 1:
			_ = q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, amount)
		case 2:
			_ = q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, amount)
		case 3:
			_ = q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, amount)
		}

		acc := q.v.GetAccount(q.db, zzcrBorrower, zzcrYieldTok)
		if acc == nil {
			continue
		}
		zzcrAtLeast(t, "collateral never goes negative", acc.Collateral, big.NewInt(0))
		zzcrAtLeast(t, "debt never goes negative", acc.Debt, big.NewInt(0))
		zzcrAtMost(t, "debt stays inside the limit", acc.Debt, q.v.calculateMaxDebt(acc.Collateral))
		zzcrAtMost(t, "the ratio stays inside the limit",
			q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(MaxLTV))
		zzcrAtLeast(t, "the token total never goes negative",
			q.v.yieldTokens[zzcrYieldTok].TotalDeposited, big.NewInt(0))
	}
}

// =========================================================================
// Yield
// =========================================================================

func TestZzcrHarvestRefusals(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(1), zzcrCeiling())

	if _, err := q.v.Harvest(q.db, zzcrBorrower, zzcrUnknownToken); err != ErrInvalidYieldToken {
		t.Fatalf("unknown collateral: got %v, want ErrInvalidYieldToken", err)
	}
	if _, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok); err != ErrInsufficientCollateral {
		t.Fatalf("harvest with no account: got %v, want ErrInsufficientCollateral", err)
	}
}

// Yield reduces debt and nothing else: collateral is never conjured, and once
// the debt is clear the surplus is held rather than applied to a negative debt.
func TestZzcrHarvestOnlyEverReducesDebt(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000)) // a tenth of a percent per block
	q := zzcrNewVault(t, rate, zzcrCeiling())
	unit := zzcrE18()
	zzcrSetLiquidBlock(q.db, 1)

	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	debt := new(big.Int).Div(unit, big.NewInt(2))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, debt); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	zzcrEq(t, "nothing harvested before any block passed", acc.AccruedYield, big.NewInt(0))

	// Nothing accrues inside one block.
	got, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrEq(t, "yield over zero blocks", got, big.NewInt(0))
	zzcrEq(t, "debt over zero blocks", acc.Debt, debt)

	// A hundred blocks pays down part of the debt, and collateral is untouched.
	zzcrSetLiquidBlock(q.db, 101)
	collateralBefore := new(big.Int).Set(acc.Collateral)
	got, err = q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	want := new(big.Int).Div(new(big.Int).Mul(unit, rate), zzcrE18())
	want.Mul(want, big.NewInt(100))
	zzcrEq(t, "yield over a hundred blocks", got, want)
	zzcrEq(t, "debt fell by exactly the yield", acc.Debt, new(big.Int).Sub(debt, want))
	zzcrEq(t, "collateral is untouched by a harvest", acc.Collateral, collateralBefore)
	zzcrEq(t, "nothing is left over while debt remains", acc.AccruedYield, big.NewInt(0))

	// Long enough and the debt clears; the surplus is held, the debt stops at
	// zero rather than going negative.
	zzcrSetLiquidBlock(q.db, 100_000)
	if _, err = q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrEq(t, "debt clears", acc.Debt, big.NewInt(0))
	zzcrAtLeast(t, "surplus is held", acc.AccruedYield, big.NewInt(1))
	zzcrEq(t, "collateral is still untouched", acc.Collateral, collateralBefore)

	// Harvesting a debt-free account keeps banking yield without touching debt.
	zzcrSetLiquidBlock(q.db, 200_000)
	surplus := new(big.Int).Set(acc.AccruedYield)
	if _, err = q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrAtLeast(t, "surplus keeps growing", acc.AccruedYield, surplus)
	zzcrEq(t, "debt stays clear", acc.Debt, big.NewInt(0))
}

// An account whose harvest stamp is unknown banks nothing on its first harvest
// and is stamped instead. Without that, an account rebuilt from storage -- where
// the stamp is not persisted at all -- would be paid yield for every block since
// the chain began, from collateral it only just posted.
func TestZzcrFirstHarvestBanksNothingAndStamps(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	q := zzcrNewVault(t, rate, zzcrCeiling())
	key := accountKey(zzcrBorrower, zzcrYieldTok)

	// An account with collateral and no stamp: exactly what getAccount rebuilds.
	q.v.saveAccount(q.db, key, &LiquidAccount{
		Owner: zzcrBorrower, YieldToken: zzcrYieldTok,
		Collateral: zzcrE18(), Debt: new(big.Int).Div(zzcrE18(), big.NewInt(2)),
		LastHarvestBlock: 0, AccruedYield: big.NewInt(0),
	})
	acc := q.v.accounts[key]
	debtBefore := new(big.Int).Set(acc.Debt)

	zzcrSetLiquidBlock(q.db, 1_000_000)
	got, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrEq(t, "the first harvest banks nothing", got, big.NewInt(0))
	zzcrEq(t, "the debt is untouched", acc.Debt, debtBefore)
	if acc.LastHarvestBlock != 1_000_000 {
		t.Fatalf("the stamp did not catch up: got %d, want 1000000", acc.LastHarvestBlock)
	}

	// From there yield runs normally, over the span since the stamp and no more.
	zzcrSetLiquidBlock(q.db, 1_000_100)
	got, err = q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	perBlock := new(big.Int).Div(new(big.Int).Mul(acc.Collateral, rate), zzcrE18())
	zzcrEq(t, "yield covers the span since the stamp", got, new(big.Int).Mul(perBlock, big.NewInt(100)))
}

// Banked surplus yield is applied to a debt only when a block has passed: a
// harvest inside the same block is a no-op, and the bank stays where it is until
// the clock moves. That is what stops a fresh mint being paid off out of a
// surplus that was already counted.
func TestZzcrBankedYieldWaitsForTheNextBlock(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	q := zzcrNewVault(t, rate, zzcrCeiling())
	unit := zzcrE18()
	perBlock := new(big.Int).Div(new(big.Int).Mul(unit, rate), zzcrE18())

	zzcrSetLiquidBlock(q.db, 1)
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, perBlock); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// A thousand blocks clears that debt and banks the rest.
	zzcrSetLiquidBlock(q.db, 1001)
	if _, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	zzcrEq(t, "the debt cleared", acc.Debt, big.NewInt(0))
	banked := new(big.Int).Set(acc.AccruedYield)
	zzcrAtLeast(t, "a surplus was banked", banked, big.NewInt(1))

	// New debt in the same block: the bank does not touch it.
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, perBlock); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	zzcrEq(t, "the bank is untouched by a same-block mint", acc.AccruedYield, banked)
	got, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrEq(t, "a same-block harvest yields nothing", got, big.NewInt(0))
	zzcrEq(t, "a same-block harvest leaves the debt alone", acc.Debt, perBlock)
	zzcrEq(t, "a same-block harvest leaves the bank alone", acc.AccruedYield, banked)

	// One block on and the bank is spent against it.
	zzcrSetLiquidBlock(q.db, 1002)
	if _, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrEq(t, "the bank cleared the new debt", acc.Debt, big.NewInt(0))
	zzcrEq(t, "and the bank fell by exactly that debt",
		acc.AccruedYield, new(big.Int).Sub(new(big.Int).Add(banked, perBlock), perBlock))
}

// An account owing nothing reports no wait, whatever the bank reads -- including
// the negative bank the backward-clock defect above can leave behind.
func TestZzcrNoDebtMeansNoWaitEvenOnANegativeBank(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	q := zzcrNewVault(t, rate, zzcrCeiling())
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	acc.Debt = big.NewInt(0)
	// Large enough that, were the bank counted as a debt, the wait would be
	// thousands of blocks rather than rounding away to nothing.
	acc.AccruedYield = new(big.Int).Neg(new(big.Int).Mul(zzcrE18(), big.NewInt(2)))

	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok); got != 0 {
		t.Fatalf("time to repayment with no debt: got %d, want 0", got)
	}
	// With a real debt the negative bank is added to the wait rather than
	// subtracted from it, so the estimate is never optimistic.
	acc.Debt = new(big.Int).Mul(zzcrE18(), big.NewInt(2))
	perBlock := new(big.Int).Div(new(big.Int).Mul(acc.Collateral, rate), zzcrE18())
	want := new(big.Int).Div(new(big.Int).Sub(acc.Debt, acc.AccruedYield), perBlock)
	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok); got != want.Uint64() {
		t.Fatalf("time to repayment with a debt and a negative bank: got %d, want %s", got, want)
	}
}

// Yield is monotone in elapsed blocks and never negative over any forward span.
func TestZzcrYieldIsMonotoneInElapsedBlocks(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	prev := big.NewInt(-1)
	for _, span := range []uint64{0, 1, 2, 10, 1000, 1 << 20, 1 << 40} {
		q := zzcrNewVault(t, rate, zzcrCeiling())
		zzcrSetLiquidBlock(q.db, 1)
		if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
			t.Fatalf("Deposit: %v", err)
		}
		zzcrSetLiquidBlock(q.db, 1+span)
		got, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
		if err != nil {
			t.Fatalf("Harvest: %v", err)
		}
		zzcrAtLeast(t, "yield is never negative", got, big.NewInt(0))
		if got.Cmp(prev) < 0 {
			t.Fatalf("yield fell over a longer span (%d blocks): %s then %s", span, prev, got)
		}
		prev = got
	}
}

// DEFECT PIN, HIGH. Liquid reads its clock from its own storage slot
// (liquid.go:605) and nothing in the package ever writes that slot, so
// getCurrentBlock answers 1 for ever. The self-repaying mechanism -- the whole
// point of the vault -- never fires, however far the chain advances. Correct
// behaviour reads the block from the state the rest of the package uses
// (StateDB.GetBlockNumber, as lending.go does).
func TestZzcrVaultClockNeverAdvancesPinsDefect(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	q := zzcrNewVault(t, rate, zzcrCeiling())

	if got := q.v.getCurrentBlock(q.db); got != 1 {
		t.Fatalf("defect appears fixed: an unwritten clock reads %d -- delete this pin", got)
	}
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	debt := new(big.Int).Div(zzcrE18(), big.NewInt(2))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, debt); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Move the chain a long way. The vault does not notice.
	q.db.SetBlockNumber(10_000_000)
	if got := q.v.getCurrentBlock(q.db); got != 1 {
		t.Fatalf("defect appears fixed: the vault now reads block %d from the chain -- "+
			"delete this pin", got)
	}
	for i := 0; i < 50; i++ {
		got, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
		if err != nil {
			t.Fatalf("Harvest: %v", err)
		}
		if got.Sign() != 0 {
			t.Fatalf("defect appears fixed: a harvest returned %s -- delete this pin", got)
		}
	}
	zzcrEq(t, "the debt never self-repaid", q.account(t, zzcrBorrower).Debt, debt)
	if q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok) == 0 {
		t.Fatal("the view claims the debt is already repaid")
	}
}

// DEFECT PIN, HIGH. blocksElapsed is a uint64 difference narrowed through int64
// at liquid.go:425, and nothing checks that the clock has moved forward. A clock
// reading behind the account's last harvest makes the elapsed count wrap, the
// yield come out negative, and the account's banked yield go below zero -- so a
// later, genuine harvest is silently swallowed paying off a debt that was never
// there. Correct behaviour refuses a clock that has gone backwards.
func TestZzcrHarvestGoesNegativeOnABackwardClockPinsDefect(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	q := zzcrNewVault(t, rate, zzcrCeiling())
	zzcrSetLiquidBlock(q.db, 1000)
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	debt := new(big.Int).Div(zzcrE18(), big.NewInt(2))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, debt); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	if acc.LastHarvestBlock != 1000 {
		t.Fatalf("fixture stamp: got %d, want 1000", acc.LastHarvestBlock)
	}

	zzcrSetLiquidBlock(q.db, 901) // the clock reads ninety-nine blocks earlier
	got, err := q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok)
	if err != nil {
		t.Fatalf("defect appears fixed: a backward clock now returns %v -- "+
			"refuse it at liquid.go:418 and delete this pin", err)
	}
	if got.Sign() >= 0 {
		t.Fatalf("defect appears fixed: a backward clock yielded %s -- delete this pin", got)
	}
	perBlock := new(big.Int).Div(new(big.Int).Mul(zzcrE18(), rate), zzcrE18())
	zzcrEq(t, "yield ran ninety-nine blocks backwards", got, new(big.Int).Mul(perBlock, big.NewInt(-99)))
	if acc.AccruedYield.Sign() >= 0 {
		t.Fatalf("defect appears fixed: banked yield is %s -- delete this pin", acc.AccruedYield)
	}
	zzcrEq(t, "the debt was left alone", acc.Debt, debt)

	// The negative bank then eats a genuine harvest: ninety-nine blocks of real
	// yield pay off nothing at all.
	zzcrSetLiquidBlock(q.db, 1000)
	if _, err = q.v.Harvest(q.db, zzcrBorrower, zzcrYieldTok); err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	zzcrEq(t, "real yield was swallowed", acc.Debt, debt)
	zzcrEq(t, "the bank is back to nothing", acc.AccruedYield, big.NewInt(0))
}

// =========================================================================
// Views
// =========================================================================

func TestZzcrVaultViewsOnAbsentThings(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(1), zzcrCeiling())

	if q.v.GetAccount(q.db, zzcrBorrower, zzcrYieldTok) != nil {
		t.Fatal("an account materialised out of nothing")
	}
	zzcrEq(t, "headroom on unknown collateral", q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrUnknownToken), big.NewInt(0))
	zzcrEq(t, "headroom with no account", q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(0))
	zzcrEq(t, "ratio on unknown collateral", q.v.GetLTV(q.db, zzcrBorrower, zzcrUnknownToken), big.NewInt(0))
	zzcrEq(t, "ratio with no account", q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(0))
	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrUnknownToken); got != 0 {
		t.Fatalf("time to repayment on unknown collateral: got %d, want 0", got)
	}
	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok); got != 0 {
		t.Fatalf("time to repayment with no account: got %d, want 0", got)
	}

	// A collateral token that pays nothing never repays anything.
	still := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	if err := still.v.Deposit(still.db, zzcrBorrower, zzcrYieldTok, zzcrE18()); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := still.v.Mint(still.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1000)); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if got := still.v.GetTimeToRepayment(still.db, zzcrBorrower, zzcrYieldTok); got != 0 {
		t.Fatalf("time to repayment on idle collateral: got %d, want 0", got)
	}

	// Collateral too small to earn a whole unit per block also never repays.
	dust := zzcrNewVault(t, big.NewInt(1), zzcrCeiling())
	if err := dust.v.Deposit(dust.db, zzcrBorrower, zzcrYieldTok, big.NewInt(1000)); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := dust.v.Mint(dust.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(500)); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if got := dust.v.GetTimeToRepayment(dust.db, zzcrBorrower, zzcrYieldTok); got != 0 {
		t.Fatalf("time to repayment on dust: got %d, want 0", got)
	}
}

func TestZzcrVaultViewsTrackThePosition(t *testing.T) {
	rate := new(big.Int).Div(zzcrE18(), big.NewInt(1000))
	q := zzcrNewVault(t, rate, zzcrCeiling())
	unit := zzcrE18()
	zzcrSetLiquidBlock(q.db, 1)
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	// No debt: no ratio, nothing to wait for, full headroom.
	zzcrEq(t, "ratio with no debt", q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(0))
	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok); got != 0 {
		t.Fatalf("time to repayment with no debt: got %d, want 0", got)
	}
	zzcrEq(t, "headroom", q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok), q.v.calculateMaxDebt(unit))

	debt := new(big.Int).Div(unit, big.NewInt(2))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, debt); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// The ratio is the debt over the collateral, in the advertised precision.
	want := new(big.Int).Div(new(big.Int).Mul(debt, big.NewInt(LTVPrecision)), unit)
	zzcrEq(t, "ratio", q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok), want)
	// The wait is the debt over the yield per block.
	perBlock := new(big.Int).Div(new(big.Int).Mul(unit, rate), zzcrE18())
	wait := new(big.Int).Div(debt, perBlock)
	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok); got != wait.Uint64() {
		t.Fatalf("time to repayment: got %d, want %s", got, wait)
	}
	// Headroom is what the limit allows less what is owed.
	zzcrEq(t, "headroom after minting",
		q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok),
		new(big.Int).Sub(q.v.calculateMaxDebt(unit), debt))

	// Banked yield counts against the debt in both views, and neither goes
	// negative when it covers the whole thing.
	acc := q.account(t, zzcrBorrower)
	acc.AccruedYield = new(big.Int).Mul(debt, big.NewInt(2))
	zzcrEq(t, "headroom with banked yield past the debt",
		q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok), q.v.calculateMaxDebt(unit))
	if got := q.v.GetTimeToRepayment(q.db, zzcrBorrower, zzcrYieldTok); got != 0 {
		t.Fatalf("time to repayment with the debt already covered: got %d, want 0", got)
	}

	// A position already past its limit reports no headroom rather than a
	// negative one.
	acc.AccruedYield = big.NewInt(0)
	acc.Debt = new(big.Int).Mul(unit, big.NewInt(10))
	zzcrEq(t, "headroom past the limit", q.v.GetMaxMintable(q.db, zzcrBorrower, zzcrYieldTok), big.NewInt(0))
}

// The limit and the fee both round down, toward the protocol: the borrower
// never gets a unit more of either.
func TestZzcrVaultArithmeticRoundsDown(t *testing.T) {
	v := NewLiquid(NewPoolManager())

	for _, collateral := range []int64{0, 1, 9, 10, 11, 9999, 1_000_003} {
		c := big.NewInt(collateral)
		got := v.calculateMaxDebt(c)
		want := new(big.Int).Div(new(big.Int).Mul(c, big.NewInt(MaxLTV)), big.NewInt(LTVPrecision))
		zzcrEq(t, "limit", got, want)
		zzcrAtMost(t, "the limit never reaches the collateral", got, c)
	}
	// Ten units at ninety per cent is nine, not ten; one unit is none at all.
	zzcrEq(t, "limit on ten", v.calculateMaxDebt(big.NewInt(10)), big.NewInt(9))
	zzcrEq(t, "limit on one", v.calculateMaxDebt(big.NewInt(1)), big.NewInt(0))

	for _, amount := range []int64{0, 1, 99_999, 100_000, 100_001} {
		a := big.NewInt(amount)
		got := v.calculateFee(a, 10)
		want := new(big.Int).Div(new(big.Int).Mul(a, big.NewInt(10)), big.NewInt(1_000_000))
		zzcrEq(t, "fee", got, want)
		zzcrAtMost(t, "the fee never exceeds the amount", got, a)
	}
	// A tenth of a basis point on 99,999 is under one unit, and the floor gives
	// it to the borrower.
	zzcrEq(t, "fee under one unit", v.calculateFee(big.NewInt(99_999), 10), big.NewInt(0))
	zzcrEq(t, "fee at one unit", v.calculateFee(big.NewInt(100_000), 10), big.NewInt(1))
	zzcrEq(t, "a zero rate charges nothing", v.calculateFee(big.NewInt(1_000_000), 0), big.NewInt(0))
}

// The vault prices collateral one for one today, and the clock reads back what
// was written to it.
func TestZzcrVaultCollateralPricingAndClock(t *testing.T) {
	v := NewLiquid(NewPoolManager())
	db := NewMockStateDB()
	yt := &YieldToken{Address: zzcrYieldTok, YieldPerBlock: big.NewInt(1)}

	for _, amount := range []int64{0, 1, 1_000_000} {
		in := big.NewInt(amount)
		out := v.getCollateralValue(db, in, yt)
		zzcrEq(t, "collateral value", out, in)
		// It hands back a copy, so a caller mutating the result cannot reach
		// into the account it came from.
		out.SetInt64(-1)
		zzcrEq(t, "the input is not aliased", in, big.NewInt(amount))
	}

	if got := v.getCurrentBlock(db); got != 1 {
		t.Fatalf("an unwritten clock: got %d, want 1", got)
	}
	for _, n := range []uint64{1, 2, 1 << 32, 1<<64 - 1} {
		zzcrSetLiquidBlock(db, n)
		if got := v.getCurrentBlock(db); got != n {
			t.Fatalf("clock: got %d, want %d", got, n)
		}
	}
}

// DEFECT PIN, HIGH. saveAccount writes each figure LEFT-aligned into its
// sixteen-byte half (liquid.go:647) and getAccount reads the half back as a
// big-endian integer (liquid.go:631), so the round trip multiplies by 2^112 and
// is not injective. Banked yield, owner, collateral token and the harvest stamp
// are not written at all, so unharvested yield is destroyed and the rebuilt
// account belongs to nobody. Correct behaviour right-aligns and persists the
// rest of the struct.
func TestZzcrVaultAccountStorageRoundTripIsNotTheIdentityPinsDefect(t *testing.T) {
	v := NewLiquid(NewPoolManager())
	db := NewMockStateDB()
	key := accountKey(zzcrBorrower, zzcrYieldTok)

	v.saveAccount(db, key, &LiquidAccount{
		Owner: zzcrBorrower, YieldToken: zzcrYieldTok,
		Collateral: big.NewInt(1000), Debt: big.NewInt(750),
		LastHarvestBlock: 42, AccruedYield: big.NewInt(5),
	})
	delete(v.accounts, key) // force the read to come off storage

	got := v.getAccount(db, key)
	if got == nil {
		t.Fatal("a saved account did not come back")
	}
	shift := new(big.Int).Lsh(big.NewInt(1), 112)
	if got.Collateral.Cmp(big.NewInt(1000)) == 0 {
		t.Fatal("defect appears fixed: collateral round-trips intact -- " +
			"right-align the copy at liquid.go:647 and delete this pin")
	}
	zzcrEq(t, "collateral comes back scaled by 2^112", got.Collateral, new(big.Int).Mul(big.NewInt(1000), shift))
	zzcrEq(t, "debt comes back scaled by 2^112", got.Debt, new(big.Int).Mul(big.NewInt(750), shift))
	zzcrEq(t, "banked yield is destroyed", got.AccruedYield, big.NewInt(0))
	if got.Owner != (common.Address{}) || got.YieldToken != (common.Address{}) {
		t.Fatalf("defect appears fixed: identity survived storage (%s,%s) -- delete this pin",
			got.Owner.Hex(), got.YieldToken.Hex())
	}
	if got.LastHarvestBlock != 0 {
		t.Fatalf("defect appears fixed: the stamp survived storage (%d) -- delete this pin", got.LastHarvestBlock)
	}

	// Not injective: two different holdings persist to the same bytes.
	kA, kB := accountKey(zzcrKeeper, zzcrYieldTok), accountKey(zzcrThird, zzcrYieldTok)
	v.saveAccount(db, kA, &LiquidAccount{Collateral: big.NewInt(1), Debt: big.NewInt(0)})
	v.saveAccount(db, kB, &LiquidAccount{Collateral: big.NewInt(256), Debt: big.NewInt(0)})
	delete(v.accounts, kA)
	delete(v.accounts, kB)
	if v.getAccount(db, kA).Collateral.Cmp(v.getAccount(db, kB).Collateral) != 0 {
		t.Fatal("defect appears fixed: 1 and 256 now persist apart -- delete this pin")
	}
}

// A key with nothing behind it reads as no account rather than an empty one.
func TestZzcrUnknownVaultAccountReadsAsAbsent(t *testing.T) {
	v := NewLiquid(NewPoolManager())
	db := NewMockStateDB()
	if got := v.getAccount(db, accountKey(zzcrBorrower, zzcrYieldTok)); got != nil {
		t.Fatalf("an unwritten key produced an account: %+v", got)
	}
	if len(v.accounts) != 0 {
		t.Fatalf("an unwritten key was cached: %d entries", len(v.accounts))
	}
	// One key per (owner, collateral) pair, ordered, and stable.
	if accountKey(zzcrBorrower, zzcrYieldTok) == accountKey(zzcrYieldTok, zzcrBorrower) {
		t.Fatal("the key ignores which half is the owner")
	}
	if accountKey(zzcrBorrower, zzcrYieldTok) != accountKey(zzcrBorrower, zzcrYieldTok) {
		t.Fatal("the key is not stable across calls")
	}
	if accountKey(zzcrBorrower, zzcrYieldTok) == accountKey(zzcrKeeper, zzcrYieldTok) {
		t.Fatal("two owners share one key")
	}
}

// =========================================================================
// Unchecked signs
// =========================================================================

// DEFECT PIN, HIGH. Burn does not check the sign of its argument. A negative
// burn runs the transfer backwards -- the caller is paid -- and adds the fee-net
// figure to their debt, with no loan-to-value check and no debt ceiling check on
// that path. It is a mint that ignores both limits, and because the fee is
// applied with the wrong sign the caller takes out more than the debt they take
// on. Correct behaviour refuses a non-positive amount.
func TestZzcrNegativeBurnIsAnUnlimitedMintPinsDefect(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), big.NewInt(600_000))
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(500_000)); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	before := q.bal(zzcrBorrower)
	debtBefore := new(big.Int).Set(q.account(t, zzcrBorrower).Debt)
	const grab = 200_000

	if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(-grab)); err != nil {
		t.Fatalf("defect appears fixed: a negative burn now returns %v -- "+
			"refuse a non-positive amount at liquid.go:343 and delete this pin", err)
	}
	zzcrEq(t, "the caller was paid the gross", q.bal(zzcrBorrower), new(big.Int).Add(before, big.NewInt(grab)))
	// They take on less debt than they took out: the fee lands on their side.
	fee := new(big.Int).Div(big.NewInt(grab*10), big.NewInt(1_000_000))
	zzcrEq(t, "the debt grew by the net", q.account(t, zzcrBorrower).Debt,
		new(big.Int).Add(debtBefore, new(big.Int).Sub(big.NewInt(grab), fee)))

	// And the ceiling that Mint enforces was walked straight past.
	st := q.v.liquidTokens[zzcrSynthTok]
	if st.TotalMinted.Cmp(st.DebtCeiling) <= 0 {
		t.Fatalf("defect appears fixed: minted %s is still inside the ceiling %s -- delete this pin",
			st.TotalMinted, st.DebtCeiling)
	}
	zzcrEq(t, "total minted past the ceiling", st.TotalMinted, big.NewInt(700_000))
}

// DEFECT PIN. Mint does not check the sign either. A negative mint is a
// repayment that pays the fee to the borrower instead of the protocol: the debt
// falls by the gross while the caller is charged only the net. Repeated, it
// drives the debt below zero, which then reads as unlimited headroom. Correct
// behaviour refuses a non-positive amount.
func TestZzcrNegativeMintIsADiscountedRepaymentPinsDefect(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(500_000)); err != nil {
		t.Fatalf("Mint: %v", err)
	}

	before := q.bal(zzcrBorrower)
	debtBefore := new(big.Int).Set(q.account(t, zzcrBorrower).Debt)
	const repay = 100_000

	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(-repay)); err != nil {
		t.Fatalf("defect appears fixed: a negative mint now returns %v -- "+
			"refuse a non-positive amount at liquid.go:270 and delete this pin", err)
	}
	fee := new(big.Int).Div(big.NewInt(repay*10), big.NewInt(1_000_000))
	zzcrEq(t, "the debt fell by the gross", q.account(t, zzcrBorrower).Debt,
		new(big.Int).Sub(debtBefore, big.NewInt(repay)))
	zzcrEq(t, "the caller was charged only the net", q.bal(zzcrBorrower),
		new(big.Int).Sub(before, new(big.Int).Sub(big.NewInt(repay), fee)))

	// Enough of them and the debt goes below zero -- a negative liability, which
	// the ratio reports as a negative ratio.
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(-10_000_000)); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	if acc.Debt.Sign() >= 0 {
		t.Fatalf("defect appears fixed: debt is %s -- delete this pin", acc.Debt)
	}
	if q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok).Sign() >= 0 {
		t.Fatalf("defect appears fixed: the ratio is %s -- delete this pin",
			q.v.GetLTV(q.db, zzcrBorrower, zzcrYieldTok))
	}

	// And the limit check reads off that negative liability, so a single mint
	// for more than the collateral allows is now accepted.
	limit := q.v.calculateMaxDebt(unit)
	past := new(big.Int).Add(limit, big.NewInt(1))
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, past); err != nil {
		t.Fatalf("defect appears fixed: a mint of %s past a limit of %s now returns %v -- "+
			"delete this pin", past, limit, err)
	}
}

// A debt driven below zero is erased rather than paid back out: burning against
// it clamps the debt at nothing, so the negative balance is not reclaimable.
// That clamp is only reachable once a negative mint has inverted the debt (see
// the pin above), which is how this fixture gets there.
func TestZzcrBurnClampsAnInvertedDebtToNothing(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(500_000)); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := q.v.Mint(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, new(big.Int).Neg(unit)); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	acc := q.account(t, zzcrBorrower)
	if acc.Debt.Sign() >= 0 {
		t.Fatalf("the fixture did not invert the debt: %s", acc.Debt)
	}

	if err := q.v.Burn(q.db, zzcrBorrower, zzcrYieldTok, zzcrSynthTok, big.NewInt(1)); err != nil {
		t.Fatalf("Burn: %v", err)
	}
	zzcrEq(t, "an inverted debt is clamped to nothing", acc.Debt, big.NewInt(0))
	zzcrAtLeast(t, "debt never reads negative afterwards", acc.Debt, big.NewInt(0))
}

// DEFECT PIN. Vault withdrawal checks neither the sign of the amount nor whether
// the collateral token is still listed, so a negative withdrawal is a deposit
// into a delisted token. Correct behaviour refuses both.
func TestZzcrNegativeVaultWithdrawIsADepositPinsDefect(t *testing.T) {
	q := zzcrNewVault(t, big.NewInt(0), zzcrCeiling())
	unit := zzcrE18()
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	// Delist it: the front door is shut.
	q.v.yieldTokens[zzcrYieldTok].IsActive = false
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, unit); err != ErrInvalidYieldToken {
		t.Fatalf("the front door is not shut: %v", err)
	}

	before := q.bal(zzcrBorrower)
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, new(big.Int).Neg(unit)); err != nil {
		t.Fatalf("defect appears fixed: a negative withdrawal now returns %v -- "+
			"refuse a non-positive amount at liquid.go:214 and delete this pin", err)
	}
	zzcrEq(t, "collateral grew", q.account(t, zzcrBorrower).Collateral, new(big.Int).Mul(unit, big.NewInt(2)))
	zzcrEq(t, "the caller paid for it", q.bal(zzcrBorrower), new(big.Int).Sub(before, unit))
	zzcrEq(t, "the delisted token's total grew",
		q.v.yieldTokens[zzcrYieldTok].TotalDeposited, new(big.Int).Mul(unit, big.NewInt(2)))

	// A zero withdrawal is accepted too, where a zero deposit is refused.
	q.v.yieldTokens[zzcrYieldTok].IsActive = true
	if err := q.v.Deposit(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(0)); err != ErrInsufficientCollateral {
		t.Fatalf("zero deposit: got %v, want ErrInsufficientCollateral", err)
	}
	if err := q.v.Withdraw(q.db, zzcrBorrower, zzcrYieldTok, big.NewInt(0)); err != nil {
		t.Fatalf("defect appears fixed: a zero withdrawal now returns %v -- delete this pin", err)
	}
}
