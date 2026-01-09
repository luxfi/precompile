// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// Test addresses for lending
var (
	testLendingAsset = common.HexToAddress("0x4444444444444444444444444444444444444444")
	testLendingUser1 = common.HexToAddress("0x5555555555555555555555555555555555555555")
	testLendingUser2 = common.HexToAddress("0x6666666666666666666666666666666666666666")
)

// =========================================================================
// Interest Rate Model Tests
// =========================================================================

func TestInterestRateModel_DefaultModel(t *testing.T) {
	model := DefaultInterestRateModel()

	if model.BaseRate.Sign() != 0 {
		t.Errorf("expected base rate 0, got %v", model.BaseRate)
	}

	// Slope1 should be 4% = 0.04 * 1e18
	expectedSlope1 := new(big.Int).Div(new(big.Int).Mul(big.NewInt(4), RAY), big.NewInt(100))
	if model.Slope1.Cmp(expectedSlope1) != 0 {
		t.Errorf("expected slope1 %v, got %v", expectedSlope1, model.Slope1)
	}

	// OptimalUtilization should be 80%
	expectedOptimal := new(big.Int).Div(new(big.Int).Mul(big.NewInt(80), RAY), big.NewInt(100))
	if model.OptimalUtilization.Cmp(expectedOptimal) != 0 {
		t.Errorf("expected optimal %v, got %v", expectedOptimal, model.OptimalUtilization)
	}
}

func TestInterestRateModel_GetUtilizationRate(t *testing.T) {
	model := DefaultInterestRateModel()

	// No borrows = 0% utilization
	util := model.GetUtilizationRate(bigInt("1000000000000000000"), big.NewInt(0), big.NewInt(0))
	if util.Sign() != 0 {
		t.Errorf("expected 0 utilization, got %v", util)
	}

	// 50% utilization: 500 borrowed, 500 cash, 0 reserves
	cash := bigInt("500000000000000000000")
	borrows := bigInt("500000000000000000000")
	util = model.GetUtilizationRate(cash, borrows, big.NewInt(0))

	// Expected: 500 / 1000 = 0.5 = 50%
	expectedUtil := new(big.Int).Div(RAY, big.NewInt(2))
	if util.Cmp(expectedUtil) != 0 {
		t.Errorf("expected 50%% utilization (%v), got %v", expectedUtil, util)
	}
}

func TestInterestRateModel_GetBorrowRate_BelowKink(t *testing.T) {
	model := DefaultInterestRateModel()

	// 50% utilization (below 80% kink)
	cash := bigInt("500000000000000000000")
	borrows := bigInt("500000000000000000000")

	rate := model.GetBorrowRate(cash, borrows, big.NewInt(0))

	// Rate should be positive
	if rate.Sign() <= 0 {
		t.Errorf("expected positive borrow rate, got %v", rate)
	}
}

func TestInterestRateModel_GetBorrowRate_AboveKink(t *testing.T) {
	model := DefaultInterestRateModel()

	// 95% utilization (above 80% kink)
	cash := bigInt("50000000000000000000")
	borrows := bigInt("950000000000000000000")

	rate := model.GetBorrowRate(cash, borrows, big.NewInt(0))

	// Rate should be higher than at 50% utilization
	rate50 := model.GetBorrowRate(bigInt("500000000000000000000"), bigInt("500000000000000000000"), big.NewInt(0))

	if rate.Cmp(rate50) <= 0 {
		t.Errorf("expected higher rate above kink, got rate=%v, rate50=%v", rate, rate50)
	}
}

func TestInterestRateModel_GetSupplyRate(t *testing.T) {
	model := DefaultInterestRateModel()

	cash := bigInt("500000000000000000000")
	borrows := bigInt("500000000000000000000")

	supplyRate := model.GetSupplyRate(cash, borrows, big.NewInt(0))
	borrowRate := model.GetBorrowRate(cash, borrows, big.NewInt(0))

	// Supply rate should be less than borrow rate (due to reserve factor)
	if supplyRate.Cmp(borrowRate) >= 0 {
		t.Errorf("expected supply rate < borrow rate")
	}
}

func TestInterestRateModel_AccrueInterest(t *testing.T) {
	model := DefaultInterestRateModel()

	principal := bigInt("1000000000000000000000") // 1000 tokens
	cash := bigInt("500000000000000000000")
	borrows := bigInt("500000000000000000000")
	blocks := uint64(100)

	interest := model.AccrueInterest(principal, cash, borrows, big.NewInt(0), blocks)

	// Interest should be positive
	if interest.Sign() <= 0 {
		t.Errorf("expected positive interest, got %v", interest)
	}

	// Interest should be less than principal for 100 blocks
	if interest.Cmp(principal) >= 0 {
		t.Errorf("interest too high: %v >= %v", interest, principal)
	}
}

// =========================================================================
// Lending Pool Tests
// =========================================================================

func TestLendingPool_NewLendingPool(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)

	if lp == nil {
		t.Fatal("NewLendingPool returned nil")
	}

	if lp.poolManager != pm {
		t.Error("pool manager not set correctly")
	}
}

func TestLendingPool_InitializeReserve(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// 75% collateral factor
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	// 5% liquidation bonus
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))

	err := lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())
	if err != nil {
		t.Fatalf("InitializeReserve failed: %v", err)
	}

	// Check reserve was created
	reserve := lp.GetReserve(testLendingAsset)
	if reserve == nil {
		t.Fatal("reserve not found after initialization")
	}

	if !reserve.IsActive {
		t.Error("reserve should be active")
	}

	if reserve.CollateralFactor.Cmp(collateralFactor) != 0 {
		t.Errorf("wrong collateral factor: got %v, want %v", reserve.CollateralFactor, collateralFactor)
	}
}

func TestLendingPool_InitializeReserve_AlreadyExists(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))

	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Try to initialize again
	err := lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())
	if err != ErrReserveAlreadyExists {
		t.Errorf("expected ErrReserveAlreadyExists, got %v", err)
	}
}

func TestLendingPool_Supply(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Give user balance
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000")) // 10,000 tokens

	// Supply 1000 tokens
	supplyAmount := bigInt("1000000000000000000000")
	supplyTokens, err := lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)
	if err != nil {
		t.Fatalf("Supply failed: %v", err)
	}

	// At 1:1 exchange rate, supply tokens should equal supply amount
	if supplyTokens.Cmp(supplyAmount) != 0 {
		t.Errorf("wrong supply tokens: got %v, want %v", supplyTokens, supplyAmount)
	}

	// Check position
	position := lp.GetPosition(stateDB, testLendingUser1, testLendingAsset)
	if position == nil {
		t.Fatal("position not found")
	}

	if position.SupplyShares.Cmp(supplyAmount) != 0 {
		t.Errorf("wrong supply shares: got %v, want %v", position.SupplyShares, supplyAmount)
	}

	// Check reserve total
	reserve := lp.GetReserve(testLendingAsset)
	if reserve.TotalSupply.Cmp(supplyAmount) != 0 {
		t.Errorf("wrong total supply: got %v, want %v", reserve.TotalSupply, supplyAmount)
	}
}

func TestLendingPool_Borrow(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve with 75% LTV
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply first
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000") // 1000 tokens
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Borrow 500 tokens (50% of collateral, well below 75% limit)
	borrowAmount := bigInt("500000000000000000000")
	err := lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)
	if err != nil {
		t.Fatalf("Borrow failed: %v", err)
	}

	// Check position
	position := lp.GetPosition(stateDB, testLendingUser1, testLendingAsset)
	if position.BorrowAmount.Cmp(borrowAmount) != 0 {
		t.Errorf("wrong borrow amount: got %v, want %v", position.BorrowAmount, borrowAmount)
	}

	// Check reserve
	reserve := lp.GetReserve(testLendingAsset)
	if reserve.TotalBorrows.Cmp(borrowAmount) != 0 {
		t.Errorf("wrong total borrows: got %v, want %v", reserve.TotalBorrows, borrowAmount)
	}
}

func TestLendingPool_Borrow_ExceedsLTV(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve with 75% LTV
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply 1000 tokens
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Try to borrow 800 tokens (80% > 75% limit)
	borrowAmount := bigInt("800000000000000000000")
	err := lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)
	if err != ErrMaxLTVExceeded {
		t.Errorf("expected ErrMaxLTVExceeded, got %v", err)
	}
}

func TestLendingPool_Repay(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply and borrow
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	borrowAmount := bigInt("500000000000000000000")
	lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)

	// Repay half
	repayAmount := bigInt("250000000000000000000")
	actualRepaid, err := lp.Repay(stateDB, testLendingUser1, testLendingAsset, repayAmount)
	if err != nil {
		t.Fatalf("Repay failed: %v", err)
	}

	if actualRepaid.Cmp(repayAmount) != 0 {
		t.Errorf("wrong repaid amount: got %v, want %v", actualRepaid, repayAmount)
	}

	// Check position
	position := lp.GetPosition(stateDB, testLendingUser1, testLendingAsset)
	expectedDebt := new(big.Int).Sub(borrowAmount, repayAmount)
	if position.BorrowAmount.Cmp(expectedDebt) != 0 {
		t.Errorf("wrong debt after repay: got %v, want %v", position.BorrowAmount, expectedDebt)
	}
}

func TestLendingPool_Withdraw(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Withdraw half
	withdrawShares := bigInt("500000000000000000000")
	withdrawn, err := lp.Withdraw(stateDB, testLendingUser1, testLendingAsset, withdrawShares)
	if err != nil {
		t.Fatalf("Withdraw failed: %v", err)
	}

	// At 1:1 exchange rate, withdrawn should equal shares
	if withdrawn.Cmp(withdrawShares) != 0 {
		t.Errorf("wrong withdrawn amount: got %v, want %v", withdrawn, withdrawShares)
	}

	// Check position
	position := lp.GetPosition(stateDB, testLendingUser1, testLendingAsset)
	expectedShares := new(big.Int).Sub(supplyAmount, withdrawShares)
	if position.SupplyShares.Cmp(expectedShares) != 0 {
		t.Errorf("wrong shares after withdraw: got %v, want %v", position.SupplyShares, expectedShares)
	}
}

func TestLendingPool_Withdraw_WithDebt(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve with 75% LTV
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply 1000 tokens
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Borrow 500 tokens (50% LTV)
	borrowAmount := bigInt("500000000000000000000")
	lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)

	// Try to withdraw too much (would break health factor)
	// With 500 debt and 75% LTV, need at least 667 collateral
	// Withdrawing 400 would leave 600, which is below minimum
	withdrawShares := bigInt("400000000000000000000")
	_, err := lp.Withdraw(stateDB, testLendingUser1, testLendingAsset, withdrawShares)
	if err != ErrHealthFactorTooLow {
		t.Errorf("expected ErrHealthFactorTooLow, got %v", err)
	}
}

func TestLendingPool_GetHealthFactor(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve with 75% LTV
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply 1000 tokens
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Borrow 500 tokens
	borrowAmount := bigInt("500000000000000000000")
	lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)

	// Health factor = (1000 * 0.75) / 500 = 1.5
	healthFactor := lp.GetHealthFactor(stateDB, testLendingUser1, testLendingAsset)

	// Expected: 1.5 * RAY
	expectedHF := new(big.Int).Mul(RAY, big.NewInt(3))
	expectedHF.Div(expectedHF, big.NewInt(2))

	if healthFactor.Cmp(expectedHF) != 0 {
		t.Errorf("wrong health factor: got %v, want %v", healthFactor, expectedHF)
	}
}

func TestLendingPool_GetUserAccountData(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve with 75% LTV
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply 1000 tokens
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Borrow 500 tokens
	borrowAmount := bigInt("500000000000000000000")
	lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)

	supplyValue, borrowValue, availableToBorrow, healthFactor := lp.GetUserAccountData(stateDB, testLendingUser1, testLendingAsset)

	// Supply value should be 1000
	if supplyValue.Cmp(supplyAmount) != 0 {
		t.Errorf("wrong supply value: got %v, want %v", supplyValue, supplyAmount)
	}

	// Borrow value should be 500
	if borrowValue.Cmp(borrowAmount) != 0 {
		t.Errorf("wrong borrow value: got %v, want %v", borrowValue, borrowAmount)
	}

	// Available to borrow = (1000 * 0.75) - 500 = 250
	expectedAvailable := bigInt("250000000000000000000")
	if availableToBorrow.Cmp(expectedAvailable) != 0 {
		t.Errorf("wrong available to borrow: got %v, want %v", availableToBorrow, expectedAvailable)
	}

	// Health factor should be > 1 (position is healthy)
	if healthFactor.Cmp(RAY) <= 0 {
		t.Errorf("health factor should be > 1, got %v", healthFactor)
	}
}

// =========================================================================
// Liquidator Tests
// =========================================================================

func TestLiquidator_NewLiquidator(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	liquidator := NewLiquidator(lp)

	if liquidator == nil {
		t.Fatal("NewLiquidator returned nil")
	}

	if liquidator.lendingPool != lp {
		t.Error("lending pool not set correctly")
	}
}

func TestLiquidator_DefaultConfig(t *testing.T) {
	config := DefaultLiquidatorConfig()

	// Close factor should be 50%
	expectedCloseFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(50), RAY), big.NewInt(100))
	if config.CloseFactor.Cmp(expectedCloseFactor) != 0 {
		t.Errorf("wrong close factor: got %v, want %v", config.CloseFactor, expectedCloseFactor)
	}

	// Threshold should be 1.0
	if config.LiquidationThreshold.Cmp(RAY) != 0 {
		t.Errorf("wrong threshold: got %v, want %v", config.LiquidationThreshold, RAY)
	}
}

func TestLiquidator_IsLiquidatable(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	liquidator := NewLiquidator(lp)
	stateDB := NewMockStateDB()

	// Initialize reserve with 75% LTV
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply 1000 tokens
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	// Borrow 500 tokens (healthy position)
	borrowAmount := bigInt("500000000000000000000")
	lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)

	// Should not be liquidatable
	if liquidator.IsLiquidatable(stateDB, testLendingUser1, testLendingAsset) {
		t.Error("position should not be liquidatable")
	}
}

func TestLiquidator_GetLiquidatableAmount(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	liquidator := NewLiquidator(lp)
	stateDB := NewMockStateDB()

	// Initialize reserve
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// Supply and borrow (healthy position)
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supplyAmount := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supplyAmount)

	borrowAmount := bigInt("500000000000000000000")
	lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrowAmount)

	// Liquidatable amount should be 0 (position is healthy)
	liquidatableAmount := liquidator.GetLiquidatableAmount(stateDB, testLendingUser1, testLendingAsset)
	if liquidatableAmount.Sign() != 0 {
		t.Errorf("expected 0 liquidatable amount, got %v", liquidatableAmount)
	}
}

func TestLendingPool_FullFlow(t *testing.T) {
	pm := NewPoolManager()
	lp := NewLendingPool(pm)
	stateDB := NewMockStateDB()

	// Initialize reserve
	collateralFactor := new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100))
	liquidationBonus := new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100))
	lp.InitializeReserve(stateDB, testLendingAsset, collateralFactor, liquidationBonus, DefaultInterestRateModel())

	// User 1 supplies 1000 tokens
	setBalance(stateDB, testLendingUser1, bigInt("10000000000000000000000"))
	supply1 := bigInt("1000000000000000000000")
	lp.Supply(stateDB, testLendingUser1, testLendingAsset, supply1)

	// User 2 supplies 500 tokens
	setBalance(stateDB, testLendingUser2, bigInt("10000000000000000000000"))
	supply2 := bigInt("500000000000000000000")
	lp.Supply(stateDB, testLendingUser2, testLendingAsset, supply2)

	// User 1 borrows 400 tokens
	borrow1 := bigInt("400000000000000000000")
	err := lp.Borrow(stateDB, testLendingUser1, testLendingAsset, borrow1)
	if err != nil {
		t.Fatalf("User 1 borrow failed: %v", err)
	}

	// Check total supply
	reserve := lp.GetReserve(testLendingAsset)
	expectedTotalSupply := new(big.Int).Add(supply1, supply2)
	if reserve.TotalSupply.Cmp(expectedTotalSupply) != 0 {
		t.Errorf("wrong total supply: got %v, want %v", reserve.TotalSupply, expectedTotalSupply)
	}

	// User 1 repays full debt
	lp.Repay(stateDB, testLendingUser1, testLendingAsset, borrow1)

	// Check debt is 0
	position := lp.GetPosition(stateDB, testLendingUser1, testLendingAsset)
	if position.BorrowAmount.Sign() != 0 {
		t.Errorf("debt should be 0 after full repay, got %v", position.BorrowAmount)
	}

	// User 1 withdraws all
	lp.Withdraw(stateDB, testLendingUser1, testLendingAsset, supply1)

	// Check user 1 has no shares
	position = lp.GetPosition(stateDB, testLendingUser1, testLendingAsset)
	if position.SupplyShares.Sign() != 0 {
		t.Errorf("shares should be 0 after full withdraw, got %v", position.SupplyShares)
	}

	t.Logf("Full lending flow completed:")
	t.Logf("  User 1 supplied: %v", supply1)
	t.Logf("  User 2 supplied: %v", supply2)
	t.Logf("  User 1 borrowed: %v", borrow1)
	t.Logf("  User 1 repaid: %v", borrow1)
	t.Logf("  Total supply remaining: %v", reserve.TotalSupply)
}
