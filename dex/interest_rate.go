// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
)

// InterestRateModel implements a Compound-style kink interest rate model
// Rate = BaseRate + Utilization * Slope1 (below kink)
// Rate = BaseRate + Kink * Slope1 + (Utilization - Kink) * Slope2 (above kink)
//
// This creates two-slope dynamics:
// - Low utilization: gentle rate increase to encourage borrowing
// - High utilization: steep rate increase to encourage deposits
type InterestRateModel struct {
	// Base rate at 0% utilization (scaled by 1e18)
	BaseRate *big.Int

	// Slope of rate increase below optimal utilization (scaled by 1e18)
	Slope1 *big.Int

	// Slope of rate increase above optimal utilization (scaled by 1e18)
	Slope2 *big.Int

	// Optimal utilization rate / kink point (scaled by 1e18, e.g., 0.8e18 = 80%)
	OptimalUtilization *big.Int

	// Reserve factor - portion of interest that goes to protocol (scaled by 1e18)
	ReserveFactor *big.Int
}

// Scaling constants
var (
	// 1e18 for fixed-point arithmetic
	RAY = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

	// Seconds per year for APR/APY conversion
	SecondsPerYear = big.NewInt(31536000)

	// Blocks per year (assuming ~2 second blocks)
	BlocksPerYear = big.NewInt(15768000)
)

// DefaultInterestRateModel returns a standard interest rate model
// Similar to Compound/Aave defaults:
// - 0% base rate
// - 4% slope below kink
// - 75% slope above kink
// - 80% optimal utilization
// - 10% reserve factor
func DefaultInterestRateModel() *InterestRateModel {
	return &InterestRateModel{
		BaseRate:           big.NewInt(0),
		Slope1:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(4), RAY), big.NewInt(100)),  // 4%
		Slope2:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(75), RAY), big.NewInt(100)), // 75%
		OptimalUtilization: new(big.Int).Div(new(big.Int).Mul(big.NewInt(80), RAY), big.NewInt(100)), // 80%
		ReserveFactor:      new(big.Int).Div(new(big.Int).Mul(big.NewInt(10), RAY), big.NewInt(100)), // 10%
	}
}

// StablecoinInterestRateModel returns a model optimized for stablecoins
// Lower rates since stablecoins have less volatility risk
func StablecoinInterestRateModel() *InterestRateModel {
	return &InterestRateModel{
		BaseRate:           big.NewInt(0),
		Slope1:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(2), RAY), big.NewInt(100)),  // 2%
		Slope2:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(60), RAY), big.NewInt(100)), // 60%
		OptimalUtilization: new(big.Int).Div(new(big.Int).Mul(big.NewInt(90), RAY), big.NewInt(100)), // 90%
		ReserveFactor:      new(big.Int).Div(new(big.Int).Mul(big.NewInt(5), RAY), big.NewInt(100)),  // 5%
	}
}

// VolatileInterestRateModel returns a model for volatile assets
// Higher rates to compensate for volatility risk
func VolatileInterestRateModel() *InterestRateModel {
	return &InterestRateModel{
		BaseRate:           new(big.Int).Div(new(big.Int).Mul(big.NewInt(2), RAY), big.NewInt(100)),   // 2% base
		Slope1:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(7), RAY), big.NewInt(100)),   // 7%
		Slope2:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(100), RAY), big.NewInt(100)), // 100%
		OptimalUtilization: new(big.Int).Div(new(big.Int).Mul(big.NewInt(65), RAY), big.NewInt(100)),  // 65%
		ReserveFactor:      new(big.Int).Div(new(big.Int).Mul(big.NewInt(20), RAY), big.NewInt(100)),  // 20%
	}
}

// GetUtilizationRate calculates the utilization rate
// Utilization = TotalBorrows / (TotalCash + TotalBorrows - Reserves)
func (m *InterestRateModel) GetUtilizationRate(
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
) *big.Int {
	if totalBorrows.Sign() == 0 {
		return big.NewInt(0)
	}

	// Total available = cash + borrows - reserves
	totalAvailable := new(big.Int).Add(totalCash, totalBorrows)
	totalAvailable.Sub(totalAvailable, reserves)

	if totalAvailable.Sign() <= 0 {
		return new(big.Int).Set(RAY) // 100% utilization
	}

	// utilization = borrows * RAY / totalAvailable
	utilization := new(big.Int).Mul(totalBorrows, RAY)
	utilization.Div(utilization, totalAvailable)

	// Cap at 100%
	if utilization.Cmp(RAY) > 0 {
		return new(big.Int).Set(RAY)
	}

	return utilization
}

// GetBorrowRate calculates the borrow interest rate per block
// Returns rate scaled by 1e18
func (m *InterestRateModel) GetBorrowRate(
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
) *big.Int {
	utilization := m.GetUtilizationRate(totalCash, totalBorrows, reserves)

	if utilization.Cmp(m.OptimalUtilization) <= 0 {
		// Below kink: baseRate + utilization * slope1 / RAY
		rate := new(big.Int).Mul(utilization, m.Slope1)
		rate.Div(rate, RAY)
		rate.Add(rate, m.BaseRate)
		return m.toBlockRate(rate)
	}

	// Above kink:
	// normalRate = baseRate + optimalUtilization * slope1 / RAY
	// excessRate = (utilization - optimalUtilization) * slope2 / RAY
	normalRate := new(big.Int).Mul(m.OptimalUtilization, m.Slope1)
	normalRate.Div(normalRate, RAY)
	normalRate.Add(normalRate, m.BaseRate)

	excessUtilization := new(big.Int).Sub(utilization, m.OptimalUtilization)
	excessRate := new(big.Int).Mul(excessUtilization, m.Slope2)
	excessRate.Div(excessRate, RAY)

	totalRate := new(big.Int).Add(normalRate, excessRate)
	return m.toBlockRate(totalRate)
}

// GetSupplyRate calculates the supply interest rate per block
// SupplyRate = BorrowRate * Utilization * (1 - ReserveFactor) / RAY
func (m *InterestRateModel) GetSupplyRate(
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
) *big.Int {
	borrowRate := m.GetBorrowRate(totalCash, totalBorrows, reserves)
	utilization := m.GetUtilizationRate(totalCash, totalBorrows, reserves)

	// Calculate (1 - reserveFactor)
	oneMinusReserve := new(big.Int).Sub(RAY, m.ReserveFactor)

	// supplyRate = borrowRate * utilization * oneMinusReserve / RAY / RAY
	supplyRate := new(big.Int).Mul(borrowRate, utilization)
	supplyRate.Div(supplyRate, RAY)
	supplyRate.Mul(supplyRate, oneMinusReserve)
	supplyRate.Div(supplyRate, RAY)

	return supplyRate
}

// GetBorrowAPR returns the annual borrow rate as a percentage (scaled by 1e18)
func (m *InterestRateModel) GetBorrowAPR(
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
) *big.Int {
	blockRate := m.GetBorrowRate(totalCash, totalBorrows, reserves)
	return new(big.Int).Mul(blockRate, BlocksPerYear)
}

// GetSupplyAPR returns the annual supply rate as a percentage (scaled by 1e18)
func (m *InterestRateModel) GetSupplyAPR(
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
) *big.Int {
	blockRate := m.GetSupplyRate(totalCash, totalBorrows, reserves)
	return new(big.Int).Mul(blockRate, BlocksPerYear)
}

// toBlockRate converts an annual rate to per-block rate
func (m *InterestRateModel) toBlockRate(annualRate *big.Int) *big.Int {
	return new(big.Int).Div(annualRate, BlocksPerYear)
}

// AccrueInterest calculates accrued interest over a number of blocks
// Uses simple interest approximation: principal * rate * blocks
func (m *InterestRateModel) AccrueInterest(
	principal *big.Int,
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
	blocks uint64,
) *big.Int {
	if blocks == 0 || principal.Sign() == 0 {
		return big.NewInt(0)
	}

	borrowRate := m.GetBorrowRate(totalCash, totalBorrows, reserves)

	// interest = principal * borrowRate * blocks / RAY
	interest := new(big.Int).Mul(principal, borrowRate)
	interest.Mul(interest, big.NewInt(int64(blocks)))
	interest.Div(interest, RAY)

	return interest
}

// GetReserveAmount calculates reserve portion from interest
func (m *InterestRateModel) GetReserveAmount(interest *big.Int) *big.Int {
	// reserve = interest * reserveFactor / RAY
	reserve := new(big.Int).Mul(interest, m.ReserveFactor)
	reserve.Div(reserve, RAY)
	return reserve
}

// CalculateCompoundInterest calculates compound interest over blocks
// Uses the formula: principal * (1 + rate)^blocks - principal
// Approximated for efficiency
func (m *InterestRateModel) CalculateCompoundInterest(
	principal *big.Int,
	totalCash *big.Int,
	totalBorrows *big.Int,
	reserves *big.Int,
	blocks uint64,
) *big.Int {
	if blocks == 0 || principal.Sign() == 0 {
		return big.NewInt(0)
	}

	// For small number of blocks, use simple interest
	if blocks <= 100 {
		return m.AccrueInterest(principal, totalCash, totalBorrows, reserves, blocks)
	}

	// For larger periods, use approximation: e^(rate * time) - 1
	// Approximated as: rate * time + (rate * time)^2 / 2
	borrowRate := m.GetBorrowRate(totalCash, totalBorrows, reserves)

	// rt = rate * blocks
	rt := new(big.Int).Mul(borrowRate, big.NewInt(int64(blocks)))

	// rt^2 / (2 * RAY)
	rtSquared := new(big.Int).Mul(rt, rt)
	rtSquared.Div(rtSquared, RAY)
	rtSquared.Div(rtSquared, big.NewInt(2))

	// total multiplier = rt + rt^2 / 2
	multiplier := new(big.Int).Add(rt, rtSquared)

	// interest = principal * multiplier / RAY
	interest := new(big.Int).Mul(principal, multiplier)
	interest.Div(interest, RAY)

	return interest
}
