// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"sync"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// Precompile address
var liquidatorAddr = common.HexToAddress(LiquidatorAddress)

// Storage key prefixes for Liquidator state
var (
	liquidatorConfigPrefix = []byte("liq/cfg")
	liquidatorEventPrefix  = []byte("liq/evt")
)

// Liquidator handles liquidation of undercollateralized positions
// Features:
// - Partial and full liquidation
// - Configurable liquidation bonus
// - Health factor based trigger
// - Close factor limits (max % per liquidation)
type Liquidator struct {
	mu sync.RWMutex

	// Reference to lending pool
	lendingPool *LendingPool

	// Global configuration
	config *LiquidatorConfig

	// Liquidation history (optional, for events)
	liquidations []*LiquidationEvent
}

// LiquidatorConfig holds global liquidation parameters
type LiquidatorConfig struct {
	// Close factor - maximum % of debt that can be liquidated at once
	// Scaled by 1e18 (e.g., 0.5e18 = 50%)
	CloseFactor *big.Int

	// Minimum health factor threshold for liquidation
	// Positions with health factor < this can be liquidated
	// Scaled by 1e18 (e.g., 1e18 = 1.0)
	LiquidationThreshold *big.Int

	// Protocol fee on liquidation bonus
	// Scaled by 1e18 (e.g., 0.1e18 = 10% of bonus)
	ProtocolFee *big.Int

	// Minimum liquidation amount (in underlying)
	MinLiquidation *big.Int

	// Whether flash liquidations are enabled
	FlashLiquidationEnabled bool
}

// LiquidationEvent records a liquidation
type LiquidationEvent struct {
	Liquidator       common.Address
	Borrower         common.Address
	Asset            common.Address
	DebtRepaid       *big.Int
	CollateralSeized *big.Int
	Bonus            *big.Int
	Timestamp        uint64
}

// NewLiquidator creates a new Liquidator instance
func NewLiquidator(lendingPool *LendingPool) *Liquidator {
	return &Liquidator{
		lendingPool:  lendingPool,
		config:       DefaultLiquidatorConfig(),
		liquidations: make([]*LiquidationEvent, 0),
	}
}

// DefaultLiquidatorConfig returns default configuration
func DefaultLiquidatorConfig() *LiquidatorConfig {
	return &LiquidatorConfig{
		CloseFactor:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(50), RAY), big.NewInt(100)), // 50%
		LiquidationThreshold:    new(big.Int).Set(RAY),                                                    // 1.0
		ProtocolFee:             new(big.Int).Div(new(big.Int).Mul(big.NewInt(10), RAY), big.NewInt(100)), // 10%
		MinLiquidation:          big.NewInt(0),
		FlashLiquidationEnabled: true,
	}
}

// =========================================================================
// Admin Functions
// =========================================================================

// SetCloseFactor updates the close factor
func (l *Liquidator) SetCloseFactor(closeFactor *big.Int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if closeFactor.Sign() <= 0 || closeFactor.Cmp(RAY) > 0 {
		return ErrInvalidParameter
	}

	l.config.CloseFactor = new(big.Int).Set(closeFactor)
	return nil
}

// SetProtocolFee updates the protocol fee on liquidations
func (l *Liquidator) SetProtocolFee(fee *big.Int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if fee.Sign() < 0 || fee.Cmp(RAY) > 0 {
		return ErrInvalidParameter
	}

	l.config.ProtocolFee = new(big.Int).Set(fee)
	return nil
}

// =========================================================================
// Core Liquidation Functions
// =========================================================================

// Liquidate allows a liquidator to repay debt and seize collateral
// with a bonus from an undercollateralized position
func (l *Liquidator) Liquidate(
	stateDB StateDB,
	liquidator common.Address,
	borrower common.Address,
	asset common.Address,
	debtToRepay *big.Int,
) (*big.Int, *big.Int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Get lending pool (thread-safe, but we already have the lock)
	reserve := l.lendingPool.GetReserve(asset)
	if reserve == nil {
		return nil, nil, ErrReserveNotFound
	}

	// Get borrower's position
	position := l.lendingPool.GetPosition(stateDB, borrower, asset)
	if position == nil || position.BorrowAmount.Sign() == 0 {
		return nil, nil, ErrNoDebtToRepay
	}

	// Check health factor
	healthFactor := l.lendingPool.GetHealthFactor(stateDB, borrower, asset)
	if healthFactor.Cmp(l.config.LiquidationThreshold) >= 0 {
		return nil, nil, ErrPositionHealthy
	}

	// Calculate maximum liquidatable amount
	maxLiquidatable := l.calculateMaxLiquidatable(position, reserve)

	// Cap debt repayment to max liquidatable
	actualDebtToRepay := debtToRepay
	if actualDebtToRepay.Cmp(maxLiquidatable) > 0 {
		actualDebtToRepay = new(big.Int).Set(maxLiquidatable)
	}

	// Check minimum liquidation
	if actualDebtToRepay.Cmp(l.config.MinLiquidation) < 0 {
		return nil, nil, ErrLiquidationTooSmall
	}

	// Calculate collateral to seize (debt + bonus)
	collateralToSeize, bonus := l.calculateCollateralToSeize(actualDebtToRepay, reserve)

	// Calculate supply value of borrower
	supplyValue := new(big.Int).Mul(position.SupplyShares, reserve.ExchangeRate)
	supplyValue.Div(supplyValue, RAY)

	// Cap collateral seizure to available
	if collateralToSeize.Cmp(supplyValue) > 0 {
		collateralToSeize = new(big.Int).Set(supplyValue)
		// Recalculate debt from collateral (without bonus)
		actualDebtToRepay = new(big.Int).Mul(collateralToSeize, RAY)
		actualDebtToRepay.Div(actualDebtToRepay, new(big.Int).Add(RAY, reserve.LiquidationBonus))
		bonus = new(big.Int).Sub(collateralToSeize, actualDebtToRepay)
	}

	// Execute liquidation
	err := l.executeLiquidation(
		stateDB,
		liquidator,
		borrower,
		asset,
		actualDebtToRepay,
		collateralToSeize,
		reserve,
	)
	if err != nil {
		return nil, nil, err
	}

	// Record event
	l.liquidations = append(l.liquidations, &LiquidationEvent{
		Liquidator:       liquidator,
		Borrower:         borrower,
		Asset:            asset,
		DebtRepaid:       actualDebtToRepay,
		CollateralSeized: collateralToSeize,
		Bonus:            bonus,
		Timestamp:        stateDB.GetBlockNumber(),
	})

	return actualDebtToRepay, collateralToSeize, nil
}

// LiquidateWithFlash allows liquidation using flash loan for capital efficiency
func (l *Liquidator) LiquidateWithFlash(
	stateDB StateDB,
	liquidator common.Address,
	borrower common.Address,
	asset common.Address,
	debtToRepay *big.Int,
) (*big.Int, *big.Int, error) {
	if !l.config.FlashLiquidationEnabled {
		return nil, nil, ErrFlashLiquidationDisabled
	}

	// Flash loan the debt amount
	// In a real implementation, this would:
	// 1. Borrow from pool manager flash loan
	// 2. Repay borrower's debt
	// 3. Receive collateral
	// 4. Swap collateral to repay flash loan
	// 5. Keep profit

	// For this implementation, proceed with regular liquidation
	// The liquidator needs to have the funds
	return l.Liquidate(stateDB, liquidator, borrower, asset, debtToRepay)
}

// =========================================================================
// View Functions
// =========================================================================

// GetLiquidatableAmount returns how much debt can be liquidated
func (l *Liquidator) GetLiquidatableAmount(
	stateDB StateDB,
	borrower common.Address,
	asset common.Address,
) *big.Int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	reserve := l.lendingPool.GetReserve(asset)
	if reserve == nil {
		return big.NewInt(0)
	}

	position := l.lendingPool.GetPosition(stateDB, borrower, asset)
	if position == nil || position.BorrowAmount.Sign() == 0 {
		return big.NewInt(0)
	}

	healthFactor := l.lendingPool.GetHealthFactor(stateDB, borrower, asset)
	if healthFactor.Cmp(l.config.LiquidationThreshold) >= 0 {
		return big.NewInt(0)
	}

	return l.calculateMaxLiquidatable(position, reserve)
}

// GetLiquidationBonus returns the bonus for liquidating a position
func (l *Liquidator) GetLiquidationBonus(
	stateDB StateDB,
	borrower common.Address,
	asset common.Address,
	debtToRepay *big.Int,
) *big.Int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	reserve := l.lendingPool.GetReserve(asset)
	if reserve == nil {
		return big.NewInt(0)
	}

	_, bonus := l.calculateCollateralToSeize(debtToRepay, reserve)
	return bonus
}

// IsLiquidatable checks if a position can be liquidated
func (l *Liquidator) IsLiquidatable(
	stateDB StateDB,
	borrower common.Address,
	asset common.Address,
) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	healthFactor := l.lendingPool.GetHealthFactor(stateDB, borrower, asset)
	return healthFactor.Cmp(l.config.LiquidationThreshold) < 0
}

// GetLiquidationHistory returns recent liquidations
func (l *Liquidator) GetLiquidationHistory(limit int) []*LiquidationEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > len(l.liquidations) {
		limit = len(l.liquidations)
	}

	// Return most recent
	start := len(l.liquidations) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*LiquidationEvent, limit)
	copy(result, l.liquidations[start:])
	return result
}

// GetConfig returns the liquidator configuration
func (l *Liquidator) GetConfig() *LiquidatorConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// =========================================================================
// Internal Functions
// =========================================================================

// calculateMaxLiquidatable calculates max debt that can be liquidated
func (l *Liquidator) calculateMaxLiquidatable(position *LendingPosition, reserve *Reserve) *big.Int {
	// maxLiquidatable = debt * closeFactor
	maxLiquidatable := new(big.Int).Mul(position.BorrowAmount, l.config.CloseFactor)
	maxLiquidatable.Div(maxLiquidatable, RAY)
	return maxLiquidatable
}

// calculateCollateralToSeize calculates collateral to seize including bonus
func (l *Liquidator) calculateCollateralToSeize(debtToRepay *big.Int, reserve *Reserve) (*big.Int, *big.Int) {
	// collateral = debt + (debt * bonus)
	// bonus is scaled by RAY
	bonus := new(big.Int).Mul(debtToRepay, reserve.LiquidationBonus)
	bonus.Div(bonus, RAY)

	collateral := new(big.Int).Add(debtToRepay, bonus)
	return collateral, bonus
}

// executeLiquidation performs the actual liquidation
func (l *Liquidator) executeLiquidation(
	stateDB StateDB,
	liquidator common.Address,
	borrower common.Address,
	asset common.Address,
	debtToRepay *big.Int,
	collateralToSeize *big.Int,
	reserve *Reserve,
) error {
	// Transfer debt payment from liquidator to pool
	amountU256, _ := uint256.FromBig(debtToRepay)
	stateDB.SubBalance(liquidator, amountU256)
	stateDB.AddBalance(lendingPoolAddr, amountU256)

	// Get borrower position
	borrowerKey := positionKey(borrower, asset)
	borrowerPosition := l.lendingPool.positions[borrowerKey]
	if borrowerPosition == nil {
		return ErrPositionNotFound
	}

	// Calculate shares to seize
	// shares = collateral * RAY / exchangeRate
	sharesToSeize := new(big.Int).Mul(collateralToSeize, RAY)
	sharesToSeize.Div(sharesToSeize, reserve.ExchangeRate)

	// Cap to available shares
	if sharesToSeize.Cmp(borrowerPosition.SupplyShares) > 0 {
		sharesToSeize = new(big.Int).Set(borrowerPosition.SupplyShares)
	}

	// Update borrower position
	borrowerPosition.SupplyShares = new(big.Int).Sub(borrowerPosition.SupplyShares, sharesToSeize)
	borrowerPosition.BorrowAmount = new(big.Int).Sub(borrowerPosition.BorrowAmount, debtToRepay)
	if borrowerPosition.BorrowAmount.Sign() < 0 {
		borrowerPosition.BorrowAmount = big.NewInt(0)
	}

	// Calculate protocol fee from bonus
	bonus := new(big.Int).Sub(collateralToSeize, debtToRepay)
	protocolFee := new(big.Int).Mul(bonus, l.config.ProtocolFee)
	protocolFee.Div(protocolFee, RAY)

	// Transfer collateral to liquidator (minus protocol fee)
	liquidatorReceives := new(big.Int).Sub(collateralToSeize, protocolFee)
	liquidatorReceivesU256, _ := uint256.FromBig(liquidatorReceives)
	stateDB.SubBalance(lendingPoolAddr, liquidatorReceivesU256)
	stateDB.AddBalance(liquidator, liquidatorReceivesU256)

	// Protocol fee stays in pool as reserves
	reserve.TotalReserves = new(big.Int).Add(reserve.TotalReserves, protocolFee)

	// Update reserve totals
	reserve.TotalSupply = new(big.Int).Sub(reserve.TotalSupply, collateralToSeize)
	reserve.TotalBorrows = new(big.Int).Sub(reserve.TotalBorrows, debtToRepay)

	// Save state
	l.lendingPool.savePosition(stateDB, borrowerKey, borrowerPosition)
	l.lendingPool.saveReserve(stateDB, reserve)

	return nil
}

// =========================================================================
// Batch Liquidation
// =========================================================================

// BatchLiquidationTarget represents a position to liquidate
type BatchLiquidationTarget struct {
	Borrower    common.Address
	Asset       common.Address
	DebtToRepay *big.Int
}

// BatchLiquidate liquidates multiple positions in one call
func (l *Liquidator) BatchLiquidate(
	stateDB StateDB,
	liquidator common.Address,
	targets []BatchLiquidationTarget,
) (totalDebtRepaid, totalCollateralSeized *big.Int, errors []error) {
	totalDebtRepaid = big.NewInt(0)
	totalCollateralSeized = big.NewInt(0)
	errors = make([]error, len(targets))

	for i, target := range targets {
		debtRepaid, collateralSeized, err := l.Liquidate(
			stateDB,
			liquidator,
			target.Borrower,
			target.Asset,
			target.DebtToRepay,
		)

		if err != nil {
			errors[i] = err
			continue
		}

		totalDebtRepaid.Add(totalDebtRepaid, debtRepaid)
		totalCollateralSeized.Add(totalCollateralSeized, collateralSeized)
	}

	return totalDebtRepaid, totalCollateralSeized, errors
}

// FindLiquidatablePositions searches for positions that can be liquidated
// This is a view function for off-chain liquidation bots
func (l *Liquidator) FindLiquidatablePositions(
	stateDB StateDB,
	assets []common.Address,
) []BatchLiquidationTarget {
	l.mu.RLock()
	defer l.mu.RUnlock()

	targets := make([]BatchLiquidationTarget, 0)

	for _, asset := range assets {
		reserve := l.lendingPool.GetReserve(asset)
		if reserve == nil {
			continue
		}

		// Check all known positions for this asset
		for key, position := range l.lendingPool.positions {
			if position.BorrowAmount.Sign() == 0 {
				continue
			}

			// Reconstruct user address from position
			// In production, would need proper index
			healthFactor := l.lendingPool.calculateHealthFactor(
				new(big.Int).Mul(position.SupplyShares, reserve.ExchangeRate),
				position.BorrowAmount,
				reserve,
			)

			if healthFactor.Cmp(l.config.LiquidationThreshold) < 0 {
				maxLiquidatable := l.calculateMaxLiquidatable(position, reserve)
				targets = append(targets, BatchLiquidationTarget{
					Borrower:    position.Owner,
					Asset:       asset,
					DebtToRepay: maxLiquidatable,
				})
				_ = key // silence unused warning
			}
		}
	}

	return targets
}
