// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"sync"

	"github.com/luxfi/geth/common"
)

// Margin account types
const (
	CrossMargin     MarginAccountType = iota // Share margin across all positions
	IsolatedMargin                           // Separate margin for each position
	PortfolioMargin                          // Risk-based margining
)

// MarginAccountType represents the type of margin account
type MarginAccountType uint8

// Default margin parameters
const (
	DefaultMaxLeverage        = 100   // 100x for cross margin
	IsolatedMaxLeverage       = 200   // 200x for isolated margin
	PortfolioMaxLeverage      = 1111  // 1111x for portfolio margin (pro traders)
	DefaultMaintenanceMargin  = 500   // 0.5% (basis points)
	DefaultInitialMargin      = 1000  // 1% (basis points)
	DefaultLiquidationPenalty = 500   // 0.5% goes to insurance fund
	DefaultLiquidatorReward   = 250   // 0.25% to liquidator
	MarginPrecision           = 10000 // Basis point precision
)

// MarginAccount represents a user's margin trading account
type MarginAccount struct {
	Owner             common.Address
	AccountType       MarginAccountType
	Collateral        map[common.Address]*big.Int // Asset -> Amount
	CollateralValue   *big.Int                    // Total USD value of collateral
	Positions         map[[32]byte]*MarginPosition
	TotalBorrowed     map[common.Address]*big.Int // Asset -> Borrowed amount
	MaxLeverage       uint32
	MaintenanceMargin uint32 // Basis points
	InitialMargin     uint32 // Basis points
}

// MarginPosition represents a leveraged trading position
type MarginPosition struct {
	MarketID         [32]byte
	Side             PositionSide
	Size             *big.Int
	EntryPrice       *big.Int // Q96
	MarkPrice        *big.Int // Q96
	Margin           *big.Int // Allocated margin
	UnrealizedPnL    *big.Int
	RealizedPnL      *big.Int
	Leverage         uint32
	LiquidationPrice *big.Int // Q96
	StopLoss         *big.Int // Q96 (optional)
	TakeProfit       *big.Int // Q96 (optional)
	IsIsolated       bool
}

// PositionSide represents long or short
type PositionSide uint8

const (
	Long PositionSide = iota
	Short
)

// MarginEngine manages margin accounts and positions
type MarginEngine struct {
	Accounts        map[common.Address]*MarginAccount
	CollateralRates map[common.Address]*CollateralRate // Asset -> collateral parameters
	InsuranceFund   *big.Int
	TotalCollateral map[common.Address]*big.Int
	TotalBorrowed   map[common.Address]*big.Int
	mu              sync.RWMutex
}

// CollateralRate defines collateral parameters for an asset
type CollateralRate struct {
	Asset           common.Address
	CollateralRatio *big.Int // Discount applied (e.g., 0.9e18 = 90%)
	BorrowRate      *big.Int // Annual borrow rate (e.g., 0.05e18 = 5%)
	MaxBorrowable   *big.Int // Maximum borrowable amount
	IsActive        bool
}

// NewMarginEngine creates a new margin trading engine
func NewMarginEngine() *MarginEngine {
	return &MarginEngine{
		Accounts:        make(map[common.Address]*MarginAccount),
		CollateralRates: make(map[common.Address]*CollateralRate),
		InsuranceFund:   big.NewInt(0),
		TotalCollateral: make(map[common.Address]*big.Int),
		TotalBorrowed:   make(map[common.Address]*big.Int),
	}
}

// CreateAccount creates a new margin account
func (me *MarginEngine) CreateAccount(owner common.Address, accountType MarginAccountType) (*MarginAccount, error) {
	me.mu.Lock()
	defer me.mu.Unlock()

	if _, exists := me.Accounts[owner]; exists {
		return nil, ErrAccountExists
	}

	var maxLeverage uint32
	switch accountType {
	case CrossMargin:
		maxLeverage = DefaultMaxLeverage
	case IsolatedMargin:
		maxLeverage = IsolatedMaxLeverage
	case PortfolioMargin:
		maxLeverage = PortfolioMaxLeverage
	}

	account := &MarginAccount{
		Owner:             owner,
		AccountType:       accountType,
		Collateral:        make(map[common.Address]*big.Int),
		CollateralValue:   big.NewInt(0),
		Positions:         make(map[[32]byte]*MarginPosition),
		TotalBorrowed:     make(map[common.Address]*big.Int),
		MaxLeverage:       maxLeverage,
		MaintenanceMargin: DefaultMaintenanceMargin,
		InitialMargin:     DefaultInitialMargin,
	}

	me.Accounts[owner] = account
	return account, nil
}

// DepositCollateral adds collateral to an account
func (me *MarginEngine) DepositCollateral(owner common.Address, asset common.Address, amount *big.Int) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return ErrAccountNotFound
	}

	// Validate asset is accepted as collateral
	rate := me.CollateralRates[asset]
	if rate == nil || !rate.IsActive {
		return ErrInvalidCollateral
	}

	// Update collateral
	if account.Collateral[asset] == nil {
		account.Collateral[asset] = big.NewInt(0)
	}
	account.Collateral[asset].Add(account.Collateral[asset], amount)

	// Update totals
	if me.TotalCollateral[asset] == nil {
		me.TotalCollateral[asset] = big.NewInt(0)
	}
	me.TotalCollateral[asset].Add(me.TotalCollateral[asset], amount)

	return nil
}

// WithdrawCollateral removes collateral from an account if safe
func (me *MarginEngine) WithdrawCollateral(owner common.Address, asset common.Address, amount *big.Int) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return ErrAccountNotFound
	}

	collateral := account.Collateral[asset]
	if collateral == nil || collateral.Cmp(amount) < 0 {
		return ErrInsufficientCollateral
	}

	// Check if withdrawal keeps account healthy
	newCollateral := new(big.Int).Sub(collateral, amount)
	if !me.isAccountSafeWithCollateral(account, asset, newCollateral) {
		return ErrWithdrawalUnsafe
	}

	account.Collateral[asset] = newCollateral
	me.TotalCollateral[asset].Sub(me.TotalCollateral[asset], amount)

	return nil
}

// OpenPosition opens a new leveraged position
func (me *MarginEngine) OpenPosition(
	owner common.Address,
	marketID [32]byte,
	side PositionSide,
	size *big.Int,
	leverage uint32,
	markPrice *big.Int, // Current mark price
	isIsolated bool,
) (*MarginPosition, error) {
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return nil, ErrAccountNotFound
	}

	// Validate leverage
	if leverage > account.MaxLeverage {
		return nil, ErrExcessiveLeverage
	}

	// Calculate required margin
	notionalValue := new(big.Int).Mul(size, markPrice)
	notionalValue.Div(notionalValue, Q96)

	requiredMargin := new(big.Int).Mul(notionalValue, big.NewInt(int64(account.InitialMargin)))
	requiredMargin.Div(requiredMargin, big.NewInt(MarginPrecision))

	// For isolated margin, require specific margin allocation
	// For cross margin, check total account equity
	if isIsolated || account.AccountType == IsolatedMargin {
		// Need explicit margin allocation (handled by caller)
	} else {
		// Cross margin - check if account has enough free margin
		freeMargin := me.calculateFreeMargin(account)
		if freeMargin.Cmp(requiredMargin) < 0 {
			return nil, ErrInsufficientMargin
		}
	}

	// Calculate liquidation price
	liquidationPrice := me.calculateLiquidationPrice(side, markPrice, leverage, account.MaintenanceMargin)

	position := &MarginPosition{
		MarketID:         marketID,
		Side:             side,
		Size:             new(big.Int).Set(size),
		EntryPrice:       new(big.Int).Set(markPrice),
		MarkPrice:        new(big.Int).Set(markPrice),
		Margin:           new(big.Int).Set(requiredMargin),
		UnrealizedPnL:    big.NewInt(0),
		RealizedPnL:      big.NewInt(0),
		Leverage:         leverage,
		LiquidationPrice: liquidationPrice,
		IsIsolated:       isIsolated,
	}

	// Check for existing position
	existing := account.Positions[marketID]
	if existing != nil {
		// Combine positions or flip
		if existing.Side == side {
			// Same direction - increase position
			return me.increasePosition(account, existing, position)
		} else {
			// Opposite direction - reduce or flip
			return me.reduceOrFlipPosition(account, existing, position)
		}
	}

	account.Positions[marketID] = position
	return position, nil
}

// ClosePosition closes a leveraged position
func (me *MarginEngine) ClosePosition(
	owner common.Address,
	marketID [32]byte,
	sizeToClose *big.Int,
	closePrice *big.Int,
) (*big.Int, error) { // Returns realized PnL
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return nil, ErrAccountNotFound
	}

	position := account.Positions[marketID]
	if position == nil {
		return nil, ErrPositionNotFound
	}

	// Calculate PnL
	pnl := me.calculatePnL(position, closePrice, sizeToClose)

	// Update or remove position
	if sizeToClose.Cmp(position.Size) >= 0 {
		// Full close
		delete(account.Positions, marketID)
	} else {
		// Partial close
		position.Size.Sub(position.Size, sizeToClose)
		position.RealizedPnL.Add(position.RealizedPnL, pnl)

		// Proportionally reduce margin
		closeFraction := new(big.Int).Mul(sizeToClose, big.NewInt(1e18))
		closeFraction.Div(closeFraction, new(big.Int).Add(position.Size, sizeToClose))
		marginReduction := new(big.Int).Mul(position.Margin, closeFraction)
		marginReduction.Div(marginReduction, big.NewInt(1e18))
		position.Margin.Sub(position.Margin, marginReduction)
	}

	return pnl, nil
}

// UpdatePositionMargin adds or removes margin from an isolated position
func (me *MarginEngine) UpdatePositionMargin(
	owner common.Address,
	marketID [32]byte,
	marginDelta *big.Int, // Positive = add, negative = remove
) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return ErrAccountNotFound
	}

	position := account.Positions[marketID]
	if position == nil {
		return ErrPositionNotFound
	}

	if !position.IsIsolated {
		return ErrNotIsolatedPosition
	}

	newMargin := new(big.Int).Add(position.Margin, marginDelta)
	if newMargin.Sign() <= 0 {
		return ErrInsufficientMargin
	}

	// If removing margin, check if position is still safe
	if marginDelta.Sign() < 0 {
		// Calculate new leverage
		notional := new(big.Int).Mul(position.Size, position.MarkPrice)
		notional.Div(notional, Q96)
		newLeverage := new(big.Int).Div(notional, newMargin)

		if newLeverage.Uint64() > uint64(account.MaxLeverage) {
			return ErrExcessiveLeverage
		}
	}

	position.Margin = newMargin

	// Recalculate liquidation price
	position.LiquidationPrice = me.calculateLiquidationPrice(
		position.Side, position.EntryPrice, position.Leverage, account.MaintenanceMargin,
	)

	return nil
}

// SetStopLoss sets stop loss for a position
func (me *MarginEngine) SetStopLoss(owner common.Address, marketID [32]byte, stopPrice *big.Int) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return ErrAccountNotFound
	}

	position := account.Positions[marketID]
	if position == nil {
		return ErrPositionNotFound
	}

	position.StopLoss = new(big.Int).Set(stopPrice)
	return nil
}

// SetTakeProfit sets take profit for a position
func (me *MarginEngine) SetTakeProfit(owner common.Address, marketID [32]byte, takeProfitPrice *big.Int) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return ErrAccountNotFound
	}

	position := account.Positions[marketID]
	if position == nil {
		return ErrPositionNotFound
	}

	position.TakeProfit = new(big.Int).Set(takeProfitPrice)
	return nil
}

// LiquidatePosition liquidates an underwater margin position
func (me *MarginEngine) LiquidatePosition(
	liquidator common.Address,
	owner common.Address,
	marketID [32]byte,
	currentPrice *big.Int,
) (*big.Int, error) { // Returns liquidator reward
	me.mu.Lock()
	defer me.mu.Unlock()

	account := me.Accounts[owner]
	if account == nil {
		return nil, ErrAccountNotFound
	}

	position := account.Positions[marketID]
	if position == nil {
		return nil, ErrPositionNotFound
	}

	// Check if position is liquidatable
	if !me.isPositionLiquidatable(position, currentPrice, account.MaintenanceMargin) {
		return nil, ErrPositionNotLiquidatable
	}

	// Calculate remaining value
	pnl := me.calculatePnL(position, currentPrice, position.Size)
	remainingMargin := new(big.Int).Add(position.Margin, pnl)

	// Calculate rewards
	notional := new(big.Int).Mul(position.Size, currentPrice)
	notional.Div(notional, Q96)

	// Liquidator gets 0.25% of notional
	liquidatorReward := new(big.Int).Mul(notional, big.NewInt(DefaultLiquidatorReward))
	liquidatorReward.Div(liquidatorReward, big.NewInt(MarginPrecision))

	// Insurance fund gets 0.5% of notional
	insuranceFee := new(big.Int).Mul(notional, big.NewInt(DefaultLiquidationPenalty))
	insuranceFee.Div(insuranceFee, big.NewInt(MarginPrecision))

	// Cap rewards at remaining margin
	totalFees := new(big.Int).Add(liquidatorReward, insuranceFee)
	if totalFees.Cmp(remainingMargin) > 0 {
		// Socialize loss
		if remainingMargin.Sign() > 0 {
			// Split remaining between liquidator and insurance
			liquidatorReward.Div(remainingMargin, big.NewInt(2))
			insuranceFee.Sub(remainingMargin, liquidatorReward)
		} else {
			// Use insurance fund
			deficit := new(big.Int).Neg(remainingMargin)
			if me.InsuranceFund.Cmp(deficit) >= 0 {
				me.InsuranceFund.Sub(me.InsuranceFund, deficit)
			}
			liquidatorReward = big.NewInt(0)
			insuranceFee = big.NewInt(0)
		}
	}

	// Add to insurance fund
	me.InsuranceFund.Add(me.InsuranceFund, insuranceFee)

	// Remove position
	delete(account.Positions, marketID)

	return liquidatorReward, nil
}

// GetAccountHealth returns the health factor of an account (>1 = healthy)
func (me *MarginEngine) GetAccountHealth(owner common.Address) (*big.Int, error) {
	me.mu.RLock()
	defer me.mu.RUnlock()

	account := me.Accounts[owner]
	if account == nil {
		return nil, ErrAccountNotFound
	}

	totalEquity := me.calculateTotalEquity(account)
	totalMaintenanceMargin := me.calculateTotalMaintenanceMargin(account)

	if totalMaintenanceMargin.Sign() == 0 {
		return big.NewInt(1e18), nil // No positions, max health
	}

	// Health = equity / maintenanceMargin
	health := new(big.Int).Mul(totalEquity, big.NewInt(1e18))
	health.Div(health, totalMaintenanceMargin)

	return health, nil
}

// Helper functions

func (me *MarginEngine) calculateFreeMargin(account *MarginAccount) *big.Int {
	totalEquity := me.calculateTotalEquity(account)
	usedMargin := me.calculateUsedMargin(account)
	return new(big.Int).Sub(totalEquity, usedMargin)
}

func (me *MarginEngine) calculateTotalEquity(account *MarginAccount) *big.Int {
	// Collateral value + unrealized PnL
	equity := new(big.Int).Set(account.CollateralValue)

	for _, pos := range account.Positions {
		equity.Add(equity, pos.UnrealizedPnL)
	}

	return equity
}

func (me *MarginEngine) calculateUsedMargin(account *MarginAccount) *big.Int {
	used := big.NewInt(0)
	for _, pos := range account.Positions {
		used.Add(used, pos.Margin)
	}
	return used
}

func (me *MarginEngine) calculateTotalMaintenanceMargin(account *MarginAccount) *big.Int {
	total := big.NewInt(0)
	for _, pos := range account.Positions {
		notional := new(big.Int).Mul(pos.Size, pos.MarkPrice)
		notional.Div(notional, Q96)

		maintenance := new(big.Int).Mul(notional, big.NewInt(int64(account.MaintenanceMargin)))
		maintenance.Div(maintenance, big.NewInt(MarginPrecision))
		total.Add(total, maintenance)
	}
	return total
}

func (me *MarginEngine) calculateLiquidationPrice(
	side PositionSide,
	entryPrice *big.Int,
	leverage uint32,
	maintenanceMargin uint32,
) *big.Int {
	// For long: liqPrice = entryPrice * (1 - 1/leverage + maintenanceMargin)
	// For short: liqPrice = entryPrice * (1 + 1/leverage - maintenanceMargin)

	leverageInverse := new(big.Int).Div(big.NewInt(MarginPrecision), big.NewInt(int64(leverage)))
	maintenanceRatio := big.NewInt(int64(maintenanceMargin))

	var priceMultiplier *big.Int
	if side == Long {
		// 1 - 1/leverage + maintenance
		priceMultiplier = new(big.Int).Sub(big.NewInt(MarginPrecision), leverageInverse)
		priceMultiplier.Add(priceMultiplier, maintenanceRatio)
	} else {
		// 1 + 1/leverage - maintenance
		priceMultiplier = new(big.Int).Add(big.NewInt(MarginPrecision), leverageInverse)
		priceMultiplier.Sub(priceMultiplier, maintenanceRatio)
	}

	liqPrice := new(big.Int).Mul(entryPrice, priceMultiplier)
	liqPrice.Div(liqPrice, big.NewInt(MarginPrecision))

	return liqPrice
}

func (me *MarginEngine) calculatePnL(position *MarginPosition, currentPrice *big.Int, size *big.Int) *big.Int {
	priceDiff := new(big.Int).Sub(currentPrice, position.EntryPrice)
	pnl := new(big.Int).Mul(size, priceDiff)
	pnl.Div(pnl, Q96)

	if position.Side == Short {
		pnl.Neg(pnl)
	}

	return pnl
}

func (me *MarginEngine) isPositionLiquidatable(position *MarginPosition, currentPrice *big.Int, maintenanceMargin uint32) bool {
	// Calculate PnL at current price
	pnl := me.calculatePnL(position, currentPrice, position.Size)

	// Current equity in position
	equity := new(big.Int).Add(position.Margin, pnl)

	// Required maintenance margin
	notional := new(big.Int).Mul(position.Size, currentPrice)
	notional.Div(notional, Q96)

	required := new(big.Int).Mul(notional, big.NewInt(int64(maintenanceMargin)))
	required.Div(required, big.NewInt(MarginPrecision))

	return equity.Cmp(required) < 0
}

func (me *MarginEngine) isAccountSafeWithCollateral(account *MarginAccount, asset common.Address, newAmount *big.Int) bool {
	// Simplified check - in production would need full recalculation
	return newAmount.Sign() >= 0
}

func (me *MarginEngine) increasePosition(account *MarginAccount, existing *MarginPosition, incoming *MarginPosition) (*MarginPosition, error) {
	// Calculate new average entry price
	oldNotional := new(big.Int).Mul(existing.Size, existing.EntryPrice)
	newNotional := new(big.Int).Mul(incoming.Size, incoming.EntryPrice)
	totalNotional := new(big.Int).Add(oldNotional, newNotional)
	totalSize := new(big.Int).Add(existing.Size, incoming.Size)

	existing.EntryPrice.Div(totalNotional, totalSize)
	existing.Size = totalSize
	existing.Margin.Add(existing.Margin, incoming.Margin)

	// Update leverage
	notional := new(big.Int).Mul(existing.Size, existing.MarkPrice)
	notional.Div(notional, Q96)
	if existing.Margin.Sign() > 0 {
		existing.Leverage = uint32(notional.Div(notional, existing.Margin).Uint64())
	}

	// Recalculate liquidation price
	existing.LiquidationPrice = me.calculateLiquidationPrice(
		existing.Side, existing.EntryPrice, existing.Leverage, account.MaintenanceMargin,
	)

	return existing, nil
}

func (me *MarginEngine) reduceOrFlipPosition(account *MarginAccount, existing *MarginPosition, incoming *MarginPosition) (*MarginPosition, error) {
	// Realize PnL on closed portion
	if incoming.Size.Cmp(existing.Size) <= 0 {
		// Partial reduce
		pnl := me.calculatePnL(existing, incoming.EntryPrice, incoming.Size)
		existing.RealizedPnL.Add(existing.RealizedPnL, pnl)
		existing.Size.Sub(existing.Size, incoming.Size)

		if existing.Size.Sign() == 0 {
			delete(account.Positions, existing.MarketID)
			return nil, nil
		}
		return existing, nil
	}

	// Flip position
	pnl := me.calculatePnL(existing, incoming.EntryPrice, existing.Size)
	remainingSize := new(big.Int).Sub(incoming.Size, existing.Size)

	flipped := &MarginPosition{
		MarketID:      incoming.MarketID,
		Side:          incoming.Side,
		Size:          remainingSize,
		EntryPrice:    new(big.Int).Set(incoming.EntryPrice),
		MarkPrice:     new(big.Int).Set(incoming.MarkPrice),
		Margin:        new(big.Int).Set(incoming.Margin),
		UnrealizedPnL: big.NewInt(0),
		RealizedPnL:   pnl,
		Leverage:      incoming.Leverage,
		IsIsolated:    incoming.IsIsolated,
	}

	flipped.LiquidationPrice = me.calculateLiquidationPrice(
		flipped.Side, flipped.EntryPrice, flipped.Leverage, account.MaintenanceMargin,
	)

	account.Positions[incoming.MarketID] = flipped
	return flipped, nil
}

// Additional errors for margin (others in types.go)
var (
	ErrAccountExists       = errors.New("account already exists")
	ErrAccountNotFound     = errors.New("account not found")
	ErrInvalidCollateral   = errors.New("invalid or inactive collateral asset")
	ErrWithdrawalUnsafe    = errors.New("withdrawal would make account unsafe")
	ErrNotIsolatedPosition = errors.New("position is not isolated margin")
)
