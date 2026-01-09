// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
)

// Additional errors for perpetuals
var (
	ErrExcessiveLeverage = errors.New("leverage exceeds maximum allowed")
)

// PerpetualEngine manages perpetual futures trading
// Address: 0x0420
type PerpetualEngine struct {
	Markets       map[[32]byte]*PerpMarket                      // Market ID -> Market
	Positions     map[common.Address]map[[32]byte]*PerpPosition // User -> Market -> Position
	InsuranceFund *big.Int                                      // Global insurance fund

	// Funding state per market
	FundingStates map[[32]byte]*FundingState

	mu sync.RWMutex
}

// NewPerpetualEngine creates a new perpetual futures engine
func NewPerpetualEngine() *PerpetualEngine {
	return &PerpetualEngine{
		Markets:       make(map[[32]byte]*PerpMarket),
		Positions:     make(map[common.Address]map[[32]byte]*PerpPosition),
		InsuranceFund: big.NewInt(0),
		FundingStates: make(map[[32]byte]*FundingState),
	}
}

// CreateMarket creates a new perpetual futures market
func (pe *PerpetualEngine) CreateMarket(
	baseAsset, quoteAsset Currency,
	initialPrice *big.Int,
	maxLeverage uint32,
	maintenanceMargin *big.Int,
) ([32]byte, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	// Validate leverage
	if maxLeverage == 0 || maxLeverage > MaxLeverage {
		maxLeverage = MaxLeverage
	}

	// Generate market ID
	marketID := generateMarketID(baseAsset, quoteAsset)

	if _, exists := pe.Markets[marketID]; exists {
		return [32]byte{}, ErrPoolExists
	}

	market := &PerpMarket{
		BaseAsset:         baseAsset,
		QuoteAsset:        quoteAsset,
		MarkPrice:         new(big.Int).Set(initialPrice),
		IndexPrice:        new(big.Int).Set(initialPrice),
		OpenInterestLong:  big.NewInt(0),
		OpenInterestShort: big.NewInt(0),
		FundingRate:       big.NewInt(0),
		LastFundingTime:   time.Now().Unix(),
		MaxLeverage:       maxLeverage,
		MaintenanceMargin: maintenanceMargin,
		InsuranceFund:     big.NewInt(0),
	}

	pe.Markets[marketID] = market
	pe.FundingStates[marketID] = &FundingState{
		CumulativeFunding: big.NewInt(0),
		LastUpdateTime:    time.Now().Unix(),
		PremiumEMA:        big.NewInt(0),
		TWAPWindow:        8 * 3600, // 8 hours
	}

	return marketID, nil
}

// OpenPosition opens or increases a perpetual position
func (pe *PerpetualEngine) OpenPosition(
	owner common.Address,
	marketID [32]byte,
	size *big.Int, // Positive = long, negative = short
	margin *big.Int,
	isIsolated bool,
) (*PerpPosition, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	// Calculate effective leverage
	notionalValue := new(big.Int).Abs(size)
	notionalValue.Mul(notionalValue, market.MarkPrice)
	notionalValue.Div(notionalValue, Q96)

	leverage := new(big.Int).Mul(notionalValue, big.NewInt(100))
	leverage.Div(leverage, margin)

	if leverage.Uint64() > uint64(market.MaxLeverage)*100 {
		return nil, ErrExcessiveLeverage
	}

	// Get or create position
	userPositions := pe.Positions[owner]
	if userPositions == nil {
		userPositions = make(map[[32]byte]*PerpPosition)
		pe.Positions[owner] = userPositions
	}

	position := userPositions[marketID]
	fundingState := pe.FundingStates[marketID]

	if position == nil {
		// New position
		position = &PerpPosition{
			Owner:            owner,
			Market:           marketID,
			Size:             new(big.Int).Set(size),
			EntryPrice:       new(big.Int).Set(market.MarkPrice),
			Margin:           new(big.Int).Set(margin),
			LastFundingIndex: new(big.Int).Set(fundingState.CumulativeFunding),
			IsIsolated:       isIsolated,
		}
		userPositions[marketID] = position
	} else {
		// Settle funding before modifying
		pe.settleFundingForPosition(position, fundingState)

		// Increase position
		oldNotional := new(big.Int).Mul(position.Size, position.EntryPrice)
		newNotional := new(big.Int).Mul(size, market.MarkPrice)
		totalNotional := new(big.Int).Add(oldNotional, newNotional)

		newSize := new(big.Int).Add(position.Size, size)
		if newSize.Sign() == 0 {
			// Position closed
			delete(userPositions, marketID)
			return nil, nil
		}

		// Calculate new average entry price
		position.EntryPrice.Div(totalNotional, newSize)
		position.Size = newSize
		position.Margin.Add(position.Margin, margin)
	}

	// Update open interest
	if size.Sign() > 0 {
		market.OpenInterestLong.Add(market.OpenInterestLong, new(big.Int).Abs(size))
	} else {
		market.OpenInterestShort.Add(market.OpenInterestShort, new(big.Int).Abs(size))
	}

	return position, nil
}

// ClosePosition closes a perpetual position
func (pe *PerpetualEngine) ClosePosition(
	owner common.Address,
	marketID [32]byte,
	sizeToClose *big.Int, // Amount to close (absolute value)
) (*big.Int, error) { // Returns realized PnL
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	userPositions := pe.Positions[owner]
	if userPositions == nil {
		return nil, ErrPositionNotFound
	}

	position := userPositions[marketID]
	if position == nil {
		return nil, ErrPositionNotFound
	}

	// Settle funding first
	fundingState := pe.FundingStates[marketID]
	fundingPnL := pe.settleFundingForPosition(position, fundingState)

	// Calculate PnL
	positionSize := new(big.Int).Abs(position.Size)
	if sizeToClose.Cmp(positionSize) > 0 {
		sizeToClose = positionSize
	}

	// Price difference
	priceDiff := new(big.Int).Sub(market.MarkPrice, position.EntryPrice)

	// PnL = size * priceDiff / Q96
	pnl := new(big.Int).Mul(sizeToClose, priceDiff)
	pnl.Div(pnl, Q96)

	// If short, negate PnL
	if position.Size.Sign() < 0 {
		pnl.Neg(pnl)
	}

	// Add funding PnL
	pnl.Add(pnl, fundingPnL)

	// Update position
	if sizeToClose.Cmp(positionSize) >= 0 {
		// Full close
		delete(userPositions, marketID)
	} else {
		// Partial close
		closeFraction := new(big.Int).Mul(sizeToClose, big.NewInt(1e18))
		closeFraction.Div(closeFraction, positionSize)

		marginReduction := new(big.Int).Mul(position.Margin, closeFraction)
		marginReduction.Div(marginReduction, big.NewInt(1e18))
		position.Margin.Sub(position.Margin, marginReduction)

		if position.Size.Sign() > 0 {
			position.Size.Sub(position.Size, sizeToClose)
		} else {
			position.Size.Add(position.Size, sizeToClose)
		}
	}

	// Update open interest
	if position.Size.Sign() > 0 {
		market.OpenInterestLong.Sub(market.OpenInterestLong, sizeToClose)
	} else {
		market.OpenInterestShort.Sub(market.OpenInterestShort, sizeToClose)
	}

	return pnl, nil
}

// AddMargin adds margin to an existing position
func (pe *PerpetualEngine) AddMargin(
	owner common.Address,
	marketID [32]byte,
	amount *big.Int,
) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	userPositions := pe.Positions[owner]
	if userPositions == nil {
		return ErrPositionNotFound
	}

	position := userPositions[marketID]
	if position == nil {
		return ErrPositionNotFound
	}

	position.Margin.Add(position.Margin, amount)
	return nil
}

// RemoveMargin removes margin from an existing position (if still safe)
func (pe *PerpetualEngine) RemoveMargin(
	owner common.Address,
	marketID [32]byte,
	amount *big.Int,
) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return ErrPoolNotFound
	}

	userPositions := pe.Positions[owner]
	if userPositions == nil {
		return ErrPositionNotFound
	}

	position := userPositions[marketID]
	if position == nil {
		return ErrPositionNotFound
	}

	newMargin := new(big.Int).Sub(position.Margin, amount)
	if newMargin.Sign() <= 0 {
		return ErrInsufficientMargin
	}

	// Check if position is still safe
	if !pe.isPositionSafe(position, market, newMargin) {
		return ErrInsufficientMargin
	}

	position.Margin = newMargin
	return nil
}

// LiquidatePosition liquidates an underwater position
func (pe *PerpetualEngine) LiquidatePosition(
	liquidator common.Address,
	owner common.Address,
	marketID [32]byte,
) (*big.Int, error) { // Returns liquidation reward
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	userPositions := pe.Positions[owner]
	if userPositions == nil {
		return nil, ErrPositionNotFound
	}

	position := userPositions[marketID]
	if position == nil {
		return nil, ErrPositionNotFound
	}

	// Check if position is liquidatable
	if pe.isPositionSafe(position, market, position.Margin) {
		return nil, ErrPositionNotLiquidatable
	}

	// Calculate position value and PnL
	positionSize := new(big.Int).Abs(position.Size)
	priceDiff := new(big.Int).Sub(market.MarkPrice, position.EntryPrice)
	pnl := new(big.Int).Mul(positionSize, priceDiff)
	pnl.Div(pnl, Q96)
	if position.Size.Sign() < 0 {
		pnl.Neg(pnl)
	}

	// Remaining margin after loss
	remainingMargin := new(big.Int).Add(position.Margin, pnl)

	// Liquidation reward (5% of position notional, capped at remaining margin)
	notional := new(big.Int).Mul(positionSize, market.MarkPrice)
	notional.Div(notional, Q96)
	reward := new(big.Int).Div(notional, big.NewInt(20)) // 5%

	if reward.Cmp(remainingMargin) > 0 {
		// Socialized loss - use insurance fund
		deficit := new(big.Int).Sub(reward, remainingMargin)
		if market.InsuranceFund.Cmp(deficit) >= 0 {
			market.InsuranceFund.Sub(market.InsuranceFund, deficit)
		} else {
			// ADL would be triggered here in production
			reward = remainingMargin
		}
	}

	// Update open interest
	if position.Size.Sign() > 0 {
		market.OpenInterestLong.Sub(market.OpenInterestLong, positionSize)
	} else {
		market.OpenInterestShort.Sub(market.OpenInterestShort, positionSize)
	}

	// Remove position
	delete(userPositions, marketID)

	return reward, nil
}

// UpdateFunding calculates and applies funding rate
func (pe *PerpetualEngine) UpdateFunding(marketID [32]byte) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return ErrPoolNotFound
	}

	fundingState := pe.FundingStates[marketID]
	now := time.Now().Unix()

	// Only update every 8 hours
	if now-fundingState.LastUpdateTime < int64(fundingState.TWAPWindow) {
		return nil
	}

	// Calculate premium (mark - index) / index
	premium := new(big.Int).Sub(market.MarkPrice, market.IndexPrice)
	premium.Mul(premium, big.NewInt(1e18))
	premium.Div(premium, market.IndexPrice)

	// Update EMA of premium
	alpha := big.NewInt(125) // 0.125 for 8h EMA
	oneMinusAlpha := big.NewInt(875)

	newEMA := new(big.Int).Mul(premium, alpha)
	oldEMA := new(big.Int).Mul(fundingState.PremiumEMA, oneMinusAlpha)
	fundingState.PremiumEMA.Add(newEMA, oldEMA)
	fundingState.PremiumEMA.Div(fundingState.PremiumEMA, big.NewInt(1000))

	// Interest rate component (0.01% per 8 hours = 0.0001)
	interestRate := big.NewInt(100) // 0.01% in 1e6

	// Funding rate = premium EMA + interest rate
	// Clamped to ±0.75% per 8 hours
	fundingRate := new(big.Int).Add(fundingState.PremiumEMA, interestRate)
	maxRate := big.NewInt(7500) // 0.75% in 1e6
	minRate := big.NewInt(-7500)

	if fundingRate.Cmp(maxRate) > 0 {
		fundingRate = maxRate
	} else if fundingRate.Cmp(minRate) < 0 {
		fundingRate = minRate
	}

	market.FundingRate = fundingRate
	market.LastFundingTime = now

	// Update cumulative funding
	// cumulative += fundingRate * markPrice / 1e6
	fundingPayment := new(big.Int).Mul(fundingRate, market.MarkPrice)
	fundingPayment.Div(fundingPayment, big.NewInt(1e6))
	fundingState.CumulativeFunding.Add(fundingState.CumulativeFunding, fundingPayment)
	fundingState.LastUpdateTime = now

	return nil
}

// GetFundingRate returns current funding rate for a market
func (pe *PerpetualEngine) GetFundingRate(marketID [32]byte) (*big.Int, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	return new(big.Int).Set(market.FundingRate), nil
}

// GetPosition returns a user's position
func (pe *PerpetualEngine) GetPosition(owner common.Address, marketID [32]byte) (*PerpPosition, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	userPositions := pe.Positions[owner]
	if userPositions == nil {
		return nil, ErrPositionNotFound
	}

	position := userPositions[marketID]
	if position == nil {
		return nil, ErrPositionNotFound
	}

	// Return a copy
	return &PerpPosition{
		Owner:            position.Owner,
		Market:           position.Market,
		Size:             new(big.Int).Set(position.Size),
		EntryPrice:       new(big.Int).Set(position.EntryPrice),
		Margin:           new(big.Int).Set(position.Margin),
		LastFundingIndex: new(big.Int).Set(position.LastFundingIndex),
		IsIsolated:       position.IsIsolated,
	}, nil
}

// GetUnrealizedPnL calculates unrealized PnL for a position
func (pe *PerpetualEngine) GetUnrealizedPnL(owner common.Address, marketID [32]byte) (*big.Int, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	userPositions := pe.Positions[owner]
	if userPositions == nil {
		return nil, ErrPositionNotFound
	}

	position := userPositions[marketID]
	if position == nil {
		return nil, ErrPositionNotFound
	}

	// PnL = size * (markPrice - entryPrice) / Q96
	priceDiff := new(big.Int).Sub(market.MarkPrice, position.EntryPrice)
	pnl := new(big.Int).Mul(position.Size, priceDiff)
	pnl.Div(pnl, Q96)

	return pnl, nil
}

// UpdateMarkPrice updates the mark price for a market
func (pe *PerpetualEngine) UpdateMarkPrice(marketID [32]byte, newPrice *big.Int) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return ErrPoolNotFound
	}

	market.MarkPrice = new(big.Int).Set(newPrice)
	return nil
}

// UpdateIndexPrice updates the oracle index price for a market
func (pe *PerpetualEngine) UpdateIndexPrice(marketID [32]byte, newPrice *big.Int) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	market, exists := pe.Markets[marketID]
	if !exists {
		return ErrPoolNotFound
	}

	market.IndexPrice = new(big.Int).Set(newPrice)
	return nil
}

// Helper functions

func (pe *PerpetualEngine) settleFundingForPosition(position *PerpPosition, state *FundingState) *big.Int {
	// Funding payment = size * (currentFundingIndex - lastFundingIndex) / Q96
	fundingDiff := new(big.Int).Sub(state.CumulativeFunding, position.LastFundingIndex)
	payment := new(big.Int).Mul(position.Size, fundingDiff)
	payment.Div(payment, Q96)

	// Longs pay shorts when funding > 0
	// So longs get negative funding, shorts get positive
	payment.Neg(payment)

	position.LastFundingIndex = new(big.Int).Set(state.CumulativeFunding)
	return payment
}

func (pe *PerpetualEngine) isPositionSafe(position *PerpPosition, market *PerpMarket, margin *big.Int) bool {
	// Calculate maintenance margin requirement
	positionSize := new(big.Int).Abs(position.Size)
	notional := new(big.Int).Mul(positionSize, market.MarkPrice)
	notional.Div(notional, Q96)

	// maintenanceReq = notional * maintenanceMargin / 1e18
	maintenanceReq := new(big.Int).Mul(notional, market.MaintenanceMargin)
	maintenanceReq.Div(maintenanceReq, big.NewInt(1e18))

	// Calculate unrealized PnL
	priceDiff := new(big.Int).Sub(market.MarkPrice, position.EntryPrice)
	pnl := new(big.Int).Mul(position.Size, priceDiff)
	pnl.Div(pnl, Q96)

	// Equity = margin + unrealizedPnL
	equity := new(big.Int).Add(margin, pnl)

	return equity.Cmp(maintenanceReq) >= 0
}

func generateMarketID(base, quote Currency) [32]byte {
	var id [32]byte
	copy(id[:20], base.Address[:])
	copy(id[20:], quote.Address[:12])
	return id
}

// Note: Error definitions are in types.go to avoid duplication
