// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"sync"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/zeebo/blake3"
)

// Precompile address (LP-9050 LXLend)
var lendingPoolAddr = common.HexToAddress(LXLendAddress)

// Storage key prefixes for Lending state
var (
	lendPoolPrefix    = []byte("lend/pool")
	lendUserPrefix    = []byte("lend/user")
	lendReservePrefix = []byte("lend/resv")
)

// LendingPool implements an Aave/Compound-style lending protocol
// Features:
// - Supply assets to earn interest
// - Borrow assets using supplied assets as collateral
// - Health factor based liquidations
// - Dynamic interest rates based on utilization
type LendingPool struct {
	mu sync.RWMutex

	// Reserve configuration per asset
	reserves map[common.Address]*Reserve

	// User positions (keyed by user + asset)
	positions map[[32]byte]*LendingPosition

	// Interest rate models per asset
	rateModels map[common.Address]*InterestRateModel

	// Reference to pool manager for flash accounting
	poolManager *PoolManager
}

// Reserve represents a lending pool reserve for an asset
type Reserve struct {
	Asset common.Address

	// Total amounts
	TotalSupply   *big.Int // Total supplied (in asset decimals)
	TotalBorrows  *big.Int // Total borrowed
	TotalReserves *big.Int // Protocol reserves (fees)

	// Exchange rate for supply tokens (scaled by 1e18)
	// 1 supply token = exchangeRate * underlying
	ExchangeRate *big.Int

	// Collateral configuration
	CollateralFactor *big.Int // Max LTV for borrowing (scaled by 1e18, e.g., 0.75e18 = 75%)
	LiquidationBonus *big.Int // Bonus for liquidators (scaled by 1e18, e.g., 0.05e18 = 5%)

	// Borrow caps
	BorrowCap *big.Int // Maximum borrowable (0 = no cap)
	SupplyCap *big.Int // Maximum suppliable (0 = no cap)

	// State
	LastUpdateBlock uint64
	IsActive        bool
	IsFrozen        bool // If frozen, no new supply/borrow
	IsBorrowEnabled bool

	// Accrual index for interest distribution
	BorrowIndex *big.Int // Cumulative borrow interest index
	SupplyIndex *big.Int // Cumulative supply interest index
}

// NewLendingPool creates a new LendingPool instance
func NewLendingPool(poolManager *PoolManager) *LendingPool {
	return &LendingPool{
		reserves:    make(map[common.Address]*Reserve),
		positions:   make(map[[32]byte]*LendingPosition),
		rateModels:  make(map[common.Address]*InterestRateModel),
		poolManager: poolManager,
	}
}

// positionKey generates unique key for user position
func positionKey(user common.Address, asset common.Address) [32]byte {
	h := blake3.New()
	h.Write(user.Bytes())
	h.Write(asset.Bytes())
	var key [32]byte
	h.Digest().Read(key[:])
	return key
}

// =========================================================================
// Admin Functions
// =========================================================================

// InitializeReserve sets up a new lending reserve for an asset
func (lp *LendingPool) InitializeReserve(
	stateDB StateDB,
	asset common.Address,
	collateralFactor *big.Int, // e.g., 0.75e18 = 75% LTV
	liquidationBonus *big.Int, // e.g., 0.05e18 = 5%
	rateModel *InterestRateModel,
) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	if _, exists := lp.reserves[asset]; exists {
		return ErrReserveAlreadyExists
	}

	if collateralFactor.Cmp(RAY) > 0 {
		return ErrInvalidCollateralFactor
	}

	reserve := &Reserve{
		Asset:            asset,
		TotalSupply:      big.NewInt(0),
		TotalBorrows:     big.NewInt(0),
		TotalReserves:    big.NewInt(0),
		ExchangeRate:     new(big.Int).Set(RAY), // Start at 1:1
		CollateralFactor: collateralFactor,
		LiquidationBonus: liquidationBonus,
		BorrowCap:        big.NewInt(0),
		SupplyCap:        big.NewInt(0),
		LastUpdateBlock:  stateDB.GetBlockNumber(),
		IsActive:         true,
		IsFrozen:         false,
		IsBorrowEnabled:  true,
		BorrowIndex:      new(big.Int).Set(RAY),
		SupplyIndex:      new(big.Int).Set(RAY),
	}

	lp.reserves[asset] = reserve
	lp.rateModels[asset] = rateModel

	lp.saveReserve(stateDB, reserve)

	return nil
}

// SetReserveActive enables/disables a reserve
func (lp *LendingPool) SetReserveActive(stateDB StateDB, asset common.Address, active bool) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return ErrReserveNotFound
	}

	reserve.IsActive = active
	lp.saveReserve(stateDB, reserve)

	return nil
}

// SetBorrowCap sets the maximum borrowable for an asset
func (lp *LendingPool) SetBorrowCap(stateDB StateDB, asset common.Address, cap *big.Int) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return ErrReserveNotFound
	}

	reserve.BorrowCap = new(big.Int).Set(cap)
	lp.saveReserve(stateDB, reserve)

	return nil
}

// =========================================================================
// Core Lending Operations
// =========================================================================

// Supply adds assets to the lending pool
// Returns the amount of supply tokens minted
func (lp *LendingPool) Supply(
	stateDB StateDB,
	user common.Address,
	asset common.Address,
	amount *big.Int,
) (*big.Int, error) {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return nil, ErrReserveNotFound
	}

	if !reserve.IsActive || reserve.IsFrozen {
		return nil, ErrReserveFrozen
	}

	if amount.Sign() <= 0 {
		return nil, ErrInvalidAmount
	}

	// Check supply cap
	if reserve.SupplyCap.Sign() > 0 {
		newTotal := new(big.Int).Add(reserve.TotalSupply, amount)
		if newTotal.Cmp(reserve.SupplyCap) > 0 {
			return nil, ErrSupplyCapExceeded
		}
	}

	// Accrue interest first
	lp.accrueInterest(stateDB, reserve)

	// Calculate supply tokens to mint
	// supplyTokens = amount * RAY / exchangeRate
	supplyTokens := new(big.Int).Mul(amount, RAY)
	supplyTokens.Div(supplyTokens, reserve.ExchangeRate)

	// Get or create position
	key := positionKey(user, asset)
	position := lp.getPosition(stateDB, key)
	if position == nil {
		position = &LendingPosition{
			Owner:           user,
			Asset:           asset,
			SupplyShares:    big.NewInt(0),
			BorrowAmount:    big.NewInt(0),
			BorrowIndex:     new(big.Int).Set(reserve.BorrowIndex),
			LastUpdateBlock: stateDB.GetBlockNumber(),
		}
	}

	// Transfer asset from user
	lp.transferAsset(stateDB, asset, user, lendingPoolAddr, amount)

	// Update position
	position.SupplyShares = new(big.Int).Add(position.SupplyShares, supplyTokens)
	position.LastUpdateBlock = stateDB.GetBlockNumber()

	// Update reserve
	reserve.TotalSupply = new(big.Int).Add(reserve.TotalSupply, amount)

	// Save state
	lp.savePosition(stateDB, key, position)
	lp.saveReserve(stateDB, reserve)

	return supplyTokens, nil
}

// Withdraw removes assets from the lending pool
// Returns the amount of underlying withdrawn
func (lp *LendingPool) Withdraw(
	stateDB StateDB,
	user common.Address,
	asset common.Address,
	shareAmount *big.Int, // Amount of supply tokens to burn
) (*big.Int, error) {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return nil, ErrReserveNotFound
	}

	if !reserve.IsActive {
		return nil, ErrReserveFrozen
	}

	key := positionKey(user, asset)
	position := lp.getPosition(stateDB, key)
	if position == nil || position.SupplyShares.Sign() == 0 {
		return nil, ErrInsufficientBalance
	}

	// Accrue interest
	lp.accrueInterest(stateDB, reserve)

	// Cap withdrawal to available shares
	withdrawShares := shareAmount
	if withdrawShares.Cmp(position.SupplyShares) > 0 {
		withdrawShares = new(big.Int).Set(position.SupplyShares)
	}

	// Calculate underlying amount
	// underlying = shares * exchangeRate / RAY
	underlyingAmount := new(big.Int).Mul(withdrawShares, reserve.ExchangeRate)
	underlyingAmount.Div(underlyingAmount, RAY)

	// Check if withdrawal would make position unhealthy
	if position.BorrowAmount.Sign() > 0 {
		newSupplyShares := new(big.Int).Sub(position.SupplyShares, withdrawShares)
		newSupplyValue := new(big.Int).Mul(newSupplyShares, reserve.ExchangeRate)
		newSupplyValue.Div(newSupplyValue, RAY)

		healthFactor := lp.calculateHealthFactor(newSupplyValue, position.BorrowAmount, reserve)
		if healthFactor.Cmp(RAY) < 0 {
			return nil, ErrHealthFactorTooLow
		}
	}

	// Check available liquidity
	availableLiquidity := new(big.Int).Sub(reserve.TotalSupply, reserve.TotalBorrows)
	if underlyingAmount.Cmp(availableLiquidity) > 0 {
		return nil, ErrInsufficientLiquidity
	}

	// Update position
	position.SupplyShares = new(big.Int).Sub(position.SupplyShares, withdrawShares)
	position.LastUpdateBlock = stateDB.GetBlockNumber()

	// Update reserve
	reserve.TotalSupply = new(big.Int).Sub(reserve.TotalSupply, underlyingAmount)

	// Transfer asset to user
	lp.transferAsset(stateDB, asset, lendingPoolAddr, user, underlyingAmount)

	// Save state
	lp.savePosition(stateDB, key, position)
	lp.saveReserve(stateDB, reserve)

	return underlyingAmount, nil
}

// Borrow takes assets from the lending pool
func (lp *LendingPool) Borrow(
	stateDB StateDB,
	user common.Address,
	asset common.Address,
	amount *big.Int,
) error {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return ErrReserveNotFound
	}

	if !reserve.IsActive || !reserve.IsBorrowEnabled {
		return ErrBorrowDisabled
	}

	if amount.Sign() <= 0 {
		return ErrInvalidAmount
	}

	// Check borrow cap
	if reserve.BorrowCap.Sign() > 0 {
		newTotal := new(big.Int).Add(reserve.TotalBorrows, amount)
		if newTotal.Cmp(reserve.BorrowCap) > 0 {
			return ErrBorrowCapExceeded
		}
	}

	// Accrue interest
	lp.accrueInterest(stateDB, reserve)

	// Get position
	key := positionKey(user, asset)
	position := lp.getPosition(stateDB, key)
	if position == nil {
		return ErrInsufficientCollateral
	}

	// Update user's borrow with accrued interest
	lp.updateUserBorrow(position, reserve)

	// Calculate supply value as collateral
	supplyValue := new(big.Int).Mul(position.SupplyShares, reserve.ExchangeRate)
	supplyValue.Div(supplyValue, RAY)

	// Calculate max borrowable
	maxBorrow := new(big.Int).Mul(supplyValue, reserve.CollateralFactor)
	maxBorrow.Div(maxBorrow, RAY)

	// Check if borrow would exceed limit
	newBorrowAmount := new(big.Int).Add(position.BorrowAmount, amount)
	if newBorrowAmount.Cmp(maxBorrow) > 0 {
		return ErrMaxLTVExceeded
	}

	// Check available liquidity
	availableLiquidity := new(big.Int).Sub(reserve.TotalSupply, reserve.TotalBorrows)
	if amount.Cmp(availableLiquidity) > 0 {
		return ErrInsufficientLiquidity
	}

	// Update position
	position.BorrowAmount = newBorrowAmount
	position.BorrowIndex = new(big.Int).Set(reserve.BorrowIndex)
	position.LastUpdateBlock = stateDB.GetBlockNumber()

	// Update reserve
	reserve.TotalBorrows = new(big.Int).Add(reserve.TotalBorrows, amount)

	// Transfer asset to user
	lp.transferAsset(stateDB, asset, lendingPoolAddr, user, amount)

	// Save state
	lp.savePosition(stateDB, key, position)
	lp.saveReserve(stateDB, reserve)

	return nil
}

// Repay pays back borrowed assets
func (lp *LendingPool) Repay(
	stateDB StateDB,
	user common.Address,
	asset common.Address,
	amount *big.Int,
) (*big.Int, error) {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return nil, ErrReserveNotFound
	}

	key := positionKey(user, asset)
	position := lp.getPosition(stateDB, key)
	if position == nil || position.BorrowAmount.Sign() == 0 {
		return nil, ErrNoDebtToRepay
	}

	// Accrue interest
	lp.accrueInterest(stateDB, reserve)

	// Update user's borrow with accrued interest
	lp.updateUserBorrow(position, reserve)

	// Cap repayment to outstanding debt
	repayAmount := amount
	if repayAmount.Cmp(position.BorrowAmount) > 0 {
		repayAmount = new(big.Int).Set(position.BorrowAmount)
	}

	// Transfer asset from user
	lp.transferAsset(stateDB, asset, user, lendingPoolAddr, repayAmount)

	// Update position
	position.BorrowAmount = new(big.Int).Sub(position.BorrowAmount, repayAmount)
	position.BorrowIndex = new(big.Int).Set(reserve.BorrowIndex)
	position.LastUpdateBlock = stateDB.GetBlockNumber()

	// Update reserve
	reserve.TotalBorrows = new(big.Int).Sub(reserve.TotalBorrows, repayAmount)

	// Save state
	lp.savePosition(stateDB, key, position)
	lp.saveReserve(stateDB, reserve)

	return repayAmount, nil
}

// =========================================================================
// View Functions
// =========================================================================

// GetReserve returns reserve information
func (lp *LendingPool) GetReserve(asset common.Address) *Reserve {
	lp.mu.RLock()
	defer lp.mu.RUnlock()
	return lp.reserves[asset]
}

// GetPosition returns a user's position
func (lp *LendingPool) GetPosition(stateDB StateDB, user common.Address, asset common.Address) *LendingPosition {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	key := positionKey(user, asset)
	return lp.getPosition(stateDB, key)
}

// GetHealthFactor returns the health factor for a position
// Health factor = (collateral * collateralFactor) / debt
// < 1.0 means position can be liquidated
func (lp *LendingPool) GetHealthFactor(stateDB StateDB, user common.Address, asset common.Address) *big.Int {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return new(big.Int).Set(RAY) // Max health factor if no reserve
	}

	key := positionKey(user, asset)
	position := lp.getPosition(stateDB, key)
	if position == nil || position.BorrowAmount.Sign() == 0 {
		return new(big.Int).Set(RAY) // Max health factor if no debt
	}

	supplyValue := new(big.Int).Mul(position.SupplyShares, reserve.ExchangeRate)
	supplyValue.Div(supplyValue, RAY)

	return lp.calculateHealthFactor(supplyValue, position.BorrowAmount, reserve)
}

// GetUserAccountData returns aggregated account data
func (lp *LendingPool) GetUserAccountData(
	stateDB StateDB,
	user common.Address,
	asset common.Address,
) (supplyValue, borrowValue, availableToBorrow, healthFactor *big.Int) {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return big.NewInt(0), big.NewInt(0), big.NewInt(0), new(big.Int).Set(RAY)
	}

	key := positionKey(user, asset)
	position := lp.getPosition(stateDB, key)
	if position == nil {
		return big.NewInt(0), big.NewInt(0), big.NewInt(0), new(big.Int).Set(RAY)
	}

	// Calculate supply value
	supplyValue = new(big.Int).Mul(position.SupplyShares, reserve.ExchangeRate)
	supplyValue.Div(supplyValue, RAY)

	// Get current borrow with interest
	borrowValue = new(big.Int).Set(position.BorrowAmount)
	if position.BorrowIndex.Sign() > 0 && reserve.BorrowIndex.Cmp(position.BorrowIndex) > 0 {
		borrowValue.Mul(borrowValue, reserve.BorrowIndex)
		borrowValue.Div(borrowValue, position.BorrowIndex)
	}

	// Calculate max borrow
	maxBorrow := new(big.Int).Mul(supplyValue, reserve.CollateralFactor)
	maxBorrow.Div(maxBorrow, RAY)

	// Available to borrow
	if maxBorrow.Cmp(borrowValue) > 0 {
		availableToBorrow = new(big.Int).Sub(maxBorrow, borrowValue)
	} else {
		availableToBorrow = big.NewInt(0)
	}

	// Health factor
	healthFactor = lp.calculateHealthFactor(supplyValue, borrowValue, reserve)

	return
}

// GetSupplyAPY returns the current supply APY
func (lp *LendingPool) GetSupplyAPY(asset common.Address) *big.Int {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return big.NewInt(0)
	}

	model := lp.rateModels[asset]
	if model == nil {
		return big.NewInt(0)
	}

	cash := new(big.Int).Sub(reserve.TotalSupply, reserve.TotalBorrows)
	return model.GetSupplyAPR(cash, reserve.TotalBorrows, reserve.TotalReserves)
}

// GetBorrowAPY returns the current borrow APY
func (lp *LendingPool) GetBorrowAPY(asset common.Address) *big.Int {
	lp.mu.RLock()
	defer lp.mu.RUnlock()

	reserve, exists := lp.reserves[asset]
	if !exists {
		return big.NewInt(0)
	}

	model := lp.rateModels[asset]
	if model == nil {
		return big.NewInt(0)
	}

	cash := new(big.Int).Sub(reserve.TotalSupply, reserve.TotalBorrows)
	return model.GetBorrowAPR(cash, reserve.TotalBorrows, reserve.TotalReserves)
}

// =========================================================================
// Internal Functions
// =========================================================================

// accrueInterest updates interest for a reserve
func (lp *LendingPool) accrueInterest(stateDB StateDB, reserve *Reserve) {
	currentBlock := stateDB.GetBlockNumber()
	if currentBlock <= reserve.LastUpdateBlock {
		return
	}

	blocksDelta := currentBlock - reserve.LastUpdateBlock
	if reserve.TotalBorrows.Sign() == 0 {
		reserve.LastUpdateBlock = currentBlock
		return
	}

	model := lp.rateModels[reserve.Asset]
	if model == nil {
		reserve.LastUpdateBlock = currentBlock
		return
	}

	// Calculate interest
	cash := new(big.Int).Sub(reserve.TotalSupply, reserve.TotalBorrows)
	interestAccrued := model.AccrueInterest(
		reserve.TotalBorrows,
		cash,
		reserve.TotalBorrows,
		reserve.TotalReserves,
		blocksDelta,
	)

	// Update borrow index
	// newIndex = oldIndex + (interestAccrued * RAY / totalBorrows)
	indexIncrease := new(big.Int).Mul(interestAccrued, RAY)
	indexIncrease.Div(indexIncrease, reserve.TotalBorrows)
	reserve.BorrowIndex = new(big.Int).Add(reserve.BorrowIndex, indexIncrease)

	// Update totals
	reserve.TotalBorrows = new(big.Int).Add(reserve.TotalBorrows, interestAccrued)

	// Add reserve portion
	reserveAmount := model.GetReserveAmount(interestAccrued)
	reserve.TotalReserves = new(big.Int).Add(reserve.TotalReserves, reserveAmount)

	// Update exchange rate
	// newRate = (totalSupply + totalBorrows - reserves) / totalSupply
	if reserve.TotalSupply.Sign() > 0 {
		totalValue := new(big.Int).Add(reserve.TotalSupply, reserve.TotalBorrows)
		totalValue.Sub(totalValue, reserve.TotalReserves)
		// Actually: exchangeRate = totalValue * RAY / supplyShares
		// For simplicity, increase exchange rate proportionally
		supplyInterest := new(big.Int).Sub(interestAccrued, reserveAmount)
		rateIncrease := new(big.Int).Mul(supplyInterest, RAY)
		rateIncrease.Div(rateIncrease, reserve.TotalSupply)
		reserve.ExchangeRate = new(big.Int).Add(reserve.ExchangeRate, rateIncrease)
	}

	reserve.LastUpdateBlock = currentBlock
}

// updateUserBorrow updates a user's borrow amount with accrued interest
func (lp *LendingPool) updateUserBorrow(position *LendingPosition, reserve *Reserve) {
	if position.BorrowAmount.Sign() == 0 {
		return
	}

	if position.BorrowIndex.Sign() == 0 || reserve.BorrowIndex.Cmp(position.BorrowIndex) == 0 {
		return
	}

	// newBorrow = oldBorrow * currentIndex / userIndex
	position.BorrowAmount = new(big.Int).Mul(position.BorrowAmount, reserve.BorrowIndex)
	position.BorrowAmount.Div(position.BorrowAmount, position.BorrowIndex)
	position.BorrowIndex = new(big.Int).Set(reserve.BorrowIndex)
}

// calculateHealthFactor computes health factor
func (lp *LendingPool) calculateHealthFactor(collateralValue, debtValue *big.Int, reserve *Reserve) *big.Int {
	if debtValue.Sign() == 0 {
		// No debt = maximum health factor
		maxHealth := new(big.Int).Mul(RAY, big.NewInt(1000))
		return maxHealth
	}

	// healthFactor = (collateral * collateralFactor) / debt
	adjustedCollateral := new(big.Int).Mul(collateralValue, reserve.CollateralFactor)
	adjustedCollateral.Div(adjustedCollateral, RAY)

	healthFactor := new(big.Int).Mul(adjustedCollateral, RAY)
	healthFactor.Div(healthFactor, debtValue)

	return healthFactor
}

// =========================================================================
// Storage Management
// =========================================================================

func (lp *LendingPool) getPosition(stateDB StateDB, key [32]byte) *LendingPosition {
	if position, ok := lp.positions[key]; ok {
		return position
	}

	// Load from state
	storageKey := makeStorageKey(lendUserPrefix, key[:])
	data := stateDB.GetState(lendingPoolAddr, storageKey)
	if data == (common.Hash{}) {
		return nil
	}

	position := &LendingPosition{
		SupplyShares: big.NewInt(0).SetBytes(data[:16]),
		BorrowAmount: big.NewInt(0).SetBytes(data[16:]),
		BorrowIndex:  new(big.Int).Set(RAY),
	}
	lp.positions[key] = position
	return position
}

func (lp *LendingPool) savePosition(stateDB StateDB, key [32]byte, position *LendingPosition) {
	lp.positions[key] = position

	storageKey := makeStorageKey(lendUserPrefix, key[:])
	var data common.Hash
	supplyBytes := position.SupplyShares.Bytes()
	borrowBytes := position.BorrowAmount.Bytes()
	copy(data[:16], supplyBytes)
	copy(data[16:], borrowBytes)
	stateDB.SetState(lendingPoolAddr, storageKey, data)
}

func (lp *LendingPool) saveReserve(stateDB StateDB, reserve *Reserve) {
	lp.reserves[reserve.Asset] = reserve

	storageKey := makeStorageKey(lendPoolPrefix, reserve.Asset.Bytes())
	var data common.Hash
	supplyBytes := reserve.TotalSupply.Bytes()
	borrowBytes := reserve.TotalBorrows.Bytes()
	copy(data[:16], supplyBytes)
	copy(data[16:], borrowBytes)
	stateDB.SetState(lendingPoolAddr, storageKey, data)
}

// transferAsset handles asset transfers
func (lp *LendingPool) transferAsset(stateDB StateDB, asset common.Address, from, to common.Address, amount *big.Int) {
	amountU256, _ := uint256.FromBig(amount)
	stateDB.SubBalance(from, amountU256)
	stateDB.AddBalance(to, amountU256)
}
