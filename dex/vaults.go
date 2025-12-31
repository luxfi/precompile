// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"sync"

	"github.com/luxfi/geth/common"
)

// YieldVault represents a yield-generating vault
type YieldVault struct {
	Address         common.Address
	Asset           Currency         // Underlying asset
	TotalAssets     *big.Int         // Total assets in vault
	TotalShares     *big.Int         // Total shares issued
	Strategy        VaultStrategy    // Active strategy
	PerformanceFee  uint32           // Fee on profits (basis points)
	ManagementFee   uint32           // Annual management fee (basis points)
	DepositLimit    *big.Int         // Max deposits
	WithdrawEnabled bool
	DepositEnabled  bool
	LastHarvest     int64            // Last harvest timestamp
	Strategist      common.Address   // Strategy manager
}

// VaultStrategy represents a yield strategy
type VaultStrategy interface {
	// Name returns the strategy name
	Name() string

	// Deposit deploys assets into the strategy
	Deposit(amount *big.Int) error

	// Withdraw retrieves assets from the strategy
	Withdraw(amount *big.Int) (*big.Int, error)

	// Harvest collects and compounds yields
	Harvest() (*big.Int, error)

	// EstimatedAPY returns expected annual yield
	EstimatedAPY() *big.Int

	// TotalDeployed returns assets currently deployed
	TotalDeployed() *big.Int
}

// VaultPosition represents a user's position in a vault
type VaultPosition struct {
	Owner       common.Address
	Vault       common.Address
	Shares      *big.Int
	DepositTime int64
	LastAction  int64
}

// VaultManager manages all yield vaults
type VaultManager struct {
	Vaults     map[common.Address]*YieldVault
	Positions  map[common.Address]map[common.Address]*VaultPosition // User -> Vault -> Position
	Strategies map[string]VaultStrategy
	mu         sync.RWMutex
}

// NewVaultManager creates a new vault manager
func NewVaultManager() *VaultManager {
	return &VaultManager{
		Vaults:     make(map[common.Address]*YieldVault),
		Positions:  make(map[common.Address]map[common.Address]*VaultPosition),
		Strategies: make(map[string]VaultStrategy),
	}
}

// CreateVault creates a new yield vault
func (vm *VaultManager) CreateVault(
	asset Currency,
	strategy VaultStrategy,
	performanceFee uint32,
	managementFee uint32,
	depositLimit *big.Int,
	strategist common.Address,
) (common.Address, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Validate fees
	if performanceFee > 5000 { // Max 50%
		return common.Address{}, ErrInvalidFee
	}
	if managementFee > 500 { // Max 5%
		return common.Address{}, ErrInvalidFee
	}

	// Generate vault address (in production, would be CREATE2)
	vaultAddr := generateVaultAddress(asset, strategy.Name())

	if _, exists := vm.Vaults[vaultAddr]; exists {
		return common.Address{}, ErrVaultExists
	}

	vault := &YieldVault{
		Address:         vaultAddr,
		Asset:           asset,
		TotalAssets:     big.NewInt(0),
		TotalShares:     big.NewInt(0),
		Strategy:        strategy,
		PerformanceFee:  performanceFee,
		ManagementFee:   managementFee,
		DepositLimit:    depositLimit,
		WithdrawEnabled: true,
		DepositEnabled:  true,
		LastHarvest:     0,
		Strategist:      strategist,
	}

	vm.Vaults[vaultAddr] = vault
	return vaultAddr, nil
}

// Deposit deposits assets into a vault
func (vm *VaultManager) Deposit(user common.Address, vault common.Address, assets *big.Int) (*big.Int, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	v := vm.Vaults[vault]
	if v == nil {
		return nil, ErrVaultNotFound
	}

	if !v.DepositEnabled {
		return nil, ErrDepositsDisabled
	}

	// Check deposit limit
	newTotal := new(big.Int).Add(v.TotalAssets, assets)
	if v.DepositLimit.Sign() > 0 && newTotal.Cmp(v.DepositLimit) > 0 {
		return nil, ErrDepositLimitExceeded
	}

	// Calculate shares to mint
	var shares *big.Int
	if v.TotalShares.Sign() == 0 {
		// First deposit: 1:1 ratio
		shares = new(big.Int).Set(assets)
	} else {
		// shares = assets * totalShares / totalAssets
		shares = new(big.Int).Mul(assets, v.TotalShares)
		shares.Div(shares, v.TotalAssets)
	}

	if shares.Sign() == 0 {
		return nil, ErrZeroShares
	}

	// Update vault state
	v.TotalAssets.Add(v.TotalAssets, assets)
	v.TotalShares.Add(v.TotalShares, shares)

	// Deploy to strategy
	if err := v.Strategy.Deposit(assets); err != nil {
		// Revert state changes
		v.TotalAssets.Sub(v.TotalAssets, assets)
		v.TotalShares.Sub(v.TotalShares, shares)
		return nil, err
	}

	// Update user position
	vm.updatePosition(user, vault, shares, true)

	return shares, nil
}

// Withdraw withdraws assets from a vault
func (vm *VaultManager) Withdraw(user common.Address, vault common.Address, shares *big.Int) (*big.Int, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	v := vm.Vaults[vault]
	if v == nil {
		return nil, ErrVaultNotFound
	}

	if !v.WithdrawEnabled {
		return nil, ErrWithdrawalsDisabled
	}

	// Check user has enough shares
	position := vm.getPosition(user, vault)
	if position == nil || position.Shares.Cmp(shares) < 0 {
		return nil, ErrInsufficientShares
	}

	// Calculate assets to return
	// assets = shares * totalAssets / totalShares
	assets := new(big.Int).Mul(shares, v.TotalAssets)
	assets.Div(assets, v.TotalShares)

	// Withdraw from strategy
	actualAssets, err := v.Strategy.Withdraw(assets)
	if err != nil {
		return nil, err
	}

	// Update vault state
	v.TotalAssets.Sub(v.TotalAssets, actualAssets)
	v.TotalShares.Sub(v.TotalShares, shares)

	// Update user position
	vm.updatePosition(user, vault, shares, false)

	return actualAssets, nil
}

// Harvest harvests yields and compounds
func (vm *VaultManager) Harvest(vault common.Address) (*big.Int, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	v := vm.Vaults[vault]
	if v == nil {
		return nil, ErrVaultNotFound
	}

	// Harvest from strategy
	profit, err := v.Strategy.Harvest()
	if err != nil {
		return nil, err
	}

	if profit.Sign() <= 0 {
		return big.NewInt(0), nil
	}

	// Calculate fees
	performanceFee := new(big.Int).Mul(profit, big.NewInt(int64(v.PerformanceFee)))
	performanceFee.Div(performanceFee, big.NewInt(10000))

	netProfit := new(big.Int).Sub(profit, performanceFee)

	// Add net profit to total assets (compounds for all shareholders)
	v.TotalAssets.Add(v.TotalAssets, netProfit)

	return netProfit, nil
}

// GetSharePrice returns current price per share
func (vm *VaultManager) GetSharePrice(vault common.Address) (*big.Int, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v := vm.Vaults[vault]
	if v == nil {
		return nil, ErrVaultNotFound
	}

	if v.TotalShares.Sign() == 0 {
		return big.NewInt(1e18), nil // 1:1 if no shares
	}

	// price = totalAssets * 1e18 / totalShares
	price := new(big.Int).Mul(v.TotalAssets, big.NewInt(1e18))
	price.Div(price, v.TotalShares)

	return price, nil
}

// GetUserAssets returns user's share of assets
func (vm *VaultManager) GetUserAssets(user common.Address, vault common.Address) (*big.Int, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v := vm.Vaults[vault]
	if v == nil {
		return nil, ErrVaultNotFound
	}

	position := vm.getPosition(user, vault)
	if position == nil {
		return big.NewInt(0), nil
	}

	if v.TotalShares.Sign() == 0 {
		return big.NewInt(0), nil
	}

	// assets = shares * totalAssets / totalShares
	assets := new(big.Int).Mul(position.Shares, v.TotalAssets)
	assets.Div(assets, v.TotalShares)

	return assets, nil
}

// GetVaultAPY returns estimated APY for a vault
func (vm *VaultManager) GetVaultAPY(vault common.Address) (*big.Int, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v := vm.Vaults[vault]
	if v == nil {
		return nil, ErrVaultNotFound
	}

	return v.Strategy.EstimatedAPY(), nil
}

// Helper functions

func (vm *VaultManager) updatePosition(user common.Address, vault common.Address, shares *big.Int, isDeposit bool) {
	if vm.Positions[user] == nil {
		vm.Positions[user] = make(map[common.Address]*VaultPosition)
	}

	position := vm.Positions[user][vault]
	if position == nil {
		position = &VaultPosition{
			Owner:       user,
			Vault:       vault,
			Shares:      big.NewInt(0),
			DepositTime: 0,
		}
		vm.Positions[user][vault] = position
	}

	if isDeposit {
		position.Shares.Add(position.Shares, shares)
		if position.DepositTime == 0 {
			position.DepositTime = currentTimestamp()
		}
	} else {
		position.Shares.Sub(position.Shares, shares)
		if position.Shares.Sign() == 0 {
			delete(vm.Positions[user], vault)
		}
	}
}

func (vm *VaultManager) getPosition(user common.Address, vault common.Address) *VaultPosition {
	userPositions := vm.Positions[user]
	if userPositions == nil {
		return nil
	}
	return userPositions[vault]
}

func generateVaultAddress(asset Currency, strategyName string) common.Address {
	// Simplified - in production use CREATE2
	var addr common.Address
	copy(addr[:], asset.Address[:10])
	copy(addr[10:], []byte(strategyName)[:10])
	return addr
}

func currentTimestamp() int64 {
	return 0 // In production, get from block timestamp
}

// =========================================================================
// Pre-built Strategies
// =========================================================================

// LPYieldStrategy farms LP tokens for yield
type LPYieldStrategy struct {
	PoolManager *PoolManager
	PoolID      [32]byte
	Deployed    *big.Int
	APY         *big.Int // Estimated APY in basis points
}

func NewLPYieldStrategy(pm *PoolManager, poolID [32]byte) *LPYieldStrategy {
	return &LPYieldStrategy{
		PoolManager: pm,
		PoolID:      poolID,
		Deployed:    big.NewInt(0),
		APY:         big.NewInt(1000), // 10% default
	}
}

func (s *LPYieldStrategy) Name() string { return "LP_YIELD" }

func (s *LPYieldStrategy) Deposit(amount *big.Int) error {
	// Add liquidity to pool
	s.Deployed.Add(s.Deployed, amount)
	return nil
}

func (s *LPYieldStrategy) Withdraw(amount *big.Int) (*big.Int, error) {
	if s.Deployed.Cmp(amount) < 0 {
		return nil, ErrInsufficientLiquidity
	}
	s.Deployed.Sub(s.Deployed, amount)
	return amount, nil
}

func (s *LPYieldStrategy) Harvest() (*big.Int, error) {
	// Collect trading fees from pool
	// Simplified - in production would query actual fees
	profit := new(big.Int).Div(s.Deployed, big.NewInt(100)) // 1% of deployed
	return profit, nil
}

func (s *LPYieldStrategy) EstimatedAPY() *big.Int {
	return new(big.Int).Set(s.APY)
}

func (s *LPYieldStrategy) TotalDeployed() *big.Int {
	return new(big.Int).Set(s.Deployed)
}

// LendingYieldStrategy supplies assets to lending pool
type LendingYieldStrategy struct {
	LendingPool *LendingPool
	Asset       common.Address
	Deployed    *big.Int
}

func NewLendingYieldStrategy(lp *LendingPool, asset common.Address) *LendingYieldStrategy {
	return &LendingYieldStrategy{
		LendingPool: lp,
		Asset:       asset,
		Deployed:    big.NewInt(0),
	}
}

func (s *LendingYieldStrategy) Name() string { return "LENDING_YIELD" }

func (s *LendingYieldStrategy) Deposit(amount *big.Int) error {
	s.Deployed.Add(s.Deployed, amount)
	return nil
}

func (s *LendingYieldStrategy) Withdraw(amount *big.Int) (*big.Int, error) {
	if s.Deployed.Cmp(amount) < 0 {
		return nil, ErrInsufficientLiquidity
	}
	s.Deployed.Sub(s.Deployed, amount)
	return amount, nil
}

func (s *LendingYieldStrategy) Harvest() (*big.Int, error) {
	// Collect interest from lending
	// In production, query actual accrued interest
	profit := new(big.Int).Div(s.Deployed, big.NewInt(200)) // 0.5% of deployed
	return profit, nil
}

func (s *LendingYieldStrategy) EstimatedAPY() *big.Int {
	// Return supply APY from lending pool
	// In production, calculate from actual rates
	return big.NewInt(500) // 5%
}

func (s *LendingYieldStrategy) TotalDeployed() *big.Int {
	return new(big.Int).Set(s.Deployed)
}

// DeltaNeutralStrategy maintains delta-neutral position with funding income
type DeltaNeutralStrategy struct {
	PerpEngine *PerpetualEngine
	SpotDEX    *PoolManager
	MarketID   [32]byte
	Deployed   *big.Int
}

func NewDeltaNeutralStrategy(pe *PerpetualEngine, spot *PoolManager, marketID [32]byte) *DeltaNeutralStrategy {
	return &DeltaNeutralStrategy{
		PerpEngine: pe,
		SpotDEX:    spot,
		MarketID:   marketID,
		Deployed:   big.NewInt(0),
	}
}

func (s *DeltaNeutralStrategy) Name() string { return "DELTA_NEUTRAL" }

func (s *DeltaNeutralStrategy) Deposit(amount *big.Int) error {
	// Buy spot + short perp to create delta-neutral position
	s.Deployed.Add(s.Deployed, amount)
	return nil
}

func (s *DeltaNeutralStrategy) Withdraw(amount *big.Int) (*big.Int, error) {
	if s.Deployed.Cmp(amount) < 0 {
		return nil, ErrInsufficientLiquidity
	}
	// Unwind delta-neutral position
	s.Deployed.Sub(s.Deployed, amount)
	return amount, nil
}

func (s *DeltaNeutralStrategy) Harvest() (*big.Int, error) {
	// Collect funding payments (shorts receive when funding > 0)
	// In production, query actual funding received
	profit := new(big.Int).Div(s.Deployed, big.NewInt(50)) // 2% of deployed
	return profit, nil
}

func (s *DeltaNeutralStrategy) EstimatedAPY() *big.Int {
	// Funding rate based APY
	return big.NewInt(2000) // 20%
}

func (s *DeltaNeutralStrategy) TotalDeployed() *big.Int {
	return new(big.Int).Set(s.Deployed)
}

// Additional errors for vaults (ErrInvalidFee in types.go)
var (
	ErrVaultExists          = errors.New("vault already exists")
	ErrVaultNotFound        = errors.New("vault not found")
	ErrDepositsDisabled     = errors.New("deposits are disabled")
	ErrWithdrawalsDisabled  = errors.New("withdrawals are disabled")
	ErrDepositLimitExceeded = errors.New("deposit limit exceeded")
	ErrZeroShares           = errors.New("would mint zero shares")
	ErrInsufficientShares   = errors.New("insufficient shares")
)
