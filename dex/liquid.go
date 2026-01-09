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

// Precompile address (LP-9060 LXLiquid)
var liquidAddr = common.HexToAddress(LXLiquidAddress)

// Storage key prefixes for Liquid state
var (
	liquidYieldTokenPrefix = []byte("liquid/ytok") // Approved yield tokens
	liquidTokenPrefix      = []byte("liquid/syn")  // Synthetic tokens
	liquidAccountPrefix    = []byte("liquid/acc")  // User accounts
	liquidGlobalPrefix     = []byte("liquid/glob") // Global state
)

// Liquid implements the self-repaying loan vault precompile
// Based on Alchemix architecture with 90% LTV (vs 50% in original)
//
// Key features:
// - Deposit yield-bearing tokens (LP tokens) as collateral
// - Mint liquid tokens (LUSD, LETH) up to 90% of collateral value
// - Yield automatically harvested and applied to debt repayment
// - NO LIQUIDATIONS - positions are always solvent (debt <= collateral)
// - Manual repayment also supported
type Liquid struct {
	mu sync.RWMutex

	// Approved yield-bearing tokens that can be used as collateral
	yieldTokens map[common.Address]*YieldToken

	// Registered liquid tokens that can be minted
	liquidTokens map[common.Address]*LiquidToken

	// User accounts (keyed by owner + yieldToken)
	accounts map[[32]byte]*LiquidAccount

	// Reference to pool manager for LP token valuations
	poolManager *PoolManager
}

// NewLiquid creates a new Liquid instance
func NewLiquid(pm *PoolManager) *Liquid {
	return &Liquid{
		yieldTokens:  make(map[common.Address]*YieldToken),
		liquidTokens: make(map[common.Address]*LiquidToken),
		accounts:     make(map[[32]byte]*LiquidAccount),
		poolManager:  pm,
	}
}

// accountKey generates unique key for user account
func accountKey(owner common.Address, yieldToken common.Address) [32]byte {
	h := blake3.New()
	h.Write(owner.Bytes())
	h.Write(yieldToken.Bytes())
	var key [32]byte
	h.Digest().Read(key[:])
	return key
}

// =========================================================================
// Admin Functions (would be controlled by governance)
// =========================================================================

// AddYieldToken registers a new yield-bearing token as valid collateral
func (a *Liquid) AddYieldToken(
	stateDB StateDB,
	token common.Address,
	underlying Currency,
	yieldPerBlock *big.Int,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.yieldTokens[token]; exists {
		return ErrInvalidYieldToken
	}

	yt := &YieldToken{
		Address:         token,
		UnderlyingAsset: underlying,
		YieldPerBlock:   new(big.Int).Set(yieldPerBlock),
		IsActive:        true,
		TotalDeposited:  big.NewInt(0),
	}

	a.yieldTokens[token] = yt
	a.saveYieldToken(stateDB, yt)
	return nil
}

// AddLiquidToken registers a new liquid token
func (a *Liquid) AddLiquidToken(
	stateDB StateDB,
	synthetic common.Address,
	underlying Currency,
	debtCeiling *big.Int,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.liquidTokens[synthetic]; exists {
		return ErrLiquidTokenNotRegistered
	}

	st := &LiquidToken{
		Address:         synthetic,
		UnderlyingAsset: underlying,
		TotalMinted:     big.NewInt(0),
		DebtCeiling:     new(big.Int).Set(debtCeiling),
		MintFee:         10, // 0.10%
		BurnFee:         10, // 0.10%
	}

	a.liquidTokens[synthetic] = st
	a.saveLiquidToken(stateDB, st)
	return nil
}

// =========================================================================
// Core Liquid Operations
// =========================================================================

// Deposit deposits yield-bearing tokens as collateral
// This is the first step to taking a self-repaying loan
func (a *Liquid) Deposit(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
	amount *big.Int,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify yield token is approved
	yt, exists := a.yieldTokens[yieldToken]
	if !exists || !yt.IsActive {
		return ErrInvalidYieldToken
	}

	if amount.Sign() <= 0 {
		return ErrInsufficientCollateral
	}

	// Get or create account
	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil {
		account = &LiquidAccount{
			Owner:            owner,
			YieldToken:       yieldToken,
			Collateral:       big.NewInt(0),
			Debt:             big.NewInt(0),
			LastHarvestBlock: 0,
			AccruedYield:     big.NewInt(0),
		}
	}

	// Harvest any accrued yield first
	a.harvestYieldInternal(stateDB, account, yt)

	// Transfer yield tokens from user to Liquid
	a.transferFrom(stateDB, yieldToken, owner, liquidAddr, amount)

	// Update account
	account.Collateral = new(big.Int).Add(account.Collateral, amount)

	// Update global state
	yt.TotalDeposited = new(big.Int).Add(yt.TotalDeposited, amount)

	// Save state
	a.saveAccount(stateDB, key, account)
	a.saveYieldToken(stateDB, yt)

	return nil
}

// Withdraw withdraws yield-bearing collateral
// Only allowed if it doesn't bring position below minimum collateralization
func (a *Liquid) Withdraw(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
	amount *big.Int,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	yt, exists := a.yieldTokens[yieldToken]
	if !exists {
		return ErrInvalidYieldToken
	}

	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil || account.Collateral.Sign() == 0 {
		return ErrInsufficientCollateral
	}

	// Harvest yield first
	a.harvestYieldInternal(stateDB, account, yt)

	// Check withdrawal doesn't exceed collateral
	if amount.Cmp(account.Collateral) > 0 {
		return ErrInsufficientCollateral
	}

	// Calculate new collateral after withdrawal
	newCollateral := new(big.Int).Sub(account.Collateral, amount)

	// Ensure position remains healthy (debt <= 90% of collateral)
	// Since this is Alchemix-style, debt can never exceed collateral
	if account.Debt.Sign() > 0 {
		maxDebt := a.calculateMaxDebt(newCollateral)
		if account.Debt.Cmp(maxDebt) > 0 {
			return ErrMaxLTVExceeded
		}
	}

	// Update account
	account.Collateral = newCollateral

	// Update global state
	yt.TotalDeposited = new(big.Int).Sub(yt.TotalDeposited, amount)

	// Transfer yield tokens back to user
	a.transfer(stateDB, yieldToken, liquidAddr, owner, amount)

	// Save state
	a.saveAccount(stateDB, key, account)
	a.saveYieldToken(stateDB, yt)

	return nil
}

// Mint mints liquid tokens against deposited collateral
// Maximum 90% LTV (vs Alchemix's 50%)
func (a *Liquid) Mint(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
	syntheticToken common.Address,
	amount *big.Int,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Verify yield token and liquid token
	yt, exists := a.yieldTokens[yieldToken]
	if !exists || !yt.IsActive {
		return ErrInvalidYieldToken
	}

	st, exists := a.liquidTokens[syntheticToken]
	if !exists {
		return ErrLiquidTokenNotRegistered
	}

	// Check debt ceiling
	newTotalMinted := new(big.Int).Add(st.TotalMinted, amount)
	if newTotalMinted.Cmp(st.DebtCeiling) > 0 {
		return ErrDebtCeiling
	}

	// Get account
	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil || account.Collateral.Sign() == 0 {
		return ErrInsufficientCollateral
	}

	// Harvest yield first
	a.harvestYieldInternal(stateDB, account, yt)

	// Calculate max mintable (90% of collateral value minus existing debt)
	collateralValue := a.getCollateralValue(stateDB, account.Collateral, yt)
	maxDebt := a.calculateMaxDebt(collateralValue)
	availableToMint := new(big.Int).Sub(maxDebt, account.Debt)

	if amount.Cmp(availableToMint) > 0 {
		return ErrMaxLTVExceeded
	}

	// Apply mint fee
	feeAmount := a.calculateFee(amount, st.MintFee)
	netMintAmount := new(big.Int).Sub(amount, feeAmount)

	// Update account debt
	account.Debt = new(big.Int).Add(account.Debt, amount)

	// Update synthetic total minted
	st.TotalMinted = newTotalMinted

	// Mint liquid tokens to user
	a.mintSynthetic(stateDB, syntheticToken, owner, netMintAmount)

	// Save state
	a.saveAccount(stateDB, key, account)
	a.saveLiquidToken(stateDB, st)

	return nil
}

// Burn burns liquid tokens to reduce debt
// Manual repayment option
func (a *Liquid) Burn(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
	syntheticToken common.Address,
	amount *big.Int,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	st, exists := a.liquidTokens[syntheticToken]
	if !exists {
		return ErrLiquidTokenNotRegistered
	}

	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil || account.Debt.Sign() == 0 {
		return ErrNoDebtToRepay
	}

	yt := a.yieldTokens[yieldToken]
	if yt != nil {
		a.harvestYieldInternal(stateDB, account, yt)
	}

	// Cap burn amount to outstanding debt
	burnAmount := amount
	if burnAmount.Cmp(account.Debt) > 0 {
		burnAmount = new(big.Int).Set(account.Debt)
	}

	// Apply burn fee
	feeAmount := a.calculateFee(burnAmount, st.BurnFee)
	debtReduction := new(big.Int).Sub(burnAmount, feeAmount)

	// Burn liquid tokens from user
	a.burnSynthetic(stateDB, syntheticToken, owner, burnAmount)

	// Reduce debt
	account.Debt = new(big.Int).Sub(account.Debt, debtReduction)
	if account.Debt.Sign() < 0 {
		account.Debt = big.NewInt(0)
	}

	// Update synthetic total
	st.TotalMinted = new(big.Int).Sub(st.TotalMinted, burnAmount)

	// Save state
	a.saveAccount(stateDB, key, account)
	a.saveLiquidToken(stateDB, st)

	return nil
}

// Harvest harvests accrued yield and applies it to debt repayment
// This is the "self-repaying" mechanism
func (a *Liquid) Harvest(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
) (*big.Int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	yt, exists := a.yieldTokens[yieldToken]
	if !exists {
		return nil, ErrInvalidYieldToken
	}

	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil {
		return nil, ErrInsufficientCollateral
	}

	harvested := a.harvestYieldInternal(stateDB, account, yt)

	a.saveAccount(stateDB, key, account)

	return harvested, nil
}

// =========================================================================
// Internal Yield Harvesting
// =========================================================================

// harvestYieldInternal calculates and applies accrued yield to debt
func (a *Liquid) harvestYieldInternal(
	stateDB StateDB,
	account *LiquidAccount,
	yt *YieldToken,
) *big.Int {
	// Get current block
	currentBlock := a.getCurrentBlock(stateDB)

	if account.LastHarvestBlock == 0 {
		account.LastHarvestBlock = currentBlock
		return big.NewInt(0)
	}

	// Calculate blocks elapsed
	blocksElapsed := currentBlock - account.LastHarvestBlock
	if blocksElapsed == 0 {
		return big.NewInt(0)
	}

	// Calculate yield: collateral * yieldPerBlock * blocksElapsed / 1e18
	yieldAmount := new(big.Int).Mul(account.Collateral, yt.YieldPerBlock)
	yieldAmount.Mul(yieldAmount, big.NewInt(int64(blocksElapsed)))
	yieldAmount.Div(yieldAmount, big.NewInt(1e18))

	// Add to accrued yield
	account.AccruedYield = new(big.Int).Add(account.AccruedYield, yieldAmount)

	// Apply accrued yield to debt repayment
	if account.Debt.Sign() > 0 && account.AccruedYield.Sign() > 0 {
		if account.AccruedYield.Cmp(account.Debt) >= 0 {
			// Yield covers all debt
			account.AccruedYield = new(big.Int).Sub(account.AccruedYield, account.Debt)
			account.Debt = big.NewInt(0)
		} else {
			// Partial debt repayment
			account.Debt = new(big.Int).Sub(account.Debt, account.AccruedYield)
			account.AccruedYield = big.NewInt(0)
		}
	}

	account.LastHarvestBlock = currentBlock

	return yieldAmount
}

// =========================================================================
// View Functions
// =========================================================================

// GetAccount returns a user's account state
func (a *Liquid) GetAccount(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
) *LiquidAccount {
	a.mu.RLock()
	defer a.mu.RUnlock()

	key := accountKey(owner, yieldToken)
	return a.getAccount(stateDB, key)
}

// GetMaxMintable returns the maximum amount a user can mint
func (a *Liquid) GetMaxMintable(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
) *big.Int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	yt, exists := a.yieldTokens[yieldToken]
	if !exists {
		return big.NewInt(0)
	}

	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil || account.Collateral.Sign() == 0 {
		return big.NewInt(0)
	}

	collateralValue := a.getCollateralValue(stateDB, account.Collateral, yt)
	maxDebt := a.calculateMaxDebt(collateralValue)

	// Account for accrued yield that will reduce debt
	effectiveDebt := new(big.Int).Sub(account.Debt, account.AccruedYield)
	if effectiveDebt.Sign() < 0 {
		effectiveDebt = big.NewInt(0)
	}

	available := new(big.Int).Sub(maxDebt, effectiveDebt)
	if available.Sign() < 0 {
		return big.NewInt(0)
	}

	return available
}

// GetLTV returns the current loan-to-value ratio for an account
func (a *Liquid) GetLTV(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
) *big.Int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	yt, exists := a.yieldTokens[yieldToken]
	if !exists {
		return big.NewInt(0)
	}

	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil || account.Collateral.Sign() == 0 {
		return big.NewInt(0)
	}

	collateralValue := a.getCollateralValue(stateDB, account.Collateral, yt)
	if collateralValue.Sign() == 0 {
		return big.NewInt(0)
	}

	// LTV = (debt * 10000) / collateralValue
	ltv := new(big.Int).Mul(account.Debt, big.NewInt(LTVPrecision))
	ltv.Div(ltv, collateralValue)

	return ltv
}

// GetTimeToRepayment estimates blocks until debt is fully repaid
func (a *Liquid) GetTimeToRepayment(
	stateDB StateDB,
	owner common.Address,
	yieldToken common.Address,
) uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	yt, exists := a.yieldTokens[yieldToken]
	if !exists || yt.YieldPerBlock.Sign() == 0 {
		return 0
	}

	key := accountKey(owner, yieldToken)
	account := a.getAccount(stateDB, key)
	if account == nil || account.Debt.Sign() == 0 {
		return 0
	}

	// Calculate yield per block for this position
	yieldPerBlock := new(big.Int).Mul(account.Collateral, yt.YieldPerBlock)
	yieldPerBlock.Div(yieldPerBlock, big.NewInt(1e18))

	if yieldPerBlock.Sign() == 0 {
		return 0 // Would never repay
	}

	// Blocks = debt / yieldPerBlock
	effectiveDebt := new(big.Int).Sub(account.Debt, account.AccruedYield)
	if effectiveDebt.Sign() <= 0 {
		return 0 // Already repaid
	}

	blocks := new(big.Int).Div(effectiveDebt, yieldPerBlock)
	return blocks.Uint64()
}

// =========================================================================
// Helper Functions
// =========================================================================

// calculateMaxDebt calculates maximum debt for given collateral (90% LTV)
func (a *Liquid) calculateMaxDebt(collateralValue *big.Int) *big.Int {
	// maxDebt = collateralValue * MaxLTV / LTVPrecision
	// MaxLTV = 9000 (90%)
	maxDebt := new(big.Int).Mul(collateralValue, big.NewInt(MaxLTV))
	maxDebt.Div(maxDebt, big.NewInt(LTVPrecision))
	return maxDebt
}

// calculateFee calculates fee amount
func (a *Liquid) calculateFee(amount *big.Int, feeBps uint24) *big.Int {
	fee := new(big.Int).Mul(amount, big.NewInt(int64(feeBps)))
	fee.Div(fee, big.NewInt(1_000_000)) // Fee in basis points (1 bp = 0.01%)
	return fee
}

// getCollateralValue returns the value of collateral in underlying terms
func (a *Liquid) getCollateralValue(stateDB StateDB, amount *big.Int, yt *YieldToken) *big.Int {
	// For LP tokens, would query the pool for underlying value
	// Simplified: assume 1:1 for now
	// In production, this would call poolManager to get real value
	return new(big.Int).Set(amount)
}

// getCurrentBlock returns the current block number
func (a *Liquid) getCurrentBlock(stateDB StateDB) uint64 {
	// In production, would read from block context
	// For testing, use state-based tracking
	blockKey := makeStorageKey(liquidGlobalPrefix, []byte("block"))
	blockHash := stateDB.GetState(liquidAddr, blockKey)
	if blockHash == (common.Hash{}) {
		return 1
	}
	return uint256.NewInt(0).SetBytes(blockHash[:]).Uint64()
}

// =========================================================================
// Storage Management
// =========================================================================

func (a *Liquid) getAccount(stateDB StateDB, key [32]byte) *LiquidAccount {
	if acc, ok := a.accounts[key]; ok {
		return acc
	}

	// Load from state
	storageKey := makeStorageKey(liquidAccountPrefix, key[:])
	data := stateDB.GetState(liquidAddr, storageKey)
	if data == (common.Hash{}) {
		return nil
	}

	// Deserialize (simplified - in production would be full encoding)
	acc := &LiquidAccount{
		Collateral:   big.NewInt(0).SetBytes(data[:16]),
		Debt:         big.NewInt(0).SetBytes(data[16:]),
		AccruedYield: big.NewInt(0),
	}
	a.accounts[key] = acc
	return acc
}

func (a *Liquid) saveAccount(stateDB StateDB, key [32]byte, acc *LiquidAccount) {
	a.accounts[key] = acc

	// Save to state (simplified)
	storageKey := makeStorageKey(liquidAccountPrefix, key[:])
	var data common.Hash
	collateralBytes := acc.Collateral.Bytes()
	debtBytes := acc.Debt.Bytes()
	copy(data[:16], collateralBytes)
	copy(data[16:], debtBytes)
	stateDB.SetState(liquidAddr, storageKey, data)
}

func (a *Liquid) saveYieldToken(stateDB StateDB, yt *YieldToken) {
	a.yieldTokens[yt.Address] = yt
	// In production, would serialize full struct to state
}

func (a *Liquid) saveLiquidToken(stateDB StateDB, st *LiquidToken) {
	a.liquidTokens[st.Address] = st
	// In production, would serialize full struct to state
}

// Token transfer helpers (simplified)
func (a *Liquid) transfer(stateDB StateDB, token common.Address, from, to common.Address, amount *big.Int) {
	// In production, would call ERC20 transfer
	amountU256, _ := uint256.FromBig(amount)
	stateDB.SubBalance(from, amountU256)
	stateDB.AddBalance(to, amountU256)
}

func (a *Liquid) transferFrom(stateDB StateDB, token common.Address, from, to common.Address, amount *big.Int) {
	a.transfer(stateDB, token, from, to, amount)
}

func (a *Liquid) mintSynthetic(stateDB StateDB, token common.Address, to common.Address, amount *big.Int) {
	// In production, would call liquid token mint
	amountU256, _ := uint256.FromBig(amount)
	stateDB.AddBalance(to, amountU256)
}

func (a *Liquid) burnSynthetic(stateDB StateDB, token common.Address, from common.Address, amount *big.Int) {
	// In production, would call liquid token burn
	amountU256, _ := uint256.FromBig(amount)
	stateDB.SubBalance(from, amountU256)
}
