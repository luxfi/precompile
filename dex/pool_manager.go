// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/zeebo/blake3"
)

// StateDB interface for accessing and modifying EVM state
type StateDB interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	SetState(addr common.Address, key common.Hash, value common.Hash)
	GetBalance(addr common.Address) *uint256.Int
	AddBalance(addr common.Address, amount *uint256.Int)
	SubBalance(addr common.Address, amount *uint256.Int)
	Exist(addr common.Address) bool
	CreateAccount(addr common.Address)
	GetBlockNumber() uint64
	AddLog(log *ethtypes.Log)
}

// Precompile address as bytes (LP-9010 LXPool)
var poolManagerAddr = common.HexToAddress(LXPoolAddress)

// Storage key prefixes for pool manager state
var (
	poolStatePrefix     = []byte("pool")
	poolLiquidityPrefix = []byte("pliq")
	positionPrefix      = []byte("posn")
	tickPrefix          = []byte("tick")
	deltaPrefix         = []byte("dlta")
	lockerPrefix        = []byte("lock")
	settledPrefix       = []byte("setl")
	protocolFeePrefix   = []byte("pfee")
	hookRegistryPrefix  = []byte("hook")
)

// PoolManager implements the singleton DEX pool manager precompile
// All pools live in this single contract, enabling:
// - Flash accounting (net token transfers at end of transaction)
// - Unified liquidity across all markets
// - Gas-efficient multi-hop swaps
// - Native LUX support without wrapping
type PoolManager struct {
	// mu protects concurrent access to shared state
	mu sync.RWMutex

	// locked prevents reentrancy attacks
	locked bool

	// pools stores all pool states by pool ID
	// Key: BLAKE3(poolKey) -> Pool state
	pools map[[32]byte]*Pool

	// positions stores all liquidity positions
	// Key: BLAKE3(owner || tickLower || tickUpper || salt) -> Position
	positions map[[32]byte]*Position

	// currentDeltas tracks balance changes during callback execution
	// Only valid within a lock() callback, settled at end
	currentDeltas map[common.Address]map[Currency]*big.Int

	// lockers tracks active callback contexts (for reentrancy)
	lockers []common.Address

	// protocolFeeController can set protocol fees
	protocolFeeController common.Address
}

// NewPoolManager creates a new pool manager instance
func NewPoolManager() *PoolManager {
	return &PoolManager{
		pools:         make(map[[32]byte]*Pool),
		positions:     make(map[[32]byte]*Position),
		currentDeltas: make(map[common.Address]map[Currency]*big.Int),
		lockers:       make([]common.Address, 0),
	}
}

// pushLocker adds a caller to the locker stack for direct precompile calls.
// This enables Swap/ModifyLiquidity without a full lock() callback cycle.
func (pm *PoolManager) pushLocker(caller common.Address) {
	pm.lockers = append(pm.lockers, caller)
	if pm.currentDeltas[caller] == nil {
		pm.currentDeltas[caller] = make(map[Currency]*big.Int)
	}
}

// popLocker removes a caller from the locker stack.
// F9: Verifies the caller matches the top of the stack before popping.
// Returns an error if the caller is not the current locker (stack corruption).
func (pm *PoolManager) popLocker(caller common.Address) error {
	if len(pm.lockers) == 0 {
		return fmt.Errorf("popLocker: locker stack is empty")
	}
	top := pm.lockers[len(pm.lockers)-1]
	if top != caller {
		return fmt.Errorf("popLocker: caller %s does not match top of stack %s", caller.Hex(), top.Hex())
	}
	delete(pm.currentDeltas, caller)
	pm.lockers = pm.lockers[:len(pm.lockers)-1]
	return nil
}

// makeStorageKey creates a storage key from prefix and identifier
func makeStorageKey(prefix []byte, id []byte) common.Hash {
	h := blake3.New()
	h.Write(prefix)
	h.Write(id)
	var key common.Hash
	h.Digest().Read(key[:])
	return key
}

// =========================================================================
// Pool Initialization
// =========================================================================

// Initialize creates and initializes a new pool
// Returns the tick corresponding to the starting price
func (pm *PoolManager) Initialize(
	stateDB StateDB,
	key PoolKey,
	sqrtPriceX96 *big.Int,
	hookData []byte,
) (int24, error) {
	// Validate currencies are sorted
	if !pm.areCurrenciesSorted(key.Currency0, key.Currency1) {
		return 0, ErrCurrencyNotSorted
	}

	// Validate fee
	if key.Fee > FeeMax {
		return 0, ErrInvalidFee
	}

	// Validate sqrt price
	if sqrtPriceX96.Cmp(MinSqrtRatio) < 0 || sqrtPriceX96.Cmp(MaxSqrtRatio) > 0 {
		return 0, ErrInvalidSqrtPrice
	}

	poolId := key.ID()

	// Check if pool already exists
	pool := pm.getPool(stateDB, poolId)
	if pool.IsInitialized() {
		return 0, ErrPoolAlreadyInitialized
	}

	// Calculate initial tick from sqrt price
	tick := pm.sqrtPriceX96ToTick(sqrtPriceX96)

	// Call beforeInitialize hook if present
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeInitialize, key, sqrtPriceX96, hookData); err != nil {
			return 0, err
		}
	}

	// Initialize pool state
	pool.SqrtPriceX96 = new(big.Int).Set(sqrtPriceX96)
	pool.Tick = tick
	pool.Liquidity = big.NewInt(0)
	pool.FeeGrowth0X128 = big.NewInt(0)
	pool.FeeGrowth1X128 = big.NewInt(0)

	// Save pool state
	pm.setPool(stateDB, poolId, pool)

	// Call afterInitialize hook if present
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterInitialize, key, sqrtPriceX96, hookData); err != nil {
			return 0, err
		}
	}

	// Emit Initialize event for subgraph indexing
	emitInitializeEvent(stateDB, poolId, key, sqrtPriceX96, tick)

	return tick, nil
}

// =========================================================================
// Flash Accounting - Lock/Unlock Pattern
// =========================================================================

// Lock acquires a callback context for flash accounting
// The caller's callback will be executed, during which token transfers
// are tracked but not executed. At the end, all deltas must net to zero.
func (pm *PoolManager) Lock(
	stateDB StateDB,
	caller common.Address,
	data []byte,
) ([]byte, error) {
	// Reentrancy guard
	pm.mu.Lock()
	if pm.locked {
		pm.mu.Unlock()
		return nil, ErrReentrant
	}
	pm.locked = true
	pm.mu.Unlock()

	defer func() {
		pm.mu.Lock()
		pm.locked = false
		pm.mu.Unlock()
	}()

	// Push caller onto locker stack
	pm.lockers = append(pm.lockers, caller)

	// Initialize delta tracking for this caller
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Execute callback (would be EVM call in real implementation)
	// The callback can call swap, modifyLiquidity, etc.
	result, err := pm.executeCallback(stateDB, caller, data)
	if err != nil {
		pm.cleanupLocker(caller)
		return nil, err
	}

	// Verify all deltas are settled
	if err := pm.verifySettlement(caller); err != nil {
		pm.cleanupLocker(caller)
		return nil, err
	}

	// Pop caller from locker stack
	pm.cleanupLocker(caller)

	return result, nil
}

// cleanupLocker removes a caller from the locker stack.
// F9: Verifies caller identity before popping.
func (pm *PoolManager) cleanupLocker(caller common.Address) {
	if len(pm.lockers) > 0 && pm.lockers[len(pm.lockers)-1] == caller {
		delete(pm.currentDeltas, caller)
		pm.lockers = pm.lockers[:len(pm.lockers)-1]
	}
}

// verifySettlement ensures all deltas for a caller are zero
func (pm *PoolManager) verifySettlement(caller common.Address) error {
	deltas, ok := pm.currentDeltas[caller]
	if !ok {
		return nil
	}

	for currency, delta := range deltas {
		if delta.Sign() != 0 {
			return fmt.Errorf("%w: currency=%s, delta=%s",
				ErrNonZeroDelta, currency.Address.Hex(), delta.String())
		}
	}
	return nil
}

// Settle settles a currency delta for the current locker
// Called by the locker to pay/receive tokens
func (pm *PoolManager) Settle(
	stateDB StateDB,
	currency Currency,
	amount *big.Int,
) error {
	locker := pm.getCurrentLocker()
	if locker == (common.Address{}) {
		return ErrUnauthorized
	}

	// Update delta (settlement reduces the owed amount)
	pm.updateDelta(locker, currency, new(big.Int).Neg(amount))

	// Handle actual token transfer
	if currency.IsNative() {
		// Native LUX transfer
		if amount.Sign() > 0 {
			// Locker is paying pool
			if err := pm.transferToken(stateDB, currency, locker, poolManagerAddr, amount); err != nil {
				return err
			}
		} else {
			// Pool is paying locker
			absAmount := new(big.Int).Abs(amount)
			if err := pm.transferToken(stateDB, currency, poolManagerAddr, locker, absAmount); err != nil {
				return err
			}
		}
	} else {
		// ERC20 transfer via direct state manipulation
		if err := pm.transferERC20(stateDB, currency, locker, poolManagerAddr, amount); err != nil {
			return err
		}
	}

	return nil
}

// Take allows locker to take tokens owed to them
func (pm *PoolManager) Take(
	stateDB StateDB,
	currency Currency,
	to common.Address,
	amount *big.Int,
) error {
	locker := pm.getCurrentLocker()
	if locker == (common.Address{}) {
		return ErrUnauthorized
	}

	// Update delta (taking increases what locker owes)
	pm.updateDelta(locker, currency, amount)

	// Transfer tokens to recipient
	if currency.IsNative() {
		amountU256, _ := uint256.FromBig(amount)
		stateDB.SubBalance(poolManagerAddr, amountU256)
		stateDB.AddBalance(to, amountU256)
	} else {
		pm.transferERC20(stateDB, currency, poolManagerAddr, to, amount)
	}

	return nil
}

// Sync syncs the reserves for a currency
// Used after external token transfer to pool manager
func (pm *PoolManager) Sync(
	stateDB StateDB,
	currency Currency,
) error {
	// For native currency, sync balance with tracked reserves
	// For ERC20, sync with actual balance
	return nil
}

// getCurrentLocker returns the current callback context owner
func (pm *PoolManager) getCurrentLocker() common.Address {
	if len(pm.lockers) == 0 {
		return common.Address{}
	}
	return pm.lockers[len(pm.lockers)-1]
}

// updateDelta updates the balance delta for a currency
func (pm *PoolManager) updateDelta(locker common.Address, currency Currency, delta *big.Int) {
	deltas, ok := pm.currentDeltas[locker]
	if !ok {
		deltas = make(map[Currency]*big.Int)
		pm.currentDeltas[locker] = deltas
	}

	current, ok := deltas[currency]
	if !ok {
		current = big.NewInt(0)
	}

	deltas[currency] = new(big.Int).Add(current, delta)
}

// =========================================================================
// Core DEX Operations
// =========================================================================

// Swap executes a swap in a pool
func (pm *PoolManager) Swap(
	stateDB StateDB,
	key PoolKey,
	params SwapParams,
	hookData []byte,
) (BalanceDelta, error) {
	locker := pm.getCurrentLocker()
	if locker == (common.Address{}) {
		return ZeroBalanceDelta(), ErrUnauthorized
	}

	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)

	if !pool.IsInitialized() {
		return ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	// Call beforeSwap hook if present
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeSwap, key, params, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	// Execute swap math
	delta, newTick, err := pm.executeSwap(pool, key, params)
	if err != nil {
		return ZeroBalanceDelta(), err
	}

	// Update pool state
	pool.Tick = newTick
	pm.setPool(stateDB, poolId, pool)

	// Update caller's deltas
	pm.updateDelta(locker, key.Currency0, delta.Amount0)
	pm.updateDelta(locker, key.Currency1, delta.Amount1)

	// Call afterSwap hook if present
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterSwap, key, params, delta, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	// Emit Swap event for subgraph indexing
	emitSwapEvent(stateDB, poolId, locker, delta, pool.SqrtPriceX96, pool.Liquidity, pool.Tick, key.Fee)

	return delta, nil
}

// ModifyLiquidity adds or removes liquidity from a pool
func (pm *PoolManager) ModifyLiquidity(
	stateDB StateDB,
	key PoolKey,
	params ModifyLiquidityParams,
	hookData []byte,
) (BalanceDelta, BalanceDelta, error) {
	locker := pm.getCurrentLocker()
	if locker == (common.Address{}) {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrUnauthorized
	}

	// Validate tick range
	if params.TickLower >= params.TickUpper {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrInvalidTickRange
	}
	if params.TickLower < MinTick || params.TickUpper > MaxTick {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrTickOutOfRange
	}

	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)

	if !pool.IsInitialized() {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	// Call beforeAddLiquidity or beforeRemoveLiquidity hook
	isAdd := params.LiquidityDelta.Sign() > 0
	if key.Hooks != (common.Address{}) {
		var hookFlag HookFlags
		if isAdd {
			hookFlag = HookBeforeAddLiquidity
		} else {
			hookFlag = HookBeforeRemoveLiquidity
		}
		if err := pm.callHook(stateDB, key.Hooks, hookFlag, key, params, hookData); err != nil {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), err
		}
	}

	// Calculate token amounts for liquidity change
	callerDelta, feesAccrued := pm.calculateLiquidityAmounts(pool, key, params, locker)

	// Update pool liquidity
	if params.TickLower <= pool.Tick && pool.Tick < params.TickUpper {
		pool.Liquidity = new(big.Int).Add(pool.Liquidity, params.LiquidityDelta)
		// F10: Guard against negative pool liquidity (e.g., removing more than exists)
		if pool.Liquidity.Sign() < 0 {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("%w: pool liquidity would go negative", ErrInsufficientLiquidity)
		}
	}

	// Update position
	positionKey := PositionKey(locker, params.TickLower, params.TickUpper, params.Salt)
	position := pm.getPosition(stateDB, positionKey)
	newPositionLiquidity := new(big.Int).Add(position.Liquidity, params.LiquidityDelta)
	// F10: Guard against negative position liquidity
	if newPositionLiquidity.Sign() < 0 {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), fmt.Errorf("%w: position liquidity would go negative", ErrInsufficientLiquidity)
	}
	position.Liquidity = newPositionLiquidity
	position.Owner = locker
	position.TickLower = params.TickLower
	position.TickUpper = params.TickUpper
	pm.setPosition(stateDB, positionKey, position)

	// Save pool state
	pm.setPool(stateDB, poolId, pool)

	// Update caller's deltas
	pm.updateDelta(locker, key.Currency0, callerDelta.Amount0)
	pm.updateDelta(locker, key.Currency1, callerDelta.Amount1)

	// Call afterAddLiquidity or afterRemoveLiquidity hook
	if key.Hooks != (common.Address{}) {
		var hookFlag HookFlags
		if isAdd {
			hookFlag = HookAfterAddLiquidity
		} else {
			hookFlag = HookAfterRemoveLiquidity
		}
		if err := pm.callHook(stateDB, key.Hooks, hookFlag, key, params, callerDelta, feesAccrued, hookData); err != nil {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), err
		}
	}

	// Emit ModifyLiquidity event for subgraph indexing
	emitModifyLiquidityEvent(stateDB, poolId, locker, params)

	return callerDelta, feesAccrued, nil
}

// Donate donates tokens to a pool's liquidity providers
func (pm *PoolManager) Donate(
	stateDB StateDB,
	key PoolKey,
	amount0 *big.Int,
	amount1 *big.Int,
	hookData []byte,
) (BalanceDelta, error) {
	locker := pm.getCurrentLocker()
	if locker == (common.Address{}) {
		return ZeroBalanceDelta(), ErrUnauthorized
	}

	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)

	if !pool.IsInitialized() {
		return ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	// Call beforeDonate hook
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeDonate, key, amount0, amount1, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	// Update fee growth (donated tokens go to LPs)
	// Require liquidity to exist for donations
	if pool.Liquidity == nil || pool.Liquidity.Sign() <= 0 {
		return ZeroBalanceDelta(), ErrNoLiquidity
	}

	// feeGrowth += amount * 2^128 / liquidity
	if amount0 != nil && amount0.Sign() > 0 {
		growth0 := new(big.Int).Mul(amount0, Q128)
		growth0.Div(growth0, pool.Liquidity)
		pool.FeeGrowth0X128 = new(big.Int).Add(pool.FeeGrowth0X128, growth0)
	}
	if amount1 != nil && amount1.Sign() > 0 {
		growth1 := new(big.Int).Mul(amount1, Q128)
		growth1.Div(growth1, pool.Liquidity)
		pool.FeeGrowth1X128 = new(big.Int).Add(pool.FeeGrowth1X128, growth1)
	}

	pm.setPool(stateDB, poolId, pool)

	delta := NewBalanceDelta(amount0, amount1)
	pm.updateDelta(locker, key.Currency0, amount0)
	pm.updateDelta(locker, key.Currency1, amount1)

	// Call afterDonate hook
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterDonate, key, amount0, amount1, delta, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	return delta, nil
}

// =========================================================================
// Flash Loans
// =========================================================================

// Flash executes a flash loan
func (pm *PoolManager) Flash(
	stateDB StateDB,
	key PoolKey,
	params FlashParams,
	hookData []byte,
) (BalanceDelta, error) {
	locker := pm.getCurrentLocker()
	if locker == (common.Address{}) {
		return ZeroBalanceDelta(), ErrUnauthorized
	}

	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)

	if !pool.IsInitialized() {
		return ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	// Call beforeFlash hook
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeFlash, key, params, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	// Calculate fees (based on pool fee)
	fee0 := pm.calculateFlashFee(params.Amount0, key.Fee)
	fee1 := pm.calculateFlashFee(params.Amount1, key.Fee)

	// Transfer tokens to recipient (creates positive delta)
	if params.Amount0.Sign() > 0 {
		pm.updateDelta(locker, key.Currency0, params.Amount0)
	}
	if params.Amount1.Sign() > 0 {
		pm.updateDelta(locker, key.Currency1, params.Amount1)
	}

	// Execute flash loan callback (in real impl, calls external contract)
	// Callback should call settle() to repay loan + fees

	// Expected repayment (loan + fee)
	totalOwed0 := new(big.Int).Add(params.Amount0, fee0)
	totalOwed1 := new(big.Int).Add(params.Amount1, fee1)

	delta := NewBalanceDelta(totalOwed0, totalOwed1)

	// Call afterFlash hook
	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterFlash, key, params, delta, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	return delta, nil
}

// =========================================================================
// State Management
// =========================================================================

// getPool retrieves pool state from storage
func (pm *PoolManager) getPool(stateDB StateDB, poolId [32]byte) *Pool {
	// Check memory cache first
	if pool, ok := pm.pools[poolId]; ok {
		return pool
	}

	// Load from state
	pool := NewPool()

	// Read sqrtPriceX96
	sqrtPriceKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("sqrtPrice")...))
	sqrtPriceHash := stateDB.GetState(poolManagerAddr, sqrtPriceKey)
	if sqrtPriceHash != (common.Hash{}) {
		pool.SqrtPriceX96 = new(big.Int).SetBytes(sqrtPriceHash[:])
	}

	// Read tick
	tickKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("tick")...))
	tickHash := stateDB.GetState(poolManagerAddr, tickKey)
	if tickHash != (common.Hash{}) {
		pool.Tick = int24(binary.BigEndian.Uint32(tickHash[28:32]))
	}

	// Read liquidity
	liqKey := makeStorageKey(poolLiquidityPrefix, poolId[:])
	liqHash := stateDB.GetState(poolManagerAddr, liqKey)
	if liqHash != (common.Hash{}) {
		pool.Liquidity = new(big.Int).SetBytes(liqHash[:])
	}

	pm.pools[poolId] = pool
	return pool
}

// setPool saves pool state to storage
func (pm *PoolManager) setPool(stateDB StateDB, poolId [32]byte, pool *Pool) {
	pm.pools[poolId] = pool

	// Write sqrtPriceX96 (always non-negative, but guard with safeFillBytes)
	sqrtPriceKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("sqrtPrice")...))
	var sqrtPriceHash common.Hash
	safeFillBytes(pool.SqrtPriceX96, sqrtPriceHash[:])
	stateDB.SetState(poolManagerAddr, sqrtPriceKey, sqrtPriceHash)

	// Write tick
	tickKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("tick")...))
	var tickHash common.Hash
	binary.BigEndian.PutUint32(tickHash[28:32], uint32(pool.Tick))
	stateDB.SetState(poolManagerAddr, tickKey, tickHash)

	// Write liquidity (always non-negative after guards, but safeFillBytes for defense in depth)
	liqKey := makeStorageKey(poolLiquidityPrefix, poolId[:])
	var liqHash common.Hash
	safeFillBytes(pool.Liquidity, liqHash[:])
	stateDB.SetState(poolManagerAddr, liqKey, liqHash)
}

// getPosition retrieves position state from storage
func (pm *PoolManager) getPosition(stateDB StateDB, positionKey [32]byte) *Position {
	if pos, ok := pm.positions[positionKey]; ok {
		return pos
	}

	pos := &Position{
		Liquidity:                big.NewInt(0),
		TokensOwed0:              big.NewInt(0),
		TokensOwed1:              big.NewInt(0),
		FeeGrowthInside0LastX128: big.NewInt(0),
		FeeGrowthInside1LastX128: big.NewInt(0),
	}

	// Load from state
	liqKey := makeStorageKey(positionPrefix, append(positionKey[:], []byte("liq")...))
	liqHash := stateDB.GetState(poolManagerAddr, liqKey)
	if liqHash != (common.Hash{}) {
		pos.Liquidity = new(big.Int).SetBytes(liqHash[:])
	}

	pm.positions[positionKey] = pos
	return pos
}

// setPosition saves position state to storage
func (pm *PoolManager) setPosition(stateDB StateDB, positionKey [32]byte, pos *Position) {
	pm.positions[positionKey] = pos

	// Write liquidity (always non-negative after guards, but safeFillBytes for defense in depth)
	liqKey := makeStorageKey(positionPrefix, append(positionKey[:], []byte("liq")...))
	var liqHash common.Hash
	safeFillBytes(pos.Liquidity, liqHash[:])
	stateDB.SetState(poolManagerAddr, liqKey, liqHash)
}

// =========================================================================
// Helper Functions
// =========================================================================

// areCurrenciesSorted returns true if currencies are properly sorted
// Uses bytes comparison for correct address ordering
func (pm *PoolManager) areCurrenciesSorted(c0, c1 Currency) bool {
	return bytes.Compare(c0.Address.Bytes(), c1.Address.Bytes()) < 0
}

// sqrtPriceX96ToTick converts sqrt price to tick using binary search
// tick = floor(log_1.0001(price))
// price = sqrtPriceX96^2 / 2^192
func (pm *PoolManager) sqrtPriceX96ToTick(sqrtPriceX96 *big.Int) int24 {
	if sqrtPriceX96 == nil || sqrtPriceX96.Sign() <= 0 {
		return 0
	}

	// Clamp to valid range
	if sqrtPriceX96.Cmp(MinSqrtRatio) <= 0 {
		return MinTick
	}
	if sqrtPriceX96.Cmp(MaxSqrtRatio) >= 0 {
		return MaxTick
	}

	// Binary search for tick
	// tickToSqrtPrice(tick) <= sqrtPriceX96 < tickToSqrtPrice(tick+1)
	low := int24(MinTick)
	high := int24(MaxTick)

	for low < high {
		mid := low + (high-low+1)/2
		sqrtPriceMid := pm.tickToSqrtPriceX96(mid)

		if sqrtPriceMid.Cmp(sqrtPriceX96) <= 0 {
			low = mid
		} else {
			high = mid - 1
		}
	}

	return low
}

// tickToSqrtPriceX96 converts tick to sqrt price (Q64.96 format).
// Exact port of Uniswap V3 TickMath.getSqrtRatioAtTick with all 20 magic
// constants (bits 0-19), supporting the full tick range +/-887272.
//
// Each magic constant is 2^128 / sqrt(1.0001^(2^i)) in Q128 format.
// Multiplying them together for set bits computes 1/sqrt(price) in Q128.
// For positive ticks (price > 1) we invert at the end.
func (pm *PoolManager) tickToSqrtPriceX96(tick int24) *big.Int {
	if tick == 0 {
		return new(big.Int).Set(Q96)
	}

	absTick := uint32(tick)
	if tick < 0 {
		absTick = uint32(-tick)
	}

	// Start with 2^128
	ratio := new(big.Int).Lsh(big.NewInt(1), 128)

	// Exact Uniswap V3 magic numbers: 2^128 / sqrt(1.0001^(2^i))
	// Full 128-bit hex values, bits 0-19
	magics := [20]*big.Int{}
	magics[0], _ = new(big.Int).SetString("fffcb933bd6fad37aa2d162d1a594001", 16)
	magics[1], _ = new(big.Int).SetString("fff97272373d413259a46990580e213a", 16)
	magics[2], _ = new(big.Int).SetString("fff2e50f5f656932ef12357cf3c7fdcc", 16)
	magics[3], _ = new(big.Int).SetString("ffe5caca7e10e4e61c3624eaa0941cd0", 16)
	magics[4], _ = new(big.Int).SetString("ffcb9843d60f6159c9db58835c926644", 16)
	magics[5], _ = new(big.Int).SetString("ff973b41fa98c081472e6896dfb254c0", 16)
	magics[6], _ = new(big.Int).SetString("ff2ea16466c96a3843ec78b326b52861", 16)
	magics[7], _ = new(big.Int).SetString("fe5dee046a99a2a811c461f1969c3053", 16)
	magics[8], _ = new(big.Int).SetString("fcbe86c7900a88aedcffc83b479aa3a4", 16)
	magics[9], _ = new(big.Int).SetString("f987a7253ac413176f2b074cf7815e54", 16)
	magics[10], _ = new(big.Int).SetString("f3392b0822b70005940c7a398e4b70f3", 16)
	magics[11], _ = new(big.Int).SetString("e7159475a2c29b7443b29c7fa6e889d9", 16)
	magics[12], _ = new(big.Int).SetString("d097f3bdfd2022b8845ad8f792aa5825", 16)
	magics[13], _ = new(big.Int).SetString("a9f746462d870fdf8a65dc1f90e061e5", 16)
	magics[14], _ = new(big.Int).SetString("70d869a156d2a1b890bb3df62baf32f7", 16)
	magics[15], _ = new(big.Int).SetString("31be135f97d08fd981231505542fcfa6", 16)
	magics[16], _ = new(big.Int).SetString("9aa508b5b7a84e1c677de54f3e99bc9", 16)
	magics[17], _ = new(big.Int).SetString("5d6af8dedb81196699c329225ee604", 16)
	magics[18], _ = new(big.Int).SetString("2216e584f5fa1ea926041bedfa", 16)
	magics[19], _ = new(big.Int).SetString("48a170391f7dc42444e8fa2", 16)

	for i := 0; i < 20; i++ {
		if absTick&(1<<i) != 0 {
			ratio.Mul(ratio, magics[i])
			ratio.Rsh(ratio, 128)
		}
	}

	// If tick > 0, invert: ratio = 2^256 / ratio
	// The magics represent 1/sqrt(1.0001^(2^i)), so multiplying gives
	// 1/sqrt(price). For positive ticks (price > 1), invert to get sqrt(price).
	if tick > 0 {
		maxU256 := new(big.Int).Lsh(big.NewInt(1), 256)
		ratio.Div(maxU256, ratio)
	}

	// Convert from Q128 to Q96: shift right 32 bits
	result := new(big.Int).Rsh(ratio, 32)

	if result.Cmp(MinSqrtRatio) < 0 {
		return new(big.Int).Set(MinSqrtRatio)
	}
	if result.Cmp(MaxSqrtRatio) > 0 {
		return new(big.Int).Set(MaxSqrtRatio)
	}

	return result
}

// executeSwap performs the swap math
func (pm *PoolManager) executeSwap(pool *Pool, key PoolKey, params SwapParams) (BalanceDelta, int24, error) {
	// Simplified swap implementation
	// Real implementation would:
	// 1. Iterate through ticks
	// 2. Calculate amounts at each tick
	// 3. Update fee growth
	// 4. Handle price limit

	exactInput := params.AmountSpecified.Sign() > 0

	var amount0, amount1 *big.Int

	if params.ZeroForOne {
		// Swapping token0 for token1
		if exactInput {
			amount0 = params.AmountSpecified
			// Calculate output based on price and liquidity
			amount1 = pm.calculateSwapOutput(pool, amount0, true)
		} else {
			amount1 = new(big.Int).Neg(params.AmountSpecified)
			amount0 = pm.calculateSwapInput(pool, amount1, true)
		}
	} else {
		// Swapping token1 for token0
		if exactInput {
			amount1 = params.AmountSpecified
			amount0 = pm.calculateSwapOutput(pool, amount1, false)
		} else {
			amount0 = new(big.Int).Neg(params.AmountSpecified)
			amount1 = pm.calculateSwapInput(pool, amount0, false)
		}
	}

	// Apply fee
	fee := pm.calculateSwapFee(amount0, amount1, key.Fee)
	_ = fee // Fee would be distributed to LPs

	return NewBalanceDelta(amount0, new(big.Int).Neg(amount1)), pool.Tick, nil
}

// calculateSwapOutput calculates output for given input
func (pm *PoolManager) calculateSwapOutput(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int {
	// Simplified: output = input * liquidity / (liquidity + input)
	// Real implementation uses exact tick math
	if pool.Liquidity.Sign() == 0 {
		return big.NewInt(0)
	}

	numerator := new(big.Int).Mul(amountIn, pool.Liquidity)
	denominator := new(big.Int).Add(pool.Liquidity, amountIn)
	return new(big.Int).Div(numerator, denominator)
}

// calculateSwapInput calculates input required for given output
func (pm *PoolManager) calculateSwapInput(pool *Pool, amountOut *big.Int, zeroForOne bool) *big.Int {
	// Simplified calculation
	if pool.Liquidity.Sign() == 0 {
		return big.NewInt(0)
	}

	numerator := new(big.Int).Mul(amountOut, pool.Liquidity)
	denominator := new(big.Int).Sub(pool.Liquidity, amountOut)
	if denominator.Sign() <= 0 {
		return new(big.Int).Set(pool.Liquidity)
	}
	return new(big.Int).Div(numerator, denominator)
}

// calculateSwapFee calculates the fee for a swap
func (pm *PoolManager) calculateSwapFee(amount0, amount1 *big.Int, fee uint24) *big.Int {
	// Fee = max(|amount0|, |amount1|) * fee / 1_000_000
	amount := amount0
	if amount1.CmpAbs(amount0) > 0 {
		amount = amount1
	}
	absAmount := new(big.Int).Abs(amount)
	feeAmount := new(big.Int).Mul(absAmount, big.NewInt(int64(fee)))
	return feeAmount.Div(feeAmount, big.NewInt(1_000_000))
}

// calculateLiquidityAmounts calculates token amounts for liquidity change
func (pm *PoolManager) calculateLiquidityAmounts(
	pool *Pool,
	key PoolKey,
	params ModifyLiquidityParams,
	owner common.Address,
) (BalanceDelta, BalanceDelta) {
	// Simplified liquidity calculation
	// Real implementation uses sqrtPrice and tick math

	currentTick := pool.Tick
	isActive := params.TickLower <= currentTick && currentTick < params.TickUpper

	var amount0, amount1 *big.Int

	if params.LiquidityDelta.Sign() > 0 {
		// Adding liquidity
		if isActive {
			// Both tokens needed
			amount0 = new(big.Int).Div(params.LiquidityDelta, big.NewInt(2))
			amount1 = new(big.Int).Div(params.LiquidityDelta, big.NewInt(2))
		} else if currentTick < params.TickLower {
			// Only token0 needed
			amount0 = params.LiquidityDelta
			amount1 = big.NewInt(0)
		} else {
			// Only token1 needed
			amount0 = big.NewInt(0)
			amount1 = params.LiquidityDelta
		}
	} else {
		// Removing liquidity
		if isActive {
			amount0 = new(big.Int).Neg(new(big.Int).Div(new(big.Int).Neg(params.LiquidityDelta), big.NewInt(2)))
			amount1 = new(big.Int).Neg(new(big.Int).Div(new(big.Int).Neg(params.LiquidityDelta), big.NewInt(2)))
		} else if currentTick < params.TickLower {
			amount0 = params.LiquidityDelta
			amount1 = big.NewInt(0)
		} else {
			amount0 = big.NewInt(0)
			amount1 = params.LiquidityDelta
		}
	}

	callerDelta := NewBalanceDelta(amount0, amount1)
	feesAccrued := ZeroBalanceDelta() // Simplified - no fee calculation

	return callerDelta, feesAccrued
}

// calculateFlashFee calculates flash loan fee
func (pm *PoolManager) calculateFlashFee(amount *big.Int, fee uint24) *big.Int {
	// Fee = amount * fee / 1_000_000
	if amount.Sign() <= 0 {
		return big.NewInt(0)
	}
	feeAmount := new(big.Int).Mul(amount, big.NewInt(int64(fee)))
	return feeAmount.Div(feeAmount, big.NewInt(1_000_000))
}

// transferERC20 handles ERC20 transfers via direct state storage manipulation.
// Uses OZ 5.x namespaced storage slots.
func (pm *PoolManager) transferERC20(stateDB StateDB, currency Currency, from, to common.Address, amount *big.Int) error {
	return pm.transferToken(stateDB, currency, from, to, amount)
}

// transferToken handles both native and ERC20 token transfers via state manipulation.
// Returns an error if the sender has insufficient balance. No state is modified on error.
func (pm *PoolManager) transferToken(stateDB StateDB, currency Currency, from, to common.Address, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return nil
	}
	if currency.IsNative() {
		// Check native balance before any state modification
		fromBal := stateDB.GetBalance(from)
		amountU256, overflow := uint256.FromBig(amount)
		if overflow {
			return fmt.Errorf("%w: amount overflows uint256", ErrInsufficientBalance)
		}
		if fromBal.Lt(amountU256) {
			return fmt.Errorf("%w: native balance %s < transfer %s", ErrInsufficientBalance, fromBal, amountU256)
		}
		stateDB.SubBalance(from, amountU256)
		stateDB.AddBalance(to, amountU256)
		return nil
	}
	// ERC20: manipulate balance storage slots directly.
	// OZ ERC20Upgradeable (5.x) stores _balances at a namespaced base:
	//   keccak256("openzeppelin.storage.ERC20") = 0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00
	//   _balances mapping is at offset 0 from that base.
	//
	// We use the namespaced slot (OZ 5.x default). Only OZ 5.x ERC20Upgradeable
	// tokens are supported by this precompile. The previous fallback-on-zero logic
	// was removed because a zero balance at the namespaced slot is a valid state
	// (newly created account), and falling back to slot 0 would read/write the
	// wrong storage location for OZ 5.x tokens, corrupting state.
	token := currency.Address

	erc20Base, _ := new(big.Int).SetString("52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00", 16)

	fromSlot := erc20BalanceSlot(erc20Base, from)
	toSlot := erc20BalanceSlot(erc20Base, to)

	fromBal := new(big.Int).SetBytes(stateDB.GetState(token, fromSlot).Bytes())

	// F1: Check balance BEFORE any state modification
	if fromBal.Cmp(amount) < 0 {
		return fmt.Errorf("%w: ERC20 %s balance %s < transfer %s",
			ErrInsufficientBalance, token.Hex(), fromBal, amount)
	}

	toBal := new(big.Int).SetBytes(stateDB.GetState(token, toSlot).Bytes())

	// Debit from
	fromBal.Sub(fromBal, amount)
	var fromHash common.Hash
	fromBal.FillBytes(fromHash[:])
	stateDB.SetState(token, fromSlot, fromHash)

	// Credit to
	toBal.Add(toBal, amount)
	var toHash common.Hash
	toBal.FillBytes(toHash[:])
	stateDB.SetState(token, toSlot, toHash)
	return nil
}

// erc20BalanceSlot computes keccak256(abi.encode(address, mappingSlot)) for a
// Solidity mapping(address => uint256) stored at slot `base`.
func erc20BalanceSlot(base *big.Int, addr common.Address) common.Hash {
	key := make([]byte, 64)
	copy(key[12:32], addr.Bytes()) // left-pad address to 32 bytes
	safeFillBytes(base, key[32:64])
	return common.BytesToHash(crypto.Keccak256(key))
}

// autoSettle handles token transfers for the delta after a swap or liquidity
// operation. Called by auto-lock wrappers in module.go to settle directly
// without requiring a separate Lock()/Settle() cycle.
// Returns an error if any transfer fails (e.g., insufficient balance).
func (pm *PoolManager) autoSettle(stateDB StateDB, caller common.Address, key PoolKey, delta BalanceDelta) error {
	if delta.Amount0.Sign() > 0 {
		// Caller owes token0 to pool
		if err := pm.transferToken(stateDB, key.Currency0, caller, poolManagerAddr, delta.Amount0); err != nil {
			return fmt.Errorf("%w: currency0 settlement: %v", ErrSettlementFailed, err)
		}
	} else if delta.Amount0.Sign() < 0 {
		// Pool owes token0 to caller
		if err := pm.transferToken(stateDB, key.Currency0, poolManagerAddr, caller, new(big.Int).Neg(delta.Amount0)); err != nil {
			return fmt.Errorf("%w: currency0 settlement: %v", ErrSettlementFailed, err)
		}
	}
	if delta.Amount1.Sign() > 0 {
		// Caller owes token1 to pool
		if err := pm.transferToken(stateDB, key.Currency1, caller, poolManagerAddr, delta.Amount1); err != nil {
			return fmt.Errorf("%w: currency1 settlement: %v", ErrSettlementFailed, err)
		}
	} else if delta.Amount1.Sign() < 0 {
		// Pool owes token1 to caller
		if err := pm.transferToken(stateDB, key.Currency1, poolManagerAddr, caller, new(big.Int).Neg(delta.Amount1)); err != nil {
			return fmt.Errorf("%w: currency1 settlement: %v", ErrSettlementFailed, err)
		}
	}
	// Clear deltas for this caller
	delete(pm.currentDeltas, caller)
	return nil
}

// executeCallback executes the locker's callback (simplified)
func (pm *PoolManager) executeCallback(stateDB StateDB, caller common.Address, data []byte) ([]byte, error) {
	// In real implementation, this would be an EVM call
	// For testing, we return success
	return nil, nil
}

// callHook calls a hook function (simplified)
func (pm *PoolManager) callHook(stateDB StateDB, hookAddr common.Address, flag HookFlags, args ...interface{}) error {
	// In real implementation, this would be an EVM call to hook contract
	// For now, just return success
	return nil
}

// safeFillBytes writes a big.Int into a byte slice without panicking.
// FillBytes panics on negative values, so this guards against that.
// For non-negative values, behaves identically to FillBytes.
// For negative values (which should never reach storage), writes zero.
func safeFillBytes(v *big.Int, buf []byte) {
	if v == nil || v.Sign() < 0 {
		// Zero the buffer -- negative values should never be stored.
		// The caller should have already rejected negative values upstream.
		for i := range buf {
			buf[i] = 0
		}
		return
	}
	v.FillBytes(buf)
}

// =========================================================================
// View Functions
// =========================================================================

// GetPool returns the current state of a pool
func (pm *PoolManager) GetPool(stateDB StateDB, key PoolKey) (*Pool, error) {
	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)

	if !pool.IsInitialized() {
		return nil, ErrPoolNotInitialized
	}

	return pool, nil
}

// GetPosition returns a liquidity position
func (pm *PoolManager) GetPosition(
	stateDB StateDB,
	key PoolKey,
	owner common.Address,
	tickLower, tickUpper int24,
	salt [32]byte,
) (*Position, error) {
	posKey := PositionKey(owner, tickLower, tickUpper, salt)
	pos := pm.getPosition(stateDB, posKey)
	return pos, nil
}

// GetDelta returns the current delta for a currency
func (pm *PoolManager) GetDelta(locker common.Address, currency Currency) *big.Int {
	deltas, ok := pm.currentDeltas[locker]
	if !ok {
		return big.NewInt(0)
	}
	delta, ok := deltas[currency]
	if !ok {
		return big.NewInt(0)
	}
	return new(big.Int).Set(delta)
}
