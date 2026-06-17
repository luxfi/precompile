// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

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
	protocolFeePrefix   = []byte("pfee")
	hookRegistryPrefix  = []byte("hook")
	pauseStatePrefix    = []byte("paus")
	freezeStatePrefix   = []byte("frzn")
)

// PoolState extends the basic Pool with V4 tick-level state for concentrated
// liquidity. Each pool tracks per-tick info, a bitmap of initialized ticks,
// per-position fee growth, and fee/spacing parameters from the pool key.
type PoolState struct {
	*Pool                              // Base pool (sqrtPriceX96, tick, liquidity, feeGrowth)
	Ticks       map[int32]*TickInfo    // Per-tick state
	TickBitmap  *TickBitmap            // Initialized tick tracking
	Positions   map[[32]byte]*Position // Position states keyed by BLAKE3(owner||tickLower||tickUpper||salt)
	TickSpacing int32                  // From pool key
	LPFee       uint32                 // LP fee in pips (hundredths of a bip)
	ProtocolFee uint32                 // Protocol fee in pips
}

// NewPoolState wraps a Pool with V4 tick-level state.
func NewPoolState(pool *Pool, tickSpacing int32, lpFee uint32) *PoolState {
	return &PoolState{
		Pool:        pool,
		Ticks:       make(map[int32]*TickInfo),
		TickBitmap:  NewTickBitmap(),
		Positions:   make(map[[32]byte]*Position),
		TickSpacing: tickSpacing,
		LPFee:       lpFee,
	}
}

// routePool tells a poolRouter backend (e.g. ZAPEngine) which canonical pool a
// PoolState maps to, so the next engine delegation forwards to the right
// server-side pool. No-op for the embedded engine (not a poolRouter). Called on
// every swap/modify/donate/quote because the cache PoolState may be rebuilt
// from StateDB between calls, so the route must be (re)asserted each time.
func (pm *PoolManager) routePool(poolId [32]byte, ps *PoolState) {
	if router, ok := pm.engine.(poolRouter); ok {
		router.SetPoolID(ps, poolId)
	}
}

// txIdentified is the OPTIONAL capability a StateDB exposes when it can name the
// executing EVM transaction. The production poolStateAdapter implements it
// (sourced from contract.StateDB.TxHash); test StateDBs need not. PoolManager
// uses it only to thread tx identity into an idempotencyBinder backend.
type txIdentified interface {
	TxHash() common.Hash
}

// bindTx threads the executing tx hash into an idempotencyBinder backend (e.g.
// ZAPEngine) so a marketable order is submitted to the d-chain at most once per
// EVM tx — re-execution / reorg / retry returns the committed delta instead of
// double-filling (RED H1). No-op when the engine is not a binder or the StateDB
// cannot name the tx (the binder then disables its cache for that call).
func (pm *PoolManager) bindTx(stateDB StateDB, ps *PoolState) {
	binder, ok := pm.engine.(idempotencyBinder)
	if !ok {
		return
	}
	var txHash common.Hash
	if tx, ok := stateDB.(txIdentified); ok {
		txHash = tx.TxHash()
	}
	binder.BindTx(ps, txHash)
}

// getOrCreateTick returns the TickInfo for a tick, creating it if absent.
func (ps *PoolState) getOrCreateTick(tick int32) *TickInfo {
	ti, ok := ps.Ticks[tick]
	if !ok {
		ti = NewTickInfo()
		ps.Ticks[tick] = ti
	}
	return ti
}

// PoolManager implements the singleton DEX pool manager precompile.
// It is a thin shim: validation, hooks, state persistence, and events.
// ALL AMM math is delegated to the Engine.
//
// Pause/Freeze hierarchy (ATS regulatory compliance):
//   - DEX-level pause: stops ALL swap/modifyLiquidity/donate across every pool
//   - Pool-level pause: stops operations on a single pool (reversible by admin)
//   - Pool-level freeze: permanently stops a pool (irreversible without governance)
//
// Checks are ordered: DEX pause > pool freeze > pool pause.
// Freeze takes precedence over pause — a frozen pool cannot be un-paused.
//
// Pause/freeze are read STRAIGHT FROM StateDB on every check. The previous
// design cached them in process memory; that cache survived StateDB
// revertToSnapshot, producing a permanent DoS when a PauseDEX tx reverted but
// the in-memory flag did not (RED V6). Reading from StateDB every call costs
// 1–3 SLOAD-equivalents, which is acceptable on the swap hot path and
// eliminates an entire class of divergence bug.
type PoolManager struct {
	engine     Engine
	pools      map[[32]byte]*Pool
	poolStates map[[32]byte]*PoolState
	positions  map[[32]byte]*Position

	protocolFeeController common.Address
}

// NewPoolManager creates a new pool manager with the given engine.
// An engine must be provided (ZAPEngine for production, or any Engine
// implementation for testing). The precompile contains no math.
func NewPoolManager(engine ...Engine) *PoolManager {
	var e Engine
	if len(engine) > 0 && engine[0] != nil {
		e = engine[0]
	}
	return &PoolManager{
		engine:     e,
		pools:      make(map[[32]byte]*Pool),
		poolStates: make(map[[32]byte]*PoolState),
		positions:  make(map[[32]byte]*Position),
	}
}

// getPoolState returns the extended V4 pool state, creating one from the
// base pool if it doesn't exist yet.
func (pm *PoolManager) getPoolState(stateDB StateDB, poolId [32]byte, tickSpacing int32, lpFee uint32) *PoolState {
	if ps, ok := pm.poolStates[poolId]; ok {
		return ps
	}
	pool := pm.getPool(stateDB, poolId)
	ps := NewPoolState(pool, tickSpacing, lpFee)
	pm.poolStates[poolId] = ps
	return ps
}

// setPoolState saves extended pool state and syncs back to base pool storage.
func (pm *PoolManager) setPoolState(stateDB StateDB, poolId [32]byte, ps *PoolState) {
	pm.poolStates[poolId] = ps
	pm.setPool(stateDB, poolId, ps.Pool)
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

// Initialize creates and initializes a new pool.
func (pm *PoolManager) Initialize(
	stateDB StateDB,
	key PoolKey,
	sqrtPriceX96 *big.Int,
	hookData []byte,
) (int24, error) {
	if !pm.areCurrenciesSorted(key.Currency0, key.Currency1) {
		return 0, ErrCurrencyNotSorted
	}
	if key.Fee > FeeMax {
		return 0, ErrInvalidFee
	}
	if sqrtPriceX96.Cmp(MinSqrtRatio) < 0 || sqrtPriceX96.Cmp(MaxSqrtRatio) > 0 {
		return 0, ErrInvalidSqrtPrice
	}

	poolId := key.ID()

	pool := pm.getPool(stateDB, poolId)
	if pool.IsInitialized() {
		return 0, ErrPoolAlreadyInitialized
	}

	tick, err := pm.engine.Initialize(sqrtPriceX96)
	if err != nil {
		return 0, err
	}

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeInitialize, key, sqrtPriceX96, hookData); err != nil {
			return 0, err
		}
	}

	pool.SqrtPriceX96 = new(big.Int).Set(sqrtPriceX96)
	pool.Tick = tick
	pool.Liquidity = big.NewInt(0)
	pool.FeeGrowth0X128 = big.NewInt(0)
	pool.FeeGrowth1X128 = big.NewInt(0)

	ps := NewPoolState(pool, key.TickSpacing, key.Fee)
	pm.poolStates[poolId] = ps

	// ZAP path: create the CANONICAL pool on the D-Chain server and route this
	// (cache) PoolState to it. The server's copy is the source of truth; the
	// local ps/pool above are a read-through view persisted to StateDB. The
	// embedded path skips this (engine is not a poolRouter) and keeps ps as the
	// authoritative state, unchanged.
	if router, ok := pm.engine.(poolRouter); ok {
		serverTick, perr := router.InitializePool(ps, poolId, sqrtPriceX96, key.TickSpacing, uint32(key.Fee))
		if perr != nil {
			return 0, perr
		}
		// The server's tick is authoritative; sync the cache to it.
		tick = serverTick
		pool.Tick = serverTick
	}

	pm.setPool(stateDB, poolId, pool)

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterInitialize, key, sqrtPriceX96, hookData); err != nil {
			return 0, err
		}
	}

	emitInitializeEvent(stateDB, poolId, key, sqrtPriceX96, tick)

	return tick, nil
}

// =========================================================================
// Pause/Freeze Controls (ATS Regulatory Compliance)
// =========================================================================

// dexPauseStorageKey is the single storage slot that carries the DEX-level
// pause flag. Computed once at init time so the hot path doesn't re-hash.
var dexPauseStorageKey = makeStorageKey(pauseStatePrefix, []byte("dex"))

// isDEXPaused reads the durable pause flag from StateDB. Reading every call
// (instead of caching in process memory) is what makes this safe under tx
// revertToSnapshot: if a PauseDEX tx reverts, the StateDB write reverts with
// it, and the next call reads the un-paused value. RED V6.
func isDEXPaused(stateDB StateDB) bool {
	v := stateDB.GetState(poolManagerAddr, dexPauseStorageKey)
	return v[31] == 1
}

// isPoolFrozen reads the durable per-pool freeze flag from StateDB.
func isPoolFrozen(stateDB StateDB, poolId [32]byte) bool {
	v := stateDB.GetState(poolManagerAddr, makeStorageKey(freezeStatePrefix, poolId[:]))
	return v[31] == 1
}

// isPoolPaused reads the durable per-pool pause flag from StateDB.
func isPoolPaused(stateDB StateDB, poolId [32]byte) bool {
	v := stateDB.GetState(poolManagerAddr, makeStorageKey(pauseStatePrefix, poolId[:]))
	return v[31] == 1
}

// checkPauseState verifies that the DEX and pool are not paused or frozen.
// Check order: DEX-level > pool freeze > pool pause. Returns nil if all
// operations are permitted.
//
// All reads come from StateDB — no in-process cache. See V6 docs above.
func (pm *PoolManager) checkPauseState(stateDB StateDB, poolId [32]byte) error {
	if isDEXPaused(stateDB) {
		return ErrDEXPaused
	}
	if isPoolFrozen(stateDB, poolId) {
		return ErrPoolFrozen
	}
	if isPoolPaused(stateDB, poolId) {
		return ErrPoolPaused
	}
	return nil
}

// IsPaused returns true if the entire DEX is paused. Reads from StateDB.
// Kept on the type so callers don't need to know the storage layout.
func (pm *PoolManager) IsPaused(stateDB StateDB) bool {
	return isDEXPaused(stateDB)
}

// IsPoolPaused returns true if the given pool is paused (not frozen).
func (pm *PoolManager) IsPoolPaused(stateDB StateDB, poolId [32]byte) bool {
	return isPoolPaused(stateDB, poolId)
}

// IsPoolFrozen returns true if the given pool is permanently frozen.
func (pm *PoolManager) IsPoolFrozen(stateDB StateDB, poolId [32]byte) bool {
	return isPoolFrozen(stateDB, poolId)
}

// PauseDEX pauses ALL DEX operations. Only callable by admin (protocolFeeController).
// When paused, Swap/ModifyLiquidity/Donate all revert with ErrDEXPaused.
//
// Writes only to StateDB — no process-memory cache to drift on revert. V6.
func (pm *PoolManager) PauseDEX(stateDB StateDB, caller common.Address) error {
	if caller != pm.protocolFeeController {
		return ErrUnauthorized
	}
	if isDEXPaused(stateDB) {
		return ErrAlreadyPaused
	}
	var val common.Hash
	val[31] = 1
	stateDB.SetState(poolManagerAddr, dexPauseStorageKey, val)
	emitDEXPausedEvent(stateDB, caller)
	return nil
}

// ResumeDEX resumes all DEX operations. Only callable by admin (protocolFeeController).
func (pm *PoolManager) ResumeDEX(stateDB StateDB, caller common.Address) error {
	if caller != pm.protocolFeeController {
		return ErrUnauthorized
	}
	if !isDEXPaused(stateDB) {
		return ErrDEXNotPaused
	}
	stateDB.SetState(poolManagerAddr, dexPauseStorageKey, common.Hash{})
	emitDEXResumedEvent(stateDB, caller)
	return nil
}

// PausePool pauses a single pool. Only callable by admin (protocolFeeController).
// A frozen pool cannot be paused (it is already permanently halted).
//
// Refuses to act on a pool that has not been Initialize'd. Without this guard
// an admin call against an arbitrary poolId would poison the storage slot,
// and a future Initialize for that same id would find it pre-paused with no
// way back. RED V5.
func (pm *PoolManager) PausePool(stateDB StateDB, caller common.Address, poolId [32]byte) error {
	if caller != pm.protocolFeeController {
		return ErrUnauthorized
	}
	if !pm.getPool(stateDB, poolId).IsInitialized() {
		return ErrPoolNotInitialized
	}
	if isPoolFrozen(stateDB, poolId) {
		return ErrPoolFrozen
	}
	if isPoolPaused(stateDB, poolId) {
		return ErrAlreadyPaused
	}
	var val common.Hash
	val[31] = 1
	stateDB.SetState(poolManagerAddr, makeStorageKey(pauseStatePrefix, poolId[:]), val)
	emitPoolPausedEvent(stateDB, caller, poolId)
	return nil
}

// ResumePool resumes a single pool. Only callable by admin (protocolFeeController).
// A frozen pool CANNOT be resumed — freeze is irreversible without governance.
func (pm *PoolManager) ResumePool(stateDB StateDB, caller common.Address, poolId [32]byte) error {
	if caller != pm.protocolFeeController {
		return ErrUnauthorized
	}
	if !pm.getPool(stateDB, poolId).IsInitialized() {
		return ErrPoolNotInitialized
	}
	if isPoolFrozen(stateDB, poolId) {
		return ErrFreezeIrreversible
	}
	if !isPoolPaused(stateDB, poolId) {
		return ErrPoolNotPaused
	}
	stateDB.SetState(poolManagerAddr, makeStorageKey(pauseStatePrefix, poolId[:]), common.Hash{})
	emitPoolResumedEvent(stateDB, caller, poolId)
	return nil
}

// FreezePool permanently freezes a pool. IRREVERSIBLE without governance action.
// Only callable by admin (protocolFeeController).
// A frozen pool rejects all swap/modifyLiquidity/donate operations forever.
// Existing positions can still be read but not modified.
//
// Refuses to act on a pool that has not been Initialize'd. See PausePool for
// the attack this guards (RED V5).
func (pm *PoolManager) FreezePool(stateDB StateDB, caller common.Address, poolId [32]byte) error {
	if caller != pm.protocolFeeController {
		return ErrUnauthorized
	}
	if !pm.getPool(stateDB, poolId).IsInitialized() {
		return ErrPoolNotInitialized
	}
	if isPoolFrozen(stateDB, poolId) {
		return ErrAlreadyFrozen
	}
	// Freeze supersedes pause — clear any pending pause flag.
	stateDB.SetState(poolManagerAddr, makeStorageKey(pauseStatePrefix, poolId[:]), common.Hash{})
	var val common.Hash
	val[31] = 1
	stateDB.SetState(poolManagerAddr, makeStorageKey(freezeStatePrefix, poolId[:]), val)
	emitPoolFrozenEvent(stateDB, caller, poolId)
	return nil
}

// =========================================================================
// Core DEX Operations
// =========================================================================

// Swap executes a swap in a pool using the V4 tick-crossing loop.
func (pm *PoolManager) Swap(
	stateDB StateDB,
	caller common.Address,
	key PoolKey,
	params SwapParams,
	hookData []byte,
) (BalanceDelta, error) {
	poolId := key.ID()

	// Pause/freeze gate: check BEFORE any state reads or mutations.
	// Reads from StateDB on cold cache (survives node restarts).
	if err := pm.checkPauseState(stateDB, poolId); err != nil {
		return ZeroBalanceDelta(), err
	}

	ps := pm.getPoolState(stateDB, poolId, key.TickSpacing, key.Fee)

	if !ps.Pool.IsInitialized() {
		return ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeSwap, key, params, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	pm.routePool(poolId, ps)
	pm.bindTx(stateDB, ps)
	delta, err := pm.engine.Swap(ps, params)
	if err != nil {
		return ZeroBalanceDelta(), err
	}

	pm.setPoolState(stateDB, poolId, ps)

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterSwap, key, params, delta, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	emitSwapEvent(stateDB, poolId, caller, delta, ps.SqrtPriceX96, ps.Liquidity, ps.Tick, key.Fee)

	return delta, nil
}

// ModifyLiquidity adds or removes liquidity from a pool using V4 concentrated liquidity math.
func (pm *PoolManager) ModifyLiquidity(
	stateDB StateDB,
	caller common.Address,
	key PoolKey,
	params ModifyLiquidityParams,
	hookData []byte,
) (BalanceDelta, BalanceDelta, error) {
	if params.TickLower >= params.TickUpper {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrInvalidTickRange
	}
	if params.TickLower < MinTick || params.TickUpper > MaxTick {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrTickOutOfRange
	}

	poolId := key.ID()

	// Pause/freeze gate with LP escape hatch (RED V13).
	//
	// A frozen pool with LP funds inside is a rug if withdrawals are blocked
	// uniformly — the admin could permanently lock user assets. The
	// regulatory intent of FreezePool is to halt PRICE DISCOVERY (no new
	// trades, no fee accumulation, no new LPs), not seize existing principal.
	// So we permit LiquidityDelta < 0 (burn) on frozen pools.
	//
	// Pool-level pause is reversible by admin, so withdrawal can wait —
	// blocking is fine. DEX-level pause is the global emergency stop and
	// blocks every direction including burns; that is the deliberate
	// "freeze the entire venue" semantic.
	isWithdraw := params.LiquidityDelta.Sign() < 0
	if isWithdraw {
		// Only the DEX-level kill switch blocks an LP exit.
		if isDEXPaused(stateDB) {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrDEXPaused
		}
	} else {
		// Mint or zero-mod: pool must be fully active.
		if err := pm.checkPauseState(stateDB, poolId); err != nil {
			return ZeroBalanceDelta(), ZeroBalanceDelta(), err
		}
	}

	ps := pm.getPoolState(stateDB, poolId, key.TickSpacing, key.Fee)

	if !ps.Pool.IsInitialized() {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrPoolNotInitialized
	}

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

	pm.routePool(poolId, ps)
	callerDelta, feesAccrued, err := pm.engine.ModifyLiquidity(ps, caller, params)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), err
	}

	posKey := PositionKey(caller, params.TickLower, params.TickUpper, params.Salt)
	if pos, ok := ps.Positions[posKey]; ok {
		pm.positions[posKey] = pos
		pm.setPosition(stateDB, posKey, pos)
	}

	pm.setPoolState(stateDB, poolId, ps)

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

	emitModifyLiquidityEvent(stateDB, poolId, caller, params)

	return callerDelta, feesAccrued, nil
}

// Donate donates tokens to a pool's liquidity providers.
func (pm *PoolManager) Donate(
	stateDB StateDB,
	caller common.Address,
	key PoolKey,
	amount0 *big.Int,
	amount1 *big.Int,
	hookData ...[]byte,
) (BalanceDelta, error) {
	poolId := key.ID()

	// Pause/freeze gate: check BEFORE any state reads or mutations.
	if err := pm.checkPauseState(stateDB, poolId); err != nil {
		return ZeroBalanceDelta(), err
	}

	ps := pm.getPoolState(stateDB, poolId, key.TickSpacing, key.Fee)

	if !ps.Pool.IsInitialized() {
		return ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	var hd []byte
	if len(hookData) > 0 {
		hd = hookData[0]
	}

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeDonate, key, amount0, amount1, hd); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	pm.routePool(poolId, ps)
	delta, err := pm.engine.Donate(ps, amount0, amount1)
	if err != nil {
		return ZeroBalanceDelta(), err
	}

	pm.setPoolState(stateDB, poolId, ps)

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookAfterDonate, key, amount0, amount1, delta, hd); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	return delta, nil
}

// =========================================================================
// Flash Loans
// =========================================================================

// Flash executes a flash loan.
func (pm *PoolManager) Flash(
	stateDB StateDB,
	caller common.Address,
	key PoolKey,
	params FlashParams,
	hookData []byte,
) (BalanceDelta, error) {
	poolId := key.ID()

	// Pause/freeze gate: flash loans must also be blocked during halts.
	if err := pm.checkPauseState(stateDB, poolId); err != nil {
		return ZeroBalanceDelta(), err
	}

	pool := pm.getPool(stateDB, poolId)

	if !pool.IsInitialized() {
		return ZeroBalanceDelta(), ErrPoolNotInitialized
	}

	// V4 flash has no hook callbacks — flash is hookless by design.

	fee0 := pm.calculateFlashFee(params.Amount0, key.Fee)
	fee1 := pm.calculateFlashFee(params.Amount1, key.Fee)

	totalOwed0 := new(big.Int).Add(params.Amount0, fee0)
	totalOwed1 := new(big.Int).Add(params.Amount1, fee1)

	delta := NewBalanceDelta(totalOwed0, totalOwed1)

	return delta, nil
}

// =========================================================================
// State Management
// =========================================================================

func (pm *PoolManager) getPool(stateDB StateDB, poolId [32]byte) *Pool {
	if pool, ok := pm.pools[poolId]; ok {
		return pool
	}
	pool := NewPool()

	sqrtPriceKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("sqrtPrice")...))
	sqrtPriceHash := stateDB.GetState(poolManagerAddr, sqrtPriceKey)
	if sqrtPriceHash != (common.Hash{}) {
		pool.SqrtPriceX96 = new(big.Int).SetBytes(sqrtPriceHash[:])
	}

	tickKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("tick")...))
	tickHash := stateDB.GetState(poolManagerAddr, tickKey)
	if tickHash != (common.Hash{}) {
		pool.Tick = int24(binary.BigEndian.Uint32(tickHash[28:32]))
	}

	liqKey := makeStorageKey(poolLiquidityPrefix, poolId[:])
	liqHash := stateDB.GetState(poolManagerAddr, liqKey)
	if liqHash != (common.Hash{}) {
		pool.Liquidity = new(big.Int).SetBytes(liqHash[:])
	}

	// Fee growth and protocol fees — critical for LP accounting across restarts
	fg0Key := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("feeGrowth0")...))
	fg0Hash := stateDB.GetState(poolManagerAddr, fg0Key)
	if fg0Hash != (common.Hash{}) {
		pool.FeeGrowth0X128 = new(big.Int).SetBytes(fg0Hash[:])
	}

	fg1Key := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("feeGrowth1")...))
	fg1Hash := stateDB.GetState(poolManagerAddr, fg1Key)
	if fg1Hash != (common.Hash{}) {
		pool.FeeGrowth1X128 = new(big.Int).SetBytes(fg1Hash[:])
	}

	pf0Key := makeStorageKey(protocolFeePrefix, append(poolId[:], []byte("0")...))
	pf0Hash := stateDB.GetState(poolManagerAddr, pf0Key)
	if pf0Hash != (common.Hash{}) {
		pool.ProtocolFees0 = new(big.Int).SetBytes(pf0Hash[:])
	}

	pf1Key := makeStorageKey(protocolFeePrefix, append(poolId[:], []byte("1")...))
	pf1Hash := stateDB.GetState(poolManagerAddr, pf1Key)
	if pf1Hash != (common.Hash{}) {
		pool.ProtocolFees1 = new(big.Int).SetBytes(pf1Hash[:])
	}

	pm.pools[poolId] = pool
	return pool
}

func (pm *PoolManager) setPool(stateDB StateDB, poolId [32]byte, pool *Pool) {
	pm.pools[poolId] = pool

	sqrtPriceKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("sqrtPrice")...))
	var sqrtPriceHash common.Hash
	safeFillBytes(pool.SqrtPriceX96, sqrtPriceHash[:])
	stateDB.SetState(poolManagerAddr, sqrtPriceKey, sqrtPriceHash)

	tickKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("tick")...))
	var tickHash common.Hash
	binary.BigEndian.PutUint32(tickHash[28:32], uint32(pool.Tick))
	stateDB.SetState(poolManagerAddr, tickKey, tickHash)

	liqKey := makeStorageKey(poolLiquidityPrefix, poolId[:])
	var liqHash common.Hash
	safeFillBytes(pool.Liquidity, liqHash[:])
	stateDB.SetState(poolManagerAddr, liqKey, liqHash)

	// Fee growth — LP accounting depends on these surviving restarts
	fg0Key := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("feeGrowth0")...))
	var fg0Hash common.Hash
	safeFillBytes(pool.FeeGrowth0X128, fg0Hash[:])
	stateDB.SetState(poolManagerAddr, fg0Key, fg0Hash)

	fg1Key := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("feeGrowth1")...))
	var fg1Hash common.Hash
	safeFillBytes(pool.FeeGrowth1X128, fg1Hash[:])
	stateDB.SetState(poolManagerAddr, fg1Key, fg1Hash)

	// Protocol fees
	pf0Key := makeStorageKey(protocolFeePrefix, append(poolId[:], []byte("0")...))
	var pf0Hash common.Hash
	safeFillBytes(pool.ProtocolFees0, pf0Hash[:])
	stateDB.SetState(poolManagerAddr, pf0Key, pf0Hash)

	pf1Key := makeStorageKey(protocolFeePrefix, append(poolId[:], []byte("1")...))
	var pf1Hash common.Hash
	safeFillBytes(pool.ProtocolFees1, pf1Hash[:])
	stateDB.SetState(poolManagerAddr, pf1Key, pf1Hash)
}

func (pm *PoolManager) getPosition(stateDB StateDB, positionKey [32]byte) *Position {
	if pos, ok := pm.positions[positionKey]; ok {
		return pos
	}
	pos := &Position{
		Liquidity: big.NewInt(0), TokensOwed0: big.NewInt(0), TokensOwed1: big.NewInt(0),
		FeeGrowthInside0LastX128: big.NewInt(0), FeeGrowthInside1LastX128: big.NewInt(0),
	}
	liqKey := makeStorageKey(positionPrefix, append(positionKey[:], []byte("liq")...))
	liqHash := stateDB.GetState(poolManagerAddr, liqKey)
	if liqHash != (common.Hash{}) {
		pos.Liquidity = new(big.Int).SetBytes(liqHash[:])
	}

	fgi0Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("fgi0")...))
	fgi0Hash := stateDB.GetState(poolManagerAddr, fgi0Key)
	if fgi0Hash != (common.Hash{}) {
		pos.FeeGrowthInside0LastX128 = new(big.Int).SetBytes(fgi0Hash[:])
	}

	fgi1Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("fgi1")...))
	fgi1Hash := stateDB.GetState(poolManagerAddr, fgi1Key)
	if fgi1Hash != (common.Hash{}) {
		pos.FeeGrowthInside1LastX128 = new(big.Int).SetBytes(fgi1Hash[:])
	}

	to0Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("to0")...))
	to0Hash := stateDB.GetState(poolManagerAddr, to0Key)
	if to0Hash != (common.Hash{}) {
		pos.TokensOwed0 = new(big.Int).SetBytes(to0Hash[:])
	}

	to1Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("to1")...))
	to1Hash := stateDB.GetState(poolManagerAddr, to1Key)
	if to1Hash != (common.Hash{}) {
		pos.TokensOwed1 = new(big.Int).SetBytes(to1Hash[:])
	}

	pm.positions[positionKey] = pos
	return pos
}

func (pm *PoolManager) setPosition(stateDB StateDB, positionKey [32]byte, pos *Position) {
	pm.positions[positionKey] = pos

	liqKey := makeStorageKey(positionPrefix, append(positionKey[:], []byte("liq")...))
	var liqHash common.Hash
	safeFillBytes(pos.Liquidity, liqHash[:])
	stateDB.SetState(poolManagerAddr, liqKey, liqHash)

	fgi0Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("fgi0")...))
	var fgi0Hash common.Hash
	safeFillBytes(pos.FeeGrowthInside0LastX128, fgi0Hash[:])
	stateDB.SetState(poolManagerAddr, fgi0Key, fgi0Hash)

	fgi1Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("fgi1")...))
	var fgi1Hash common.Hash
	safeFillBytes(pos.FeeGrowthInside1LastX128, fgi1Hash[:])
	stateDB.SetState(poolManagerAddr, fgi1Key, fgi1Hash)

	to0Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("to0")...))
	var to0Hash common.Hash
	safeFillBytes(pos.TokensOwed0, to0Hash[:])
	stateDB.SetState(poolManagerAddr, to0Key, to0Hash)

	to1Key := makeStorageKey(positionPrefix, append(positionKey[:], []byte("to1")...))
	var to1Hash common.Hash
	safeFillBytes(pos.TokensOwed1, to1Hash[:])
	stateDB.SetState(poolManagerAddr, to1Key, to1Hash)
}

// =========================================================================
// Helper Functions
// =========================================================================

func (pm *PoolManager) areCurrenciesSorted(c0, c1 Currency) bool {
	return bytes.Compare(c0.Address.Bytes(), c1.Address.Bytes()) < 0
}

func (pm *PoolManager) calculateFlashFee(amount *big.Int, fee uint24) *big.Int {
	if amount.Sign() <= 0 {
		return big.NewInt(0)
	}
	feeAmount := new(big.Int).Mul(amount, big.NewInt(int64(fee)))
	return feeAmount.Div(feeAmount, big.NewInt(1_000_000))
}

func (pm *PoolManager) transferERC20(stateDB StateDB, currency Currency, from, to common.Address, amount *big.Int) error {
	return pm.transferToken(stateDB, currency, from, to, amount)
}

// erc20BalanceSlot0 is the canonical Solidity storage slot for a `balanceOf`
// mapping declared as the FIRST state variable (slot 0):
// keccak256(abi.encode(holder, uint256(0))). This is the layout emitted by
// OpenZeppelin ERC20 and the Lux-canonical LUSD/LETH tokens. It is NOT a guess
// for arbitrary third-party tokens — a token whose balance mapping is not at
// slot 0 must settle through the d-chain atomic import/export, never a poke.
func erc20BalanceSlot0(holder common.Address) common.Hash {
	key := make([]byte, 64)
	copy(key[12:32], holder.Bytes()) // mapping key: left-padded address
	// slot 0: key[32:64] left as zero.
	return common.BytesToHash(crypto.Keccak256(key))
}

// transferToken settles a single currency leg on the C-Chain.
//
// Two — and only two — paths exist (decomplect: one home per asset class):
//   - Native LUX (address(0)): move account balance directly.
//   - C-resident ERC-20 using the canonical slot-0 balanceOf layout: adjust the
//     two holders' balance slots with full sufficiency checks.
//
// The previous code poked a single HARDCODED slot for EVERY token, which
// silently corrupted state for any token whose balanceOf was not at that magic
// slot and bypassed allowances entirely (RED H3/C2). That magic constant is
// removed: ERC-20 settlement is restricted to the documented standard layout,
// and the maker/taker proceeds for D-chain-canonical or non-standard assets are
// conserved by the d-chain atomic import/export + fill_attestation channel, not
// by a C-Chain storage write.
func (pm *PoolManager) transferToken(stateDB StateDB, currency Currency, from, to common.Address, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return nil
	}
	if currency.IsNative() {
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

	// C-resident ERC-20, canonical slot-0 balanceOf layout.
	token := currency.Address
	fromSlot := erc20BalanceSlot0(from)
	toSlot := erc20BalanceSlot0(to)
	fromBal := new(big.Int).SetBytes(stateDB.GetState(token, fromSlot).Bytes())
	if fromBal.Cmp(amount) < 0 {
		return fmt.Errorf("%w: ERC20 %s balance %s < transfer %s", ErrInsufficientBalance, token.Hex(), fromBal, amount)
	}
	toBal := new(big.Int).SetBytes(stateDB.GetState(token, toSlot).Bytes())
	newFrom := new(big.Int).Sub(fromBal, amount)
	newTo := new(big.Int).Add(toBal, amount)

	// Conservation guard: the two legs must net to zero. A credit that does not
	// exactly match the debit (overflow, aliasing from==to) is refused rather
	// than minting or burning token supply.
	if from != to {
		if new(big.Int).Add(newFrom, newTo).Cmp(new(big.Int).Add(fromBal, toBal)) != 0 {
			return fmt.Errorf("%w: ERC20 %s settlement not conserving", ErrSettlementFailed, token.Hex())
		}
	}

	var fromHash common.Hash
	safeFillBytes(newFrom, fromHash[:])
	stateDB.SetState(token, fromSlot, fromHash)
	var toHash common.Hash
	safeFillBytes(newTo, toHash[:])
	stateDB.SetState(token, toSlot, toHash)
	return nil
}

func (pm *PoolManager) autoSettle(stateDB StateDB, caller common.Address, key PoolKey, delta BalanceDelta) error {
	if delta.Amount0.Sign() > 0 {
		if err := pm.transferToken(stateDB, key.Currency0, caller, poolManagerAddr, delta.Amount0); err != nil {
			return fmt.Errorf("%w: currency0 settlement: %v", ErrSettlementFailed, err)
		}
	} else if delta.Amount0.Sign() < 0 {
		if err := pm.transferToken(stateDB, key.Currency0, poolManagerAddr, caller, new(big.Int).Neg(delta.Amount0)); err != nil {
			return fmt.Errorf("%w: currency0 settlement: %v", ErrSettlementFailed, err)
		}
	}
	if delta.Amount1.Sign() > 0 {
		if err := pm.transferToken(stateDB, key.Currency1, caller, poolManagerAddr, delta.Amount1); err != nil {
			return fmt.Errorf("%w: currency1 settlement: %v", ErrSettlementFailed, err)
		}
	} else if delta.Amount1.Sign() < 0 {
		if err := pm.transferToken(stateDB, key.Currency1, poolManagerAddr, caller, new(big.Int).Neg(delta.Amount1)); err != nil {
			return fmt.Errorf("%w: currency1 settlement: %v", ErrSettlementFailed, err)
		}
	}
	return nil
}

func (pm *PoolManager) callHook(stateDB StateDB, hookAddr common.Address, flag HookFlags, args ...any) error {
	return nil
}

func safeFillBytes(v *big.Int, buf []byte) {
	if v == nil || v.Sign() < 0 {
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

func (pm *PoolManager) GetPool(stateDB StateDB, key PoolKey) (*Pool, error) {
	poolId := key.ID()
	pool := pm.getPool(stateDB, poolId)
	if !pool.IsInitialized() {
		return nil, ErrPoolNotInitialized
	}
	return pool, nil
}

func (pm *PoolManager) GetPosition(
	stateDB StateDB, key PoolKey, owner common.Address, tickLower, tickUpper int24, salt [32]byte,
) (*Position, error) {
	posKey := PositionKey(owner, tickLower, tickUpper, salt)
	pos := pm.getPosition(stateDB, posKey)
	return pos, nil
}

// calculateSwapOutput estimates the output for a given input without mutating state.
// Used by the router for best-path estimation. Delegates to engine.Quote.
//
// On the ZAP path the backend reads its own canonical pool, so the *Pool must
// be routed to a canonical poolId first; callers with a poolId/key in hand
// should use calculateSwapOutputRouted instead. This bare form is kept for the
// embedded engine and tests where the *Pool itself carries the state.
func (pm *PoolManager) calculateSwapOutput(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int {
	return pm.engine.Quote(pool, amountIn, zeroForOne)
}

// calculateSwapOutputRouted is the router's quote path. It resolves the cache
// PoolState for poolId (so the ZAP backend can be routed to its canonical pool)
// and then quotes. Embedded engine ignores the routing and quotes locally.
func (pm *PoolManager) calculateSwapOutputRouted(stateDB StateDB, key PoolKey, poolId [32]byte, amountIn *big.Int, zeroForOne bool) *big.Int {
	ps := pm.getPoolState(stateDB, poolId, key.TickSpacing, key.Fee)
	pm.routePool(poolId, ps)
	return pm.engine.Quote(ps.Pool, amountIn, zeroForOne)
}
