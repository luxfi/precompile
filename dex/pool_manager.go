// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
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
	swapBindPrefix      = []byte("swpb")
	modBindPrefix       = []byte("modb")
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
// uses it to derive the DURABLE idempotency key for a marketable order (Swap).
type txIdentified interface {
	TxHash() common.Hash
}

// swapBindKey derives the storage slot that records whether THIS swap has already
// settled against the d-chain book, and the committed BalanceDelta if so. The key
// is the consensus-deterministic tuple (txHash, poolId, swapParams) — the same
// value on every validator and across a restart — so the idempotency guard is
// DURABLE and consensus-shared, not a per-node in-memory cache (RED H1).
//
// txHash is the EVM transaction identity the host sets via SetTxContext (read
// through the txIdentified seam). It is folded together with the poolId and the
// marketable-order parameters so that a single EVM tx which calls swap multiple
// times (router / multicall) gets one slot per distinct (pool, order), while a
// re-execution / reorg-redo / retry of the SAME tx hits the same slot.
//
// ok=false means the StateDB cannot name the tx (e.g. a non-EVM caller); the
// caller then skips the durable guard for that call rather than colliding every
// unbound swap onto the zero-hash slot.
func swapBindKey(stateDB StateDB, poolId [32]byte, params SwapParams) (common.Hash, bool) {
	idr, ok := stateDB.(txIdentified)
	if !ok {
		return common.Hash{}, false
	}
	txHash := idr.TxHash()
	if txHash == (common.Hash{}) {
		return common.Hash{}, false
	}
	h := blake3.New()
	h.Write(txHash[:])
	h.Write(poolId[:])
	h.Write([]byte(swapParamsDigest(params)))
	var id [32]byte
	h.Digest().Read(id[:])
	return makeStorageKey(swapBindPrefix, id[:]), true
}

// swapParamsDigest serializes the marketable-order parameters that distinguish
// two swaps issued by the SAME tx against the SAME pool, so each gets its own
// durable slot. Encodes direction, |amountSpecified| sign+magnitude, and the
// price limit — the full input that determines the submit.
func swapParamsDigest(params SwapParams) string {
	var b [1 + 1 + 32 + 32]byte
	if params.ZeroForOne {
		b[0] = 1
	}
	if params.AmountSpecified != nil && params.AmountSpecified.Sign() < 0 {
		b[1] = 1 // sign bit: exact-input
	}
	if params.AmountSpecified != nil {
		new(big.Int).Abs(params.AmountSpecified).FillBytes(b[2:34])
	}
	if params.SqrtPriceLimitX96 != nil && params.SqrtPriceLimitX96.Sign() > 0 {
		params.SqrtPriceLimitX96.FillBytes(b[34:66])
	}
	return string(b[:])
}

// swapBindLayout: the binding occupies three slots distinguished by field suffix
// — a presence flag (so a genuine zero/zero delta still counts as settled), and
// the two signed delta words.
var (
	swapBindFlagSuffix = []byte("f")
	swapBindAmt0Suffix = []byte("0")
	swapBindAmt1Suffix = []byte("1")
)

// loadSwapBinding returns the committed BalanceDelta for bindKey if this swap has
// already settled (settled=true), reading straight from StateDB. A settled tx
// found here means the d-chain already matched this exact swap, so the caller
// MUST NOT submit again — it returns the recorded delta verbatim.
func loadSwapBinding(stateDB StateDB, bindKey common.Hash) (delta BalanceDelta, settled bool) {
	flag := stateDB.GetState(poolManagerAddr, deriveSlot(bindKey, swapBindFlagSuffix))
	if flag[31] != 1 {
		return ZeroBalanceDelta(), false
	}
	a0 := stateDB.GetState(poolManagerAddr, deriveSlot(bindKey, swapBindAmt0Suffix))
	a1 := stateDB.GetState(poolManagerAddr, deriveSlot(bindKey, swapBindAmt1Suffix))
	return NewBalanceDelta(slotToSigned(a0), slotToSigned(a1)), true
}

// storeSwapBinding durably records that bindKey's swap settled with delta, so a
// later re-execution of the same tx is served from StateDB instead of issuing a
// second clob_submit. The write reverts atomically with the tx if it later
// reverts (StateDB snapshot semantics), so an aborted swap leaves no binding —
// the same revert-safety the V6 pause/freeze move relies on.
func storeSwapBinding(stateDB StateDB, bindKey common.Hash, delta BalanceDelta) {
	stateDB.SetState(poolManagerAddr, deriveSlot(bindKey, swapBindAmt0Suffix), signedToSlot(delta.Amount0))
	stateDB.SetState(poolManagerAddr, deriveSlot(bindKey, swapBindAmt1Suffix), signedToSlot(delta.Amount1))
	var flag common.Hash
	flag[31] = 1
	stateDB.SetState(poolManagerAddr, deriveSlot(bindKey, swapBindFlagSuffix), flag)
}

// deriveSlot re-hashes a base key with a field suffix so the flag and the two
// delta words occupy distinct, collision-free slots under the same binding.
func deriveSlot(base common.Hash, suffix []byte) common.Hash {
	return makeStorageKey(swapBindPrefix, append(base[:], suffix...))
}

// signedToSlot encodes a signed *big.Int as a 32-byte two's-complement word —
// the int256 representation — so a NEGATIVE BalanceDelta leg (pool owes the user)
// round-trips exactly. safeFillBytes is unusable here: it zeroes negatives.
func signedToSlot(v *big.Int) common.Hash {
	var h common.Hash
	if v == nil || v.Sign() == 0 {
		return h
	}
	if v.Sign() > 0 {
		v.FillBytes(h[:])
		return h
	}
	// two's complement: 2^256 + v (v negative).
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	enc := new(big.Int).Add(mod, v)
	enc.FillBytes(h[:])
	return h
}

// slotToSigned decodes a 32-byte two's-complement word back to a signed
// *big.Int, inverting signedToSlot.
func slotToSigned(h common.Hash) *big.Int {
	v := new(big.Int).SetBytes(h[:])
	if v.Sign() == 0 {
		return v
	}
	// high bit set => negative: subtract 2^256.
	if h[0]&0x80 != 0 {
		mod := new(big.Int).Lsh(big.NewInt(1), 256)
		v.Sub(v, mod)
	}
	return v
}

// modifyBindKey is the ModifyLiquidity analog of swapBindKey (RED H1, same
// reasoning): a place/cancel is an IRREVERSIBLE clob_place/clob_cancel on the
// d-chain book, so the EVM's repeated executions of ONE modifyLiquidity tx
// (gas-estimate, mempool validate, block build, block verify) must issue the
// venue op EXACTLY ONCE. Without this, exec #1 rests the order on the venue and
// every re-exec gets "order rejected" off the now-occupied book, reverting the
// tx while the venue keeps the order — the C↔D split the swap path already
// closes. The key is the consensus-deterministic tuple (txHash, poolId,
// modifyParams): same on every validator, durable across restart, revert-safe
// (StateDB snapshot). ok=false for a non-EVM caller (no tx identity) — that
// caller skips the guard rather than colliding on the zero slot.
func modifyBindKey(stateDB StateDB, poolId [32]byte, params ModifyLiquidityParams) (common.Hash, bool) {
	idr, ok := stateDB.(txIdentified)
	if !ok {
		return common.Hash{}, false
	}
	txHash := idr.TxHash()
	if txHash == (common.Hash{}) {
		return common.Hash{}, false
	}
	h := blake3.New()
	h.Write(txHash[:])
	h.Write(poolId[:])
	h.Write([]byte(modifyParamsDigest(params)))
	var id [32]byte
	h.Digest().Read(id[:])
	return makeStorageKey(modBindPrefix, id[:]), true
}

// modifyParamsDigest serializes the position parameters that distinguish two
// modifyLiquidity calls issued by the SAME tx against the SAME pool (tick range,
// signed liquidity delta, salt) so each gets its own durable slot.
func modifyParamsDigest(p ModifyLiquidityParams) string {
	var b [4 + 4 + 1 + 32 + 32]byte
	binary.BigEndian.PutUint32(b[0:4], uint32(p.TickLower))
	binary.BigEndian.PutUint32(b[4:8], uint32(p.TickUpper))
	if p.LiquidityDelta != nil && p.LiquidityDelta.Sign() < 0 {
		b[8] = 1
	}
	if p.LiquidityDelta != nil {
		new(big.Int).Abs(p.LiquidityDelta).FillBytes(b[9:41])
	}
	copy(b[41:73], p.Salt[:])
	return string(b[:])
}

// loadModifyBinding / storeModifyBinding mirror loadSwapBinding / storeSwapBinding
// (same three-slot flag+amount0+amount1 layout, reusing deriveSlot's suffix
// scheme under modBindPrefix). A bound modifyLiquidity returns its recorded
// callerDelta verbatim on re-execution WITHOUT a second clob_place/clob_cancel.
func loadModifyBinding(stateDB StateDB, bindKey common.Hash) (delta BalanceDelta, settled bool) {
	flag := stateDB.GetState(poolManagerAddr, deriveModSlot(bindKey, swapBindFlagSuffix))
	if flag[31] != 1 {
		return ZeroBalanceDelta(), false
	}
	a0 := stateDB.GetState(poolManagerAddr, deriveModSlot(bindKey, swapBindAmt0Suffix))
	a1 := stateDB.GetState(poolManagerAddr, deriveModSlot(bindKey, swapBindAmt1Suffix))
	return NewBalanceDelta(slotToSigned(a0), slotToSigned(a1)), true
}

func storeModifyBinding(stateDB StateDB, bindKey common.Hash, delta BalanceDelta) {
	stateDB.SetState(poolManagerAddr, deriveModSlot(bindKey, swapBindAmt0Suffix), signedToSlot(delta.Amount0))
	stateDB.SetState(poolManagerAddr, deriveModSlot(bindKey, swapBindAmt1Suffix), signedToSlot(delta.Amount1))
	var flag common.Hash
	flag[31] = 1
	stateDB.SetState(poolManagerAddr, deriveModSlot(bindKey, swapBindFlagSuffix), flag)
}

func deriveModSlot(base common.Hash, suffix []byte) common.Hash {
	return makeStorageKey(modBindPrefix, append(base[:], suffix...))
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
	// Same revert-safety rule as getPool: the poolStates cache survives the EVM's
	// repeated executions of one tx, so a cached PoolState from a speculative
	// (later reverted) Initialize must NOT mask the StateDB truth. Gate the cache
	// on the pool's StateDB existence; a cached state for a pool StateDB no longer
	// has is stale and is rebuilt from the (StateDB-authoritative) getPool.
	sqrtPriceKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("sqrtPrice")...))
	committed := stateDB.GetState(poolManagerAddr, sqrtPriceKey) != (common.Hash{})
	if ps, ok := pm.poolStates[poolId]; ok {
		if committed {
			return ps
		}
		delete(pm.poolStates, poolId)
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

	// Replay-idempotency (RED H1): a marketable order is an IRREVERSIBLE submit to
	// the d-chain book. Re-execution / reorg-redo / retry of the same EVM tx, OR a
	// node restart that replays the block, MUST map to EXACTLY ONE match — never a
	// double-fill. The guard lives in StateDB (durable on disk, identical on every
	// validator replaying the same ordered block, and reverted atomically with the
	// tx) rather than in process memory: an in-memory cache cannot survive a
	// restart and each validator keeps its own copy, so it fixes neither the
	// restart re-submit nor the N-fold per-validator fan-out. This mirrors the V6
	// pause/freeze move from in-process flags to StateDB.
	bindKey, bound := swapBindKey(stateDB, poolId, params)
	if bound {
		if prior, settled := loadSwapBinding(stateDB, bindKey); settled {
			return prior, nil
		}
	}

	if key.Hooks != (common.Address{}) {
		if err := pm.callHook(stateDB, key.Hooks, HookBeforeSwap, key, params, hookData); err != nil {
			return ZeroBalanceDelta(), err
		}
	}

	pm.routePool(poolId, ps)
	delta, err := pm.engine.Swap(ps, params)
	if err != nil {
		return ZeroBalanceDelta(), err
	}

	// Persist the committed delta under the durable idempotency key BEFORE
	// returning, so any later replay of this tx is served from StateDB instead of
	// re-submitting to the book.
	if bound {
		storeSwapBinding(stateDB, bindKey, delta)
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

	// Replay-idempotency (RED H1), mirroring Swap: a place/cancel is an
	// irreversible venue op, so the EVM's repeated executions of one tx must issue
	// it exactly once. A bound modify returns its recorded delta without a second
	// clob_place/clob_cancel.
	bindKey, bound := modifyBindKey(stateDB, poolId, params)
	if bound {
		if prior, settled := loadModifyBinding(stateDB, bindKey); settled {
			return prior, ZeroBalanceDelta(), nil
		}
	}

	pm.routePool(poolId, ps)
	callerDelta, feesAccrued, err := pm.engine.ModifyLiquidity(ps, caller, params)
	if err != nil {
		return ZeroBalanceDelta(), ZeroBalanceDelta(), err
	}
	if bound {
		storeModifyBinding(stateDB, bindKey, callerDelta)
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
	// StateDB is the revert-safe authority for pool EXISTENCE: a pool's sqrtPrice
	// slot is zero unless an Initialize committed it, and it reverts to zero with
	// any tx that rolls back. The process-memory cache (pm.pools) does NOT roll
	// back, so trusting it first leaks state across the EVM's multiple
	// (estimate/build/verify) executions of one tx — a speculative Initialize
	// would populate the cache, then every re-execution sees "already
	// initialized" off the stale cache and reverts. So consult StateDB FIRST;
	// only serve the cached *Pool when StateDB confirms the pool still exists
	// (matches the StateDB-authoritative discipline already used for
	// pause/freeze — see isDEXPaused, RED V6). A cache entry contradicted by
	// StateDB is stale and dropped.
	sqrtPriceKey := makeStorageKey(poolStatePrefix, append(poolId[:], []byte("sqrtPrice")...))
	sqrtPriceHash := stateDB.GetState(poolManagerAddr, sqrtPriceKey)
	committed := sqrtPriceHash != (common.Hash{})
	if pool, ok := pm.pools[poolId]; ok {
		if committed {
			return pool
		}
		delete(pm.pools, poolId)
	}
	pool := NewPool()

	if committed {
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

// transferToken moves a single NATIVE-LUX (address(0)) currency leg on C-Chain.
//
// It is NATIVE-ONLY by design (the CLOB custody model — see settleNativeLegs).
// The former ERC-20 slot-0 poke is REMOVED: a non-native asset's value lives in
// the D-Chain (deposited via the proxy's atomic import, settled in the D-Chain
// ledger), never in a C-Chain storage write. A non-native currency reaching here
// is a routing bug, not a settlement path — refused explicitly rather than
// silently poking a storage slot (the RED H3/C2 hazard). Native LUX moves as
// account balance with a full sufficiency check.
func (pm *PoolManager) transferToken(stateDB StateDB, currency Currency, from, to common.Address, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return nil
	}
	if !currency.IsNative() {
		// A non-native leg must settle in the D-Chain (deposit/withdraw + ledger),
		// never as a C-Chain ERC-20 storage poke.
		return fmt.Errorf("%w: non-native currency %s settles in the D-Chain, not on C-Chain", ErrSettlementFailed, currency.Address.Hex())
	}
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

// settleNativeLegs moves ONLY the native-LUX (address(0)) leg of a V4
// BalanceDelta on C-Chain. It is the corrected replacement for the former
// "autoSettle", which poked C-Chain ERC-20 balance slots for BOTH legs.
//
// WHY THIS IS RIGHT (the CLOB custody model): the D-Chain is a central-limit
// order book where the money LIVES IN THE BOOK. A token's value is DEPOSITED into
// the D-Chain (atomic shared-memory ImportTx via the chains/dexvm proxy), lives
// as the account's available D-Chain balance the book draws from, and is settled
// ENTIRELY inside D-Chain consensus when an order fills (the maker's locked base
// moves to the taker and the taker's locked quote moves to the maker — see
// dchain.settleFills). A swap therefore has NO two-leg C-Chain ERC-20 settlement:
// the token leg is already on the D-Chain. The previous autoSettle tried to
// transfer the token ON C-Chain (caller -> poolManager), which (a) required the
// caller to hold the C-Chain ERC-20 it had actually deposited into the D-Chain
// (the "ERC20 balance 0 < transfer N" e2e failure) and (b) poked a hardcoded
// storage slot that corrupted any non-standard token (RED H3/C2).
//
// The ONLY asset that genuinely settles on C-Chain is NATIVE LUX (address(0)):
// it is C-Chain account balance, and the V4 facade backs resting native
// liquidity with real native value held by the PoolManager (the e2e proved the
// PoolManager holding 17 wei behind 17 resting asks). A non-native leg is a
// D-Chain-canonical asset and is intentionally NOT moved here — its value
// conservation is the D-Chain ledger's job + the proxy's atomic import/export.
func (pm *PoolManager) settleNativeLegs(stateDB StateDB, caller common.Address, key PoolKey, delta BalanceDelta) error {
	if key.Currency0.IsNative() {
		if err := pm.settleNativeLeg(stateDB, caller, delta.Amount0); err != nil {
			return fmt.Errorf("%w: currency0 native settlement: %v", ErrSettlementFailed, err)
		}
	}
	if key.Currency1.IsNative() {
		if err := pm.settleNativeLeg(stateDB, caller, delta.Amount1); err != nil {
			return fmt.Errorf("%w: currency1 native settlement: %v", ErrSettlementFailed, err)
		}
	}
	return nil
}

// settleNativeLeg moves one native-LUX leg: a positive delta (caller owes the
// pool) debits the caller and credits the PoolManager; a negative delta (pool
// owes the caller) does the reverse. Zero is a no-op.
func (pm *PoolManager) settleNativeLeg(stateDB StateDB, caller common.Address, amount *big.Int) error {
	switch amount.Sign() {
	case 1:
		return pm.transferToken(stateDB, NativeCurrency, caller, poolManagerAddr, amount)
	case -1:
		return pm.transferToken(stateDB, NativeCurrency, poolManagerAddr, caller, new(big.Int).Neg(amount))
	default:
		return nil
	}
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
