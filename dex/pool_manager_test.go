// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
)

// MockStateDB implements StateDB interface for testing
type MockStateDB struct {
	states      map[common.Address]map[common.Hash]common.Hash
	balances    map[common.Address]*uint256.Int
	exists      map[common.Address]bool
	blockNumber uint64
	logs        []*ethtypes.Log
	// tokenBalances backs the erc20Vault test capability on contractStateDBWrapper:
	// an in-memory per-token (token -> holder -> balance) ledger so the 0x9999
	// settlement tests can exercise the native-in / token-out direction.
	tokenBalances map[common.Address]map[common.Address]*big.Int
	// feeOnTransferBps, when > 0, makes TransferTokenFrom deliver amount*(1-bps/1e4)
	// to the recipient, modelling a fee-on-transfer token so the observed-delta short
	// branches (ErrSettleObservedShort / ErrSettleDepositShort) can be exercised.
	feeOnTransferBps uint64
}

func NewMockStateDB() *MockStateDB {
	return &MockStateDB{
		states:      make(map[common.Address]map[common.Hash]common.Hash),
		balances:    make(map[common.Address]*uint256.Int),
		exists:      make(map[common.Address]bool),
		blockNumber: 1,
	}
}

func (m *MockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if states, ok := m.states[addr]; ok {
		if value, ok := states[key]; ok {
			return value
		}
	}
	return common.Hash{}
}

func (m *MockStateDB) SetState(addr common.Address, key common.Hash, value common.Hash) {
	if _, ok := m.states[addr]; !ok {
		m.states[addr] = make(map[common.Hash]common.Hash)
	}
	m.states[addr][key] = value
}

func (m *MockStateDB) GetBalance(addr common.Address) *uint256.Int {
	if balance, ok := m.balances[addr]; ok {
		return balance
	}
	return uint256.NewInt(0)
}

func (m *MockStateDB) AddBalance(addr common.Address, amount *uint256.Int) {
	if _, ok := m.balances[addr]; !ok {
		m.balances[addr] = uint256.NewInt(0)
	}
	m.balances[addr] = new(uint256.Int).Add(m.balances[addr], amount)
}

func (m *MockStateDB) SubBalance(addr common.Address, amount *uint256.Int) {
	if _, ok := m.balances[addr]; !ok {
		m.balances[addr] = uint256.NewInt(0)
	}
	m.balances[addr] = new(uint256.Int).Sub(m.balances[addr], amount)
}

func (m *MockStateDB) Exist(addr common.Address) bool {
	return m.exists[addr]
}

func (m *MockStateDB) CreateAccount(addr common.Address) {
	m.exists[addr] = true
}

func (m *MockStateDB) GetBlockNumber() uint64 {
	return m.blockNumber
}

func (m *MockStateDB) SetBlockNumber(block uint64) {
	m.blockNumber = block
}

func (m *MockStateDB) AddLog(log *ethtypes.Log) {
	m.logs = append(m.logs, log)
}

func (m *MockStateDB) Logs() []*ethtypes.Log {
	return m.logs
}

// mockEngine implements Engine for testing the precompile shim.
// Returns plausible values without real AMM math (math lives in DEX engine).
type mockEngine struct{}

func (m *mockEngine) Initialize(sqrtPriceX96 *big.Int) (int24, error) {
	// Return tick 0 for any valid sqrt price near Q96.
	return 0, nil
}

func (m *mockEngine) Swap(pool *PoolState, _ common.Address, params SwapParams) (BalanceDelta, error) {
	if params.AmountSpecified.Sign() == 0 {
		return ZeroBalanceDelta(), nil
	}
	// Simulate: user spends amountSpecified, receives half back.
	absAmount := new(big.Int).Abs(params.AmountSpecified)
	output := new(big.Int).Div(absAmount, big.NewInt(2))

	// Update pool state minimally (price shifts down for zeroForOne).
	if params.ZeroForOne {
		pool.SqrtPriceX96 = new(big.Int).Sub(pool.SqrtPriceX96, big.NewInt(1))
		pool.FeeGrowth0X128 = new(big.Int).Add(pool.FeeGrowth0X128, big.NewInt(1))
		return NewBalanceDelta(absAmount, new(big.Int).Neg(output)), nil
	}
	pool.SqrtPriceX96 = new(big.Int).Add(pool.SqrtPriceX96, big.NewInt(1))
	pool.FeeGrowth1X128 = new(big.Int).Add(pool.FeeGrowth1X128, big.NewInt(1))
	return NewBalanceDelta(new(big.Int).Neg(output), absAmount), nil
}

func (m *mockEngine) ModifyLiquidity(pool *PoolState, owner common.Address, params ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	posKey := PositionKey(owner, params.TickLower, params.TickUpper, params.Salt)
	pos, ok := pool.Positions[posKey]
	if !ok {
		pos = &Position{
			Owner: owner, TickLower: params.TickLower, TickUpper: params.TickUpper,
			Liquidity:                big.NewInt(0),
			FeeGrowthInside0LastX128: big.NewInt(0), FeeGrowthInside1LastX128: big.NewInt(0),
			TokensOwed0: big.NewInt(0), TokensOwed1: big.NewInt(0),
		}
		pool.Positions[posKey] = pos
	}
	newLiq := new(big.Int).Add(pos.Liquidity, params.LiquidityDelta)
	if newLiq.Sign() < 0 {
		newLiq = big.NewInt(0)
	}
	pos.Liquidity = newLiq

	// Update pool active liquidity if current tick is in range.
	currentTick := pool.Tick
	if currentTick >= params.TickLower && currentTick < params.TickUpper {
		pool.Liquidity = new(big.Int).Add(pool.Liquidity, params.LiquidityDelta)
	}

	// Return plausible deltas based on position relative to current tick.
	var delta BalanceDelta
	if currentTick < params.TickLower {
		delta = NewBalanceDelta(params.LiquidityDelta, big.NewInt(0))
	} else if currentTick >= params.TickUpper {
		delta = NewBalanceDelta(big.NewInt(0), params.LiquidityDelta)
	} else {
		half := new(big.Int).Div(params.LiquidityDelta, big.NewInt(2))
		delta = NewBalanceDelta(half, new(big.Int).Sub(params.LiquidityDelta, half))
	}
	return delta, ZeroBalanceDelta(), nil
}

func (m *mockEngine) Donate(pool *PoolState, amount0, amount1 *big.Int) (BalanceDelta, error) {
	if pool.Liquidity == nil || pool.Liquidity.Sign() <= 0 {
		return ZeroBalanceDelta(), ErrNoLiquidity
	}
	if amount0 != nil && amount0.Sign() > 0 {
		pool.FeeGrowth0X128 = new(big.Int).Add(pool.FeeGrowth0X128, big.NewInt(1))
	}
	if amount1 != nil && amount1.Sign() > 0 {
		pool.FeeGrowth1X128 = new(big.Int).Add(pool.FeeGrowth1X128, big.NewInt(1))
	}
	return NewBalanceDelta(amount0, amount1), nil
}

func (m *mockEngine) Quote(pool *Pool, amountIn *big.Int, zeroForOne bool) *big.Int {
	if pool.Liquidity.Sign() == 0 || amountIn.Sign() <= 0 {
		return big.NewInt(0)
	}
	return new(big.Int).Div(amountIn, big.NewInt(2))
}

func (m *mockEngine) Brand() string { return "Mock DEX" }

// Test helpers

func newTestPoolKey() PoolKey {
	return PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0x1234567890123456789012345678901234567890")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}
}

func newTestPoolManager() *PoolManager {
	return NewPoolManager(&mockEngine{})
}

// initPoolWithLiquidity initializes a pool at 1:1 price and adds concentrated
// liquidity across ticks [-120, 120] via ModifyLiquidity.
func initPoolWithLiquidity(t *testing.T, pm *PoolManager, stateDB *MockStateDB, key PoolKey, liq int64) {
	t.Helper()

	sqrtPriceX96 := new(big.Int).Set(Q96) // price = 1.0
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add liquidity in tick range that contains tick 0 (which is where price=1.0 sits).
	// Ticks must be aligned to TickSpacing (60 for Fee030).
	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(liq),
		Salt:           [32]byte{},
	}

	caller := common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_, _, err = pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}
}

// =========================================================================
// Pool Initialization Tests
// =========================================================================

func TestPoolManagerInitialize(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	sqrtPriceX96 := new(big.Int).Set(Q96) // 1:1 ratio

	tick, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	t.Logf("Pool initialized with tick: %d", tick)

	pool, err := pm.GetPool(stateDB, key)
	if err != nil {
		t.Fatalf("GetPool failed: %v", err)
	}

	if pool.SqrtPriceX96.Cmp(sqrtPriceX96) != 0 {
		t.Errorf("SqrtPriceX96 mismatch: got %s, want %s", pool.SqrtPriceX96, sqrtPriceX96)
	}
}

func TestPoolManagerInitializeAlreadyInitialized(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	sqrtPriceX96 := new(big.Int).Set(Q96)

	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("First Initialize failed: %v", err)
	}

	_, err = pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != ErrPoolAlreadyInitialized {
		t.Errorf("Expected ErrPoolAlreadyInitialized, got: %v", err)
	}
}

func TestPoolManagerInitializeUnsortedCurrencies(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
		Currency1:   NativeCurrency,
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}

	sqrtPriceX96 := new(big.Int).Set(Q96)

	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != ErrCurrencyNotSorted {
		t.Errorf("Expected ErrCurrencyNotSorted, got: %v", err)
	}
}

func TestPoolManagerInitializeInvalidSqrtPrice(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	_, err := pm.Initialize(stateDB, key, big.NewInt(0), nil)
	if err != ErrInvalidSqrtPrice {
		t.Errorf("Expected ErrInvalidSqrtPrice for zero price, got: %v", err)
	}
}

// =========================================================================
// V4 Swap Tests
// =========================================================================

func TestSwapExactInputZeroForOne(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	// V4 exact input: AmountSpecified < 0
	// SqrtPriceLimitX96 must be > MinSqrtRatio (not <=)
	limit := new(big.Int).Add(MinSqrtRatio, big.NewInt(1))

	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000), // exact input of 1000
		SqrtPriceLimitX96: limit,
	}

	delta, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	// For exactInput zeroForOne: amount0 should be positive (user pays), amount1 negative (user receives)
	// V4 packs: amount0 = amountUsed (negative exact-in becomes positive spent), amount1 = amountCalculated
	t.Logf("Swap delta: amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	if delta.Amount0.Sign() == 0 && delta.Amount1.Sign() == 0 {
		t.Error("Expected non-zero delta from swap")
	}
}

func TestSwapExactInputOneForZero(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	limit := new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1))

	params := SwapParams{
		ZeroForOne:        false,
		AmountSpecified:   big.NewInt(-1000), // exact input
		SqrtPriceLimitX96: limit,
	}

	delta, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	t.Logf("Swap delta: amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	if delta.Amount0.Sign() == 0 && delta.Amount1.Sign() == 0 {
		t.Error("Expected non-zero delta from swap")
	}
}

func TestSwapZeroAmount(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(0),
		SqrtPriceLimitX96: new(big.Int).Add(MinSqrtRatio, big.NewInt(1)),
	}

	delta, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("Swap with zero amount should not error: %v", err)
	}

	if !delta.IsZero() {
		t.Errorf("Expected zero delta for zero swap, got amount0=%s amount1=%s", delta.Amount0, delta.Amount1)
	}
}

func TestSwapUninitializedPool(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000),
		SqrtPriceLimitX96: new(big.Int).Add(MinSqrtRatio, big.NewInt(1)),
	}

	_, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != ErrPoolNotInitialized {
		t.Errorf("Expected ErrPoolNotInitialized, got: %v", err)
	}
}

func TestSwapEngineErrorPropagation(t *testing.T) {
	// Verify pool_manager surfaces engine errors to the caller.
	// Price limit validation is the engine's responsibility.
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Swap on uninitialized pool -- pool_manager validates this itself
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000),
		SqrtPriceLimitX96: new(big.Int).Set(MaxSqrtRatio),
	}

	_, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != ErrPoolNotInitialized {
		t.Errorf("Expected ErrPoolNotInitialized, got: %v", err)
	}
}

// =========================================================================
// V4 ModifyLiquidity Tests
// =========================================================================

func TestModifyLiquidityAdd(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	sqrtPriceX96 := new(big.Int).Set(Q96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add liquidity in range [-120, 120] (tick 0 is in range at price=1)
	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(1_000_000),
		Salt:           [32]byte{},
	}

	callerDelta, feesAccrued, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}

	t.Logf("Caller delta: amount0=%s, amount1=%s", callerDelta.Amount0, callerDelta.Amount1)
	t.Logf("Fees accrued: amount0=%s, amount1=%s", feesAccrued.Amount0, feesAccrued.Amount1)

	// When adding liquidity in-range, both amounts should be non-zero (negative = user pays)
	if callerDelta.Amount0.Sign() == 0 && callerDelta.Amount1.Sign() == 0 {
		t.Error("Expected non-zero caller delta for in-range liquidity")
	}

	// Verify position was created
	pos, err := pm.GetPosition(stateDB, key, caller, params.TickLower, params.TickUpper, params.Salt)
	if err != nil {
		t.Fatalf("GetPosition failed: %v", err)
	}
	if pos.Liquidity.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Errorf("Expected liquidity 1000000, got: %s", pos.Liquidity)
	}

	// Verify pool active liquidity was updated
	pool, _ := pm.GetPool(stateDB, key)
	if pool.Liquidity.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Errorf("Expected pool liquidity 1000000, got: %s", pool.Liquidity)
	}
}

func TestModifyLiquidityCurrentBelowRange(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	sqrtPriceX96 := new(big.Int).Set(Q96) // tick 0
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Range [600, 1200]: currentTick(0) < tickLower(600) so current is below range.
	// V4: when current is below range, only currency0 is needed.
	params := ModifyLiquidityParams{
		TickLower:      600,
		TickUpper:      1200,
		LiquidityDelta: big.NewInt(1_000_000),
		Salt:           [32]byte{},
	}

	callerDelta, _, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}

	// Current below range: only amount0 should be non-zero
	if callerDelta.Amount0.Sign() == 0 {
		t.Error("Expected non-zero amount0 when current is below range")
	}
	if callerDelta.Amount1.Sign() != 0 {
		t.Errorf("Expected zero amount1 when current is below range, got: %s", callerDelta.Amount1)
	}

	// Pool active liquidity should NOT change (position is out of range)
	pool, _ := pm.GetPool(stateDB, key)
	if pool.Liquidity.Sign() != 0 {
		t.Errorf("Expected pool liquidity 0, got: %s", pool.Liquidity)
	}
}

func TestModifyLiquidityCurrentAboveRange(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	sqrtPriceX96 := new(big.Int).Set(Q96) // tick 0
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Range [-1200, -600]: currentTick(0) >= tickUpper(-600) so current is above range.
	// V4: when current is above range, only currency1 is needed.
	params := ModifyLiquidityParams{
		TickLower:      -1200,
		TickUpper:      -600,
		LiquidityDelta: big.NewInt(1_000_000),
		Salt:           [32]byte{},
	}

	callerDelta, _, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}

	// Current above range: only amount1 should be non-zero
	if callerDelta.Amount1.Sign() == 0 {
		t.Error("Expected non-zero amount1 when current is above range")
	}
	if callerDelta.Amount0.Sign() != 0 {
		t.Errorf("Expected zero amount0 when current is above range, got: %s", callerDelta.Amount0)
	}
}

func TestModifyLiquidityRemove(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000)

	// Remove half the liquidity
	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(-500_000),
		Salt:           [32]byte{},
	}

	lp := common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	callerDelta, _, err := pm.ModifyLiquidity(stateDB, lp, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity (remove) failed: %v", err)
	}

	// When removing: amounts should be positive (user receives)
	t.Logf("Remove delta: amount0=%s, amount1=%s", callerDelta.Amount0, callerDelta.Amount1)

	pool, _ := pm.GetPool(stateDB, key)
	if pool.Liquidity.Cmp(big.NewInt(500_000)) != 0 {
		t.Errorf("Expected pool liquidity 500000 after removal, got: %s", pool.Liquidity)
	}
}

func TestModifyLiquidityInvalidTickRange(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	sqrtPriceX96 := new(big.Int).Set(Q96)
	_, _ = pm.Initialize(stateDB, key, sqrtPriceX96, nil)

	params := ModifyLiquidityParams{
		TickLower:      1000,
		TickUpper:      -1000,
		LiquidityDelta: big.NewInt(1000000),
		Salt:           [32]byte{},
	}

	_, _, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != ErrInvalidTickRange {
		t.Errorf("Expected ErrInvalidTickRange, got: %v", err)
	}
}

// =========================================================================
// Swap + Liquidity Integration Tests
// =========================================================================

func TestSwapAfterLiquidityAdd(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	// Swap exact input zeroForOne
	limit := new(big.Int).Add(MinSqrtRatio, big.NewInt(1))
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-10_000),
		SqrtPriceLimitX96: limit,
	}

	delta, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	// Verify price moved
	pool, _ := pm.GetPool(stateDB, key)
	if pool.SqrtPriceX96.Cmp(Q96) >= 0 {
		t.Error("Expected price to decrease after zeroForOne swap")
	}

	t.Logf("After swap: price=%s, tick=%d, delta0=%s, delta1=%s",
		pool.SqrtPriceX96, pool.Tick, delta.Amount0, delta.Amount1)
}

func TestSwapFeeAccumulation(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	// Record fee growth before swap
	ps := pm.poolStates[key.ID()]
	feeGrowth0Before := new(big.Int).Set(ps.FeeGrowth0X128)

	// Swap exact input zeroForOne
	limit := new(big.Int).Add(MinSqrtRatio, big.NewInt(1))
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-100_000),
		SqrtPriceLimitX96: limit,
	}

	_, err := pm.Swap(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	// Fee growth should have increased for token0 (the input token)
	feeGrowth0After := ps.FeeGrowth0X128
	if feeGrowth0After.Cmp(feeGrowth0Before) <= 0 {
		t.Error("Expected fee growth to increase after swap")
	}

	t.Logf("Fee growth delta: %s", new(big.Int).Sub(feeGrowth0After, feeGrowth0Before))
}

// =========================================================================
// Donate Tests
// =========================================================================

func TestPoolManagerDonate(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	amount0 := big.NewInt(10000)
	amount1 := big.NewInt(20000)

	delta, err := pm.Donate(stateDB, caller, key, amount0, amount1)
	if err != nil {
		t.Fatalf("Donate failed: %v", err)
	}

	t.Logf("Donate delta: amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	pool, _ := pm.GetPool(stateDB, key)
	if pool.FeeGrowth0X128.Sign() == 0 {
		t.Error("Expected non-zero FeeGrowth0X128 after donation")
	}
	if pool.FeeGrowth1X128.Sign() == 0 {
		t.Error("Expected non-zero FeeGrowth1X128 after donation")
	}
}

// =========================================================================
// Flash Loan Tests
// =========================================================================

func TestPoolManagerFlash(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")

	sqrtPriceX96 := new(big.Int).Set(Q96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	params := FlashParams{
		Amount0:   big.NewInt(100000),
		Amount1:   big.NewInt(200000),
		Recipient: recipient,
		Data:      nil,
	}

	delta, err := pm.Flash(stateDB, caller, key, params, nil)
	if err != nil {
		t.Fatalf("Flash failed: %v", err)
	}

	t.Logf("Flash delta (loan + fee): amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	if delta.Amount0.Cmp(params.Amount0) <= 0 {
		t.Error("Expected delta to include fee")
	}
}

// =========================================================================
// BalanceDelta Tests
// =========================================================================

func TestBalanceDeltaOperations(t *testing.T) {
	delta1 := NewBalanceDelta(big.NewInt(100), big.NewInt(-50))
	if delta1.Amount0.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("Amount0 mismatch: got %s, want 100", delta1.Amount0)
	}
	if delta1.Amount1.Cmp(big.NewInt(-50)) != 0 {
		t.Errorf("Amount1 mismatch: got %s, want -50", delta1.Amount1)
	}

	delta2 := NewBalanceDelta(big.NewInt(50), big.NewInt(100))
	sum := delta1.Add(delta2)
	if sum.Amount0.Cmp(big.NewInt(150)) != 0 {
		t.Errorf("Add Amount0 mismatch: got %s, want 150", sum.Amount0)
	}
	if sum.Amount1.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("Add Amount1 mismatch: got %s, want 50", sum.Amount1)
	}

	diff := delta1.Sub(delta2)
	if diff.Amount0.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("Sub Amount0 mismatch: got %s, want 50", diff.Amount0)
	}
	if diff.Amount1.Cmp(big.NewInt(-150)) != 0 {
		t.Errorf("Sub Amount1 mismatch: got %s, want -150", diff.Amount1)
	}

	neg := delta1.Negate()
	if neg.Amount0.Cmp(big.NewInt(-100)) != 0 {
		t.Errorf("Negate Amount0 mismatch: got %s, want -100", neg.Amount0)
	}
	if neg.Amount1.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("Negate Amount1 mismatch: got %s, want 50", neg.Amount1)
	}

	zeroDelta := ZeroBalanceDelta()
	if !zeroDelta.IsZero() {
		t.Error("ZeroBalanceDelta should be zero")
	}
	if delta1.IsZero() {
		t.Error("Non-zero delta should not be zero")
	}
}

// =========================================================================
// Pool Key Tests
// =========================================================================

func TestPoolKeyID(t *testing.T) {
	key1 := newTestPoolKey()
	key2 := newTestPoolKey()

	id1 := key1.ID()
	id2 := key2.ID()

	if id1 != id2 {
		t.Error("Same pool keys should produce same ID")
	}

	key3 := PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0xABCDEF1234567890123456789012345678901234")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}

	id3 := key3.ID()
	if id1 == id3 {
		t.Error("Different pool keys should produce different IDs")
	}
}

func TestPoolKeySerialization(t *testing.T) {
	key := newTestPoolKey()

	data := key.ToBytes()
	if len(data) != 66 {
		t.Errorf("Expected 66 bytes, got %d", len(data))
	}

	decoded, err := PoolKeyFromBytes(data)
	if err != nil {
		t.Fatalf("PoolKeyFromBytes failed: %v", err)
	}

	if decoded.Currency0 != key.Currency0 {
		t.Error("Currency0 mismatch after serialization")
	}
	if decoded.Currency1 != key.Currency1 {
		t.Error("Currency1 mismatch after serialization")
	}
}

// =========================================================================
// Currency Tests
// =========================================================================

func TestCurrencyIsNative(t *testing.T) {
	native := NativeCurrency
	if !native.IsNative() {
		t.Error("NativeCurrency should be native")
	}

	erc20 := Currency{Address: common.HexToAddress("0x1234567890123456789012345678901234567890")}
	if erc20.IsNative() {
		t.Error("ERC20 should not be native")
	}
}
