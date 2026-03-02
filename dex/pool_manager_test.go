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

// Test helper functions
func newTestPoolKey() PoolKey {
	return PoolKey{
		Currency0:   NativeCurrency, // LUX
		Currency1:   Currency{Address: common.HexToAddress("0x1234567890123456789012345678901234567890")},
		Fee:         Fee030, // 0.30%
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}
}

func newTestPoolManager() *PoolManager {
	return NewPoolManager()
}

// =========================================================================
// Pool Initialization Tests
// =========================================================================

func TestPoolManagerInitialize(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	// Initial sqrt price (1:1 ratio)
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)

	tick, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	t.Logf("Pool initialized with tick: %d", tick)

	// Verify pool was created
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

	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)

	// First initialization should succeed
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("First Initialize failed: %v", err)
	}

	// Second initialization should fail
	_, err = pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != ErrPoolAlreadyInitialized {
		t.Errorf("Expected ErrPoolAlreadyInitialized, got: %v", err)
	}
}

func TestPoolManagerInitializeUnsortedCurrencies(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	// Create key with currencies in wrong order
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
		Currency1:   NativeCurrency, // Should be currency0
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}

	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)

	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != ErrCurrencyNotSorted {
		t.Errorf("Expected ErrCurrencyNotSorted, got: %v", err)
	}
}

func TestPoolManagerInitializeInvalidSqrtPrice(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	// Test with price below minimum
	_, err := pm.Initialize(stateDB, key, big.NewInt(0), nil)
	if err != ErrInvalidSqrtPrice {
		t.Errorf("Expected ErrInvalidSqrtPrice for zero price, got: %v", err)
	}
}

// =========================================================================
// Flash Accounting Tests
// =========================================================================

func TestPoolManagerLock(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Lock should succeed
	_, err := pm.Lock(stateDB, caller, nil)
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Verify no deltas remain
	delta := pm.GetDelta(caller, NativeCurrency)
	if delta.Sign() != 0 {
		t.Errorf("Expected zero delta, got: %s", delta)
	}
}

func TestPoolManagerSettlement(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize caller balance
	stateDB.CreateAccount(caller)
	stateDB.AddBalance(caller, uint256.NewInt(1000000))

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Create a positive delta (caller owes pool)
	pm.updateDelta(caller, NativeCurrency, big.NewInt(1000))

	// Settle the delta
	err := pm.Settle(stateDB, NativeCurrency, big.NewInt(1000))
	if err != nil {
		t.Fatalf("Settle failed: %v", err)
	}

	// Verify delta is now zero
	delta := pm.GetDelta(caller, NativeCurrency)
	if delta.Sign() != 0 {
		t.Errorf("Expected zero delta after settlement, got: %s", delta)
	}
}

// =========================================================================
// Swap Tests
// =========================================================================

func TestPoolManagerSwap(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add liquidity first (simulate)
	pool := pm.pools[key.ID()]
	pool.Liquidity = big.NewInt(1000000000) // 1B liquidity

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Execute swap
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000), // Exact input
		SqrtPriceLimitX96: MinSqrtRatio,
	}

	delta, err := pm.Swap(stateDB, key, params, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	t.Logf("Swap delta: amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	// Verify delta reflects the swap
	if delta.Amount0.Sign() == 0 && delta.Amount1.Sign() == 0 {
		t.Error("Expected non-zero delta from swap")
	}
}

func TestPoolManagerSwapWithoutLock(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Try to swap without lock context
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: MinSqrtRatio,
	}

	_, err = pm.Swap(stateDB, key, params, nil)
	if err != ErrUnauthorized {
		t.Errorf("Expected ErrUnauthorized, got: %v", err)
	}
}

func TestPoolManagerSwapUninitializedPool(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Try to swap in uninitialized pool
	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: MinSqrtRatio,
	}

	_, err := pm.Swap(stateDB, key, params, nil)
	if err != ErrPoolNotInitialized {
		t.Errorf("Expected ErrPoolNotInitialized, got: %v", err)
	}
}

// =========================================================================
// Liquidity Tests
// =========================================================================

func TestPoolManagerModifyLiquidity(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Add liquidity
	params := ModifyLiquidityParams{
		TickLower:      -1000,
		TickUpper:      1000,
		LiquidityDelta: big.NewInt(1000000),
		Salt:           [32]byte{},
	}

	callerDelta, feesAccrued, err := pm.ModifyLiquidity(stateDB, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}

	t.Logf("Caller delta: amount0=%s, amount1=%s", callerDelta.Amount0, callerDelta.Amount1)
	t.Logf("Fees accrued: amount0=%s, amount1=%s", feesAccrued.Amount0, feesAccrued.Amount1)

	// Verify position was created
	pos, err := pm.GetPosition(stateDB, key, caller, params.TickLower, params.TickUpper, params.Salt)
	if err != nil {
		t.Fatalf("GetPosition failed: %v", err)
	}

	if pos.Liquidity.Cmp(big.NewInt(1000000)) != 0 {
		t.Errorf("Expected liquidity 1000000, got: %s", pos.Liquidity)
	}
}

func TestPoolManagerModifyLiquidityInvalidTickRange(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Try to add liquidity with invalid tick range (lower >= upper)
	params := ModifyLiquidityParams{
		TickLower:      1000,
		TickUpper:      -1000, // Invalid: lower > upper
		LiquidityDelta: big.NewInt(1000000),
		Salt:           [32]byte{},
	}

	_, _, err = pm.ModifyLiquidity(stateDB, key, params, nil)
	if err != ErrInvalidTickRange {
		t.Errorf("Expected ErrInvalidTickRange, got: %v", err)
	}
}

// =========================================================================
// Donate Tests
// =========================================================================

func TestPoolManagerDonate(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool with liquidity
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add liquidity
	pool := pm.pools[key.ID()]
	pool.Liquidity = big.NewInt(1000000000)

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Donate tokens
	amount0 := big.NewInt(10000)
	amount1 := big.NewInt(20000)

	delta, err := pm.Donate(stateDB, key, amount0, amount1, nil)
	if err != nil {
		t.Fatalf("Donate failed: %v", err)
	}

	t.Logf("Donate delta: amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	// Verify fee growth was updated
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

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Simulate lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	// Execute flash loan
	params := FlashParams{
		Amount0:   big.NewInt(100000),
		Amount1:   big.NewInt(200000),
		Recipient: recipient,
		Data:      nil,
	}

	delta, err := pm.Flash(stateDB, key, params, nil)
	if err != nil {
		t.Fatalf("Flash failed: %v", err)
	}

	t.Logf("Flash delta (loan + fee): amount0=%s, amount1=%s", delta.Amount0, delta.Amount1)

	// Verify delta includes loan + fee
	if delta.Amount0.Cmp(params.Amount0) <= 0 {
		t.Error("Expected delta to include fee")
	}
}

// =========================================================================
// BalanceDelta Tests
// =========================================================================

func TestBalanceDeltaOperations(t *testing.T) {
	// Test creation
	delta1 := NewBalanceDelta(big.NewInt(100), big.NewInt(-50))
	if delta1.Amount0.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("Amount0 mismatch: got %s, want 100", delta1.Amount0)
	}
	if delta1.Amount1.Cmp(big.NewInt(-50)) != 0 {
		t.Errorf("Amount1 mismatch: got %s, want -50", delta1.Amount1)
	}

	// Test addition
	delta2 := NewBalanceDelta(big.NewInt(50), big.NewInt(100))
	sum := delta1.Add(delta2)
	if sum.Amount0.Cmp(big.NewInt(150)) != 0 {
		t.Errorf("Add Amount0 mismatch: got %s, want 150", sum.Amount0)
	}
	if sum.Amount1.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("Add Amount1 mismatch: got %s, want 50", sum.Amount1)
	}

	// Test subtraction
	diff := delta1.Sub(delta2)
	if diff.Amount0.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("Sub Amount0 mismatch: got %s, want 50", diff.Amount0)
	}
	if diff.Amount1.Cmp(big.NewInt(-150)) != 0 {
		t.Errorf("Sub Amount1 mismatch: got %s, want -150", diff.Amount1)
	}

	// Test negation
	neg := delta1.Negate()
	if neg.Amount0.Cmp(big.NewInt(-100)) != 0 {
		t.Errorf("Negate Amount0 mismatch: got %s, want -100", neg.Amount0)
	}
	if neg.Amount1.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("Negate Amount1 mismatch: got %s, want 50", neg.Amount1)
	}

	// Test IsZero
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

	// Same keys should produce same ID
	id1 := key1.ID()
	id2 := key2.ID()

	if id1 != id2 {
		t.Error("Same pool keys should produce same ID")
	}

	// Different keys should produce different IDs
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

	// Serialize
	data := key.ToBytes()
	if len(data) != 66 {
		t.Errorf("Expected 66 bytes, got %d", len(data))
	}

	// Deserialize
	decoded, err := PoolKeyFromBytes(data)
	if err != nil {
		t.Fatalf("PoolKeyFromBytes failed: %v", err)
	}

	// Verify fields match
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
		t.Error("ERC20 currency should not be native")
	}
}

// =========================================================================
// Event Emission Tests
// =========================================================================

func TestInitializeEmitsEvent(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)

	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	logs := stateDB.Logs()
	if len(logs) != 1 {
		t.Fatalf("Expected 1 log, got %d", len(logs))
	}

	log := logs[0]
	if log.Address != lxPoolAddr {
		t.Errorf("Expected log address %s, got %s", lxPoolAddr.Hex(), log.Address.Hex())
	}
	if len(log.Topics) != 4 {
		t.Fatalf("Expected 4 topics, got %d", len(log.Topics))
	}
	if log.Topics[0] != initializeEventSig {
		t.Errorf("Expected Initialize event sig %s, got %s", initializeEventSig.Hex(), log.Topics[0].Hex())
	}
	// topic1 = poolId
	poolId := key.ID()
	if log.Topics[1] != common.BytesToHash(poolId[:]) {
		t.Errorf("Expected poolId topic, got %s", log.Topics[1].Hex())
	}
	// topic2 = currency0
	if log.Topics[2] != common.BytesToHash(key.Currency0.Address.Bytes()) {
		t.Errorf("Expected currency0 topic, got %s", log.Topics[2].Hex())
	}
	// topic3 = currency1
	if log.Topics[3] != common.BytesToHash(key.Currency1.Address.Bytes()) {
		t.Errorf("Expected currency1 topic, got %s", log.Topics[3].Hex())
	}
	// Data should be 5 words (fee, tickSpacing, hooks, sqrtPriceX96, tick) = 160 bytes
	if len(log.Data) != 160 {
		t.Errorf("Expected 160 bytes of data, got %d", len(log.Data))
	}
}

func TestSwapEmitsEvent(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add liquidity
	pool := pm.pools[key.ID()]
	pool.Liquidity = big.NewInt(1000000000)

	// Clear logs from Initialize
	stateDB.logs = nil

	// Setup lock context and swap
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: MinSqrtRatio,
	}

	_, err = pm.Swap(stateDB, key, params, nil)
	if err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	logs := stateDB.Logs()
	if len(logs) != 1 {
		t.Fatalf("Expected 1 log, got %d", len(logs))
	}

	log := logs[0]
	if log.Topics[0] != swapEventSig {
		t.Errorf("Expected Swap event sig %s, got %s", swapEventSig.Hex(), log.Topics[0].Hex())
	}
	if len(log.Topics) != 3 {
		t.Fatalf("Expected 3 topics, got %d", len(log.Topics))
	}
	// topic1 = poolId
	poolId := key.ID()
	if log.Topics[1] != common.BytesToHash(poolId[:]) {
		t.Errorf("Expected poolId topic")
	}
	// topic2 = sender
	if log.Topics[2] != common.BytesToHash(caller.Bytes()) {
		t.Errorf("Expected sender topic")
	}
	// Data should be 6 words = 192 bytes
	if len(log.Data) != 192 {
		t.Errorf("Expected 192 bytes of data, got %d", len(log.Data))
	}
}

func TestModifyLiquidityEmitsEvent(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Clear logs from Initialize
	stateDB.logs = nil

	// Setup lock context
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	params := ModifyLiquidityParams{
		TickLower:      -1000,
		TickUpper:      1000,
		LiquidityDelta: big.NewInt(1000000),
		Salt:           [32]byte{},
	}

	_, _, err = pm.ModifyLiquidity(stateDB, key, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}

	logs := stateDB.Logs()
	if len(logs) != 1 {
		t.Fatalf("Expected 1 log, got %d", len(logs))
	}

	log := logs[0]
	if log.Topics[0] != modifyLiquidityEventSig {
		t.Errorf("Expected ModifyLiquidity event sig %s, got %s", modifyLiquidityEventSig.Hex(), log.Topics[0].Hex())
	}
	if len(log.Topics) != 3 {
		t.Fatalf("Expected 3 topics, got %d", len(log.Topics))
	}
	// topic2 = sender
	if log.Topics[2] != common.BytesToHash(caller.Bytes()) {
		t.Errorf("Expected sender topic")
	}
	// Data should be 4 words = 128 bytes
	if len(log.Data) != 128 {
		t.Errorf("Expected 128 bytes of data, got %d", len(log.Data))
	}
}

func TestNoEventOnFailedInitialize(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	// Use unsorted currencies - should fail before emitting event
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")},
		Currency1:   NativeCurrency,
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}

	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err == nil {
		t.Fatal("Expected error for unsorted currencies")
	}

	logs := stateDB.Logs()
	if len(logs) != 0 {
		t.Errorf("Expected 0 logs on failed initialize, got %d", len(logs))
	}
}

// =========================================================================
// Benchmark Tests
// =========================================================================

func BenchmarkPoolManagerSwap(b *testing.B) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	pm.Initialize(stateDB, key, sqrtPriceX96, nil)

	// Add liquidity
	pool := pm.pools[key.ID()]
	pool.Liquidity = big.NewInt(1000000000)

	params := SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(1000),
		SqrtPriceLimitX96: MinSqrtRatio,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Setup lock context
		pm.lockers = []common.Address{caller}
		pm.currentDeltas[caller] = make(map[Currency]*big.Int)

		pm.Swap(stateDB, key, params, nil)

		// Cleanup
		pm.lockers = nil
		delete(pm.currentDeltas, caller)
	}
}

func BenchmarkPoolManagerModifyLiquidity(b *testing.B) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	pm.Initialize(stateDB, key, sqrtPriceX96, nil)

	params := ModifyLiquidityParams{
		TickLower:      -1000,
		TickUpper:      1000,
		LiquidityDelta: big.NewInt(1000000),
		Salt:           [32]byte{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Setup lock context
		pm.lockers = []common.Address{caller}
		pm.currentDeltas[caller] = make(map[Currency]*big.Int)

		pm.ModifyLiquidity(stateDB, key, params, nil)

		// Cleanup
		pm.lockers = nil
		delete(pm.currentDeltas, caller)
	}
}

func BenchmarkPoolKeyID(b *testing.B) {
	key := newTestPoolKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = key.ID()
	}
}

// =========================================================================
// Red Team Regression Tests — F1 through F12
// =========================================================================

// F1: transferToken must reject insufficient balance before any state change.
func TestTransferTokenInsufficientBalance(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	token := Currency{Address: common.HexToAddress("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// from has 0 balance at the ERC20 storage slot, try to transfer 100
	err := pm.transferToken(stateDB, token, from, to, big.NewInt(100))
	if err == nil {
		t.Fatal("expected insufficient balance error, got nil")
	}
	t.Logf("F1 correctly rejected: %v", err)
}

// F1: transferToken must reject insufficient native balance.
func TestTransferTokenInsufficientNativeBalance(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	stateDB.AddBalance(from, uint256.NewInt(50))

	err := pm.transferToken(stateDB, NativeCurrency, from, to, big.NewInt(100))
	if err == nil {
		t.Fatal("expected insufficient native balance error, got nil")
	}
	t.Logf("F1 native correctly rejected: %v", err)
}

// F2: autoSettle must propagate transfer failures.
func TestAutoSettleReturnsError(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// caller has 0 native balance, delta says caller owes pool 1000
	delta := NewBalanceDelta(big.NewInt(1000), big.NewInt(0))
	err := pm.autoSettle(stateDB, caller, key, delta)
	if err == nil {
		t.Fatal("expected autoSettle error for insufficient balance, got nil")
	}
	t.Logf("F2 correctly propagated: %v", err)
}

// F4: DecodeSwapInput must handle negative AmountSpecified (two's complement).
func TestDecodeSwapInputNegativeAmount(t *testing.T) {
	// Build input: 128 bytes PoolKey + 1 byte zeroForOne + 32 bytes amount + 32 bytes limit
	input := make([]byte, 193)
	// currency0 at [12:32]
	copy(input[12:32], common.HexToAddress("0x1000000000000000000000000000000000000001").Bytes())
	// currency1 at [44:64]
	copy(input[44:64], common.HexToAddress("0x2000000000000000000000000000000000000002").Bytes())
	// fee at [64:67]: 3000 = 0x000BB8
	input[64] = 0x00
	input[65] = 0x0B
	input[66] = 0xB8
	// tickSpacing at [67:70]: 60 = 0x00003C
	input[67] = 0x00
	input[68] = 0x00
	input[69] = 0x3C
	// hooks at [76:96]: zero
	// zeroForOne at [128]: 1
	input[128] = 1
	// AmountSpecified at [129:161]: -1000 in two's complement
	neg1000 := new(big.Int).SetInt64(-1000)
	tc := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), neg1000)
	tcBytes := tc.Bytes()
	copy(input[129+(32-len(tcBytes)):161], tcBytes)
	// SqrtPriceLimitX96 at [161:193]: just some value
	big.NewInt(100).FillBytes(input[161:193])

	_, params, _, err := DecodeSwapInput(input)
	if err != nil {
		t.Fatalf("DecodeSwapInput failed: %v", err)
	}
	if params.AmountSpecified.Sign() >= 0 {
		t.Fatalf("expected negative AmountSpecified, got %s", params.AmountSpecified)
	}
	if params.AmountSpecified.Int64() != -1000 {
		t.Fatalf("expected -1000, got %s", params.AmountSpecified)
	}
	t.Logf("F4: correctly decoded AmountSpecified = %s", params.AmountSpecified)
}

// F5: bigIntTo32Bytes must produce correct two's complement for negatives.
func TestBigIntTo32BytesNegative(t *testing.T) {
	neg := big.NewInt(-1)
	result := bigIntTo32Bytes(neg)

	// -1 in two's complement 256-bit should be all 0xFF
	for i := 0; i < 32; i++ {
		if result[i] != 0xFF {
			t.Fatalf("byte %d: expected 0xFF, got 0x%02X", i, result[i])
		}
	}

	// Test -1000
	neg1000 := big.NewInt(-1000)
	result = bigIntTo32Bytes(neg1000)
	// Decode back
	decoded := decodeSigned256(result)
	if decoded.Int64() != -1000 {
		t.Fatalf("round-trip failed: expected -1000, got %s", decoded)
	}
	t.Logf("F5: -1000 round-trips correctly through two's complement encoding")
}

// F5: bigIntTo32Bytes positive values work correctly.
func TestBigIntTo32BytesPositive(t *testing.T) {
	val := big.NewInt(42)
	result := bigIntTo32Bytes(val)
	decoded := new(big.Int).SetBytes(result)
	if decoded.Int64() != 42 {
		t.Fatalf("expected 42, got %s", decoded)
	}
}

// F10: ModifyLiquidity must reject removal that would make pool liquidity negative.
func TestModifyLiquidityRejectsNegativePoolLiquidity(t *testing.T) {
	pm := newTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// Initialize pool
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Add some liquidity first
	pm.lockers = append(pm.lockers, caller)
	pm.currentDeltas[caller] = make(map[Currency]*big.Int)

	addParams := ModifyLiquidityParams{
		TickLower:      -1000,
		TickUpper:      1000,
		LiquidityDelta: big.NewInt(500),
	}
	_, _, err = pm.ModifyLiquidity(stateDB, key, addParams, nil)
	if err != nil {
		t.Fatalf("AddLiquidity failed: %v", err)
	}

	// Now try to remove more than exists
	removeParams := ModifyLiquidityParams{
		TickLower:      -1000,
		TickUpper:      1000,
		LiquidityDelta: big.NewInt(-1000), // more than the 500 we added
	}
	_, _, err = pm.ModifyLiquidity(stateDB, key, removeParams, nil)
	if err == nil {
		t.Fatal("expected error when removing more liquidity than exists")
	}
	t.Logf("F10 correctly rejected: %v", err)
}

// F10: safeFillBytes must not panic on negative big.Int.
func TestSafeFillBytesNegative(t *testing.T) {
	buf := make([]byte, 32)
	// Should not panic
	safeFillBytes(big.NewInt(-1), buf)
	for i := range buf {
		if buf[i] != 0 {
			t.Fatalf("expected zero buf for negative value, byte %d = %d", i, buf[i])
		}
	}
	t.Log("F10: safeFillBytes handles negative values without panic")
}

// F12: decodeInt24 must handle negative tick values.
func TestDecodeInt24Negative(t *testing.T) {
	// -1000 = 0xFFFC18 in 24-bit two's complement
	// 24-bit: 2^24 - 1000 = 16777216 - 1000 = 16776216 = 0xFFFC18
	b := []byte{0xFF, 0xFC, 0x18}
	val := decodeInt24(b)
	if val != -1000 {
		t.Fatalf("expected -1000, got %d", val)
	}

	// Test positive
	b = []byte{0x00, 0x03, 0xE8} // 1000
	val = decodeInt24(b)
	if val != 1000 {
		t.Fatalf("expected 1000, got %d", val)
	}

	// Test zero
	b = []byte{0x00, 0x00, 0x00}
	val = decodeInt24(b)
	if val != 0 {
		t.Fatalf("expected 0, got %d", val)
	}

	// Test max positive (2^23 - 1 = 8388607)
	b = []byte{0x7F, 0xFF, 0xFF}
	val = decodeInt24(b)
	if val != 8388607 {
		t.Fatalf("expected 8388607, got %d", val)
	}

	// Test min negative (-2^23 = -8388608)
	b = []byte{0x80, 0x00, 0x00}
	val = decodeInt24(b)
	if val != -8388608 {
		t.Fatalf("expected -8388608, got %d", val)
	}

	t.Log("F12: decodeInt24 handles all int24 edge cases correctly")
}

// F12: DecodeModifyLiquidityInput must handle negative ticks.
func TestDecodeModifyLiquidityInputNegativeTicks(t *testing.T) {
	input := make([]byte, 192)
	// currency0 at [12:32]
	copy(input[12:32], common.HexToAddress("0x1000000000000000000000000000000000000001").Bytes())
	// currency1 at [44:64]
	copy(input[44:64], common.HexToAddress("0x2000000000000000000000000000000000000002").Bytes())
	// fee at [64:67]: 3000
	input[64] = 0x00
	input[65] = 0x0B
	input[66] = 0xB8
	// tickSpacing at [67:70]: 60
	input[67] = 0x00
	input[68] = 0x00
	input[69] = 0x3C

	// TickLower at [128:131]: -887272 = 0xF27618 in 24-bit two's complement
	// 2^24 - 887272 = 16777216 - 887272 = 15889944 = 0xF27618
	input[128] = 0xF2
	input[129] = 0x76
	input[130] = 0x18
	// TickUpper at [131:134]: 887272 = 0x0D89E8
	input[131] = 0x0D
	input[132] = 0x89
	input[133] = 0xE8
	// LiquidityDelta at [134:166]: 1000000
	big.NewInt(1000000).FillBytes(input[134:166])

	_, params, _, err := DecodeModifyLiquidityInput(input)
	if err != nil {
		t.Fatalf("DecodeModifyLiquidityInput failed: %v", err)
	}
	if params.TickLower != -887272 {
		t.Fatalf("expected TickLower=-887272, got %d", params.TickLower)
	}
	if params.TickUpper != 887272 {
		t.Fatalf("expected TickUpper=887272, got %d", params.TickUpper)
	}
	t.Logf("F12: TickLower=%d, TickUpper=%d decoded correctly", params.TickLower, params.TickUpper)
}

// F9: popLocker must verify caller identity.
func TestPopLockerVerifiesCaller(t *testing.T) {
	pm := newTestPoolManager()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	other := common.HexToAddress("0x2222222222222222222222222222222222222222")

	pm.pushLocker(caller)

	// Wrong caller should fail
	err := pm.popLocker(other)
	if err == nil {
		t.Fatal("expected error when popping with wrong caller")
	}
	t.Logf("F9 correctly rejected: %v", err)

	// Correct caller should succeed
	err = pm.popLocker(caller)
	if err != nil {
		t.Fatalf("expected success for correct caller, got: %v", err)
	}

	// Empty stack should fail
	err = pm.popLocker(caller)
	if err == nil {
		t.Fatal("expected error when popping empty stack")
	}
	t.Log("F9: popLocker identity verification works correctly")
}

// F8: Router executeV4Swap must use actual PoolKey (non-zero fee).
func TestRouterExecuteV4SwapWithPoolKey(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	key := setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	// Verify the key has a non-zero fee
	if key.Fee == 0 {
		t.Fatal("expected non-zero fee in pool key")
	}

	// Quote to get poolID and key
	_, poolID, returnedKey, err := router.quoteV4(stateDB, testTokenA, testTokenB, big.NewInt(10_000), 0)
	if err != nil {
		t.Fatalf("quoteV4 failed: %v", err)
	}
	if returnedKey.Fee == 0 {
		t.Fatal("F8: quoteV4 returned zero-fee key, fee would be ignored in swap")
	}

	// Execute through V4 with the actual key
	amountOut, err := router.executeV4Swap(stateDB, testCaller, poolID, returnedKey, testTokenA, testTokenB, big.NewInt(10_000), nil)
	if err != nil {
		t.Fatalf("executeV4Swap failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatal("expected positive output")
	}
	t.Logf("F8: executeV4Swap with real key (fee=%d) produced output=%s", returnedKey.Fee, amountOut)
}
