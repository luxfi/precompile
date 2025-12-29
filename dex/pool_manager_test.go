// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// MockStateDB implements StateDB interface for testing
type MockStateDB struct {
	states      map[common.Address]map[common.Hash]common.Hash
	balances    map[common.Address]*uint256.Int
	exists      map[common.Address]bool
	blockNumber uint64
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
