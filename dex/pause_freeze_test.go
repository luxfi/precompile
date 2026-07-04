// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// Admin address used as protocolFeeController for pause/freeze tests.
var adminAddr = common.HexToAddress("0xADMN000000000000000000000000000000000001")

// nonAdminAddr is an address without admin privileges.
var nonAdminAddr = common.HexToAddress("0xBEEF000000000000000000000000000000000002")

func newPauseTestPoolManager() *PoolManager {
	pm := NewPoolManager(&mockEngine{})
	pm.protocolFeeController = adminAddr
	return pm
}

// =========================================================================
// Level 2: DEX-Level Pause Tests
// =========================================================================

func TestPauseDEX(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()

	// Pause the DEX
	err := pm.PauseDEX(stateDB, adminAddr)
	if err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	if !pm.IsPaused(stateDB) {
		t.Fatal("DEX should be paused")
	}

	// Verify event was emitted
	logs := stateDB.Logs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].Topics[0] != dexPausedEventSig {
		t.Error("expected DEXPaused event")
	}
}

func TestPauseDEXUnauthorized(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()

	err := pm.PauseDEX(stateDB, nonAdminAddr)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}

	if pm.IsPaused(stateDB) {
		t.Fatal("DEX should not be paused after unauthorized call")
	}
}

func TestPauseDEXAlreadyPaused(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()

	pm.PauseDEX(stateDB, adminAddr)
	err := pm.PauseDEX(stateDB, adminAddr)
	if err != ErrAlreadyPaused {
		t.Fatalf("expected ErrAlreadyPaused, got: %v", err)
	}
}

func TestResumeDEX(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()

	pm.PauseDEX(stateDB, adminAddr)
	err := pm.ResumeDEX(stateDB, adminAddr)
	if err != nil {
		t.Fatalf("ResumeDEX failed: %v", err)
	}

	if pm.IsPaused(stateDB) {
		t.Fatal("DEX should not be paused after resume")
	}
}

func TestResumeDEXNotPaused(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()

	err := pm.ResumeDEX(stateDB, adminAddr)
	if err != ErrDEXNotPaused {
		t.Fatalf("expected ErrDEXNotPaused, got: %v", err)
	}
}

func TestResumeDEXUnauthorized(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()

	pm.PauseDEX(stateDB, adminAddr)
	err := pm.ResumeDEX(stateDB, nonAdminAddr)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}
}

func TestDEXPausePreventsModifyLiquidity(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	pm.PauseDEX(stateDB, adminAddr)

	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(1000),
		Salt:           [32]byte{},
	}

	_, _, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != ErrDEXPaused {
		t.Fatalf("expected ErrDEXPaused, got: %v", err)
	}
}

func TestDEXPausePreventsDonate(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	pm.PauseDEX(stateDB, adminAddr)

	_, err := pm.Donate(stateDB, caller, key, big.NewInt(100), big.NewInt(200))
	if err != ErrDEXPaused {
		t.Fatalf("expected ErrDEXPaused, got: %v", err)
	}
}

// =========================================================================
// Level 3: Pool-Level Pause Tests
// =========================================================================

func TestPausePool(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	poolId := key.ID()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	err := pm.PausePool(stateDB, adminAddr, poolId)
	if err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	if !pm.IsPoolPaused(stateDB, poolId) {
		t.Fatal("pool should be paused")
	}
}

func TestPausePoolUnauthorized(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	poolId := key.ID()

	err := pm.PausePool(stateDB, nonAdminAddr, poolId)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}

	if pm.IsPoolPaused(stateDB, poolId) {
		t.Fatal("pool should not be paused after unauthorized call")
	}
}

func TestPausedPoolPreventsModifyLiquidity(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	poolId := key.ID()
	pm.PausePool(stateDB, adminAddr, poolId)

	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(1000),
		Salt:           [32]byte{},
	}

	_, _, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != ErrPoolPaused {
		t.Fatalf("expected ErrPoolPaused, got: %v", err)
	}
}

// =========================================================================
// Level 3: Pool-Level Freeze Tests
// =========================================================================

func TestFreezePool(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)
	poolId := key.ID()

	err := pm.FreezePool(stateDB, adminAddr, poolId)
	if err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	if !pm.IsPoolFrozen(stateDB, poolId) {
		t.Fatal("pool should be frozen")
	}
}

func TestFreezePoolUnauthorized(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	poolId := key.ID()

	err := pm.FreezePool(stateDB, nonAdminAddr, poolId)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}

	if pm.IsPoolFrozen(stateDB, poolId) {
		t.Fatal("pool should not be frozen after unauthorized call")
	}
}

func TestFreezePoolAlreadyFrozen(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)
	poolId := key.ID()

	pm.FreezePool(stateDB, adminAddr, poolId)
	err := pm.FreezePool(stateDB, adminAddr, poolId)
	if err != ErrAlreadyFrozen {
		t.Fatalf("expected ErrAlreadyFrozen, got: %v", err)
	}
}

func TestFrozenPoolPreventsModifyLiquidity(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	poolId := key.ID()
	pm.FreezePool(stateDB, adminAddr, poolId)

	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(1000),
		Salt:           [32]byte{},
	}

	_, _, err := pm.ModifyLiquidity(stateDB, caller, key, params, nil)
	if err != ErrPoolFrozen {
		t.Fatalf("expected ErrPoolFrozen, got: %v", err)
	}
}

func TestFrozenPoolPreventsDonate(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	poolId := key.ID()
	pm.FreezePool(stateDB, adminAddr, poolId)

	_, err := pm.Donate(stateDB, caller, key, big.NewInt(100), big.NewInt(200))
	if err != ErrPoolFrozen {
		t.Fatalf("expected ErrPoolFrozen, got: %v", err)
	}
}

func TestFrozenPoolCannotBeResumed(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)
	poolId := key.ID()

	pm.FreezePool(stateDB, adminAddr, poolId)

	err := pm.ResumePool(stateDB, adminAddr, poolId)
	if err != ErrFreezeIrreversible {
		t.Fatalf("expected ErrFreezeIrreversible, got: %v", err)
	}

	// Pool should still be frozen
	if !pm.IsPoolFrozen(stateDB, poolId) {
		t.Fatal("pool should still be frozen")
	}
}

func TestFrozenPoolCannotBePaused(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)
	poolId := key.ID()

	pm.FreezePool(stateDB, adminAddr, poolId)

	err := pm.PausePool(stateDB, adminAddr, poolId)
	if err != ErrPoolFrozen {
		t.Fatalf("expected ErrPoolFrozen, got: %v", err)
	}
}

func TestFreezeClearsPauseState(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)
	poolId := key.ID()

	// Pause first, then freeze
	pm.PausePool(stateDB, adminAddr, poolId)
	if !pm.IsPoolPaused(stateDB, poolId) {
		t.Fatal("pool should be paused")
	}

	pm.FreezePool(stateDB, adminAddr, poolId)

	// Pause state should be cleared (freeze supersedes)
	if pm.IsPoolPaused(stateDB, poolId) {
		t.Fatal("pool pause should be cleared after freeze")
	}
	if !pm.IsPoolFrozen(stateDB, poolId) {
		t.Fatal("pool should be frozen")
	}
}

// =========================================================================
// Precedence Tests: DEX pause > Pool freeze > Pool pause
// =========================================================================

// =========================================================================
// Event Emission Tests
// =========================================================================

func TestPauseResumeEmitsEvents(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	poolId := key.ID()

	// Initialize the pool so per-pool ops have a pool to act on.
	// Under V5 fix, PausePool/ResumePool/FreezePool require an
	// initialized pool (return ErrPoolNotInitialized otherwise).
	if _, err := pm.Initialize(stateDB, key, new(big.Int).Add(MinSqrtRatio, big.NewInt(1)), nil); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	// Clear init log so the 5 we assert are the pause/resume/freeze ones.
	stateDB.logs = nil

	// Pause DEX
	pm.PauseDEX(stateDB, adminAddr)
	// Resume DEX
	pm.ResumeDEX(stateDB, adminAddr)
	// Pause pool
	pm.PausePool(stateDB, adminAddr, poolId)
	// Resume pool
	pm.ResumePool(stateDB, adminAddr, poolId)
	// Freeze pool
	pm.FreezePool(stateDB, adminAddr, poolId)

	logs := stateDB.Logs()
	if len(logs) != 5 {
		t.Fatalf("expected 5 logs, got %d", len(logs))
	}

	expected := []common.Hash{
		dexPausedEventSig,
		dexResumedEventSig,
		poolPausedEventSig,
		poolResumedEventSig,
		poolFrozenEventSig,
	}

	for i, sig := range expected {
		if logs[i].Topics[0] != sig {
			t.Errorf("log[%d]: expected topic %s, got %s", i, sig.Hex(), logs[i].Topics[0].Hex())
		}
	}
}

// =========================================================================
// Read-Only Access Tests: frozen/paused pools are still readable
// =========================================================================

func TestFrozenPoolIsStillReadable(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	poolId := key.ID()
	pm.FreezePool(stateDB, adminAddr, poolId)

	// GetPool should still work on frozen pool
	pool, err := pm.GetPool(stateDB, key)
	if err != nil {
		t.Fatalf("GetPool on frozen pool should succeed: %v", err)
	}
	if !pool.IsInitialized() {
		t.Fatal("frozen pool should still be initialized")
	}
}

func TestPausedPoolIsStillReadable(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	initPoolWithLiquidity(t, pm, stateDB, key, 1_000_000_000)

	poolId := key.ID()
	pm.PausePool(stateDB, adminAddr, poolId)

	pool, err := pm.GetPool(stateDB, key)
	if err != nil {
		t.Fatalf("GetPool on paused pool should succeed: %v", err)
	}
	if !pool.IsInitialized() {
		t.Fatal("paused pool should still be initialized")
	}
}

// =========================================================================
// Initialize is NOT blocked by pause (pools can be created while paused)
// This is a deliberate design choice: initialization is admin-initiated
// and does not move funds.
// =========================================================================

func TestInitializeNotBlockedByDEXPause(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()

	pm.PauseDEX(stateDB, adminAddr)

	sqrtPriceX96 := new(big.Int).Set(Q96)
	_, err := pm.Initialize(stateDB, key, sqrtPriceX96, nil)
	if err != nil {
		t.Fatalf("Initialize should succeed during DEX pause: %v", err)
	}
}

// =========================================================================
// Flash loan is NOT blocked by pause (reads only, no state mutation of pool)
// =========================================================================

func TestFlashBlockedByDEXPause(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")

	sqrtPriceX96 := new(big.Int).Set(Q96)
	pm.Initialize(stateDB, key, sqrtPriceX96, nil)

	pm.PauseDEX(stateDB, adminAddr)

	params := FlashParams{
		Amount0:   big.NewInt(100000),
		Amount1:   big.NewInt(200000),
		Recipient: recipient,
		Data:      nil,
	}

	// Flash MUST be blocked during DEX pause — an attacker could exploit
	// flash loans during regulatory halts to manipulate external state.
	_, err := pm.Flash(stateDB, caller, key, params, nil)
	if err != ErrDEXPaused {
		t.Fatalf("Flash should be blocked during DEX pause, got: %v", err)
	}
}

func TestFlashBlockedByPoolFreeze(t *testing.T) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	key := newTestPoolKey()
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")

	sqrtPriceX96 := new(big.Int).Set(Q96)
	pm.Initialize(stateDB, key, sqrtPriceX96, nil)

	poolId := key.ID()
	pm.FreezePool(stateDB, adminAddr, poolId)

	params := FlashParams{
		Amount0:   big.NewInt(100000),
		Amount1:   big.NewInt(200000),
		Recipient: recipient,
		Data:      nil,
	}

	_, err := pm.Flash(stateDB, caller, key, params, nil)
	if err != ErrPoolFrozen {
		t.Fatalf("Flash should be blocked on frozen pool, got: %v", err)
	}
}

// =========================================================================
// Benchmark: pause check overhead
// =========================================================================

func BenchmarkCheckPauseState(b *testing.B) {
	pm := newPauseTestPoolManager()
	poolId := newTestPoolKey().ID()
	stateDB := NewMockStateDB()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pm.checkPauseState(stateDB, poolId)
	}
}

func BenchmarkCheckPauseStatePaused(b *testing.B) {
	pm := newPauseTestPoolManager()
	stateDB := NewMockStateDB()
	pm.PauseDEX(stateDB, adminAddr)
	poolId := newTestPoolKey().ID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pm.checkPauseState(stateDB, poolId)
	}
}
