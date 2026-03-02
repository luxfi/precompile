// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// =========================================================================
// Test Addresses
// =========================================================================

var (
	// admin is the protocolFeeController for pause/freeze tests.
	admin = common.HexToAddress("0xADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	// randomCaller is an unauthorized caller for ACL tests.
	randomCaller = common.HexToAddress("0xBADBADBADBADBADBADBADBADBADBADBADBADBADB")
)

// newPauseTestPM creates a PoolManager with admin as protocolFeeController.
func newPauseTestPM() *PoolManager {
	pm := NewPoolManager(&mockEngine{})
	pm.protocolFeeController = admin
	return pm
}

// initTwoPoolsPF initializes two pools (A/B and B/C) for pause/freeze tests.
// Returns the pool keys and pool IDs.
func initTwoPoolsPF(t *testing.T, pm *PoolManager, stateDB *MockStateDB) (PoolKey, [32]byte, PoolKey, [32]byte) {
	t.Helper()
	keyAB := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}
	keyBC := PoolKey{
		Currency0:   Currency{Address: testTokenB},
		Currency1:   Currency{Address: testTokenC},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}

	_, err := pm.Initialize(stateDB, keyAB, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize A/B failed: %v", err)
	}
	_, err = pm.Initialize(stateDB, keyBC, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize B/C failed: %v", err)
	}

	// Add liquidity to both pools.
	liqParams := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(1_000_000),
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, testLP, keyAB, liqParams, nil); err != nil {
		t.Fatalf("ModifyLiquidity A/B failed: %v", err)
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, testLP, keyBC, liqParams, nil); err != nil {
		t.Fatalf("ModifyLiquidity B/C failed: %v", err)
	}

	return keyAB, keyAB.ID(), keyBC, keyBC.ID()
}

// swapParams returns standard ExactInput swap params for testing.
func swapParams() SwapParams {
	return SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1000),
		SqrtPriceLimitX96: new(big.Int).Set(MinSqrtRatio),
	}
}

// =========================================================================
// 1. PauseDEX blocks Swap
// =========================================================================

func TestPauseFreeze_PauseDEXBlocksSwap(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, _, _, _ := initTwoPoolsPF(t, pm, stateDB)

	// Swap works before pause.
	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if err != nil {
		t.Fatalf("swap before pause should succeed: %v", err)
	}

	// Pause DEX.
	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	// Swap must fail with ErrDEXPaused.
	_, err = pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused, got: %v", err)
	}
}

// =========================================================================
// 2. PauseDEX blocks ModifyLiquidity
// =========================================================================

func TestPauseFreeze_PauseDEXBlocksModifyLiquidity(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, _, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(500),
	}
	_, _, err := pm.ModifyLiquidity(stateDB, testCaller, keyAB, params, nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused, got: %v", err)
	}
}

// =========================================================================
// 3. PauseDEX blocks Donate
// =========================================================================

func TestPauseFreeze_PauseDEXBlocksDonate(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, _, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	_, err := pm.Donate(stateDB, testCaller, keyAB, big.NewInt(100), big.NewInt(100))
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused, got: %v", err)
	}
}

// =========================================================================
// 4. PauseDEX does NOT block Initialize
// =========================================================================

func TestPauseFreeze_PauseDEXDoesNotBlockInitialize(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	key := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}
	_, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize should succeed during DEX pause, got: %v", err)
	}
}

// =========================================================================
// 5. ResumeDEX re-enables operations
// =========================================================================

func TestPauseFreeze_ResumeDEXReenablesSwap(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, _, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	// Swap blocked.
	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused, got: %v", err)
	}

	// Resume.
	if err := pm.ResumeDEX(stateDB, admin); err != nil {
		t.Fatalf("ResumeDEX failed: %v", err)
	}

	// Swap works again.
	_, err = pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if err != nil {
		t.Fatalf("swap after resume should succeed: %v", err)
	}
}

// =========================================================================
// 6. PausePool blocks only that pool
// =========================================================================

func TestPauseFreeze_PausePoolBlocksOnlyThatPool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, poolIdAB, keyBC, _ := initTwoPoolsPF(t, pm, stateDB)

	// Pause pool A/B only.
	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool A/B failed: %v", err)
	}

	// Swap on A/B must fail.
	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolPaused) {
		t.Fatalf("expected ErrPoolPaused for A/B, got: %v", err)
	}

	// Swap on B/C must still work.
	_, err = pm.Swap(stateDB, testCaller, keyBC, swapParams(), nil)
	if err != nil {
		t.Fatalf("swap on B/C should succeed while A/B paused: %v", err)
	}
}

// =========================================================================
// 7. ResumePool re-enables the pool
// =========================================================================

func TestPauseFreeze_ResumePoolReenables(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolPaused) {
		t.Fatalf("expected ErrPoolPaused, got: %v", err)
	}

	if err := pm.ResumePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("ResumePool failed: %v", err)
	}

	_, err = pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if err != nil {
		t.Fatalf("swap after ResumePool should succeed: %v", err)
	}
}

// =========================================================================
// 8. FreezePool blocks operations permanently
// =========================================================================

func TestPauseFreeze_FreezePoolBlocksOperations(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Swap blocked.
	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("expected ErrPoolFrozen on swap, got: %v", err)
	}

	// ModifyLiquidity blocked.
	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(500),
	}
	_, _, err = pm.ModifyLiquidity(stateDB, testCaller, keyAB, params, nil)
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("expected ErrPoolFrozen on ModifyLiquidity, got: %v", err)
	}

	// Donate blocked.
	_, err = pm.Donate(stateDB, testCaller, keyAB, big.NewInt(10), big.NewInt(10))
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("expected ErrPoolFrozen on Donate, got: %v", err)
	}
}

// =========================================================================
// 9. FreezePool clears pause state
// =========================================================================

func TestPauseFreeze_FreezePoolClearsPauseState(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	// Pause first.
	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}
	if !pm.IsPoolPaused(poolIdAB) {
		t.Fatal("pool should be paused after PausePool")
	}

	// Freeze supersedes pause.
	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Pause state should be cleared.
	if pm.IsPoolPaused(poolIdAB) {
		t.Fatal("pool pause state should be cleared after freeze")
	}
	if !pm.IsPoolFrozen(poolIdAB) {
		t.Fatal("pool should be frozen")
	}
}

// =========================================================================
// 10. ResumePool on frozen pool -> ErrFreezeIrreversible
// =========================================================================

func TestPauseFreeze_ResumePoolOnFrozen(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	err := pm.ResumePool(stateDB, admin, poolIdAB)
	if !errors.Is(err, ErrFreezeIrreversible) {
		t.Fatalf("expected ErrFreezeIrreversible, got: %v", err)
	}
}

// =========================================================================
// 11. PausePool on frozen pool -> ErrPoolFrozen
// =========================================================================

func TestPauseFreeze_PausePoolOnFrozen(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	err := pm.PausePool(stateDB, admin, poolIdAB)
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("expected ErrPoolFrozen, got: %v", err)
	}
}

// =========================================================================
// 12. Only protocolFeeController can pause/resume/freeze
// =========================================================================

func TestPauseFreeze_UnauthorizedPauseDEX(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	err := pm.PauseDEX(stateDB, randomCaller)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for PauseDEX by random caller, got: %v", err)
	}
}

func TestPauseFreeze_UnauthorizedResumeDEX(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	// Pause first with admin.
	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	err := pm.ResumeDEX(stateDB, randomCaller)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for ResumeDEX by random caller, got: %v", err)
	}
}

func TestPauseFreeze_UnauthorizedPausePool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	err := pm.PausePool(stateDB, randomCaller, poolIdAB)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for PausePool by random caller, got: %v", err)
	}
}

func TestPauseFreeze_UnauthorizedResumePool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	err := pm.ResumePool(stateDB, randomCaller, poolIdAB)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for ResumePool by random caller, got: %v", err)
	}
}

func TestPauseFreeze_UnauthorizedFreezePool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	err := pm.FreezePool(stateDB, randomCaller, poolIdAB)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for FreezePool by random caller, got: %v", err)
	}
}

// =========================================================================
// 13. Double-pause -> ErrAlreadyPaused
// =========================================================================

func TestPauseFreeze_DoublePauseDEX(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("first PauseDEX failed: %v", err)
	}

	err := pm.PauseDEX(stateDB, admin)
	if !errors.Is(err, ErrAlreadyPaused) {
		t.Fatalf("expected ErrAlreadyPaused on double PauseDEX, got: %v", err)
	}
}

func TestPauseFreeze_DoublePausePool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("first PausePool failed: %v", err)
	}

	err := pm.PausePool(stateDB, admin, poolIdAB)
	if !errors.Is(err, ErrAlreadyPaused) {
		t.Fatalf("expected ErrAlreadyPaused on double PausePool, got: %v", err)
	}
}

// =========================================================================
// 14. Double-freeze -> ErrAlreadyFrozen
// =========================================================================

func TestPauseFreeze_DoubleFreezePool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("first FreezePool failed: %v", err)
	}

	err := pm.FreezePool(stateDB, admin, poolIdAB)
	if !errors.Is(err, ErrAlreadyFrozen) {
		t.Fatalf("expected ErrAlreadyFrozen on double FreezePool, got: %v", err)
	}
}

// =========================================================================
// 15. Resume when not paused -> ErrPoolNotPaused / ErrDEXNotPaused
// =========================================================================

func TestPauseFreeze_ResumeWhenNotPaused_DEX(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	err := pm.ResumeDEX(stateDB, admin)
	if !errors.Is(err, ErrDEXNotPaused) {
		t.Fatalf("expected ErrDEXNotPaused, got: %v", err)
	}
}

func TestPauseFreeze_ResumeWhenNotPaused_Pool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	err := pm.ResumePool(stateDB, admin, poolIdAB)
	if !errors.Is(err, ErrPoolNotPaused) {
		t.Fatalf("expected ErrPoolNotPaused, got: %v", err)
	}
}

// =========================================================================
// 16. Check ordering: DEX pause checked before pool freeze before pool pause
// =========================================================================

func TestPauseFreeze_CheckOrdering(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	// First: freeze the pool.
	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Second: pause the DEX globally.
	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	// With both DEX paused and pool frozen, DEX pause should be checked first.
	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused (checked before pool freeze), got: %v", err)
	}

	// Resume DEX -> now pool freeze should be the error.
	if err := pm.ResumeDEX(stateDB, admin); err != nil {
		t.Fatalf("ResumeDEX failed: %v", err)
	}

	_, err = pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("expected ErrPoolFrozen (checked after DEX pause cleared), got: %v", err)
	}
}

func TestPauseFreeze_CheckOrdering_FreezeBeforePause(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	// Create a different pool for this test to avoid collision.
	keyAB := PoolKey{
		Currency0:   Currency{Address: testTokenA},
		Currency1:   Currency{Address: testTokenB},
		Fee:         Fee005,
		TickSpacing: TickSpacing005,
	}
	_, err := pm.Initialize(stateDB, keyAB, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	lp := ModifyLiquidityParams{
		TickLower:      -10,
		TickUpper:      10,
		LiquidityDelta: big.NewInt(1_000_000),
	}
	if _, _, err := pm.ModifyLiquidity(stateDB, testLP, keyAB, lp, nil); err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}
	poolIdAB := keyAB.ID()

	// Pause the pool, then freeze it. Freeze supersedes pause.
	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}
	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// checkPauseState should return ErrPoolFrozen, not ErrPoolPaused.
	_, err = pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("expected ErrPoolFrozen (freeze supersedes pause), got: %v", err)
	}
}

// =========================================================================
// 17. Frozen pool positions readable via getPoolState (extsload)
// =========================================================================

func TestPauseFreeze_FrozenPoolReadable(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	// Freeze the pool.
	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Reading pool state should still work via the view function.
	pool, err := pm.GetPool(stateDB, keyAB)
	if err != nil {
		t.Fatalf("GetPool on frozen pool should succeed: %v", err)
	}
	if pool.SqrtPriceX96 == nil || pool.SqrtPriceX96.Sign() <= 0 {
		t.Fatal("frozen pool should have valid sqrtPriceX96")
	}

	// Reading positions should still work.
	pos, err := pm.GetPosition(stateDB, keyAB, testLP, -120, 120, [32]byte{})
	if err != nil {
		t.Fatalf("GetPosition on frozen pool should succeed: %v", err)
	}
	if pos == nil {
		t.Fatal("expected non-nil position from frozen pool")
	}
}

// =========================================================================
// 18. Register ExternalVenue, quote returns best price from venue
// =========================================================================

func TestPauseFreeze_ExternalVenueQuote(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Register an external venue offering 5x pricing.
	venue := &mockVenue{
		id: [32]byte{0xEE},
		quoteFunc: func(_, _ common.Address, amountIn *big.Int) (*big.Int, error) {
			return new(big.Int).Mul(amountIn, big.NewInt(5)), nil
		},
	}
	router.RegisterVenue(venue)

	// No V4 pool. External venue should appear in quotes.
	quotes, err := router.QuoteExactInputSingle(stateDB, testTokenA, testTokenB, big.NewInt(2000), 0)
	if err != nil {
		t.Fatalf("QuoteExactInputSingle with external venue failed: %v", err)
	}

	found := false
	for _, q := range quotes {
		if q.Venue == VenueExternal {
			found = true
			expected := big.NewInt(10000)
			if q.AmountOut.Cmp(expected) != 0 {
				t.Errorf("expected %s from external venue, got %s", expected, q.AmountOut)
			}
		}
	}
	if !found {
		t.Fatal("expected external venue in quote results")
	}
}

// =========================================================================
// 19. External venue blocked from execution (ErrNoOnChainLiquidity)
// =========================================================================

func TestPauseFreeze_ExternalVenueBlockedInExecution(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// External venue with good pricing.
	router.RegisterVenue(&mockVenue{
		id: [32]byte{0xEE},
		quoteFunc: func(_, _ common.Address, amountIn *big.Int) (*big.Int, error) {
			return new(big.Int).Mul(amountIn, big.NewInt(10)), nil
		},
	})

	// No V4 pool. Execution must fail: external venues are quote-only.
	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(5000),
	}

	_, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error: external venue must not settle on-chain")
	}
}

// =========================================================================
// 20. Multi-hop: A->B->C where both are V4 pools
// =========================================================================

func TestPauseFreeze_MultiHopV4(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)

	params := SwapExactInputParams{
		Path:     []common.Address{testTokenA, testTokenB, testTokenC},
		AmountIn: big.NewInt(10_000),
	}

	amountOut, err := router.ExactInput(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("multi-hop A->B->C failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}
}

// =========================================================================
// 21. Multi-hop with paused intermediate pool -> error propagates
// =========================================================================

func TestPauseFreeze_MultiHopPausedIntermediate(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	keyAB := setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)

	// Pause the A/B pool (intermediate in A->B->C).
	poolIdAB := keyAB.ID()
	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	params := SwapExactInputParams{
		Path:     []common.Address{testTokenA, testTokenB, testTokenC},
		AmountIn: big.NewInt(10_000),
	}

	_, err := router.ExactInput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error when intermediate pool is paused")
	}
	t.Logf("multi-hop correctly failed with paused intermediate: %v", err)
}

// =========================================================================
// 22. ExactOutput multi-hop with pause -> error
// =========================================================================

func TestPauseFreeze_ExactOutputMultiHopPaused(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	keyBC := setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)

	// Pause the B/C pool.
	poolIdBC := keyBC.ID()
	if err := pm.PausePool(stateDB, admin, poolIdBC); err != nil {
		t.Fatalf("PausePool B/C failed: %v", err)
	}

	// ExactOutput path is reversed: [C, B, A] means want C, pay in A.
	params := SwapExactOutputParams{
		Path:      []common.Address{testTokenC, testTokenB, testTokenA},
		AmountOut: big.NewInt(3_000),
	}

	_, err := router.ExactOutput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error when pool in exact-output path is paused")
	}
	t.Logf("exact-output correctly failed with paused pool: %v", err)
}

// =========================================================================
// 23. After PauseDEX, verify stateDB.SetState was called with correct key
// =========================================================================

func TestPauseFreeze_StoragePersistencePauseDEX(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	// Verify the pause state was persisted to storage.
	storageKey := makeStorageKey(pauseStatePrefix, []byte("dex"))
	val := stateDB.GetState(poolManagerAddr, storageKey)
	if val[31] != 1 {
		t.Fatalf("expected storage value byte[31] = 1, got %d", val[31])
	}

	// All other bytes should be zero.
	for i := 0; i < 31; i++ {
		if val[i] != 0 {
			t.Fatalf("expected storage value byte[%d] = 0, got %d", i, val[i])
		}
	}

	// After resume, storage should be cleared.
	if err := pm.ResumeDEX(stateDB, admin); err != nil {
		t.Fatalf("ResumeDEX failed: %v", err)
	}

	val = stateDB.GetState(poolManagerAddr, storageKey)
	if val != (common.Hash{}) {
		t.Fatalf("expected zero storage after resume, got %x", val)
	}
}

// =========================================================================
// 24. After FreezePool, verify freeze key set and pause key cleared
// =========================================================================

func TestPauseFreeze_StoragePersistenceFreezePool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, _ := initTwoPoolsPF(t, pm, stateDB)

	// Pause first, then freeze. Freeze should clear pause storage.
	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	// Verify pause key is set.
	pauseKey := makeStorageKey(pauseStatePrefix, poolIdAB[:])
	pauseVal := stateDB.GetState(poolManagerAddr, pauseKey)
	if pauseVal[31] != 1 {
		t.Fatalf("pause storage should be set after PausePool, byte[31] = %d", pauseVal[31])
	}

	// Freeze.
	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Freeze key should be set.
	freezeKey := makeStorageKey(freezeStatePrefix, poolIdAB[:])
	freezeVal := stateDB.GetState(poolManagerAddr, freezeKey)
	if freezeVal[31] != 1 {
		t.Fatalf("freeze storage should be set after FreezePool, byte[31] = %d", freezeVal[31])
	}

	// Pause key should be cleared.
	pauseVal = stateDB.GetState(poolManagerAddr, pauseKey)
	if pauseVal != (common.Hash{}) {
		t.Fatalf("pause storage should be cleared after FreezePool, got %x", pauseVal)
	}
}

// =========================================================================
// Additional edge cases for completeness
// =========================================================================

// TestPauseFreeze_PausePoolDoesNotAffectModifyLiquidityOnOtherPool verifies
// that ModifyLiquidity on a different pool is unaffected by a single pool pause.
func TestPauseFreeze_PausePoolDoesNotAffectModifyLiquidityOnOtherPool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, keyBC, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	// ModifyLiquidity on B/C should still work.
	params := ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      120,
		LiquidityDelta: big.NewInt(500),
	}
	_, _, err := pm.ModifyLiquidity(stateDB, testLP, keyBC, params, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity on B/C should succeed while A/B paused: %v", err)
	}
}

// TestPauseFreeze_FreezePoolDoesNotAffectDonateOnOtherPool verifies
// that Donate on a different pool is unaffected by a single pool freeze.
func TestPauseFreeze_FreezePoolDoesNotAffectDonateOnOtherPool(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, keyBC, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Donate on B/C should still work.
	_, err := pm.Donate(stateDB, testCaller, keyBC, big.NewInt(100), big.NewInt(100))
	if err != nil {
		t.Fatalf("Donate on B/C should succeed while A/B frozen: %v", err)
	}
}

// TestPauseFreeze_PauseDEXBlocksAllPools verifies that DEX-level pause
// blocks operations on ALL pools, not just a specific one.
func TestPauseFreeze_PauseDEXBlocksAllPools(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	keyAB, _, keyBC, _ := initTwoPoolsPF(t, pm, stateDB)

	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	// Both pools should be blocked.
	_, err := pm.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused on pool A/B, got: %v", err)
	}

	_, err = pm.Swap(stateDB, testCaller, keyBC, swapParams(), nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("expected ErrDEXPaused on pool B/C, got: %v", err)
	}
}

// TestPauseFreeze_IsPausedIsFrozenAccessors tests the boolean accessors.
func TestPauseFreeze_IsPausedIsFrozenAccessors(t *testing.T) {
	pm := newPauseTestPM()
	stateDB := NewMockStateDB()
	_, poolIdAB, _, poolIdBC := initTwoPoolsPF(t, pm, stateDB)

	// Initial state: nothing paused or frozen.
	if pm.IsPaused() {
		t.Fatal("DEX should not be paused initially")
	}
	if pm.IsPoolPaused(poolIdAB) {
		t.Fatal("pool A/B should not be paused initially")
	}
	if pm.IsPoolFrozen(poolIdAB) {
		t.Fatal("pool A/B should not be frozen initially")
	}

	// Pause DEX.
	if err := pm.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}
	if !pm.IsPaused() {
		t.Fatal("DEX should be paused after PauseDEX")
	}

	// Resume.
	if err := pm.ResumeDEX(stateDB, admin); err != nil {
		t.Fatalf("ResumeDEX failed: %v", err)
	}
	if pm.IsPaused() {
		t.Fatal("DEX should not be paused after ResumeDEX")
	}

	// Pause pool A/B.
	if err := pm.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}
	if !pm.IsPoolPaused(poolIdAB) {
		t.Fatal("pool A/B should be paused")
	}
	if pm.IsPoolPaused(poolIdBC) {
		t.Fatal("pool B/C should not be paused")
	}

	// Freeze pool B/C.
	if err := pm.FreezePool(stateDB, admin, poolIdBC); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}
	if !pm.IsPoolFrozen(poolIdBC) {
		t.Fatal("pool B/C should be frozen")
	}
	if pm.IsPoolFrozen(poolIdAB) {
		t.Fatal("pool A/B should not be frozen")
	}
}

// =========================================================================
// Restart survival: new PoolManager, same StateDB
// =========================================================================

// TestPauseFreeze_DEXPauseSurvivesRestart proves that a DEX-level pause
// persists across a simulated node restart (new PoolManager, same StateDB).
func TestPauseFreeze_DEXPauseSurvivesRestart(t *testing.T) {
	stateDB := NewMockStateDB()

	// Phase 1: pause the DEX
	pm1 := newPauseTestPM()
	keyAB, _, _, _ := initTwoPoolsPF(t, pm1, stateDB)
	if err := pm1.PauseDEX(stateDB, admin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}

	// Phase 2: "restart" — new PoolManager with cold caches, same stateDB.
	// Pool already exists in StateDB from phase 1 — getPool will reload it.
	pm2 := NewPoolManager(&mockEngine{})
	pm2.protocolFeeController = admin

	// Swap should be blocked because checkPauseState reads from StateDB
	_, err := pm2.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrDEXPaused) {
		t.Fatalf("DEX pause should survive restart, got: %v", err)
	}
}

// TestPauseFreeze_PoolFreezeSurvivesRestart proves that a pool freeze
// persists across a simulated node restart.
func TestPauseFreeze_PoolFreezeSurvivesRestart(t *testing.T) {
	stateDB := NewMockStateDB()

	// Phase 1: freeze pool A/B
	pm1 := newPauseTestPM()
	keyAB, poolIdAB, keyBC, _ := initTwoPoolsPF(t, pm1, stateDB)
	if err := pm1.FreezePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}

	// Phase 2: "restart" — new PoolManager
	pm2 := NewPoolManager(&mockEngine{})
	pm2.protocolFeeController = admin

	// Frozen pool A/B should be blocked — checkPauseState reads freeze from StateDB
	_, err := pm2.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolFrozen) {
		t.Fatalf("Pool freeze should survive restart, got: %v", err)
	}

	// Unfrozen pool B/C should work (engine returns zero delta, no error)
	_, err = pm2.Swap(stateDB, testCaller, keyBC, swapParams(), nil)
	if errors.Is(err, ErrPoolFrozen) || errors.Is(err, ErrPoolPaused) || errors.Is(err, ErrDEXPaused) {
		t.Fatalf("Pool B/C should not be affected by A/B freeze after restart, got: %v", err)
	}
}

// TestPauseFreeze_PoolPauseSurvivesRestart proves that a pool pause
// persists across a simulated node restart.
func TestPauseFreeze_PoolPauseSurvivesRestart(t *testing.T) {
	stateDB := NewMockStateDB()

	// Phase 1: pause pool A/B
	pm1 := newPauseTestPM()
	keyAB, poolIdAB, _, _ := initTwoPoolsPF(t, pm1, stateDB)
	if err := pm1.PausePool(stateDB, admin, poolIdAB); err != nil {
		t.Fatalf("PausePool failed: %v", err)
	}

	// Phase 2: "restart"
	pm2 := NewPoolManager(&mockEngine{})
	pm2.protocolFeeController = admin

	_, err := pm2.Swap(stateDB, testCaller, keyAB, swapParams(), nil)
	if !errors.Is(err, ErrPoolPaused) {
		t.Fatalf("Pool pause should survive restart, got: %v", err)
	}
}

// =========================================================================
// State persistence: Pool fees and Position fields survive restarts (H1/H2)
// =========================================================================

// TestPoolFeeGrowthPersistence verifies that FeeGrowth0X128, FeeGrowth1X128,
// ProtocolFees0, and ProtocolFees1 survive a simulated restart.
func TestPoolFeeGrowthPersistence(t *testing.T) {
	stateDB := NewMockStateDB()
	pm1 := newPauseTestPM()
	keyAB, _, _, _ := initTwoPoolsPF(t, pm1, stateDB)
	poolId := keyAB.ID()

	// Set fee growth values directly on the pool
	pool := pm1.getPool(stateDB, poolId)
	pool.FeeGrowth0X128 = big.NewInt(123456789)
	pool.FeeGrowth1X128 = big.NewInt(987654321)
	pool.ProtocolFees0 = big.NewInt(5000)
	pool.ProtocolFees1 = big.NewInt(6000)
	pm1.setPool(stateDB, poolId, pool)

	// "Restart" — new PoolManager, cold cache
	pm2 := NewPoolManager(&mockEngine{})
	pm2.protocolFeeController = admin

	pool2 := pm2.getPool(stateDB, poolId)
	if pool2.FeeGrowth0X128.Cmp(big.NewInt(123456789)) != 0 {
		t.Fatalf("FeeGrowth0X128 should survive restart: got %s", pool2.FeeGrowth0X128)
	}
	if pool2.FeeGrowth1X128.Cmp(big.NewInt(987654321)) != 0 {
		t.Fatalf("FeeGrowth1X128 should survive restart: got %s", pool2.FeeGrowth1X128)
	}
	if pool2.ProtocolFees0.Cmp(big.NewInt(5000)) != 0 {
		t.Fatalf("ProtocolFees0 should survive restart: got %s", pool2.ProtocolFees0)
	}
	if pool2.ProtocolFees1.Cmp(big.NewInt(6000)) != 0 {
		t.Fatalf("ProtocolFees1 should survive restart: got %s", pool2.ProtocolFees1)
	}
}

// TestPositionFieldsPersistence verifies that all Position fields (Liquidity,
// FeeGrowthInside0/1LastX128, TokensOwed0/1) survive a simulated restart.
func TestPositionFieldsPersistence(t *testing.T) {
	stateDB := NewMockStateDB()
	pm1 := newPauseTestPM()

	owner := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var salt [32]byte
	posKey := PositionKey(owner, -120, 120, salt)

	// Set all position fields
	pos := &Position{
		Liquidity:                big.NewInt(500000),
		FeeGrowthInside0LastX128: big.NewInt(111222333),
		FeeGrowthInside1LastX128: big.NewInt(444555666),
		TokensOwed0:              big.NewInt(7777),
		TokensOwed1:              big.NewInt(8888),
	}
	pm1.setPosition(stateDB, posKey, pos)

	// "Restart"
	pm2 := NewPoolManager(&mockEngine{})
	pos2 := pm2.getPosition(stateDB, posKey)

	if pos2.Liquidity.Cmp(big.NewInt(500000)) != 0 {
		t.Fatalf("Liquidity should survive restart: got %s", pos2.Liquidity)
	}
	if pos2.FeeGrowthInside0LastX128.Cmp(big.NewInt(111222333)) != 0 {
		t.Fatalf("FeeGrowthInside0LastX128 should survive restart: got %s", pos2.FeeGrowthInside0LastX128)
	}
	if pos2.FeeGrowthInside1LastX128.Cmp(big.NewInt(444555666)) != 0 {
		t.Fatalf("FeeGrowthInside1LastX128 should survive restart: got %s", pos2.FeeGrowthInside1LastX128)
	}
	if pos2.TokensOwed0.Cmp(big.NewInt(7777)) != 0 {
		t.Fatalf("TokensOwed0 should survive restart: got %s", pos2.TokensOwed0)
	}
	if pos2.TokensOwed1.Cmp(big.NewInt(8888)) != 0 {
		t.Fatalf("TokensOwed1 should survive restart: got %s", pos2.TokensOwed1)
	}
}
