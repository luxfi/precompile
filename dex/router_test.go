// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

var (
	testTokenA = common.HexToAddress("0x1000000000000000000000000000000000000001")
	testTokenB = common.HexToAddress("0x2000000000000000000000000000000000000002")
	testTokenC = common.HexToAddress("0x3000000000000000000000000000000000000003")
	testLP     = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	testCaller = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
)

// setupV4Pool creates and initializes a V4 pool with liquidity for testing.
func setupV4Pool(t *testing.T, pm *PoolManager, stateDB StateDB, c0, c1 common.Address) PoolKey {
	t.Helper()
	key := PoolKey{
		Currency0:   Currency{Address: c0},
		Currency1:   Currency{Address: c1},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}
	tick, err := pm.Initialize(stateDB, key, new(big.Int).Set(Q96), nil)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Use tick range that encompasses the actual tick returned by Initialize
	tickLower := tick - 10000
	tickUpper := tick + 10000
	if tickLower < MinTick {
		tickLower = MinTick
	}
	if tickUpper > MaxTick {
		tickUpper = MaxTick
	}

	// Add liquidity
	_, _, err = pm.ModifyLiquidity(stateDB, testLP, key, ModifyLiquidityParams{
		TickLower:      tickLower,
		TickUpper:      tickUpper,
		LiquidityDelta: big.NewInt(1_000_000),
	}, nil)
	if err != nil {
		t.Fatalf("ModifyLiquidity failed: %v", err)
	}

	return key
}

func TestRouterQuoteV4(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	amountIn := big.NewInt(10_000)
	amount, poolID, poolKey, err := router.quoteV4(stateDB, testTokenA, testTokenB, amountIn, 0)
	if err != nil {
		t.Fatalf("quoteV4 failed: %v", err)
	}
	if amount.Sign() <= 0 {
		t.Fatalf("expected positive quote, got %s", amount)
	}
	if poolID == ([32]byte{}) {
		t.Fatal("expected non-zero pool ID")
	}
	if poolKey.Fee == 0 {
		t.Fatal("expected non-zero pool key fee from quoteV4")
	}

	t.Logf("V4 quote: %s in -> %s out (pool=%x)", amountIn, amount, poolID[:4])
}

func TestRouterQuoteNoPool(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	_, _, _, err := router.quoteV4(stateDB, testTokenA, testTokenB, big.NewInt(1000), 0)
	if err == nil {
		t.Fatal("expected error for non-existent pool")
	}
}

func TestRouterExactInputSingleV4(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(10_000),
	}

	amountOut, venue, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("ExactInputSingle failed: %v", err)
	}
	if venue != VenueV4Native {
		t.Errorf("expected VenueV4Native, got %d", venue)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}

	t.Logf("Router swap: 10000 -> %s via V4", amountOut)
}

func TestRouterExactInputMultiHop(t *testing.T) {
	pm := NewPoolManager()
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
		t.Fatalf("ExactInput multi-hop failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}

	t.Logf("Multi-hop swap: 10000 A -> B -> C = %s", amountOut)
}

func TestRouterGetBestRoute(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	best, err := router.GetBestRoute(stateDB, testTokenA, testTokenB, big.NewInt(10_000))
	if err != nil {
		t.Fatalf("GetBestRoute failed: %v", err)
	}
	if best.Venue != VenueV4Native {
		t.Errorf("expected VenueV4Native, got %d", best.Venue)
	}
	if best.AmountOut.Sign() <= 0 {
		t.Fatalf("expected positive amount, got %s", best.AmountOut)
	}

	t.Logf("Best route: V4 pool %x, output: %s, gas: %d", best.PoolID[:4], best.AmountOut, best.GasEstimate)
}

func TestRouterFallbackOrder(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// No V4 pool, V3/V2 not configured — should get error
	quotes, err := router.QuoteExactInputSingle(stateDB, testTokenA, testTokenB, big.NewInt(1000), 0)
	if err == nil {
		t.Fatal("expected error when no venues available")
	}
	if quotes != nil {
		t.Fatal("expected nil quotes")
	}
}

func TestRouterModuleRegistration(t *testing.T) {
	if RouterModule.Address != lxRouterAddr {
		t.Errorf("expected router at %s, got %s", lxRouterAddr, RouterModule.Address)
	}
	if RouterModule.ConfigKey != RouterConfigKey {
		t.Errorf("expected config key %s, got %s", RouterConfigKey, RouterModule.ConfigKey)
	}
	if RouterPrecompile == nil {
		t.Fatal("RouterPrecompile is nil")
	}
	if RouterPrecompile.router == nil {
		t.Fatal("Router instance is nil")
	}
}

func TestRouterEncodeDecodeParams(t *testing.T) {
	amountIn := big.NewInt(50000)

	input := make([]byte, 75)
	copy(input[0:20], testTokenA.Bytes())
	copy(input[20:40], testTokenB.Bytes())
	copy(input[40:72], common.LeftPadBytes(amountIn.Bytes(), 32))
	input[72] = 0x00
	input[73] = 0x0B
	input[74] = 0xB8 // fee = 3000

	gotIn, gotOut, gotAmount, gotFee, err := DecodeQuoteParams(input)
	if err != nil {
		t.Fatalf("DecodeQuoteParams failed: %v", err)
	}
	if gotIn != testTokenA {
		t.Errorf("tokenIn mismatch: got %s, want %s", gotIn, testTokenA)
	}
	if gotOut != testTokenB {
		t.Errorf("tokenOut mismatch: got %s, want %s", gotOut, testTokenB)
	}
	if gotAmount.Cmp(amountIn) != 0 {
		t.Errorf("amountIn mismatch: got %s, want %s", gotAmount, amountIn)
	}
	if gotFee != 3000 {
		t.Errorf("fee mismatch: got %d, want 3000", gotFee)
	}
}

func TestRouterMinimumOutput(t *testing.T) {
	pm := NewPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	// Set unreachable minimum output
	params := SwapExactInputSingleParams{
		TokenIn:          testTokenA,
		TokenOut:         testTokenB,
		AmountIn:         big.NewInt(100),
		AmountOutMinimum: big.NewInt(1_000_000_000), // way more than pool liquidity
	}

	_, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error for insufficient output")
	}
	t.Logf("Correctly rejected: %v", err)
}
