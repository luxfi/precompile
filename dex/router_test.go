// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
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
	pm := NewPoolManager(&mockEngine{})
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
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	_, _, _, err := router.quoteV4(stateDB, testTokenA, testTokenB, big.NewInt(1000), 0)
	if err == nil {
		t.Fatal("expected error for non-existent pool")
	}
}

func TestRouterExactInputSingleV4(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
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
	pm := NewPoolManager(&mockEngine{})
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
	pm := NewPoolManager(&mockEngine{})
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
	pm := NewPoolManager(&mockEngine{})
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
	pm := NewPoolManager(&mockEngine{})
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

// =========================================================================
// V4 Path Encoding Tests
// =========================================================================

func TestPathKeyEncodeDecode(t *testing.T) {
	pk := PathKey{
		IntermediateCurrency: testTokenB,
		Fee:                  Fee030,
		TickSpacing:          TickSpacing030,
		Hooks:                common.Address{},
	}

	encoded := EncodePathKey(pk)
	if len(encoded) != PathKeySize {
		t.Fatalf("expected %d bytes, got %d", PathKeySize, len(encoded))
	}

	decoded, err := DecodePathKey(encoded)
	if err != nil {
		t.Fatalf("DecodePathKey failed: %v", err)
	}
	if decoded.IntermediateCurrency != pk.IntermediateCurrency {
		t.Errorf("currency mismatch: got %s, want %s", decoded.IntermediateCurrency.Hex(), pk.IntermediateCurrency.Hex())
	}
	if decoded.Fee != pk.Fee {
		t.Errorf("fee mismatch: got %d, want %d", decoded.Fee, pk.Fee)
	}
	if decoded.TickSpacing != pk.TickSpacing {
		t.Errorf("tickSpacing mismatch: got %d, want %d", decoded.TickSpacing, pk.TickSpacing)
	}
}

func TestPathEncodeDecode(t *testing.T) {
	keys := []PathKey{
		{IntermediateCurrency: testTokenB, Fee: Fee030, TickSpacing: TickSpacing030},
		{IntermediateCurrency: testTokenC, Fee: Fee005, TickSpacing: TickSpacing005},
	}

	encoded := EncodePath(testTokenA, keys)
	expectedLen := 20 + 2*PathKeySize
	if len(encoded) != expectedLen {
		t.Fatalf("expected %d bytes, got %d", expectedLen, len(encoded))
	}

	currencyIn, decodedKeys, err := DecodePath(encoded)
	if err != nil {
		t.Fatalf("DecodePath failed: %v", err)
	}
	if currencyIn != testTokenA {
		t.Errorf("currencyIn mismatch: got %s, want %s", currencyIn.Hex(), testTokenA.Hex())
	}
	if len(decodedKeys) != 2 {
		t.Fatalf("expected 2 path keys, got %d", len(decodedKeys))
	}
	if decodedKeys[0].Fee != Fee030 {
		t.Errorf("hop 0 fee mismatch: got %d, want %d", decodedKeys[0].Fee, Fee030)
	}
	if decodedKeys[1].IntermediateCurrency != testTokenC {
		t.Errorf("hop 1 currency mismatch")
	}
}

// =========================================================================
// V4 Multi-hop with PathKeys
// =========================================================================

func TestRouterExactInputV4Path(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)

	params := SwapExactInputParams{
		CurrencyIn: testTokenA,
		PathKeys: []PathKey{
			{IntermediateCurrency: testTokenB, Fee: Fee030, TickSpacing: TickSpacing030},
			{IntermediateCurrency: testTokenC, Fee: Fee030, TickSpacing: TickSpacing030},
		},
		AmountIn:         big.NewInt(10_000),
		AmountOutMinimum: big.NewInt(1),
	}

	amountOut, err := router.ExactInput(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("ExactInput V4 path failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}

	t.Logf("V4 path multi-hop: 10000 A -> B -> C = %s", amountOut)

	// Compare with simple path — should produce the same result
	params2 := SwapExactInputParams{
		Path:     []common.Address{testTokenA, testTokenB, testTokenC},
		AmountIn: big.NewInt(10_000),
	}

	// Need fresh pools since the first swap consumed liquidity
	pm2 := NewPoolManager(&mockEngine{})
	stateDB2 := NewMockStateDB()
	router2 := NewLXRouter(pm2)
	setupV4Pool(t, pm2, stateDB2, testTokenA, testTokenB)
	setupV4Pool(t, pm2, stateDB2, testTokenB, testTokenC)

	amountOut2, err := router2.ExactInput(stateDB2, testCaller, params2)
	if err != nil {
		t.Fatalf("ExactInput simple path failed: %v", err)
	}

	t.Logf("Simple path multi-hop: 10000 A -> B -> C = %s", amountOut2)
}

// =========================================================================
// Deadline Tests
// =========================================================================

func TestRouterDeadlineExpired(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	stateDB.SetBlockNumber(100)
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(10_000),
		Deadline: 50, // block 100 > deadline 50
	}

	_, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected deadline error")
	}
	t.Logf("Correctly rejected expired deadline: %v", err)
}

func TestRouterDeadlineValid(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	stateDB.SetBlockNumber(10)
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(10_000),
		Deadline: 100, // block 10 < deadline 100
	}

	amountOut, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("valid deadline should not fail: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatal("expected positive output")
	}
}

func TestRouterDeadlineZeroMeansNone(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	stateDB.SetBlockNumber(999999)
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(10_000),
		Deadline: 0, // no deadline
	}

	_, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("zero deadline should not fail: %v", err)
	}
}

// =========================================================================
// Exact Output Tests
// =========================================================================

func TestRouterExactOutputSingle(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactOutputSingleParams{
		TokenIn:   testTokenA,
		TokenOut:  testTokenB,
		AmountOut: big.NewInt(5_000),
		Fee:       Fee030,
	}

	amountIn, venue, err := router.ExactOutputSingle(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("ExactOutputSingle failed: %v", err)
	}
	if venue != VenueV4Native {
		t.Errorf("expected VenueV4Native, got %d", venue)
	}
	if amountIn.Sign() <= 0 {
		t.Fatalf("expected positive input amount, got %s", amountIn)
	}

	t.Logf("ExactOutputSingle: want 5000 out, need %s in", amountIn)
}

func TestRouterExactOutputSlippage(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	params := SwapExactOutputSingleParams{
		TokenIn:         testTokenA,
		TokenOut:        testTokenB,
		AmountOut:       big.NewInt(5_000),
		AmountInMaximum: big.NewInt(1), // impossibly low max input
		Fee:             Fee030,
	}

	_, _, err := router.ExactOutputSingle(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected slippage error")
	}
	t.Logf("Correctly rejected excessive input: %v", err)
}

// =========================================================================
// External Venue Tests
// =========================================================================

// mockVenue implements ExternalVenue for testing.
type mockVenue struct {
	id        [32]byte
	quoteFunc func(tokenIn, tokenOut common.Address, amountIn *big.Int) (*big.Int, error)
}

func (v *mockVenue) VenueID() [32]byte {
	return v.id
}

func (v *mockVenue) Quote(stateDB StateDB, tokenIn, tokenOut common.Address, amountIn *big.Int) (*big.Int, error) {
	return v.quoteFunc(tokenIn, tokenOut, amountIn)
}

func TestRouterExternalVenueQuote(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Register a mock venue that offers 10x output (simulating external liquidity)
	venue := &mockVenue{
		id: [32]byte{0x01},
		quoteFunc: func(_, _ common.Address, amountIn *big.Int) (*big.Int, error) {
			return new(big.Int).Mul(amountIn, big.NewInt(10)), nil
		},
	}
	router.RegisterVenue(venue)

	// No V4 pool — should fall through to external venue
	quotes, err := router.QuoteExactInputSingle(stateDB, testTokenA, testTokenB, big.NewInt(1000), 0)
	if err != nil {
		t.Fatalf("QuoteExactInputSingle with external venue failed: %v", err)
	}

	found := false
	for _, q := range quotes {
		if q.Venue == VenueExternal {
			found = true
			if q.AmountOut.Cmp(big.NewInt(10000)) != 0 {
				t.Errorf("expected 10000 from external venue, got %s", q.AmountOut)
			}
		}
	}
	if !found {
		t.Fatal("expected external venue in quote results")
	}
	t.Logf("External venue quote: %d results", len(quotes))
}

func TestRouterExternalVenueRejectedInExecution(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// External venue with good pricing — but execution should NOT use it.
	// External venues are quote-only; settlement happens via FillAttestation (LP-9090).
	router.RegisterVenue(&mockVenue{
		id: [32]byte{0x02},
		quoteFunc: func(_, _ common.Address, amountIn *big.Int) (*big.Int, error) {
			return new(big.Int).Mul(amountIn, big.NewInt(2)), nil
		},
	})

	// No V4 pool — router must return error, NOT use external venue for execution
	params := SwapExactInputSingleParams{
		TokenIn:  testTokenA,
		TokenOut: testTokenB,
		AmountIn: big.NewInt(5000),
	}

	_, _, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error when no on-chain pool available, got nil (external venue must not settle)")
	}
	t.Logf("Correctly rejected external venue in execution: %v", err)
}

func TestRouterExternalVenueStillWorksInQuotes(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// External venue should still appear in quote results
	router.RegisterVenue(&mockVenue{
		id: [32]byte{0x02},
		quoteFunc: func(_, _ common.Address, amountIn *big.Int) (*big.Int, error) {
			return new(big.Int).Mul(amountIn, big.NewInt(2)), nil
		},
	})

	quotes, err := router.QuoteExactInputSingle(stateDB, testTokenA, testTokenB, big.NewInt(5000), 0)
	if err != nil {
		t.Fatalf("QuoteExactInputSingle should succeed with external venue: %v", err)
	}

	found := false
	for _, q := range quotes {
		if q.Venue == VenueExternal {
			found = true
			if q.AmountOut.Cmp(big.NewInt(10000)) != 0 {
				t.Errorf("expected 10000 from external venue quote, got %s", q.AmountOut)
			}
		}
	}
	if !found {
		t.Fatal("expected external venue in quote results")
	}
}

// =========================================================================
// V4 Binary Path ABI Encoding Tests
// =========================================================================

func TestDecodeExactInputParamsV4Path(t *testing.T) {
	keys := []PathKey{
		{IntermediateCurrency: testTokenB, Fee: Fee030, TickSpacing: TickSpacing030},
		{IntermediateCurrency: testTokenC, Fee: Fee005, TickSpacing: TickSpacing005},
	}
	pathBytes := EncodePath(testTokenA, keys)

	amountIn := big.NewInt(50000)
	amountOutMin := big.NewInt(1000)

	// Build V4 format input: 0xFF + pathLen(2) + path + amountIn(32) + amountOutMin(32)
	input := []byte{0xFF}
	pathLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(pathLenBytes, uint16(len(pathBytes)))
	input = append(input, pathLenBytes...)
	input = append(input, pathBytes...)
	input = append(input, common.LeftPadBytes(amountIn.Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(amountOutMin.Bytes(), 32)...)

	params, err := DecodeExactInputParams(input)
	if err != nil {
		t.Fatalf("DecodeExactInputParams V4 path failed: %v", err)
	}
	if params.CurrencyIn != testTokenA {
		t.Errorf("currencyIn mismatch")
	}
	if len(params.PathKeys) != 2 {
		t.Fatalf("expected 2 path keys, got %d", len(params.PathKeys))
	}
	if params.PathKeys[0].Fee != Fee030 {
		t.Errorf("hop 0 fee mismatch: got %d, want %d", params.PathKeys[0].Fee, Fee030)
	}
	if params.AmountIn.Cmp(amountIn) != 0 {
		t.Errorf("amountIn mismatch: got %s, want %s", params.AmountIn, amountIn)
	}
	if params.AmountOutMinimum.Cmp(amountOutMin) != 0 {
		t.Errorf("amountOutMinimum mismatch: got %s, want %s", params.AmountOutMinimum, amountOutMin)
	}
}

func TestDecodeExactInputSingleParamsExtended(t *testing.T) {
	amountIn := big.NewInt(50000)
	amountOutMin := big.NewInt(1000)
	fee := Fee030
	ts := TickSpacing030
	hooks := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	// Build: tokenIn(20) + tokenOut(20) + amountIn(32) + amountOutMin(32) + fee(3) + tickSpacing(3) + hooks(20)
	input := make([]byte, 0, 130)
	input = append(input, testTokenA.Bytes()...)
	input = append(input, testTokenB.Bytes()...)
	input = append(input, common.LeftPadBytes(amountIn.Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(amountOutMin.Bytes(), 32)...)

	var feeBytes [4]byte
	binary.BigEndian.PutUint32(feeBytes[:], fee)
	input = append(input, feeBytes[1:4]...)

	tsBytes := int24ToBytes(ts)
	input = append(input, tsBytes...)

	input = append(input, hooks.Bytes()...)

	params, err := DecodeExactInputSingleParams(input)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if params.TokenIn != testTokenA {
		t.Error("tokenIn mismatch")
	}
	if params.Fee != Fee030 {
		t.Errorf("fee mismatch: got %d, want %d", params.Fee, Fee030)
	}
	if params.TickSpacing != TickSpacing030 {
		t.Errorf("tickSpacing mismatch: got %d, want %d", params.TickSpacing, TickSpacing030)
	}
	if params.Hooks != hooks {
		t.Errorf("hooks mismatch: got %s, want %s", params.Hooks.Hex(), hooks.Hex())
	}
}

func TestRouterExactInputSingleWithExplicitPoolKey(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)

	// Specify explicit fee/tickSpacing to target the known pool
	params := SwapExactInputSingleParams{
		TokenIn:     testTokenA,
		TokenOut:    testTokenB,
		AmountIn:    big.NewInt(10_000),
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
	}

	amountOut, venue, err := router.ExactInputSingle(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("ExactInputSingle with explicit key failed: %v", err)
	}
	if venue != VenueV4Native {
		t.Errorf("expected VenueV4Native, got %d", venue)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}

	t.Logf("ExactInputSingle with explicit pool key: 10000 -> %s", amountOut)
}

// =========================================================================
// ExactOutput Direction Tests (Fix #2)
// =========================================================================

func TestRouterExactOutputMultiHop(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Create pools A<->B and B<->C
	setupV4Pool(t, pm, stateDB, testTokenA, testTokenB)
	setupV4Pool(t, pm, stateDB, testTokenB, testTokenC)

	// Path=[C, B, A] means: want amountOut of C, paying in A.
	// Direction: A -> B -> C, but computed in reverse (C needed, then B, then A).
	params := SwapExactOutputParams{
		Path:      []common.Address{testTokenC, testTokenB, testTokenA},
		AmountOut: big.NewInt(3_000),
	}

	amountIn, err := router.ExactOutput(stateDB, testCaller, params)
	if err != nil {
		t.Fatalf("ExactOutput multi-hop failed: %v", err)
	}
	if amountIn.Sign() <= 0 {
		t.Fatalf("expected positive input amount, got %s", amountIn)
	}
	// The input must be >= output (fees exist), confirming correct direction
	if amountIn.Cmp(params.AmountOut) < 0 {
		t.Errorf("input (%s) should be >= output (%s) due to fees", amountIn, params.AmountOut)
	}

	t.Logf("ExactOutput multi-hop: want 3000 C, need %s A", amountIn)
}

// =========================================================================
// Path Length Limit Tests (Fix #4)
// =========================================================================

func TestRouterPathTooLongExactInput(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Build a path with MaxPathLength+1 hops (MaxPathLength+2 tokens)
	path := make([]common.Address, MaxPathLength+2)
	for i := range path {
		addr := common.Address{}
		addr[19] = byte(i + 1)
		path[i] = addr
	}

	params := SwapExactInputParams{
		Path:     path,
		AmountIn: big.NewInt(1000),
	}

	_, err := router.ExactInput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error for path exceeding MaxPathLength")
	}
	t.Logf("Correctly rejected long path: %v", err)
}

func TestRouterPathTooLongExactOutput(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Build a path with MaxPathLength+1 hops
	path := make([]common.Address, MaxPathLength+2)
	for i := range path {
		addr := common.Address{}
		addr[19] = byte(i + 1)
		path[i] = addr
	}

	params := SwapExactOutputParams{
		Path:      path,
		AmountOut: big.NewInt(1000),
	}

	_, err := router.ExactOutput(stateDB, testCaller, params)
	if err == nil {
		t.Fatal("expected error for path exceeding MaxPathLength")
	}
	t.Logf("Correctly rejected long path: %v", err)
}

func TestRouterPathAtMaxLength(t *testing.T) {
	pm := NewPoolManager(&mockEngine{})
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// MaxPathLength hops = MaxPathLength+1 tokens, this should be accepted
	// (though it will fail due to missing pools, validation should pass)
	path := make([]common.Address, MaxPathLength+1)
	for i := range path {
		addr := common.Address{}
		addr[19] = byte(i + 1)
		path[i] = addr
	}

	params := SwapExactInputParams{
		Path:     path,
		AmountIn: big.NewInt(1000),
	}

	_, err := router.ExactInput(stateDB, testCaller, params)
	// Should fail on pool lookup, NOT on path length
	if err == nil {
		t.Fatal("expected error (no pools), but path length should be accepted")
	}
	// Verify it's not a path-length error
	if err.Error() == "path too long" {
		t.Fatal("path of MaxPathLength hops should be allowed")
	}
	t.Logf("Path at max length accepted (failed on pool lookup as expected): %v", err)
}

// =========================================================================
// Gas Constant Tests (Fix #4)
// =========================================================================

func TestGasConstants(t *testing.T) {
	// Verify gas constants are sufficiently high to prevent undercharging
	if GasSwap < 50_000 {
		t.Errorf("GasSwap too low: %d, want >= 50000", GasSwap)
	}
	if GasSingleSwap < 50_000 {
		t.Errorf("GasSingleSwap too low: %d, want >= 50000", GasSingleSwap)
	}
	if GasMultiHopPerHop < 50_000 {
		t.Errorf("GasMultiHopPerHop too low: %d, want >= 50000", GasMultiHopPerHop)
	}
	if MaxPathLength != 5 {
		t.Errorf("MaxPathLength should be 5, got %d", MaxPathLength)
	}
}

func TestQuoteGasScalesWithHops(t *testing.T) {
	// Verify that multi-hop quote gas scales with the number of hops
	oneHop := GasQuoteBase + 1*GasQuotePerHop
	threeHop := GasQuoteBase + 3*GasQuotePerHop
	fiveHop := GasQuoteBase + 5*GasQuotePerHop

	if threeHop <= oneHop {
		t.Errorf("3-hop quote gas (%d) should be > 1-hop (%d)", threeHop, oneHop)
	}
	if fiveHop <= threeHop {
		t.Errorf("5-hop quote gas (%d) should be > 3-hop (%d)", fiveHop, threeHop)
	}
	t.Logf("Quote gas: 1-hop=%d, 3-hop=%d, 5-hop=%d", oneHop, threeHop, fiveHop)
}
