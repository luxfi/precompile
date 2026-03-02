// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// =========================================================================
// Integration test: multi-hop, multi-venue trading through the Partner DEX
//
// Demonstrates how the ATS backend connects to the DEX precompile:
//   - LXRouter routes swaps through V4 pools (on-chain matching)
//   - External venues (Alpaca, Hyperliquid) provide indicative quotes
//   - Actual external execution settles via FillAttestation (LP-9090)
//   - Pause/Freeze controls enforce regulatory compliance
// =========================================================================

// Deterministic token addresses for the test scenario.
var (
	tUSDL = common.HexToAddress("0x0000000000000000000000000000000000000001")
	tWBTC = common.HexToAddress("0x0000000000000000000000000000000000000002")
	tETH  = common.HexToAddress("0x0000000000000000000000000000000000000003")
	tAAPL = common.HexToAddress("0x0000000000000000000000000000000000000004")

	// Admin controls pause/freeze. Must match PoolManager.protocolFeeController.
	intAdmin = common.HexToAddress("0xADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01")

	// ATS MPC wallet: authorized attester for FillAttestations.
	intATSWallet = common.HexToAddress("0xA750000000000000000000000000000000000001")

	// End user placing trades.
	intUser = common.HexToAddress("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0001")
)

// mockAlpacaVenue simulates the Alpaca equities broker.
// Provides indicative quotes for any pair at ~5% spread (0.95x).
type mockAlpacaVenue struct{}

func (v *mockAlpacaVenue) VenueID() [32]byte {
	var id [32]byte
	copy(id[:], []byte("alpaca"))
	return id
}

func (v *mockAlpacaVenue) Quote(stateDB StateDB, tokenIn, tokenOut common.Address, amountIn *big.Int) (*big.Int, error) {
	// Alpaca gives 0.95x the input (simulating ~5% spread for equities)
	return new(big.Int).Div(new(big.Int).Mul(amountIn, big.NewInt(95)), big.NewInt(100)), nil
}

// mockHyperliquidVenue simulates the Hyperliquid perps DEX.
// Provides indicative quotes at ~3% spread (0.97x).
type mockHyperliquidVenue struct{}

func (v *mockHyperliquidVenue) VenueID() [32]byte {
	var id [32]byte
	copy(id[:], []byte("hyperliquid"))
	return id
}

func (v *mockHyperliquidVenue) Quote(stateDB StateDB, tokenIn, tokenOut common.Address, amountIn *big.Int) (*big.Int, error) {
	// Hyperliquid gives 0.97x the input (simulating ~3% spread for perps)
	return new(big.Int).Div(new(big.Int).Mul(amountIn, big.NewInt(97)), big.NewInt(100)), nil
}

// newIntegrationPoolManager creates a PoolManager with the admin set so
// pause/freeze operations are authorized.
func newIntegrationPoolManager() *PoolManager {
	pm := NewPoolManager(&mockEngine{})
	pm.protocolFeeController = intAdmin
	return pm
}

// TestIntegrationMultiHopMultiVenue is the full E2E scenario:
//
//	User wants to swap 10,000 USDL -> ETH via the Partner DEX.
//	The test walks through every step: pool setup, single-hop, multi-hop,
//	multi-venue quoting, external-venue-only fallback, compliance controls,
//	and the simulated ATS order flow with FillAttestation.
func TestIntegrationMultiHopMultiVenue(t *testing.T) {
	t.Run("Step1_Setup", testSetup)
	t.Run("Step2_SingleHopSwap", testSingleHopSwap)
	t.Run("Step3_MultiHopSwap", testMultiHopSwap)
	t.Run("Step4_MultiVenueQuote", testMultiVenueQuote)
	t.Run("Step5_ExternalVenueQuoteOnly", testExternalVenueQuoteOnly)
	t.Run("Step6_PauseFreezeCompliance", testPauseFreezeCompliance)
	t.Run("Step7_ATSOrderFlow", testATSOrderFlow)
}

// =========================================================================
// Step 1: Setup — create pools, add liquidity, register external venues
// =========================================================================

func testSetup(t *testing.T) {
	t.Log("--- Step 1: Pool and venue setup ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Initialize 3 pools: USDL/WBTC, WBTC/ETH, USDL/ETH
	t.Log("Creating pool: USDL/WBTC (Fee030)")
	key1 := setupV4Pool(t, pm, stateDB, tUSDL, tWBTC)
	id1 := key1.ID()
	t.Logf("  Pool ID: %x", id1[:8])

	t.Log("Creating pool: WBTC/ETH (Fee030)")
	key2 := setupV4Pool(t, pm, stateDB, tWBTC, tETH)
	id2 := key2.ID()
	t.Logf("  Pool ID: %x", id2[:8])

	t.Log("Creating pool: USDL/ETH (Fee030)")
	key3 := setupV4Pool(t, pm, stateDB, tUSDL, tETH)
	id3 := key3.ID()
	t.Logf("  Pool ID: %x", id3[:8])

	// Register 2 external venues
	t.Log("Registering external venue: Alpaca (equities, ~5% spread)")
	router.RegisterVenue(&mockAlpacaVenue{})

	t.Log("Registering external venue: Hyperliquid (perps, ~3% spread)")
	router.RegisterVenue(&mockHyperliquidVenue{})

	t.Logf("Setup complete: 3 pools initialized, 2 external venues registered")

	// Verify all pools exist by quoting
	for _, pair := range [][2]common.Address{{tUSDL, tWBTC}, {tWBTC, tETH}, {tUSDL, tETH}} {
		quotes, err := router.QuoteExactInputSingle(stateDB, pair[0], pair[1], big.NewInt(1000), 0)
		if err != nil {
			t.Fatalf("Pool %s/%s should be quotable: %v", pair[0].Hex()[:8], pair[1].Hex()[:8], err)
		}
		if len(quotes) == 0 {
			t.Fatalf("Pool %s/%s returned zero quotes", pair[0].Hex()[:8], pair[1].Hex()[:8])
		}
	}

	t.Log("All pools verified: quoting returns results for each pair")
}

// =========================================================================
// Step 2: Single-hop swap — ExactInputSingle USDL -> ETH
// =========================================================================

func testSingleHopSwap(t *testing.T) {
	t.Log("--- Step 2: Single-hop swap (1000 USDL -> ETH via USDL/ETH pool) ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, tUSDL, tETH)

	params := SwapExactInputSingleParams{
		TokenIn:  tUSDL,
		TokenOut: tETH,
		AmountIn: big.NewInt(1_000),
	}

	amountOut, venue, err := router.ExactInputSingle(stateDB, intUser, params)
	if err != nil {
		t.Fatalf("ExactInputSingle failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}
	if venue != VenueV4Native {
		t.Fatalf("expected VenueV4Native, got %d", venue)
	}

	t.Logf("Single-hop result: 1000 USDL -> %s ETH (venue=V4Native)", amountOut)
}

// =========================================================================
// Step 3: Multi-hop swap — ExactInput USDL -> WBTC -> ETH
// =========================================================================

func testMultiHopSwap(t *testing.T) {
	t.Log("--- Step 3: Multi-hop swap (5000 USDL -> WBTC -> ETH) ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// Both hops need pools
	setupV4Pool(t, pm, stateDB, tUSDL, tWBTC)
	setupV4Pool(t, pm, stateDB, tWBTC, tETH)

	params := SwapExactInputParams{
		Path:     []common.Address{tUSDL, tWBTC, tETH},
		AmountIn: big.NewInt(5_000),
	}

	amountOut, err := router.ExactInput(stateDB, intUser, params)
	if err != nil {
		t.Fatalf("ExactInput multi-hop failed: %v", err)
	}
	if amountOut.Sign() <= 0 {
		t.Fatalf("expected positive output, got %s", amountOut)
	}

	// With the mock engine (50% per hop), 5000 -> 2500 -> 1250
	t.Logf("Multi-hop result: 5000 USDL -> WBTC -> %s ETH", amountOut)
	t.Logf("  Hop 1: 5000 USDL -> ~2500 WBTC (V4 pool)")
	t.Logf("  Hop 2: ~2500 WBTC -> %s ETH (V4 pool)", amountOut)
}

// =========================================================================
// Step 4: Multi-venue quote — V4 pool + Alpaca + Hyperliquid
// =========================================================================

func testMultiVenueQuote(t *testing.T) {
	t.Log("--- Step 4: Multi-venue quote (10000 USDL -> ETH across all venues) ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, tUSDL, tETH)
	router.RegisterVenue(&mockAlpacaVenue{})
	router.RegisterVenue(&mockHyperliquidVenue{})

	amountIn := big.NewInt(10_000)
	quotes, err := router.QuoteExactInputSingle(stateDB, tUSDL, tETH, amountIn, 0)
	if err != nil {
		t.Fatalf("QuoteExactInputSingle failed: %v", err)
	}

	// Expect 3 quotes: V4 + Alpaca + Hyperliquid
	if len(quotes) < 3 {
		t.Fatalf("expected at least 3 quotes, got %d", len(quotes))
	}

	t.Logf("Received %d quotes for 10000 USDL -> ETH:", len(quotes))

	var bestQuote *QuoteResult
	for i, q := range quotes {
		venueName := venueLabel(q.Venue, q.PoolID)
		t.Logf("  [%d] Venue=%s, AmountOut=%s, GasEstimate=%d", i, venueName, q.AmountOut, q.GasEstimate)

		if bestQuote == nil || q.AmountOut.Cmp(bestQuote.AmountOut) > 0 {
			bestQuote = &quotes[i]
		}
	}

	// V4 mock engine gives 50% of input (5000), Alpaca gives 95% (9500),
	// Hyperliquid gives 97% (9700). Hyperliquid wins in this mock.
	t.Logf("Best price: %s from %s", bestQuote.AmountOut, venueLabel(bestQuote.Venue, bestQuote.PoolID))

	// Verify V4 is among the results
	hasV4 := false
	for _, q := range quotes {
		if q.Venue == VenueV4Native {
			hasV4 = true
		}
	}
	if !hasV4 {
		t.Fatal("expected V4Native quote in results")
	}
}

// =========================================================================
// Step 5: External venue quote-only (no on-chain execution for AAPL/USDL)
// =========================================================================

func testExternalVenueQuoteOnly(t *testing.T) {
	t.Log("--- Step 5: External venue quote-only (AAPL/USDL — no on-chain pool) ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	// No AAPL/USDL pool exists on-chain. Only Alpaca can quote it.
	router.RegisterVenue(&mockAlpacaVenue{})
	router.RegisterVenue(&mockHyperliquidVenue{})

	amountIn := big.NewInt(10_000)

	// QuoteExactInputSingle should return external venue quotes
	t.Log("Quoting AAPL/USDL (no on-chain pool)...")
	quotes, err := router.QuoteExactInputSingle(stateDB, tAAPL, tUSDL, amountIn, 0)
	if err != nil {
		t.Fatalf("QuoteExactInputSingle should succeed with external venues: %v", err)
	}

	t.Logf("Got %d quotes for AAPL/USDL:", len(quotes))
	for i, q := range quotes {
		t.Logf("  [%d] Venue=%s, AmountOut=%s", i, venueLabel(q.Venue, q.PoolID), q.AmountOut)
	}

	// All quotes should be from external venues (no V4 pool for AAPL/USDL)
	for _, q := range quotes {
		if q.Venue == VenueV4Native {
			t.Fatal("unexpected V4Native quote for AAPL/USDL (no pool exists)")
		}
	}

	// ExactInputSingle should fail: external venues are quote-only, no on-chain settlement
	t.Log("Attempting on-chain execution of AAPL/USDL (should fail)...")
	params := SwapExactInputSingleParams{
		TokenIn:  tAAPL,
		TokenOut: tUSDL,
		AmountIn: amountIn,
	}

	_, _, err = router.ExactInputSingle(stateDB, intUser, params)
	if err == nil {
		t.Fatal("expected ErrNoOnChainLiquidity for AAPL/USDL execution")
	}

	t.Logf("Correctly rejected on-chain execution: %v", err)
	t.Log("External venues provide quotes only — actual fills settle via FillAttestation (LP-9090)")
}

// =========================================================================
// Step 6: Pause/Freeze compliance
// =========================================================================

func testPauseFreezeCompliance(t *testing.T) {
	t.Log("--- Step 6: Pause/Freeze compliance (ATS regulatory controls) ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	keyUSDLETH := setupV4Pool(t, pm, stateDB, tUSDL, tETH)
	setupV4Pool(t, pm, stateDB, tUSDL, tWBTC)

	swapParams := SwapExactInputSingleParams{
		TokenIn:  tUSDL,
		TokenOut: tETH,
		AmountIn: big.NewInt(1_000),
	}

	// --- DEX-level pause ---
	t.Log("Pausing entire DEX...")
	if err := pm.PauseDEX(stateDB, intAdmin); err != nil {
		t.Fatalf("PauseDEX failed: %v", err)
	}
	if !pm.IsPaused() {
		t.Fatal("DEX should be paused")
	}

	_, _, err := router.ExactInputSingle(stateDB, intUser, swapParams)
	if err == nil {
		t.Fatal("swap should fail when DEX is paused")
	}
	t.Logf("Swap rejected during DEX pause: %v", err)

	t.Log("Resuming DEX...")
	if err := pm.ResumeDEX(stateDB, intAdmin); err != nil {
		t.Fatalf("ResumeDEX failed: %v", err)
	}

	amountOut, venue, err := router.ExactInputSingle(stateDB, intUser, swapParams)
	if err != nil {
		t.Fatalf("swap should succeed after resume: %v", err)
	}
	t.Logf("Swap succeeds after resume: 1000 USDL -> %s ETH (venue=%d)", amountOut, venue)

	// --- Pool-level freeze ---
	poolID := keyUSDLETH.ID()
	t.Logf("Freezing pool USDL/ETH (ID=%x)...", poolID[:8])
	if err := pm.FreezePool(stateDB, intAdmin, poolID); err != nil {
		t.Fatalf("FreezePool failed: %v", err)
	}
	if !pm.IsPoolFrozen(poolID) {
		t.Fatal("USDL/ETH pool should be frozen")
	}

	_, _, err = router.ExactInputSingle(stateDB, intUser, swapParams)
	if err == nil {
		t.Fatal("swap on frozen pool should fail")
	}
	t.Logf("Swap on frozen USDL/ETH rejected: %v", err)

	// Other pools should still work
	t.Log("Verifying USDL/WBTC pool still works...")
	wbtcParams := SwapExactInputSingleParams{
		TokenIn:  tUSDL,
		TokenOut: tWBTC,
		AmountIn: big.NewInt(1_000),
	}
	wbtcOut, _, err := router.ExactInputSingle(stateDB, intUser, wbtcParams)
	if err != nil {
		t.Fatalf("USDL/WBTC should still work when USDL/ETH is frozen: %v", err)
	}
	t.Logf("USDL/WBTC swap succeeds: 1000 USDL -> %s WBTC (unaffected by freeze)", wbtcOut)
}

// =========================================================================
// Step 7: ATS order flow (simulated)
//
// Simulates the full ATS backend flow:
//   1. User places market buy 100 ETH
//   2. ATS quotes on-chain V4 pool + external venues
//   3. V4 pool fills what it can
//   4. Remainder is quoted from external venues
//   5. External fill is recorded via FillAttestation (LP-9090)
// =========================================================================

func testATSOrderFlow(t *testing.T) {
	t.Log("--- Step 7: ATS order flow (simulated market buy 100 ETH) ---")

	pm := newIntegrationPoolManager()
	stateDB := NewMockStateDB()
	router := NewLXRouter(pm)

	setupV4Pool(t, pm, stateDB, tUSDL, tETH)
	router.RegisterVenue(&mockAlpacaVenue{})
	router.RegisterVenue(&mockHyperliquidVenue{})

	fillMgr := NewFillAttestationManager()

	// Configure the FillAttestation system
	if err := fillMgr.SetAttester(stateDB, common.Address{}, intATSWallet); err != nil {
		t.Fatalf("SetAttester failed: %v", err)
	}
	ceiling := new(big.Int).Mul(big.NewInt(10_000_000), big.NewInt(1e18))
	if err := fillMgr.SetCeiling(stateDB, intATSWallet, ceiling); err != nil {
		t.Fatalf("SetCeiling failed: %v", err)
	}

	// --- Phase 1: ATS gets quotes from all venues ---
	orderSize := big.NewInt(100_000) // 100,000 USDL worth of ETH
	t.Logf("ATS received market buy order: %s USDL -> ETH", orderSize)

	t.Log("Phase 1: Querying all venues for best price...")
	quotes, err := router.QuoteExactInputSingle(stateDB, tUSDL, tETH, orderSize, 0)
	if err != nil {
		t.Fatalf("ATS quote request failed: %v", err)
	}

	var v4Quote, bestExtQuote *QuoteResult
	for i, q := range quotes {
		label := venueLabel(q.Venue, q.PoolID)
		t.Logf("  Quote[%d]: %s -> %s ETH (gas=%d)", i, label, q.AmountOut, q.GasEstimate)
		if q.Venue == VenueV4Native {
			v4Quote = &quotes[i]
		}
		if q.Venue == VenueExternal {
			if bestExtQuote == nil || q.AmountOut.Cmp(bestExtQuote.AmountOut) > 0 {
				bestExtQuote = &quotes[i]
			}
		}
	}

	if v4Quote == nil {
		t.Fatal("expected V4 native pool quote")
	}

	// --- Phase 2: Execute on-chain portion via V4 ---
	t.Log("Phase 2: Executing on-chain via V4 pool...")
	onChainParams := SwapExactInputSingleParams{
		TokenIn:  tUSDL,
		TokenOut: tETH,
		AmountIn: orderSize,
	}

	onChainOut, venue, err := router.ExactInputSingle(stateDB, intUser, onChainParams)
	if err != nil {
		t.Fatalf("On-chain V4 execution failed: %v", err)
	}
	if venue != VenueV4Native {
		t.Fatalf("expected VenueV4Native execution, got %d", venue)
	}
	t.Logf("  V4 fill: %s USDL -> %s ETH (on-chain, instant settlement)", orderSize, onChainOut)

	// --- Phase 3: External venue fill via FillAttestation ---
	// In production, if V4 has insufficient liquidity the ATS splits the order:
	// part on-chain, remainder off-chain via Broker -> Alpaca/Hyperliquid.
	// Here we simulate the off-chain fill being recorded on-chain.
	t.Log("Phase 3: Recording external venue fill via FillAttestation (LP-9090)...")

	if bestExtQuote == nil {
		t.Fatal("expected at least one external venue quote")
	}

	externalFillAmount := big.NewInt(50) // 50 ETH filled externally
	externalFillPrice := new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18))
	orderID := OrderIDFromString("alpaca-order-integration-test-001")
	symbol := SymbolToBytes32("ETH")

	err = fillMgr.Attest(
		stateDB,
		intATSWallet,
		orderID,
		symbol,
		externalFillAmount,
		externalFillPrice,
		intUser,
		1711036800,
	)
	if err != nil {
		t.Fatalf("FillAttestation.Attest failed: %v", err)
	}

	att := fillMgr.GetAttestation(stateDB, orderID)
	if att == nil {
		t.Fatal("attestation not found after recording")
	}
	if att.Status != FillPending {
		t.Fatalf("expected FillPending, got %d", att.Status)
	}
	if att.User != intUser {
		t.Fatalf("attestation user mismatch: got %s, want %s", att.User, intUser)
	}

	t.Logf("  External fill attested: %s ETH @ $%s (status=Pending, fraud_window=%d blocks)",
		externalFillAmount, new(big.Int).Div(externalFillPrice, big.NewInt(1e18)), DefaultFraudWindowBlocks)

	// --- Phase 4: Summary ---
	t.Log("Phase 4: Order execution summary")
	t.Logf("  On-chain (V4 pool):  %s USDL -> %s ETH", orderSize, onChainOut)
	t.Logf("  Off-chain (Alpaca):  FillAttestation for %s ETH @ $%s",
		externalFillAmount, new(big.Int).Div(externalFillPrice, big.NewInt(1e18)))
	t.Logf("  Attestation status:  Pending (finalizes after %d blocks / ~3 days)", DefaultFraudWindowBlocks)
	t.Log("  Settlement model:    V4 = instant on-chain; External = FillAttestation + fraud window")
}

// =========================================================================
// Helpers
// =========================================================================

// venueLabel returns a human-readable label for a venue + ID combination.
func venueLabel(v SwapVenue, poolID [32]byte) string {
	switch v {
	case VenueV4Native:
		return fmt.Sprintf("V4Native(pool=%x)", poolID[:4])
	case VenueV3:
		return "V3"
	case VenueV2:
		return "V2"
	case VenueExternal:
		name := string(poolID[:])
		// Trim null bytes for readability
		for i, b := range poolID {
			if b == 0 {
				name = string(poolID[:i])
				break
			}
		}
		return fmt.Sprintf("External(%s)", name)
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}
