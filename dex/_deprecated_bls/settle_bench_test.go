// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
)

// settle_bench_test.go — REAL benchmarks for the V4 DEX precompile surface. No
// time.Sleep, no stubs: each benchmark drives the actual handler (decode → verify →
// settle, or the actual lock/unlock arithmetic, or the actual BLS aggregate verify)
// on a funded in-memory state. Reset the state-dependent slots per iteration where a
// replay/consume gate would otherwise short-circuit the path (so every iteration
// does the SAME real work, not a fast revert).
//
// The benchmarks measure the C-side settlement/registry cost — which is exactly the
// consensus-critical hot path (D matches off-band; C settles a certified fill). BLS
// pairing verification is the dominant cost of the swap path and is measured under
// Benchmark9999SwapBLSReceiptRootInclusion.

// benchHarness builds a funded 0x9999 harness for a *testing.B.
func benchHarness(b *testing.B) *settleHarness {
	b.Helper()
	h := newSettleHarness(b)
	h.fund(b, 1<<62, 1<<62) // ample sender native + vault output token.
	return h
}

// resetReceiptConsumed clears the consumed flag for a receipt so the next settle of
// the same receipt does the FULL real work again (otherwise the replay gate would
// turn every iteration after the first into a cheap revert, mismeasuring the path).
func resetReceiptConsumed(h *settleHarness, receiptID [32]byte) {
	h.state.stateDB.SetState(poolManagerAddr9999, consumedReceiptKey(receiptID), common.Hash{})
}

// topUpVaultOut restores the output-token vault holdings so repeated settles always
// have backing (otherwise the vault drains and later iterations revert ErrSettleUnbacked).
func topUpVaultOut(h *settleHarness, amount int64) {
	db := newPoolStateAdapter(h.state)
	storeSettleVault(db, h.outAssetID(), new(big.Int).Add(loadSettleVault(db, h.outAssetID()), big.NewInt(amount)))
	h.wrapper().mintTestToken(h.outToken(), poolManagerAddr9999, big.NewInt(amount))
}

// ── 0x9999 swap (receipt settlement) ─────────────────────────────────────────

// Benchmark9999SwapNativeReceipt: native-in / token-out settlement (the full
// decode→halt→bind→replay→BLS-verify→settle pipeline) per op.
func Benchmark9999SwapNativeReceipt(b *testing.B) {
	h := benchHarness(b)
	nativeID := [32]byte{}
	hookData := h.receiptFor(b, nativeID, h.outAssetID(), 1000, 990, 0, 1)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	r := mustDecodeReceipt(b, hookData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		resetReceiptConsumed(h, r.ReceiptID)
		topUpVaultOut(h, 990)
		h.state.stateDB.AddBalance(h.caller, uint256.NewInt(1000))
		b.StartTimer()
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000_000, false); err != nil {
			b.Fatalf("swap settle: %v", err)
		}
	}
}

// Benchmark9999SwapERC20StrictReceipt: ERC-20-in / ERC-20-out settlement (observed-
// delta transferFrom/transferTo legs) per op. Both legs are ERC-20 (strict, full
// amountIn required), the heavier value-movement path.
func Benchmark9999SwapERC20StrictReceipt(b *testing.B) {
	h := newSettleHarness(b)
	// An ERC-20 pool: currency0 = token A, currency1 = token B (both non-native).
	tokenA := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	tokenB := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	if new(big.Int).SetBytes(tokenA.Bytes()).Cmp(new(big.Int).SetBytes(tokenB.Bytes())) > 0 {
		tokenA, tokenB = tokenB, tokenA
	}
	h.key = PoolKey{Currency0: Currency{Address: tokenA}, Currency1: Currency{Address: tokenB}, Fee: 3000, TickSpacing: 60}
	h.params = SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(0), SqrtPriceLimitX96: big.NewInt(0)}
	inAsset := assetID(h.key.Currency0)
	outAsset := assetID(h.key.Currency1)
	// Seed vault out-token holdings + tracking; seed sender in-token.
	storeSettleVault(newPoolStateAdapter(h.state), outAsset, big.NewInt(1<<40))
	h.wrapper().mintTestToken(tokenB, poolManagerAddr9999, big.NewInt(1<<40))
	h.wrapper().mintTestToken(tokenA, h.caller, big.NewInt(1<<40))

	hookData := h.receiptFor(b, inAsset, outAsset, 1000, 990, 0, 1)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	r := mustDecodeReceipt(b, hookData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		resetReceiptConsumed(h, r.ReceiptID)
		// Restore vault out + sender in so each iteration has the same backing.
		storeSettleVault(newPoolStateAdapter(h.state), outAsset, big.NewInt(1<<40))
		h.wrapper().mintTestToken(tokenB, poolManagerAddr9999, big.NewInt(1000))
		h.wrapper().mintTestToken(tokenA, h.caller, big.NewInt(1000))
		b.StartTimer()
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000_000, false); err != nil {
			b.Fatalf("erc20 swap settle: %v", err)
		}
	}
}

// Benchmark9999SwapBLSReceiptRootInclusion: isolates the BLS aggregate-verify cost
// (the dominant crypto cost of the swap path) — the receiptRoot==receiptID day-1
// inclusion. Measures verifyCert end to end (resolve set + aggregate pubkeys +
// pairing check) over a 3-validator 2-of-3 quorum.
func Benchmark9999SwapBLSReceiptRootInclusion(b *testing.B) {
	h := newSettleHarness(b)
	r := &DFillReceiptV1{
		Version: 1, NetworkID: h.networkID, DChainID: h.dChainID, CChainID: h.cChainID,
		DHeight: 100, MarketID: h.key.ID(), ReceiptID: keccak32([]byte("bench-bls")),
		PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(h.params),
		Sender: h.caller, Recipient: h.caller,
		TokenInAssetID: [32]byte{}, TokenOutAssetID: h.outAssetID(),
		AmountIn: big.NewInt(1000), AmountOut: big.NewInt(990), FeeAmount: big.NewInt(0),
		Deadline: 1 << 40, Nonce: 1, PrecompileAddr: poolManagerAddr9999, CertType: CertTypeBLSFastPath,
	}
	cert := buildCert(b, h.vsID, h.vals, r, r.ReceiptID, 0, 1)
	db := newPoolStateAdapter(h.state)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyCert(db, r, r.ReceiptID, cert); err != nil {
			b.Fatalf("verifyCert: %v", err)
		}
	}
}

// ── 0x9999 modifyLiquidity (maker lock/unlock) ───────────────────────────────

// Benchmark9999ModifyLiquidityOpen: ADD (lock reserve + record order) per op.
func Benchmark9999ModifyLiquidityOpen(b *testing.B) {
	h := newSettleHarness(b)
	h.registerMarket(b)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(newPoolStateAdapter(h.state), h.caller, bidAsset, new(big.Int).Lsh(big.NewInt(1), 100))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		var salt [32]byte
		// Distinct salt per iteration => distinct order (each is a real fresh insert).
		big.NewInt(int64(i)).FillBytes(salt[:])
		calldata := modLiqCalldata(h.key, -60, 60, big.NewInt(100), salt, MakerSideBid)
		b.StartTimer()
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000_000, false); err != nil {
			b.Fatalf("modifyLiquidity open: %v", err)
		}
	}
}

// Benchmark9999ModifyLiquidityCancel: REMOVE (unlock reserve + cancel) per op. Each
// iteration opens then cancels a fresh order so the cancel does real unlock work.
func Benchmark9999ModifyLiquidityCancel(b *testing.B) {
	h := newSettleHarness(b)
	h.registerMarket(b)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(newPoolStateAdapter(h.state), h.caller, bidAsset, new(big.Int).Lsh(big.NewInt(1), 100))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		var salt [32]byte
		big.NewInt(int64(i)).FillBytes(salt[:])
		// Open (untimed), then time the cancel.
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			modLiqCalldata(h.key, -60, 60, big.NewInt(100), salt, MakerSideBid), 50_000_000, false); err != nil {
			b.Fatalf("pre-open: %v", err)
		}
		cancel := modLiqCalldata(h.key, -60, 60, big.NewInt(-100), salt, MakerSideBid)
		b.StartTimer()
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, cancel, 50_000_000, false); err != nil {
			b.Fatalf("modifyLiquidity cancel: %v", err)
		}
	}
}

// ── 0x9998 Quoter / 0x9997 StateView ─────────────────────────────────────────

// Benchmark9998QuoteBestBidAsk: a Quoter read (registry projection) per op.
func Benchmark9998QuoteBestBidAsk(b *testing.B) {
	h := newSettleHarness(b)
	h.registerMarket(b)
	q := QuoterPrecompile
	calldata := quoteCalldata(SelQWithSlippage, h.key, big.NewInt(1_000_000), true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := q.Run(h.state, h.caller, quoterAddr, calldata, 5_000_000, true); err != nil {
			b.Fatalf("quote: %v", err)
		}
	}
}

// Benchmark9997StateViewBookTop: a StateView getBestBidAsk read per op.
func Benchmark9997StateViewBookTop(b *testing.B) {
	h := newSettleHarness(b)
	h.registerMarket(b)
	sv := StateViewPrecompile
	poolID := h.key.ID()
	calldata := prependSelector(SelectorGetBestBidAsk, poolID[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, calldata, 5_000_000, true); err != nil {
			b.Fatalf("getBestBidAsk: %v", err)
		}
	}
}

// ── 0x9996 PositionManager ───────────────────────────────────────────────────

// Benchmark9996PositionOpenClose: an open+close round-trip through the 0x9996
// adapter into the 0x9999 kernel per op.
func Benchmark9996PositionOpenClose(b *testing.B) {
	h := newSettleHarness(b)
	h.registerMarket(b)
	pm := PositionManagerPrecompile
	bidAsset := assetID(h.key.Currency0)
	fundClaim(newPoolStateAdapter(h.state), h.caller, bidAsset, new(big.Int).Lsh(big.NewInt(1), 100))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var salt [32]byte
		big.NewInt(int64(i)).FillBytes(salt[:])
		if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
			pmLifecycleCalldata(SelectorPMOpenPosition, h.key, -60, 60, big.NewInt(100), salt, MakerSideBid), 50_000_000, false); err != nil {
			b.Fatalf("open: %v", err)
		}
		if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
			pmLifecycleCalldata(SelectorPMCancelLimit, h.key, -60, 60, big.NewInt(100), salt, MakerSideBid), 50_000_000, false); err != nil {
			b.Fatalf("close: %v", err)
		}
	}
}

// ── Block-STM access-set ─────────────────────────────────────────────────────

// BenchmarkBlockSTM_9999_NoConflicts: predicting + conflict-checking access sets for
// two DISJOINT swaps (the scheduler's per-pair cost). Disjoint => no serialization.
func BenchmarkBlockSTM_9999_NoConflicts(b *testing.B) {
	r1 := sampleReceipt()
	r1.ReceiptID = keccak32([]byte("stm-r1"))
	r1.TokenInAssetID = [32]byte{0x01}
	r1.TokenOutAssetID = [32]byte{0x02}
	r1.FeeAssetID = [32]byte{0x01}
	r1.PoolKeyHash = [32]byte{0xA1}
	r2 := sampleReceipt()
	r2.ReceiptID = keccak32([]byte("stm-r2"))
	r2.Sender = common.HexToAddress("0x2222222222222222222222222222222222222222")
	r2.Recipient = r2.Sender
	r2.TokenInAssetID = [32]byte{0x03}
	r2.TokenOutAssetID = [32]byte{0x04}
	r2.FeeAssetID = [32]byte{0x03}
	r2.PoolKeyHash = [32]byte{0xB2}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a1 := PredictAccesses(r1, 1)
		a2 := PredictAccesses(r2, 1)
		if accessSetsIntersect(a1.Writes, a2.Writes) {
			b.Fatal("disjoint swaps must not conflict")
		}
	}
}

// BenchmarkBlockSTM_9999_SameAccountConflict: two swaps that share the sender +
// in-asset must be DETECTED as conflicting (the scheduler serializes them).
func BenchmarkBlockSTM_9999_SameAccountConflict(b *testing.B) {
	r1 := sampleReceipt()
	r1.ReceiptID = keccak32([]byte("stm-c1"))
	r2 := sampleReceipt()
	r2.ReceiptID = keccak32([]byte("stm-c2")) // distinct receipt...
	// ...but SAME sender + SAME in-asset => share the sender balance-leg write.

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a1 := PredictAccesses(r1, 1)
		a2 := PredictAccesses(r2, 1)
		if !accessSetsIntersect(a1.Writes, a2.Writes) {
			b.Fatal("same-account swaps must conflict")
		}
	}
}

// ── End-to-end ───────────────────────────────────────────────────────────────

// BenchmarkE2E_QuoteReceiptSettle: the realistic client flow — quote (advisory) then
// settle the certified receipt — per op.
func BenchmarkE2E_QuoteReceiptSettle(b *testing.B) {
	h := benchHarness(b)
	h.registerMarket(b)
	q := QuoterPrecompile
	nativeID := [32]byte{}
	hookData := h.receiptFor(b, nativeID, h.outAssetID(), 1000, 990, 0, 1)
	swapCalldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	quoteCall := quoteCalldata(SelQExactInput, h.key, big.NewInt(1000), true)
	r := mustDecodeReceipt(b, hookData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		resetReceiptConsumed(h, r.ReceiptID)
		topUpVaultOut(h, 990)
		h.state.stateDB.AddBalance(h.caller, uint256.NewInt(1000))
		b.StartTimer()
		if _, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCall, 5_000_000, true); err != nil {
			b.Fatalf("quote: %v", err)
		}
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, swapCalldata, 50_000_000, false); err != nil {
			b.Fatalf("settle: %v", err)
		}
	}
}

// BenchmarkE2E_NativeD_vs_C9999: the C-side initialize (registry write + on-C tick
// compute, NO D round-trip) per op — the cost a non-D validator pays to register a
// market deterministically. The "native D" side is off-band (D matches), so the
// consensus-critical C cost is what we measure: this is the apples-to-apples C9999
// number to compare against any D-side initialize.
func BenchmarkE2E_NativeD_vs_C9999(b *testing.B) {
	h := newSettleHarness(b)
	price := new(big.Int).Set(Q96)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Fresh pool per iteration (distinct fee => distinct poolID) so each does a
		// real registry write, not an already-initialized revert.
		key := h.key
		key.Fee = uint24(1000 + i%90000)
		calldata := initCalldata(key, price)
		b.StartTimer()
		if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000_000, false); err != nil {
			b.Fatalf("initialize: %v", err)
		}
	}
}

// mustDecodeReceipt decodes the receipt from a settlement hookData (bench helper).
func mustDecodeReceipt(b *testing.B, hookData []byte) *DFillReceiptV1 {
	b.Helper()
	r, _, _, err := DecodeSettlementHookData(hookData)
	if err != nil {
		b.Fatalf("decode hookData: %v", err)
	}
	return r
}

// accessSetsIntersect reports whether two write-slot lists share any key (the
// scheduler's conflict test). A small linear scan — the lists are short.
func accessSetsIntersect(a, c []common.Hash) bool {
	set := make(map[common.Hash]struct{}, len(a))
	for _, k := range a {
		set[k] = struct{}{}
	}
	for _, k := range c {
		if _, ok := set[k]; ok {
			return true
		}
	}
	return false
}
