// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// harden_views_test.go — coverage for the read VIEW surfaces (0x9998 Quoter, 0x9997
// StateView, 0x9996 PositionManager), the STM access-set predictors, and the module
// config boilerplate. Views are write-incapable and deterministic; these tests pin
// every read selector + the determinism (no engine read) guarantee.

// ── 0x9998 Quoter: every mode + the view-purity guarantee ────────────────────

func TestCov_Quoter_AllModes(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	q := QuoterPrecompile
	amt := big.NewInt(1_000_000)

	run := func(sel uint32) []byte {
		out, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(sel, h.key, amt, true), 5_000_000, true)
		if err != nil {
			t.Fatalf("quote sel=%x: %v", sel, err)
		}
		return out
	}
	// plain / single / book all return a single word.
	for _, sel := range []uint32{SelQExactInput, SelQExactInputSingle, SelQExactOutput, SelQExactOutputSingle, SelQAgainstBook} {
		if len(run(sel)) != 32 {
			t.Fatalf("sel %x must return 32 bytes", sel)
		}
	}
	// depth => (amountOut, depthAvailable=false) — NEVER from a live book.
	depth := run(SelQWithDepth)
	if len(depth) != 64 || depth[63] != 0 {
		t.Fatalf("quoteWithDepth must report depthAvailable=false, got %x", depth[32:64])
	}
	// fees => (amountOut, feeAmount).
	fees := run(SelQWithFees)
	if new(big.Int).SetBytes(fees[32:64]).Cmp(feeOnInput(amt, h.key.Fee)) != 0 {
		t.Fatal("quoteWithFees fee mismatch")
	}
	// slippage => (amountOut, spotOut).
	if len(run(SelQWithSlippage)) != 64 {
		t.Fatal("quoteWithSlippage must return 2 words")
	}
}

// TestRED_Views_NeverReportFromBook: with a non-inert engine wired, the views STILL
// report fromBook/depthAvailable=false and the C-side projection — the live-D read
// path is gone, so the output is deterministic regardless of engine state. This is
// the test that would have caught the dead-code latent fork.
func TestRED_Views_NeverReportFromBook(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	// Wire a non-inert engine (mockEngine.Quote returns a non-zero number). The view
	// must IGNORE it (deterministic C projection only).
	prev := DEXPrecompile.poolManager
	DEXPrecompile.poolManager = NewPoolManager(&mockEngine{})
	defer func() { DEXPrecompile.poolManager = prev }()

	amt := big.NewInt(1_000_000)
	// Quoter depth mode: depthAvailable must be false even with the engine present.
	out, _, err := QuoterPrecompile.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQWithDepth, h.key, amt, true), 5_000_000, true)
	if err != nil {
		t.Fatalf("quoteWithDepth: %v", err)
	}
	if out[63] != 0 {
		t.Fatal("Quoter depth must report depthAvailable=false even with an engine wired")
	}
	// The numeric output must equal the pure C-side projection.
	rec := loadMarket(newPoolStateAdapter(h.state), h.key.ID())
	wantOut := projectSingleTick(rec, amt, true, true)
	if new(big.Int).SetBytes(out[0:32]).Cmp(wantOut) != 0 {
		t.Fatal("Quoter output must equal the deterministic C projection, not a live-engine quote")
	}

	// StateView getDepth + getBestBidAsk must report fromBook=false.
	poolID := h.key.ID()
	d, _, err := StateViewPrecompile.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetDepth, poolID[:]), 5_000_000, true)
	if err != nil || d[95] != 0 {
		t.Fatalf("getDepth must report fromBook=false, err=%v", err)
	}
	bba, _, err := StateViewPrecompile.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetBestBidAsk, poolID[:]), 5_000_000, true)
	if err != nil || bba[95] != 0 {
		t.Fatalf("getBestBidAsk must report fromBook=false, err=%v", err)
	}
}

func TestCov_Quoter_Guards(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	q := QuoterPrecompile
	// short input.
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, prependSelector(SelQExactInput, make([]byte, 10)), 5_000_000, true); err != ErrQuoteBadInput {
		t.Fatalf("short quote input must revert ErrQuoteBadInput, got: %v", err)
	}
	// zero amount.
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQExactInput, h.key, big.NewInt(0), true), 5_000_000, true); err != ErrQuoteZeroAmount {
		t.Fatalf("zero quote amount must revert ErrQuoteZeroAmount, got: %v", err)
	}
	// unknown selector.
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, prependSelector(0xDEADBEEF, make([]byte, 224)), 5_000_000, true); err == nil {
		t.Fatal("unknown quoter selector must revert")
	}
	// out of gas.
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, quoteCalldata(SelQExactInput, h.key, big.NewInt(100), true), 1, true); err == nil {
		t.Fatal("under-gassed quote must revert")
	}
	// too-short top-level input (<4).
	if _, _, err := q.Run(h.state, h.caller, quoterAddr, []byte{0x01}, 5_000_000, true); err == nil {
		t.Fatal("sub-selector input must revert")
	}
}

// ── 0x9997 StateView: every read selector ────────────────────────────────────

func TestCov_StateView_AllReads(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	sv := StateViewPrecompile
	poolID := h.key.ID()

	// Seed a maker order so getOpenOrders / getPosition / positionInfo have content.
	bidAsset := assetID(h.key.Currency0)
	fundClaim(newPoolStateAdapter(h.state), h.caller, bidAsset, big.NewInt(1000))
	var salt [32]byte
	salt[31] = 0x71
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(400), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	orderID := MakerOrderID(h.caller, poolID, salt, -60, 60)

	read := func(sel uint32, data []byte) []byte {
		out, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(sel, data), 5_000_000, true)
		if err != nil {
			t.Fatalf("stateview sel=%x: %v", sel, err)
		}
		return out
	}
	// getLiquidity (engine-free, returns 0 deterministically).
	if new(big.Int).SetBytes(read(SelectorGetLiquidity, poolID[:])).Sign() != 0 {
		t.Fatal("getLiquidity (C registry) must be 0")
	}
	// getPosition(orderID).
	pos := read(SelectorGetPosition, orderID[:])
	if common.BytesToAddress(pos[32+12:64]) != h.caller {
		t.Fatal("getPosition owner mismatch")
	}
	// getBestBidAsk (fromBook=false).
	bba := read(SelectorGetBestBidAsk, poolID[:])
	if bba[95] != 0 {
		t.Fatal("getBestBidAsk fromBook must be false")
	}
	// getDepth.
	if read(SelectorGetDepth, poolID[:])[95] != 0 {
		t.Fatal("getDepth fromBook must be false")
	}
	// getOpenOrders(owner) — one open order.
	oo := read(SelectorGetOpenOrders, leftPad32(h.caller.Bytes()))
	if new(big.Int).SetBytes(oo[32:64]).Int64() != 1 {
		t.Fatal("getOpenOrders must list 1 open order")
	}
	// getVerifierStatus(dChainID, vsID) — active.
	vsData := append(append([]byte{}, h.dChainID[:]...), h.vsID[:]...)
	vstat := read(SelectorGetVerifierStatus, vsData)
	if vstat[31] != 1 {
		t.Fatal("getVerifierStatus must report active")
	}
	// getReceiptStatus(unknown) -> false; getHaltStatus(poolID) all-off.
	if read(SelectorGetReceiptStatus, make([]byte, 32))[31] != 0 {
		t.Fatal("unknown receipt must be unconsumed")
	}
	hs := read(SelectorGetHaltStatus, poolID[:])
	if hs[31] != 0 || hs[63] != 0 {
		t.Fatal("halt status must be all-off")
	}
	// global halt + scope halt reflected.
	SetHaltGlobal(newPoolStateAdapter(h.state), true)
	SetHaltAsset(newPoolStateAdapter(h.state), bidAsset, true)
	if read(SelectorGetHaltStatus, poolID[:])[31] != 1 {
		t.Fatal("global halt must show in status")
	}
	if read(SelectorGetHaltStatus, bidAsset[:])[63] != 1 {
		t.Fatal("asset halt must show in scope status")
	}
}

func TestCov_StateView_Guards(t *testing.T) {
	h := newSettleHarness(t)
	sv := StateViewPrecompile
	// unknown selector.
	if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(0xDEADBEEF, make([]byte, 32)), 5_000_000, true); err == nil {
		t.Fatal("unknown stateview selector must revert")
	}
	// short input on a scoped read.
	if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetMarket, make([]byte, 4)), 5_000_000, true); err != ErrViewBadInput {
		t.Fatalf("short getMarket input must revert ErrViewBadInput, got: %v", err)
	}
	// getVerifierStatus short input.
	if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetVerifierStatus, make([]byte, 32)), 5_000_000, true); err != ErrViewBadInput {
		t.Fatalf("short getVerifierStatus must revert ErrViewBadInput, got: %v", err)
	}
	// out of gas.
	if _, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetPoolId, EncodePoolKeyABI(h.key)), 1, true); err == nil {
		t.Fatal("under-gassed stateview must revert")
	}
	// getVerifierStatus on an absent set -> active=false.
	absentD := [32]byte{0xEE}
	absentV := [32]byte{0xFF}
	vsData := append(append([]byte{}, absentD[:]...), absentV[:]...)
	out, _, err := sv.Run(h.state, h.caller, stateViewAddr, prependSelector(SelectorGetVerifierStatus, vsData), 5_000_000, true)
	if err != nil || out[31] != 0 {
		t.Fatalf("absent verifier must report active=false, err=%v", err)
	}
}

// ── 0x9996 PositionManager: modifyPosition (both signs) + reads ──────────────

func TestRED_PM_ModifyPosition_AcceptsBothSigns(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	pm := PositionManagerPrecompile
	db := newPoolStateAdapter(h.state)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(db, h.caller, bidAsset, big.NewInt(1000))

	var salt [32]byte
	salt[31] = 0x81
	// modifyPosition +400 => ADD (locked up, claim down).
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMModifyPosition, h.key, -60, 60, big.NewInt(400), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("modifyPosition +400: %v", err)
	}
	if loadLockedReserve(db, h.caller, bidAsset).Cmp(big.NewInt(400)) != 0 {
		t.Fatal("modifyPosition +delta must ADD (lock)")
	}
	// modifyPosition -400 => REMOVE (locked down, claim up).
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr,
		pmLifecycleCalldata(SelectorPMModifyPosition, h.key, -60, 60, big.NewInt(-400), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("modifyPosition -400: %v", err)
	}
	if loadLockedReserve(db, h.caller, bidAsset).Sign() != 0 {
		t.Fatal("modifyPosition -delta must REMOVE (unlock)")
	}
	if loadDepositorClaim(db, h.caller, bidAsset).Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("conservation: claim restored to 1000 across ADD+REMOVE")
	}
}

func TestRED_PM_ModifyPosition_CrossOwnerReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	pm := PositionManagerPrecompile
	alice := h.caller
	bob := common.HexToAddress("0xB0B0000000000000000000000000000000000000")
	fundClaim(newPoolStateAdapter(h.state), alice, assetID(h.key.Currency0), big.NewInt(1000))
	var salt [32]byte
	salt[31] = 0x82
	if _, _, err := pm.Run(h.state, alice, positionManagerAddr, pmLifecycleCalldata(SelectorPMModifyPosition, h.key, -60, 60, big.NewInt(300), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("alice modifyPosition: %v", err)
	}
	// Bob modifyPosition -delta on alice's (pool,salt,range) => his derived order is empty.
	if _, _, err := pm.Run(h.state, bob, positionManagerAddr, pmLifecycleCalldata(SelectorPMModifyPosition, h.key, -60, 60, big.NewInt(-300), salt, MakerSideBid), 5_000_000, false); err != ErrMakerNotOwner {
		t.Fatalf("cross-owner modifyPosition must revert ErrMakerNotOwner, got: %v", err)
	}
}

func TestCov_PM_Guards(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	pm := PositionManagerPrecompile
	// zero delta.
	var salt [32]byte
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, pmLifecycleCalldata(SelectorPMModifyPosition, h.key, -60, 60, big.NewInt(0), salt, MakerSideBid), 5_000_000, false); err != ErrPMZeroDelta {
		t.Fatalf("zero-delta modifyPosition must revert ErrPMZeroDelta, got: %v", err)
	}
	// short lifecycle input.
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMMint, make([]byte, 10)), 5_000_000, false); err != ErrPMBadInput {
		t.Fatalf("short lifecycle input must revert ErrPMBadInput, got: %v", err)
	}
	// unknown selector.
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(0xDEADBEEF, make([]byte, 320)), 5_000_000, false); err == nil {
		t.Fatal("unknown PM selector must revert")
	}
	// positionsOf short input + out of gas.
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMPositionsOf, make([]byte, 10)), 5_000_000, true); err != ErrPMBadInput {
		t.Fatalf("short positionsOf must revert ErrPMBadInput, got: %v", err)
	}
	// positionInfo short input.
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMPositionInfo, make([]byte, 10)), 5_000_000, true); err != ErrPMBadInput {
		t.Fatalf("short positionInfo must revert ErrPMBadInput, got: %v", err)
	}
	// collect (readOnly) reverts ErrUnsupported.
	if _, _, err := pm.Run(h.state, h.caller, positionManagerAddr, pmLifecycleCalldata(SelectorPMCollect, h.key, -60, 60, big.NewInt(1), salt, MakerSideBid), 5_000_000, true); err != ErrUnsupported {
		t.Fatalf("collect(readOnly) must revert ErrUnsupported, got: %v", err)
	}
	// positionInfo(unknown) returns a zero record (Status None), no error.
	out, _, err := pm.Run(h.state, h.caller, positionManagerAddr, prependSelector(SelectorPMPositionInfo, make([]byte, 32)), 5_000_000, true)
	if err != nil || OrderStatus(out[255]) != OrderStatusNone {
		t.Fatalf("positionInfo(unknown) must return a None record, err=%v", err)
	}
}

// ── STM access-set predictors: parity + no-global-hot-write ───────────────────

// snapshotStateKeys returns the set of 0x9999 storage keys currently set in the
// mock state (the persisted write footprint so far).
func snapshotStateKeys(db *MockStateDB) map[common.Hash]struct{} {
	out := map[common.Hash]struct{}{}
	for k := range db.states[poolManagerAddr9999] {
		out[k] = struct{}{}
	}
	return out
}

// TestRED_STM_PredictModifyLiquidity_SupersetOfActual: the declared maker access set
// must be a SUPERSET of the slots an ADD actually WRITES (under-prediction is the
// unsafe direction — a missed conflict is a fork). We diff the persisted state-key
// set before/after the handler to recover its real write footprint.
func TestRED_STM_PredictModifyLiquidity_SupersetOfActual(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	bidAsset := assetID(h.key.Currency0)
	fundClaim(newPoolStateAdapter(h.state), h.caller, bidAsset, big.NewInt(1000))

	var salt [32]byte
	salt[31] = 0x91
	declared := PredictModifyLiquidityAccesses(h.caller, h.key.ID(), salt, -60, 60, bidAsset)
	declaredSet := map[common.Hash]struct{}{}
	for _, k := range declared.Reads {
		declaredSet[k] = struct{}{}
	}
	for _, k := range declared.Writes {
		declaredSet[k] = struct{}{}
	}

	before := snapshotStateKeys(h.state.stateDB)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, modLiqCalldata(h.key, -60, 60, big.NewInt(400), salt, MakerSideBid), 5_000_000, false); err != nil {
		t.Fatalf("ADD: %v", err)
	}
	after := snapshotStateKeys(h.state.stateDB)

	// Every NEWLY-written slot must be declared (conflict-relevant axis). The
	// ownerOrdersAt(owner,count) index slot is the documented unknowable index (the
	// pure predictor cannot derive the live count; ownerOrdersCountKey captures the
	// owner conflict) and the order's "indexed" flag is the O(1) membership sentinel —
	// both are owner/order-scoped, never cross-owner global, so accept them.
	for w := range after {
		if _, existed := before[w]; existed {
			continue // not newly written by this ADD.
		}
		if _, ok := declaredSet[w]; ok {
			continue
		}
		if isOwnerScopedSlot(w, h.caller) || w == orderIndexedKey(MakerOrderID(h.caller, h.key.ID(), salt, -60, 60)) {
			continue
		}
		t.Fatalf("STM under-prediction: handler wrote undeclared slot %x", w)
	}
}

// isOwnerScopedSlot reports whether a key is an ownerOrders-prefixed slot for owner
// (the index slot at a live count the pure predictor cannot name, but which is
// owner-scoped and therefore never a cross-owner under-prediction).
func isOwnerScopedSlot(k common.Hash, owner common.Address) bool {
	// ownerOrdersAtKey(owner, i) for a small i range covers any realistic live count.
	for i := uint64(0); i < 8; i++ {
		if ownerOrdersAtKey(owner, i) == k {
			return true
		}
	}
	return false
}

// TestRED_STM_NoGlobalHotWrite_Maker: two makers on distinct (owner,asset,order)
// tuples produce disjoint maker-keyed write sets (no global hot write that would
// serialize all makers).
func TestRED_STM_NoGlobalHotWrite_Maker(t *testing.T) {
	owner1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	owner2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	asset1 := [32]byte{0x01}
	asset2 := [32]byte{0x02}
	var salt [32]byte
	a1 := PredictModifyLiquidityAccesses(owner1, [32]byte{0xAA}, salt, -60, 60, asset1)
	a2 := PredictModifyLiquidityAccesses(owner2, [32]byte{0xBB}, salt, -60, 60, asset2)
	// The ONLY shared write across owners is custodyGuardKey9999 (the reentrancy
	// guard) — a known, intentional cross-custody-op serialization point. Every other
	// write must be disjoint.
	shared := []common.Hash{}
	set := map[common.Hash]struct{}{}
	for _, w := range a1.Writes {
		set[w] = struct{}{}
	}
	for _, w := range a2.Writes {
		if _, ok := set[w]; ok {
			shared = append(shared, w)
		}
	}
	for _, w := range shared {
		if w != custodyGuardKey9999 {
			t.Fatalf("two distinct makers share a non-guard write slot %x (global hot write)", w)
		}
	}
}

// TestRED_STM_SwapPredict_NoGlobalHotWrite: a swap's write set has zero global hot
// slots (re-asserts the invariant after the haltMarket key change to PoolKeyHash).
func TestRED_STM_SwapPredict_NoGlobalHotWrite(t *testing.T) {
	r := sampleReceipt()
	r.ReceiptID = keccak32([]byte("stm-r1"))
	as := PredictAccesses(r, 1)
	for _, w := range as.Writes {
		if isGlobalHotKey(w) {
			t.Fatalf("swap write %x is a global hot slot", w)
		}
	}
	// epochOf is the single shard source the handler uses.
	if epochOf(42) != 42 {
		t.Fatal("epochOf must mirror the block number")
	}
}

// ── module config boilerplate (cheap coverage of the Config interface) ────────

func TestCov_ModuleConfigBoilerplate(t *testing.T) {
	// MakeConfig + Configure on each configurator (stateless views: Configure is a no-op).
	qc := &quoterConfigurator{}
	if _, ok := qc.MakeConfig().(*QuoterConfig); !ok {
		t.Fatal("quoter MakeConfig type")
	}
	_ = qc.Configure(nil, &QuoterConfig{}, nil, nil)
	svc := &stateViewConfigurator{}
	if _, ok := svc.MakeConfig().(*StateViewConfig); !ok {
		t.Fatal("stateview MakeConfig type")
	}
	_ = svc.Configure(nil, &StateViewConfig{}, nil, nil)
	pc := &positionConfigurator{}
	if _, ok := pc.MakeConfig().(*PositionManagerConfig); !ok {
		t.Fatal("position MakeConfig type")
	}
	_ = pc.Configure(nil, &PositionManagerConfig{}, nil, nil)
	if _, ok := (&settleConfigurator{}).MakeConfig().(*SettleConfig); !ok {
		t.Fatal("settle MakeConfig type")
	}

	// Key / Timestamp / IsDisabled / Equal(self) / Equal(nil) per config.
	qcfg := &QuoterConfig{}
	if qcfg.Key() != quoterConfigKey || qcfg.IsDisabled() || qcfg.Timestamp() != nil || !qcfg.Equal(&QuoterConfig{}) || qcfg.Equal(nil) {
		t.Fatal("QuoterConfig boilerplate mismatch")
	}
	scfg := &StateViewConfig{}
	if scfg.Key() != stateViewConfigKey || scfg.IsDisabled() || !scfg.Equal(&StateViewConfig{}) || scfg.Equal(nil) {
		t.Fatal("StateViewConfig boilerplate mismatch")
	}
	pcfg := &PositionManagerConfig{}
	if pcfg.Key() != positionConfigKey || pcfg.IsDisabled() || !pcfg.Equal(&PositionManagerConfig{}) || pcfg.Equal(nil) {
		t.Fatal("PositionManagerConfig boilerplate mismatch")
	}
	stcfg := &SettleConfig{ProtocolFeeController: common.HexToAddress("0x1")}
	if stcfg.Key() != settleConfigKey || stcfg.IsDisabled() || !stcfg.Equal(stcfg) || stcfg.Equal(nil) {
		t.Fatal("SettleConfig boilerplate mismatch")
	}

	// Verify: view configs are no-op; SettleConfig requires a controller.
	if err := qcfg.Verify(nil); err != nil {
		t.Fatalf("quoter Verify: %v", err)
	}
	if err := scfg.Verify(nil); err != nil {
		t.Fatalf("stateview Verify: %v", err)
	}
	if err := pcfg.Verify(nil); err != nil {
		t.Fatalf("position Verify: %v", err)
	}
	if err := (&SettleConfig{}).Verify(nil); err != ErrDEXNoProtocolFeeController {
		t.Fatalf("SettleConfig.Verify without controller must fail, got: %v", err)
	}
	if err := stcfg.Verify(nil); err != nil {
		t.Fatalf("SettleConfig.Verify with controller: %v", err)
	}
}
