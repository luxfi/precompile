// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// settle_decomplect_test.go pins the CANONICAL DECOMPLECT invariant: 0x9999 is the SOLE
// money path and it SETTLES ONLY — it never matches. Every swap routes to the native C<->D
// atomic seam; the ONLY way C is credited is by consuming a real D->C atomic object. There
// is NO embedded matcher (swap_sync), NO in-trie maker order book (swap_custody), NO
// synchronous on-chain router. These tests are the load-bearing guardrail for that property
// (they replace the deleted swap_sync_* / gatec_* suites, keeping the still-relevant
// permissionless-admission and governance-cannot-drain invariants).

// c1MarketKey is a market over a SYNTHETIC base (currency0, no on-chain code) and a REAL
// quote (currency1, code-backed). V4 requires currency0 < currency1, so the synthetic base
// is at the lower address and the real quote at the higher. Relocated from the deleted
// swap_sync_c1_redteam_test.go — the initialize-admission tests below still need it.
var (
	c1FabricatedBase = common.HexToAddress("0x00000000000000000000000000000000000000Ee") // synthetic: no on-chain code
	c1RealQuote      = common.HexToAddress("0x0000000000000000000000000000000000000F02") // real: code-backed ERC-20
)

func c1MarketKey() PoolKey {
	return PoolKey{
		Currency0:   Currency{Address: c1FabricatedBase},
		Currency1:   Currency{Address: c1RealQuote},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
}

// TestDecomplect_NoReceiptNoSettle is THE negative invariant: a PHASE B settlement (DS01)
// that names a D->C object which does NOT exist in shared memory MUST revert and credit
// NOTHING — even with the output vault fully funded. This is the structural "0x9999 cannot
// fabricate a fill" guarantee: absent a real D-committed atomic object, there is no credit.
func TestDecomplect_NoReceiptNoSettle(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	// Fund the output vault generously so that IF any credit path existed that did not require
	// a real D->C object, it COULD pay out — making the "no credit" assertion decisive.
	h.fundVaultOut(1_000_000)

	// An outputID that was NEVER exported by D (never PUT into shared memory).
	phantom := ids.ID{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x9999 & 0xFF}

	callerOutBefore := h.tokenBal(h.outToken(), h.caller)
	vaultOutBefore := h.tokenBal(h.outToken(), poolManagerAddr9999)

	// settlementCalldata seeds a standing per-taker intent so we get PAST the per-taker cap
	// and reach the object lookup (step 1 of ImportSettlement) — which must fail closed.
	_, err := h.runSwap(t, h.settlementCalldata(phantom, 500), false)
	if !errors.Is(err, ErrNativeNoSettlement) {
		t.Fatalf("Phase-B settle with NO D->C object must revert ErrNativeNoSettlement, got: %v", err)
	}

	// No output token moved out of the vault; the caller was credited nothing.
	if got := h.tokenBal(h.outToken(), h.caller); got.Cmp(callerOutBefore) != 0 {
		t.Fatalf("no-object settle credited the caller %s (must be 0)", new(big.Int).Sub(got, callerOutBefore))
	}
	if got := h.tokenBal(h.outToken(), poolManagerAddr9999); got.Cmp(vaultOutBefore) != 0 {
		t.Fatalf("no-object settle drained the vault by %s (must be 0)", new(big.Int).Sub(vaultOutBefore, got))
	}
}

// TestDecomplect_UntaggedSwapIsIntentNotFill proves the positive half: a PLAIN swap (empty
// hookData — no DI01/DS01 tag) is treated as a PHASE A INTENT. It LOCKS the taker's input and
// returns a 32-byte intent id; it does NOT match, does NOT credit any output. There is no
// synchronous in-trie fill. (Before the decomplect this routed to the embedded sync matcher.)
func TestDecomplect_UntaggedSwapIsIntentNotFill(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	h.fundVaultOut(1_000_000) // a matcher COULD pay from here — assert it never does.

	callerNativeBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	callerOutBefore := h.tokenBal(h.outToken(), h.caller)

	// Empty hookData: the common plain-swap case. Post-decomplect this is a Phase A intent.
	out, _, err := runWithEVMSnapshot(h.c, h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, nil)), 5_000_000, false)
	if err != nil {
		t.Fatalf("a plain (empty-hookData) swap must create a Phase A intent, got err: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Phase A intent must return a 32-byte intent id, got %d bytes", len(out))
	}
	// Input was LOCKED (debited) — |AmountSpecified| = 100 in the standard harness params.
	callerNativeAfter := h.state.stateDB.GetBalance(h.caller).ToBig()
	if new(big.Int).Sub(callerNativeBefore, callerNativeAfter).Sign() <= 0 {
		t.Fatal("a Phase A intent must LOCK (debit) the taker's input")
	}
	// NO output credited — an intent is not a fill.
	if got := h.tokenBal(h.outToken(), h.caller); got.Cmp(callerOutBefore) != 0 {
		t.Fatalf("an intent must NOT credit output; credited %s", new(big.Int).Sub(got, callerOutBefore))
	}
}

// TestDecomplect_MakerBookSelectorsGone proves the in-trie maker order book is REMOVED: the
// swapDeposit / swapPlace / swapCancel selectors (the "money lives in the order book" custody
// surface the sync matcher fed) are no longer dispatchable — 0x9999 rejects them as unknown.
func TestDecomplect_MakerBookSelectorsGone(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	for _, sig := range []string{
		"swapDeposit(address,uint256)",
		"swapWithdraw(address,uint256)",
		"swapPlace((address,address,uint24,int24,address),bool,uint256,uint256)",
		"swapCancel((address,address,uint24,int24,address),uint256)",
	} {
		sel := keccak4(sig)
		var selb [4]byte
		selb[0], selb[1], selb[2], selb[3] = byte(sel>>24), byte(sel>>16), byte(sel>>8), byte(sel)
		// 256 bytes of zero args is enough for any of these to reach the dispatch switch.
		input := append(selb[:], make([]byte, 256)...)
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, input, 5_000_000, false)
		if err == nil || err.Error() != "dex: unknown 0x9999 selector" {
			t.Fatalf("maker-book selector %q must be unknown/undispatchable, got: %v", sig, err)
		}
	}
}

// TestDecomplect_Router9012ValueSelectorsMoved proves the SECOND money path is deprecated: the
// LP-9012 router's VALUE-moving selectors (exactInput* / exactOutput* — which routed swaps
// through the synchronous engine matcher) now REVERT PRECOMPILE_MOVED, while the read-only
// quote/route VIEWS still dispatch. There is exactly ONE money path (0x9999); 0x9012 moves no
// value.
func TestDecomplect_Router9012ValueSelectorsMoved(t *testing.T) {
	h := newSettleHarness(t)
	rc := RouterPrecompile // the 0x9012 RouterContract singleton

	// (a) Every value-moving selector reverts PRECOMPILE_MOVED — no swap routes through 0x9012.
	for _, sel := range []uint32{
		SelectorExactInputSingle, SelectorExactInput, SelectorExactOutputSingle, SelectorExactOutput,
	} {
		var selb [4]byte
		binary.BigEndian.PutUint32(selb[:], sel)
		input := append(selb[:], make([]byte, 256)...)
		_, _, err := rc.Run(h.state, h.caller, lxRouterAddr, input, 5_000_000, false)
		if !errors.Is(err, ErrPrecompileMoved) {
			t.Fatalf("0x9012 value selector %#08x must revert ErrPrecompileMoved, got: %v", sel, err)
		}
	}

	// (b) A read-only quote VIEW is NOT moved — it dispatches (does not return PRECOMPILE_MOVED
	// nor "unknown selector"). It may fail for lack of bound liquidity, but that is a view-level
	// error, not the deprecation revert.
	var qselb [4]byte
	binary.BigEndian.PutUint32(qselb[:], SelectorGetBestRoute)
	qinput := append(qselb[:], make([]byte, 128)...)
	_, _, qerr := rc.Run(h.state, h.caller, lxRouterAddr, qinput, 5_000_000, true)
	if errors.Is(qerr, ErrPrecompileMoved) {
		t.Fatalf("a read-only quote/route view must NOT be moved; got PRECOMPILE_MOVED")
	}
}

// TestDecomplect_InitializeRefusesSyntheticAsset — the permissionless real-asset admission is
// PRESERVED on the KEEP initialize path: a market over a SYNTHETIC base (no on-chain code) is
// REFUSED (ErrAssetNotOnChain) and NO MarketRecord is written. (Relocated from the deleted
// swap_sync_decomplect_test.go; it exercises settle_market.go admitMarketAssets, not a matcher.)
func TestDecomplect_InitializeRefusesSyntheticAsset(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey() // base = c1FabricatedBase (synthetic, no code)

	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h)
	r.admitERC20(t, c1RealQuote, 6)
	h.state.stateDB.SetCodeSize(c1FabricatedBase, 0) // synthetic base: NO code
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil)
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrAssetNotOnChain) {
		t.Fatalf("initialize over a SYNTHETIC base (no code) must be REFUSED (ErrAssetNotOnChain), got: %v", err)
	}
	if rec := loadMarket(newPoolStateAdapter(h.state), h.key.ID()); rec.Status != MarketStatusNone {
		t.Fatalf("a refused initialize must NOT have written a MarketRecord, got status %v", rec.Status)
	}
}

// TestDecomplect_InitializeNoResolverFailsClosed proves the initialize path fails closed when
// NO resolver is installed (ErrNoAssetResolver) — a node that serves 0x9999 without wiring the
// resolver cannot even create a market record.
func TestDecomplect_InitializeNoResolverFailsClosed(t *testing.T) {
	h := newSettleHarness(t)
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil)
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrNoAssetResolver) {
		t.Fatalf("initialize with no resolver must fail closed (ErrNoAssetResolver), got: %v", err)
	}
	if rec := loadMarket(newPoolStateAdapter(h.state), h.key.ID()); rec.Status != MarketStatusNone {
		t.Fatal("a fail-closed initialize must NOT have written a MarketRecord")
	}
}

// TestDecomplect_DAOControllerCannotMintOrMoveUserFunds — the governance controller (the
// per-network DEX authority) can HALT but can NEVER mint the seam reserve nor drain a
// depositor's pot. Relocated from the deleted gatec_red_probe_test.go: it uses ONLY the KEEP
// surface (seedSeamReserve / deposit / atomicImport), no maker path. A settlement draws ONLY
// from seamReserve and ONLY against a real D->C object — a fabricated object or an empty seam
// reverts, leaving the depositor pot intact.
func TestDecomplect_DAOControllerCannotMintOrMoveUserFunds(t *testing.T) {
	h := newSettleHarness(t)
	controller := h.operator() // == the runtime-resolved DEX governance controller

	native := [32]byte{}
	seamBefore := loadSeamReserve(newPoolStateAdapter(h.state), native).Uint64()

	// (a) Controller calls seedSeamReserve(native, 1_000_000) but the host frame delivers NO
	// msg.value. A mint would inflate seamReserve; the observed-delta discipline yields 0
	// delivered and REVERTS.
	data := make([]byte, 64) // asset = address(0), amount
	new(big.Int).SetUint64(1_000_000).FillBytes(data[32:64])
	_, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false)
	if err == nil {
		t.Fatal("DAO controller MINTED seam reserve with no value delivered (do-not-ship)")
	}
	if !errors.Is(err, ErrSeedUndelivered) {
		t.Fatalf("expected ErrSeedUndelivered (no mint), got: %v", err)
	}
	if got := loadSeamReserve(newPoolStateAdapter(h.state), native).Uint64(); got != seamBefore {
		t.Fatalf("seam reserve changed on an undelivered seed: %d -> %d (mint)", seamBefore, got)
	}

	// (b) A depositor funds the depositor pot; the controller cannot drain it via a settlement
	// (settlement draws ONLY seamReserve, which is empty here).
	depositor := common.HexToAddress("0xDEadBEEF00000000000000000000000000000001")
	h.state.stateDB.AddBalance(depositor, uint256.NewInt(1000))
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1000))
	depData := make([]byte, 64)
	new(big.Int).SetInt64(1000).FillBytes(depData[32:64])
	if _, _, derr := h.c.Run(h.state, depositor, poolManagerAddr9999, prependSelector(SelectorDeposit, depData), 5_000_000, false); derr != nil {
		t.Fatalf("depositor deposit: %v", derr)
	}
	// (i) fabricated object: no privileged path to mint a settlement object.
	credited, ierr := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: [32]byte{0xAB}, Asset: native, AssetAddr: common.Address{}, Amount: 500, Recipient: controller,
	})
	if ierr == nil || credited != 0 {
		t.Fatalf("controller credited itself from a fabricated settlement object: credited=%d err=%v", credited, ierr)
	}
	// (ii) a REAL D->C object exists, but seamReserve[native] is empty (only the depositor pot
	// holds native). The credit must revert UNBACKED — it cannot draw the depositor pot.
	realObj := [32]byte{0xCD, 0xEF}
	h.putDtoCObject(t, controller, realObj, native, 500)
	credited2, ierr2 := h.c.atomicImport(h.state, SettlementClaim{
		OutputID: realObj, Asset: native, AssetAddr: common.Address{}, Amount: 500, Recipient: controller,
	})
	if ierr2 != ErrNativeSettleUnbacked {
		t.Fatalf("controller raided the depositor pot via a real object with empty seam: credited=%d err=%v (must be ErrNativeSettleUnbacked)", credited2, ierr2)
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), depositor, native).Int64() != 1000 {
		t.Fatal("depositor claim moved after controller's raid attempt (do-not-ship)")
	}
}
