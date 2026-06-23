// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/dex/pkg/dexcore"
)

// swap_sync_decomplect_test.go is the LOCK-IN proof for the 0x9999 value-path decomplect:
// the synchronous on-chain router is the ONE unconditional path (there is no value-activation
// gate), and admission is PERMISSIONLESS — canonical resolution + on-chain proof, no allowlist.
// It pins both halves of the live wiring in one place so Red can re-review the trust root:
//
//	(a) a REAL on-chain asset swaps successfully END-TO-END (resolver installed + token has
//	    code -> swap fills, real C-Chain balances move, the D book records the fill) WITHOUT
//	    being pre-registered in any manifest;
//	(b) the SAME market with a SYNTHETIC asset (no on-chain code) FAILS CLOSED at admission
//	    (ErrAssetNotOnChain — refused by the EXTCODESIZE proof, not by allowlist absence), and a
//	    node with NO resolver fails closed (ErrNoAssetResolver, a wiring guard).
//
// There is NO EnableValueSwaps / ValueSwapsEnabled / quorum gate anywhere in this path: a
// plain swap() reaches the synchronous router and the swap's intrinsic controls (permissionless
// canonical resolve + live-code on-chain proof + min-out floor + custody mutex) gate the fill.

// TestDecomplect_RealAssetFillsThenSyntheticFailsClosed proves the decomplect end-to-end: the
// unconditional synchronous router fills a swap over a real, code-backed market (permissionless
// — no pre-registration); and on a market whose base is SYNTHETIC (no on-chain code), the SAME
// router refuses the swap at the on-chain-proof gate without moving any value.
func TestDecomplect_RealAssetFillsThenSyntheticFailsClosed(t *testing.T) {
	// ── (a) REAL ASSET, RESOLVER INSTALLED → SWAP FILLS ──────────────────────────────────
	// newE2EHarness installs the permissionless resolver and gives the market's two ERC-20s
	// (LETH, LUSD) live on-chain code — exactly the trust root a value-live node carries
	// (installDEXValuePath wires a permissionless resolver; code presence is what admits).
	// There is no value gate to flip and no manifest to list: real code IS the admission.
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	// Maker rests a real-funded BID: deposit 5000 LUSD, rest a BID of 100 LETH @ 50.
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, uint64(50)*uint64(priceMultiplierConst), 100)

	// Taker SELLs 80 real LETH through 0x9999 (plain swap, untagged -> synchronous router),
	// with a permissive price floor so the SELL-protection policy is satisfied and the fill
	// at 50 clears it.
	h.mint(e2eLETH, taker, 80)
	out, err := h.swap(t, taker, true, 80, sqrtX96For(1.0))
	if err != nil {
		t.Fatalf("real-asset swap through the unconditional synchronous router must FILL, got: %v", err)
	}

	// The V4 BalanceDelta: paid 80 LETH (amount0 = -80), received 4000 LUSD (amount1 = +4000).
	a0, a1 := UnpackBalanceDelta(out)
	if a0.Int64() != -80 || a1.Int64() != 4000 {
		t.Fatalf("BalanceDelta = (%s, %s), want (-80, 4000) [80 LETH SELL @ 50]", a0, a1)
	}
	// Real C-Chain ERC-20 balances moved: taker sold all LETH, received 4000 LUSD proceeds.
	if got := h.ercBal(e2eLETH, taker); got != 0 {
		t.Fatalf("taker real LETH = %d, want 0 (sold into the vault)", got)
	}
	if got := h.ercBal(e2eLUSD, taker); got != 4000 {
		t.Fatalf("taker real LUSD = %d, want 4000 (proceeds credited from the seam reserve)", got)
	}
	// The fill is recorded ONCE in the D (dexcore) book: maker bought 80 LETH.
	if got := h.dcAvail(maker, e2eLETH); got != 80 {
		t.Fatalf("maker dexcore LETH available = %d, want 80 (the fill)", got)
	}
	// Conservation holds across the whole money surface.
	assertVaultConservation(t, h, maker, taker)

	// ── (b) SYNTHETIC ASSET (NO CODE) → SAME ROUTER FAILS CLOSED ──────────────────────────
	// A fresh harness on a market whose BASE is a SYNTHETIC asset with no on-chain code. The
	// resolver resolves it (permissionless: the identity is well-formed), but the on-chain
	// proof — the authoritative reality gate — refuses it. The SAME unconditional synchronous
	// router must REVERT at the market-open (ErrAssetNotOnChain) and bind NO market.
	hs := newSettleHarness(t)
	hs.key = c1MarketKey() // base = c1FabricatedBase (synthetic, no code), quote = c1RealQuote (real)

	r := newTestAssetResolver(hs.networkID, hs.cChainID).boundToHarness(hs)
	r.admitERC20(t, c1RealQuote, 6)                  // real quote: code-backed
	hs.state.stateDB.SetCodeSize(c1FabricatedBase, 0) // synthetic base: NO code
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil) // drop any prior harness resolver so this install lands cleanly
	if err := InstallAssetResolver(r, hs.networkID, hs.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(hs.key, params, EncodeMinOutHookData(1)) // floor met -> reaches admission
	_, _, serr := runWithEVMSnapshot(hs.c, hs.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(serr, dexcore.ErrAssetNotOnChain) {
		t.Fatalf("a swap over a SYNTHETIC base (no on-chain code) must fail closed (ErrAssetNotOnChain), got: %v", serr)
	}
	// Fail-closed before any write: no market was bound.
	if _, _, ok, rerr := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(hs.state)), hs.key.ID()); rerr != nil {
		t.Fatalf("ReadMarketAssets: %v", rerr)
	} else if ok {
		t.Fatal("a refused synthetic-asset swap must NOT have bound any market")
	}
}

// TestDecomplect_InitializeRefusesSyntheticAsset proves the parity gate on the initialize path
// (settle_market.go admitMarketAssets): a market RECORD can be created only over two assets
// that resolve AND are code-backed. An initialize over a SYNTHETIC base (no code) is REFUSED
// (ErrAssetNotOnChain) and writes NO MarketRecord — closing the phantom-stub surface where
// initialize would otherwise persist a market the swap path would only later refuse.
func TestDecomplect_InitializeRefusesSyntheticAsset(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey() // base = c1FabricatedBase (synthetic, no code)

	// Permissionless resolver; the real quote is code-backed, the base is NOT. Initialize must
	// run the SAME admission the swap path runs.
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
	// NO MarketRecord may have been written (the gate runs before storeMarket).
	if rec := loadMarket(newPoolStateAdapter(h.state), h.key.ID()); rec.Status != MarketStatusNone {
		t.Fatalf("a refused initialize must NOT have written a MarketRecord, got status %v", rec.Status)
	}
}

// TestDecomplect_InitializeNoResolverFailsClosed proves the initialize path fails closed when
// NO resolver is installed (parity with the swap path's ErrNoAssetResolver) — a node that
// serves 0x9999 without wiring the resolver cannot even create a market record.
func TestDecomplect_InitializeNoResolverFailsClosed(t *testing.T) {
	h := newSettleHarness(t)
	// Standard harness key (native + 0x..02). Force NO resolver installed.
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
