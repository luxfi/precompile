// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/geth/common"
)

// swap_sync_c1_redteam_test.go is the C1 RED suite at the 0x9999 cEVM VALUE PATH: it
// proves the AssetRegistry's admission, repointed onto the cEVM, REFUSES a swap over an
// asset that is not a registered, enabled real on-chain asset. The left-padded address
// (assetID) is no longer SUFFICIENT to create a market — a swap whose base is a
// fabricated/unregistered asset REVERTS at the market-open, and a node with no resolver
// installed fails closed. This is the cEVM-path analog of the registry's own gate, which
// before this fix was wired only into the retiring chains/dexvm proxy.

// c1MarketKey is a market over a fabricated base (currency0) and a REAL quote
// (currency1). V4 requires currency0 < currency1, so the fabricated base is at the lower
// address and the real quote at the higher.
var (
	c1FabricatedBase = common.HexToAddress("0x00000000000000000000000000000000000000Ee") // never registered
	c1RealQuote      = common.HexToAddress("0x0000000000000000000000000000000000000F02") // a real registered ERC-20
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

// TestRED_C1_SyncSwap_FabricatedBaseReverts is the decisive proof: a swap whose base is a
// fabricated, UNREGISTERED asset (only the real quote is admitted) REVERTS at the
// market-open with ErrAssetNotAdmitted — the swap can never create a market over a
// synthetic asset, even though the left-pad of 0x..Ee is a perfectly well-formed 32-byte
// assetID.
func TestRED_C1_SyncSwap_FabricatedBaseReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey()
	EnableValueSwaps(true)
	t.Cleanup(func() { EnableValueSwaps(false) })

	// Install a resolver that admits ONLY the real quote (and native) — NOT the fabricated
	// base. This is the registry's reality gate, repointed onto the value path.
	r := newTestAssetResolver(h.networkID, h.cChainID)
	r.admitNative(t, 18)
	r.admitERC20(t, c1RealQuote, 6) // only the quote is real/registered
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	// THE ATTACK: a taker tries to swap on the fabricated-base market. zeroForOne sells the
	// (fabricated) base for the real quote. A min-out is declared so the swap passes the
	// slippage-protection policy and reaches the ADMISSION gate (the property under test);
	// the swap must then REVERT at the market-open because the base is unregistered.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1)) // DM01 -> sync router, floor met
	taker := common.HexToAddress("0xbb00000000000000000000000000000000000002")
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err == nil {
		t.Fatal("a swap over a fabricated, unregistered base MUST revert (ErrAssetNotAdmitted)")
	}
	if !errors.Is(err, dexcore.ErrAssetNotAdmitted) {
		t.Fatalf("expected ErrAssetNotAdmitted, got: %v", err)
	}

	// And NO market binding may have been written (fail-closed).
	if _, _, ok, rerr := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), h.key.ID()); rerr != nil {
		t.Fatalf("ReadMarketAssets: %v", rerr)
	} else if ok {
		t.Fatal("a refused swap must NOT have bound any market assets")
	}
}

// TestRED_C1_SyncSwap_NoResolverFailsClosed proves that with native value enabled but NO
// resolver installed, the value path FAILS CLOSED (ErrNoAssetResolver) rather than
// admitting a left-padded address as a real asset. This is the pre-activation safety net:
// even a misconfigured node that flipped value on without wiring the registry refuses
// every swap.
func TestRED_C1_SyncSwap_NoResolverFailsClosed(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey()
	EnableValueSwaps(true)
	t.Cleanup(func() { EnableValueSwaps(false) })

	// Force NO resolver installed for this test.
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil)
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1)) // floor met -> reaches admission gate
	taker := common.HexToAddress("0xbb00000000000000000000000000000000000002")
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrNoAssetResolver) {
		t.Fatalf("with no resolver installed the value path must fail closed (ErrNoAssetResolver), got: %v", err)
	}
}

// TestRED_C1_SyncSwap_IdentityMismatchReverts proves that a resolver bound to a DIFFERENT
// network/C-Chain than the running chain is refused at swap time — a resolver for the
// wrong chain must never admit assets for this one (derive-don't-trust).
func TestRED_C1_SyncSwap_IdentityMismatchReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey()
	EnableValueSwaps(true)
	t.Cleanup(func() { EnableValueSwaps(false) })

	// Resolver bound to a DIFFERENT C-Chain id than the harness runs (h.cChainID == {0xCC}).
	wrongChain := h.cChainID
	wrongChain[0] ^= 0xFF
	r := newTestAssetResolver(h.networkID, wrongChain)
	r.admitNative(t, 18)
	r.admitERC20(t, c1RealQuote, 6)
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, wrongChain); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1))
	taker := common.HexToAddress("0xbb00000000000000000000000000000000000002")
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, ErrAssetResolverIdentityMismatch) {
		t.Fatalf("a resolver bound to the wrong chain must be refused at swap time (ErrAssetResolverIdentityMismatch), got: %v", err)
	}
}
