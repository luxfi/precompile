// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
)

// swap_sync_c1_redteam_test.go is the RED suite at the 0x9999 cEVM VALUE PATH under the
// PERMISSIONLESS model: it proves admission is CANONICAL RESOLUTION + ON-CHAIN PROOF, not an
// allowlist. A swap whose base is a fabricated/synthetic asset (an address with NO contract
// code) REVERTS at the market-open — refused by the EXTCODESIZE on-chain proof, NOT because
// the base is absent from any registered set. A node with no resolver wired fails closed
// (wiring guard). A resolver bound to the wrong chain is refused at swap time. The left-padded
// address (assetID) is sufficient to NAME a market but not to TRADE one: trading requires the
// canonical identity to resolve AND the asset to be proven real on-chain.

// c1MarketKey is a market over a SYNTHETIC base (currency0, no on-chain code) and a REAL quote
// (currency1, code-backed). V4 requires currency0 < currency1, so the synthetic base is at the
// lower address and the real quote at the higher.
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

// TestRED_C1_SyncSwap_SyntheticBaseRevertsViaOnChainProof is the decisive permissionless
// proof: a swap whose base is a SYNTHETIC asset (an address with NO contract code) REVERTS at
// the market-open with ErrAssetNotOnChain — refused by the EXTCODESIZE on-chain proof, NOT by
// allowlist absence. The base's canonical identity RESOLVES fine (the left-pad of 0x..Ee is a
// well-formed 32-byte assetID on this network); what stops the swap is that the asset is not
// REAL on-chain. The real quote is code-backed and would trade; the synthetic base is what
// fails.
func TestRED_C1_SyncSwap_SyntheticBaseRevertsViaOnChainProof(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey()

	// PERMISSIONLESS resolver: it resolves ANY well-formed reference (no membership). Make the
	// REAL quote tradeable by seeding its on-chain code; the synthetic base is deliberately
	// left WITHOUT code, so the on-chain proof — the authoritative reality gate — refuses it.
	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h)
	r.admitERC20(t, c1RealQuote, 6)                  // real quote: code-backed
	h.state.stateDB.SetCodeSize(c1FabricatedBase, 0) // synthetic base: NO code
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	// THE ATTACK: a taker tries to swap on the synthetic-base market. zeroForOne sells the
	// (synthetic) base for the real quote. A min-out is declared so the swap passes the
	// slippage-protection policy and reaches the ADMISSION gate (the property under test); the
	// swap must then REVERT at the market-open because the base has no on-chain code.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1)) // DM01 -> sync router, floor met
	taker := common.HexToAddress("0xbb00000000000000000000000000000000000002")
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err == nil {
		t.Fatal("a swap over a synthetic base (no on-chain code) MUST revert (ErrAssetNotOnChain)")
	}
	if !errors.Is(err, dexcore.ErrAssetNotOnChain) {
		t.Fatalf("expected ErrAssetNotOnChain (synthetic base refused by on-chain proof, not allowlist), got: %v", err)
	}

	// And NO market binding may have been written (fail-closed).
	if _, _, ok, rerr := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), h.key.ID()); rerr != nil {
		t.Fatalf("ReadMarketAssets: %v", rerr)
	} else if ok {
		t.Fatal("a refused swap must NOT have bound any market assets")
	}
}

// TestRED_C1_SyncSwap_NoResolverFailsClosed proves that with NO resolver installed, the
// always-on value path FAILS CLOSED (ErrNoAssetResolver) rather than admitting a left-padded
// address. This is a WIRING guard (the value path was never brought live), not an allowlist: a
// node that serves 0x9999 without wiring the resolver refuses every swap.
func TestRED_C1_SyncSwap_NoResolverFailsClosed(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey()

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
// network/C-Chain than the running chain is refused at swap time — a resolver for the wrong
// chain must never admit assets for this one (derive-don't-trust). This identity binding is
// KEPT under the permissionless model: permissionless means no allowlist, NOT no
// network-identity discipline.
func TestRED_C1_SyncSwap_IdentityMismatchReverts(t *testing.T) {
	h := newSettleHarness(t)
	h.key = c1MarketKey()

	// Resolver bound to a DIFFERENT C-Chain id than the harness runs (h.cChainID == {0xCC}).
	// Replace the harness's default (correct-network) resolver outright: InstallAssetResolver
	// refuses to re-install a DIFFERENT identity over an existing one (a production safety), so
	// to install the wrong-chain resolver we first clear the slot. The cleanup restores the
	// prior (default) resolver. This proves the wrong-chain resolver is refused at SWAP time
	// (ErrAssetResolverIdentityMismatch), which is the property under test — not the install guard.
	// Both currencies are code-backed so the ONLY thing that can refuse the swap is the identity
	// cross-check (not the on-chain proof).
	wrongChain := h.cChainID
	wrongChain[0] ^= 0xFF
	r := newTestAssetResolver(h.networkID, wrongChain).boundToHarness(h)
	r.admitERC20(t, c1RealQuote, 6)
	h.state.stateDB.SetCodeSize(c1FabricatedBase, 1) // code-backed here, to isolate the identity gate
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil) // drop the harness default so the wrong-chain install lands
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
