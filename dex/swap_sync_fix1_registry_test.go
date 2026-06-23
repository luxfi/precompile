// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// swap_sync_fix1_registry_test.go is the FIX-1 RED suite for the registry-route seam: it
// proves the 0x9999 value path admits a swap/route/market-open ONLY over a REGISTERED,
// ENABLED asset that is ALSO backed by LIVE on-chain code, and that the WHOLE gate runs
// BEFORE any C-balance debit and BEFORE any DEX state write. Asset identity is no longer
// asserted (a left-padded ASCII ticker) — it is VERIFIED. Every test runs the REAL 0x9999
// Run dispatch over the real EVM/vault/atomic harness (no stubs), using REAL ERC-20 token
// balances and real registry admission, exactly like the e2e suite.
//
// Token layout matches the e2e harness: LETH = currency0 (base, 0x..01), LUSD = currency1
// (quote, 0x..02); "sell LETH for LUSD" is zeroForOne.

// a32 left-pads an ASCII ticker into a 20-byte EVM address — the FAKE asset identity the
// old (assert-only) path would have admitted as if it were a real token. It has no contract
// code and no registry entry, so the FIX-1 gate must refuse it.
func a32(ticker string) common.Address {
	var addr common.Address
	b := []byte(ticker)
	if len(b) > 20 {
		b = b[:20]
	}
	copy(addr[20-len(b):], b) // right-aligned ASCII bytes in the 20-byte address
	return addr
}

// Test9999RejectsUnregisteredAsset: a swap whose base resolves to NOTHING in the registry
// (an unregistered ERC-20) reverts with ErrAssetNotAdmitted — the registry resolve gate.
func Test9999RejectsUnregisteredAsset(t *testing.T) {
	h := newE2EHarness(t)
	// Build a market over an UNREGISTERED base (not in the resolver) and the real quote.
	unregBase := common.HexToAddress("0x00000000000000000000000000000000000000A1") // never admitted
	// Give it live code so the resolve gate (not the code gate) is the one that fires.
	h.state.stateDB.SetCodeSize(unregBase, 1)
	key := PoolKey{Currency0: Currency{Address: unregBase}, Currency1: Currency{Address: e2eLUSD}, Fee: 3000, TickSpacing: 60}

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-10), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(key, params, EncodeMinOutHookData(1)) // floor met -> reach the admission gate
	_, _, err := runWithEVMSnapshot(h.c, h.state, e2eTaker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrAssetNotAdmitted) {
		t.Fatalf("a swap over an unregistered asset must revert ErrAssetNotAdmitted, got: %v", err)
	}
}

// Test9999RejectsSyntheticAsset is THE critical FIX-1 test: a swap whose assetID is a FAKE
// ASCII ticker (a32("LUSD")) — a perfectly well-formed 32-byte left-pad with no registry
// entry and NO on-chain code — MUST revert, and it must revert BEFORE any C balance debit
// and BEFORE any DEX state write (no market bound, no lock taken). The synthetic asset is
// structurally untradeable on the value path.
func Test9999RejectsSyntheticAsset(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker

	// The fake base: ASCII "LUSD" packed into an address — a perfectly well-formed 32-byte
	// left-pad an assert-only path would have admitted as a real token. We make it the
	// HARDEST case for the gate: REGISTERED in the resolver (so the resolve gate passes) but
	// with NO contract code (a synthetic/phantom token). The ON-CHAIN reality gate must be
	// what catches it — proving identity is VERIFIED against live code, not merely resolved.
	fakeBase := a32("LUSD")
	resolver := h.installAssetResolverFor(t, e2eLETH, e2eLUSD) // re-install incl. the real pair
	resolver.admitERC20(t, fakeBase, 18)                       // register the FAKE ticker too
	key := PoolKey{Currency0: Currency{Address: fakeBase}, Currency1: Currency{Address: e2eLUSD}, Fee: 3000, TickSpacing: 60}

	// Fund the taker with the fake base so a DEBIT would be observable if the gate failed to
	// run first. (The mock ERC-20 ledger lets us mint any token; the point is the gate must
	// refuse BEFORE touching it.)
	h.wrapper().mintTestToken(fakeBase, taker, big.NewInt(1_000))
	// Crucially, clear the code mintTestToken seeds — a synthetic asset has NO contract code.
	h.state.stateDB.SetCodeSize(fakeBase, 0)

	// SNAPSHOT the observable state BEFORE the swap: the taker's fake-base balance and
	// whether the market is bound.
	takerBaseBefore := h.wrapper().ercBal(fakeBase, taker).Uint64()
	store := newEVMStore(newPoolStateAdapter(h.state))
	if _, _, ok, _ := dexcore.ReadMarketAssets(store, key.ID()); ok {
		t.Fatal("precondition: the synthetic market must not already be bound")
	}

	// THE ATTACK: swap the fake LUSD base. A min-out floor is declared so the swap clears the
	// slippage policy and reaches the ADMISSION gate (the property under test).
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-100), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err == nil {
		t.Fatal("a swap over a fake ASCII assetID MUST revert (synthetic asset is untradeable)")
	}
	// It refuses at the LIVE-REALITY gate (registered, but no on-chain code) — the synthetic-
	// asset refusal that a resolve-only gate could NOT make.
	if !errors.Is(err, dexcore.ErrAssetNotOnChain) {
		t.Fatalf("expected ErrAssetNotOnChain (registered but no code at the fake address), got: %v", err)
	}

	// BEFORE ANY DEBIT: the taker's fake-base balance is UNCHANGED (no lock was taken).
	if got := h.wrapper().ercBal(fakeBase, taker).Uint64(); got != takerBaseBefore {
		t.Fatalf("synthetic-asset swap debited the taker BEFORE the gate: %d -> %d (the gate must run before any debit)", takerBaseBefore, got)
	}
	// BEFORE ANY DEX STATE WRITE: no market was bound.
	if _, _, ok, _ := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), key.ID()); ok {
		t.Fatal("synthetic-asset swap bound a market BEFORE the gate refused (no DEX state write may precede admission)")
	}
}

// Test9999RejectsWrongNetworkAsset: a resolver bound to a DIFFERENT network/C-Chain than
// the running chain is refused at swap time — a resolver for the wrong chain must never
// admit assets for this one (derive-don't-trust).
func Test9999RejectsWrongNetworkAsset(t *testing.T) {
	h := newSettleHarness(t)
	// Value gate (A2): this test exercises the SYNCHRONOUS value path (C1 admission / BLS
	// absence), which runs only when native-value swaps are enabled — enable it as a
	// quorum-finality node would; cleanup restores the fail-closed default.
	h.key = e2eMarketKey()

	// Resolver bound to a WRONG C-Chain id (the harness runs cChainID {0xCC}). Replace the
	// harness's default (correct-network) resolver: InstallAssetResolver refuses to re-install a
	// DIFFERENT identity over an existing one, so we clear the slot first; the cleanup restores
	// the default. The property under test is that the wrong-NETWORK resolver is refused at SWAP
	// time (ErrAssetResolverIdentityMismatch), not the install guard.
	wrongChain := h.cChainID
	wrongChain[0] ^= 0xFF
	r := newTestAssetResolver(h.networkID, wrongChain)
	r.admitNative(t, 18)
	r.admitERC20(t, e2eLETH, 18)
	r.admitERC20(t, e2eLUSD, 18)
	h.state.stateDB.SetCodeSize(e2eLETH, 1)
	h.state.stateDB.SetCodeSize(e2eLUSD, 1)
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil) // drop the harness default so the wrong-network install lands
	if err := InstallAssetResolver(r, h.networkID, wrongChain); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, e2eTaker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, ErrAssetResolverIdentityMismatch) {
		t.Fatalf("a resolver bound to the wrong network must be refused at swap time (ErrAssetResolverIdentityMismatch), got: %v", err)
	}
}

// Test9999CannotOpenMarketWithoutRegistryApproval: a maker RESTING an order (swapPlace,
// which BINDS the market) over an unregistered asset is refused — closing the
// "OpenMarket binds any caller-named pair" hole on the maker side.
func Test9999CannotOpenMarketWithoutRegistryApproval(t *testing.T) {
	h := newSettleHarness(t)
	// Value gate (A2): this test exercises the SYNCHRONOUS value path (C1 admission / BLS
	// absence), which runs only when native-value swaps are enabled — enable it as a
	// quorum-finality node would; cleanup restores the fail-closed default.
	h.key = e2eMarketKey()

	// Install a resolver that admits ONLY native (NOT LETH/LUSD), so the market's assets are
	// unregistered. A maker must not be able to bind a market over them.
	r := newTestAssetResolver(h.networkID, h.cChainID)
	r.admitNative(t, 18)
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	// A maker tries to rest a BID on the (unregistered) LETH/LUSD market.
	data := make([]byte, 256)
	copy(data[0:160], EncodePoolKeyABI(h.key))
	data[191] = 1                                                            // isBid
	new(big.Int).SetUint64(50 * priceMultiplierConst).FillBytes(data[192:224]) // price
	new(big.Int).SetUint64(100).FillBytes(data[224:256])                       // size
	_, _, err := h.c.Run(h.state, e2eMaker, poolManagerAddr9999, prependSelector(SelectorSwapPlace, data), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrAssetNotAdmitted) {
		t.Fatalf("a maker placing on an unregistered market must revert ErrAssetNotAdmitted, got: %v", err)
	}
	// And NO market binding may have been written (fail-closed).
	if _, _, ok, _ := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), h.key.ID()); ok {
		t.Fatal("a refused swapPlace must NOT have bound any market assets")
	}
}

// Test9999CannotRouteWithoutRegistryApproval: a taker's swap (route) over an unregistered
// market is refused at the admission gate — the taker-side twin of the maker test.
func Test9999CannotRouteWithoutRegistryApproval(t *testing.T) {
	h := newSettleHarness(t)
	// Value gate (A2): this test exercises the SYNCHRONOUS value path (C1 admission / BLS
	// absence), which runs only when native-value swaps are enabled — enable it as a
	// quorum-finality node would; cleanup restores the fail-closed default.
	h.key = e2eMarketKey()

	// Resolver admits ONLY native — the LETH/LUSD market is unregistered.
	r := newTestAssetResolver(h.networkID, h.cChainID)
	r.admitNative(t, 18)
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-50), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, e2eTaker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrAssetNotAdmitted) {
		t.Fatalf("a route over an unregistered market must revert ErrAssetNotAdmitted, got: %v", err)
	}
}

// Test9999ERC20AssetIDUsesTokenAddress proves the identity discipline for ERC-20: the
// value-path asset id IS the left-pad of the 20-byte token ADDRESS (assetID), the registry
// admission key derives from that same address, and the on-chain verifier requires CODE at
// exactly that address. So an ERC-20 is keyed by its real contract address with bytecode —
// never by a ticker.
func Test9999ERC20AssetIDUsesTokenAddress(t *testing.T) {
	// (a) The precompile's value key for an ERC-20 currency is the left-pad of its address.
	wantID := assetID(Currency{Address: e2eLUSD})
	var fromAddr [32]byte
	copy(fromAddr[12:], e2eLUSD.Bytes())
	if wantID != fromAddr {
		t.Fatalf("ERC-20 value key must be the left-pad of the token address: got %x want %x", wantID, fromAddr)
	}
	// The low 20 bytes are exactly the token address; the high 12 are zero.
	if common.BytesToAddress(wantID[12:]) != e2eLUSD {
		t.Fatalf("ERC-20 value key low-20 bytes must equal the token address, got %x", wantID[12:])
	}
	for _, b := range wantID[:12] {
		if b != 0 {
			t.Fatal("ERC-20 value key high-12 bytes must be zero (a left-padded address, not an ASCII ticker)")
		}
	}

	// (b) The live-reality verifier requires CODE at that token address; a code-less address
	// (an ASCII ticker masquerading as a token) is refused.
	h := newE2EHarness(t)
	verifier := onChainVerifierFor(newPoolStateAdapter(h.state))
	if verifier == nil {
		t.Fatal("the value path must have an on-chain verifier")
	}
	// e2eLUSD was code-seeded by the harness -> real.
	if err := verifier.VerifyOnChainAsset(dexcore.AssetKindERC20, e2eLUSD.Bytes()); err != nil {
		t.Fatalf("a code-backed ERC-20 address must verify as real on-chain: %v", err)
	}
	// A fake ASCII-ticker address has no code -> refused.
	if err := verifier.VerifyOnChainAsset(dexcore.AssetKindERC20, a32("USDC").Bytes()); err == nil {
		t.Fatal("a code-less ASCII-ticker address must NOT verify as a real ERC-20")
	}
}

// Test9999UTXOAssetIDUsesRealAssetID proves the identity discipline for UTXO assets: the
// canonical AssetID is DERIVED from the real 32-byte source-chain assetID (a domain-
// separated fold over the real reference), NEVER a left-padded ASCII ticker. Two distinct
// real assetIDs yield distinct ids; a ticker-shaped ref is not even a valid UTXO reference.
func Test9999UTXOAssetIDUsesRealAssetID(t *testing.T) {
	const net uint32 = 1
	srcChain := ids.ID{0xCC}

	// A real 32-byte UTXO assetID.
	realAssetID := ids.GenerateTestID()
	id, err := dexcore.DeriveAssetID(net, srcChain, dexcore.AssetKindUTXO, realAssetID[:])
	if err != nil {
		t.Fatalf("DeriveAssetID(UTXO, real assetID): %v", err)
	}
	// The derived id is a domain-separated fold — NOT the raw assetID and NOT a left-pad.
	if id == realAssetID {
		t.Fatal("the canonical UTXO id must be a derived fold, not the raw assetID passed through")
	}

	// A LEFT-PADDED ASCII TICKER is NOT a valid UTXO reference (UTXO refs are 32-byte real
	// assetIDs, and a ticker padded into 20 bytes is the wrong shape / would be all-zero in
	// the wrong places) — CanonicalRefFor refuses anything that is not a real 32-byte ref.
	var tickerRef [20]byte
	copy(tickerRef[:], []byte("ZOO"))
	if _, err := dexcore.CanonicalRefFor(dexcore.AssetKindUTXO, tickerRef[:]); err == nil {
		t.Fatal("a 20-byte ASCII-ticker ref must NOT be accepted as a UTXO assetID (UTXO refs are real 32-byte assetIDs)")
	}

	// Two distinct real assetIDs derive to two distinct ids (injective over the real ref).
	other := ids.GenerateTestID()
	id2, err := dexcore.DeriveAssetID(net, srcChain, dexcore.AssetKindUTXO, other[:])
	if err != nil {
		t.Fatalf("DeriveAssetID(UTXO, other): %v", err)
	}
	if id == id2 {
		t.Fatal("distinct real UTXO assetIDs must derive distinct canonical ids")
	}
}

// Test9999RegistryGateRunsBeforeAnyDebit is the ordering proof: even with the taker FUNDED
// and a min-out floor that would clear the slippage policy, a swap whose asset fails
// admission moves NEITHER the taker's C balance NOR any DEX state — the gate runs strictly
// before the lock. We use an unregistered (but code-backed) base so the RESOLVE gate fires,
// and assert no debit and no market binding occurred.
func Test9999RegistryGateRunsBeforeAnyDebit(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker

	unregBase := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	h.state.stateDB.SetCodeSize(unregBase, 1) // has code, but NOT registered
	key := PoolKey{Currency0: Currency{Address: unregBase}, Currency1: Currency{Address: e2eLUSD}, Fee: 3000, TickSpacing: 60}

	// Fund the taker generously so a debit would be unmistakable.
	h.wrapper().mintTestToken(unregBase, taker, big.NewInt(10_000))
	takerBefore := h.wrapper().ercBal(unregBase, taker).Uint64()
	seamBefore := h.seamReserveOf(unregBase)

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-5_000), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrAssetNotAdmitted) {
		t.Fatalf("expected ErrAssetNotAdmitted, got: %v", err)
	}
	// NO DEBIT: the taker's balance is untouched and the vault reserve did not grow.
	if got := h.wrapper().ercBal(unregBase, taker).Uint64(); got != takerBefore {
		t.Fatalf("the registry gate debited the taker BEFORE refusing: %d -> %d", takerBefore, got)
	}
	if got := h.seamReserveOf(unregBase); got != seamBefore {
		t.Fatalf("the registry gate moved value into the vault BEFORE refusing: %d -> %d", seamBefore, got)
	}
	// NO DEX STATE WRITE: no market bound.
	if _, _, ok, _ := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), key.ID()); ok {
		t.Fatal("the registry gate bound a market BEFORE refusing (no DEX write may precede admission)")
	}
}
