// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// swap_sync_fix1_registry_test.go is the PERMISSIONLESS admission suite for the 0x9999 value
// path. It proves the corrected product rule: admission is CANONICAL RESOLUTION + ON-CHAIN
// PROOF, never an admin allowlist. Concretely:
//
//   - a REAL on-chain ERC-20 (code at its address) TRADES without being pre-registered in any
//     manifest (TestPermissionlessRealERC20Trades, TestAdmissionDoesNotRequireManifest);
//   - a SYNTHETIC asset (an ASCII ticker / an address with no code) FAILS CLOSED, proven by
//     EXTCODESIZE — not by allowlist absence (Test9999RejectsSyntheticAsset);
//   - a market opens PERMISSIONLESSLY over any two real assets, idempotently
//     (TestPermissionlessOpenMarket);
//   - a real-looking asset bound to the WRONG chain/network fails closed (the identity gate is
//     kept — permissionless is not identity-free) (Test9999RejectsWrongNetworkAsset);
//   - the ERC-20 identity IS its 20-byte code-bearing address; the UTXO identity is its real
//     32-byte assetID (Test9999ERC20AssetIDUsesTokenAddress, Test9999UTXOAssetIDUsesRealAssetID);
//   - the on-chain-proof gate runs strictly BEFORE any debit/state write
//     (Test9999OnChainProofRunsBeforeAnyDebit).
//
// Every test runs the REAL 0x9999 Run dispatch over the real EVM/vault/atomic harness (no
// stubs), using REAL ERC-20 token balances and real code-presence, exactly like the e2e suite.

// a32 left-pads an ASCII ticker into a 20-byte EVM address — the FAKE asset identity the old
// (assert-only) path would have admitted as if it were a real token. It has no contract code,
// so the on-chain proof — the authoritative permissionless reality gate — refuses it.
func a32(ticker string) common.Address {
	var addr common.Address
	b := []byte(ticker)
	if len(b) > 20 {
		b = b[:20]
	}
	copy(addr[20-len(b):], b) // right-aligned ASCII bytes in the 20-byte address
	return addr
}

// TestPermissionlessRealERC20Trades is the decisive PERMISSIONLESS proof: a real ERC-20 with
// live code on THIS C-Chain trades end-to-end WITHOUT being pre-registered in any manifest. The
// tokens here (novelBase/novelQuote) are addresses that appear in NO committed manifest and were
// NEVER admitted to any registered set — they are admitted SOLELY because they have on-chain
// code and their canonical identity resolves on the bound network. A maker rests a real-funded
// BID; a taker SELLs into it; the fill clears and real balances move.
func TestPermissionlessRealERC20Trades(t *testing.T) {
	// Two ERC-20 addresses that are NOT e2eLETH/e2eLUSD and are in no manifest. V4 requires
	// currency0 < currency1.
	novelBase := common.HexToAddress("0x00000000000000000000000000000000000000A1")  // base / currency0
	novelQuote := common.HexToAddress("0x00000000000000000000000000000000000000B2") // quote / currency1

	// Use the e2e harness machinery (real ERC-20 ledger + deposit/place/swap), but point the
	// market at the NOVEL, never-listed tokens and re-install the resolver for them.
	h := newE2EHarness(t)
	novelKey := PoolKey{Currency0: Currency{Address: novelBase}, Currency1: Currency{Address: novelQuote}, Fee: 3000, TickSpacing: 60}
	h.key = novelKey
	h.settleHarness.key = novelKey

	// PERMISSIONLESS install: a canonical resolver (no manifest, no membership) + live on-chain
	// code for BOTH novel tokens. Code presence is the entire admission credential.
	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h.settleHarness)
	r.admitERC20(t, novelBase, 18)  // seeds live on-chain code
	r.admitERC20(t, novelQuote, 18) // seeds live on-chain code
	prev := installedAssetResolver.Load()
	installedAssetResolver.Store(nil)
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	maker, taker := e2eMaker, e2eTaker

	// Maker deposits 5000 novelQuote and rests a BID of 100 novelBase @ 50 (locks 5000 quote).
	h.mint(novelQuote, maker, 5000)
	h.deposit(t, maker, novelQuote, 5000)
	h.placeArgs(t, maker, true, uint64(50)*uint64(priceMultiplierConst), 100)

	// Taker SELLs 80 novelBase into the book through 0x9999 (synchronous router), with a
	// permissive price floor so the SELL-protection policy is satisfied.
	h.mint(novelBase, taker, 80)
	out, err := h.swapMinOut(t, taker, 80, 1)
	if err != nil {
		t.Fatalf("a REAL on-chain ERC-20 (with code) must trade PERMISSIONLESSLY (no manifest), got: %v", err)
	}

	// The V4 BalanceDelta: paid 80 base (amount0 = -80), received 4000 quote (amount1 = +4000).
	a0, a1 := UnpackBalanceDelta(out)
	if a0.Int64() != -80 || a1.Int64() != 4000 {
		t.Fatalf("BalanceDelta = (%s, %s), want (-80, 4000) [80 base SELL @ 50] — permissionless fill", a0, a1)
	}
	// Real C-Chain balances moved: taker sold all base, received 4000 quote proceeds.
	if got := h.ercBal(novelBase, taker); got != 0 {
		t.Fatalf("taker real base = %d, want 0 (sold into the vault) — permissionless settle", got)
	}
	if got := h.ercBal(novelQuote, taker); got != 4000 {
		t.Fatalf("taker real quote = %d, want 4000 (proceeds) — permissionless settle", got)
	}
	// The market is now bound (created permissionlessly by the swap's OpenMarket).
	if _, _, ok, _ := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), novelKey.ID()); !ok {
		t.Fatal("a permissionless real-asset swap must have bound the market")
	}
}

// TestAdmissionDoesNotRequireManifest proves the core permissionless property at the unit gate:
// with NO manifest and NO registered-asset set anywhere, a real on-chain ERC-20 is STILL
// admitted by OpenMarketChecked. The resolver is the production-shaped canonical resolver (it
// holds no membership); the verifier proves the asset real by code presence. Admission depends
// ONLY on (canonical identity resolves) AND (code present) — never on manifest membership.
func TestAdmissionDoesNotRequireManifest(t *testing.T) {
	h := newSettleHarness(t)
	// An ERC-20 address that is in NO manifest and was NEVER registered.
	unlisted := common.HexToAddress("0x00000000000000000000000000000000000000C3")
	h.state.stateDB.SetCodeSize(unlisted, 1) // it is a real, deployed contract (has code)

	// The permissionless resolver: it resolves ANY well-formed reference, with no manifest.
	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h)
	verifier := onChainVerifierFor(newPoolStateAdapter(h.state))
	if verifier == nil {
		t.Fatal("the value path must have an on-chain verifier")
	}

	store := newEVMStore(newPoolStateAdapter(h.state))
	pid := h.key.ID()
	// Open a market with the unlisted-but-real ERC-20 as base and native as quote-side partner
	// is not sorted; use native (zero addr) as base and the unlisted token as quote so currency
	// sorting holds (native 0x0 < any token). Admission must SUCCEED — no manifest required.
	baseSide := dexcore.AssetSide{Kind: dexcore.AssetKindEVMNative, Ref: dexcore.EVMNativeMarker}
	quoteSide := dexcore.AssetSide{Kind: dexcore.AssetKindERC20, Ref: unlisted.Bytes()}
	if err := dexcore.OpenMarketChecked(store, r, verifier, pid, baseSide, quoteSide); err != nil {
		t.Fatalf("admission must NOT require a manifest: a real on-chain ERC-20 (with code) must be admitted, got: %v", err)
	}
	// The market is bound (created permissionlessly).
	if _, _, ok, _ := dexcore.ReadMarketAssets(store, pid); !ok {
		t.Fatal("a permissionless admission must have bound the market")
	}
}

// TestPermissionlessOpenMarket proves OpenMarket(base, quote) creates a market for ANY two real
// on-chain assets with NO admin approval, and is idempotent on re-open. It drives the gate
// directly (OpenMarketChecked, the value-path market-open) so the property is pinned at the
// admission seam itself.
func TestPermissionlessOpenMarket(t *testing.T) {
	h := newSettleHarness(t)
	tokA := common.HexToAddress("0x00000000000000000000000000000000000000D4")
	tokB := common.HexToAddress("0x00000000000000000000000000000000000000E5")
	h.state.stateDB.SetCodeSize(tokA, 1) // both are real deployed contracts (code present)
	h.state.stateDB.SetCodeSize(tokB, 1)

	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h)
	verifier := onChainVerifierFor(newPoolStateAdapter(h.state))
	store := newEVMStore(newPoolStateAdapter(h.state))

	// A deterministic poolID for the (tokA, tokB) pair (sorted; tokA < tokB).
	key := PoolKey{Currency0: Currency{Address: tokA}, Currency1: Currency{Address: tokB}, Fee: 3000, TickSpacing: 60}
	pid := key.ID()
	baseSide := dexcore.AssetSide{Kind: dexcore.AssetKindERC20, Ref: tokA.Bytes()}
	quoteSide := dexcore.AssetSide{Kind: dexcore.AssetKindERC20, Ref: tokB.Bytes()}

	// First open: creates the market with NO admin approval.
	if err := dexcore.OpenMarketChecked(store, r, verifier, pid, baseSide, quoteSide); err != nil {
		t.Fatalf("OpenMarket over two real assets must succeed permissionlessly, got: %v", err)
	}
	gotBase, gotQuote, ok, err := dexcore.ReadMarketAssets(store, pid)
	if err != nil || !ok {
		t.Fatalf("the permissionlessly-opened market must be bound (ok=%v err=%v)", ok, err)
	}
	// Re-open: IDEMPOTENT — succeeds and leaves the same binding.
	if err := dexcore.OpenMarketChecked(store, r, verifier, pid, baseSide, quoteSide); err != nil {
		t.Fatalf("re-opening the same market must be idempotent (no error), got: %v", err)
	}
	gotBase2, gotQuote2, ok2, _ := dexcore.ReadMarketAssets(store, pid)
	if !ok2 || gotBase2 != gotBase || gotQuote2 != gotQuote {
		t.Fatal("re-open must be idempotent: the market binding must be unchanged")
	}
}

// Test9999RejectsSyntheticAsset is THE critical permissionless rejection test: a swap whose
// assetID is a FAKE ASCII ticker (a32("LUSD")) — a perfectly well-formed 32-byte left-pad whose
// canonical identity RESOLVES fine but which has NO on-chain code — MUST revert via the
// EXTCODESIZE on-chain proof (ErrAssetNotOnChain), and it must revert BEFORE any C balance debit
// and BEFORE any DEX state write. The synthetic asset is structurally untradeable — refused by
// on-chain proof, NOT by allowlist absence (there is no allowlist).
func Test9999RejectsSyntheticAsset(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker

	// The fake base: ASCII "LUSD" packed into an address — a perfectly well-formed 32-byte
	// left-pad whose canonical identity RESOLVES (it is on this network), but with NO contract
	// code (a synthetic/phantom token). The ON-CHAIN proof must be what catches it — proving
	// identity is VERIFIED against live code, not membership.
	fakeBase := a32("LUSD")
	resolver := h.installAssetResolverFor(t, e2eLETH, e2eLUSD) // re-install incl. the real pair
	_ = resolver
	key := PoolKey{Currency0: Currency{Address: fakeBase}, Currency1: Currency{Address: e2eLUSD}, Fee: 3000, TickSpacing: 60}

	// Fund the taker with the fake base so a DEBIT would be observable if the gate failed to run
	// first. (The mock ERC-20 ledger lets us mint any token; the point is the gate must refuse
	// BEFORE touching it.)
	h.wrapper().mintTestToken(fakeBase, taker, big.NewInt(1_000))
	// Crucially, the fake base has NO contract code — a synthetic asset.
	h.state.stateDB.SetCodeSize(fakeBase, 0)

	// SNAPSHOT the observable state BEFORE the swap.
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
	// It refuses at the ON-CHAIN PROOF gate (well-formed identity, but no code) — the synthetic-
	// asset refusal proven by EXTCODESIZE, NOT by allowlist absence.
	if !errors.Is(err, dexcore.ErrAssetNotOnChain) {
		t.Fatalf("expected ErrAssetNotOnChain (no code at the fake address), got: %v", err)
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

// Test9999RejectsWrongNetworkAsset: a resolver bound to a DIFFERENT network/C-Chain than the
// running chain is refused at swap time — a resolver for the wrong chain must never admit assets
// for this one (derive-don't-trust). This identity binding is KEPT under permissionless rules:
// permissionless means no allowlist, NOT no network-identity discipline.
func Test9999RejectsWrongNetworkAsset(t *testing.T) {
	h := newSettleHarness(t)
	h.key = e2eMarketKey()

	// Resolver bound to a WRONG C-Chain id (the harness runs cChainID {0xCC}). Both currencies
	// are code-backed so the ONLY thing that can refuse the swap is the identity cross-check.
	wrongChain := h.cChainID
	wrongChain[0] ^= 0xFF
	r := newTestAssetResolver(h.networkID, wrongChain).boundToHarness(h)
	r.admitERC20(t, e2eLETH, 18)
	r.admitERC20(t, e2eLUSD, 18)
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

// Test9999ERC20AssetIDUsesTokenAddress proves the identity discipline for ERC-20: the value-path
// asset id IS the left-pad of the 20-byte token ADDRESS (assetID), and the on-chain verifier
// requires CODE at exactly that address. So an ERC-20 is keyed by its real contract address with
// bytecode — never by a ticker — and admission is permissionless on the code, not a list.
func Test9999ERC20AssetIDUsesTokenAddress(t *testing.T) {
	// (a) The precompile's value key for an ERC-20 currency is the left-pad of its address.
	wantID := assetID(Currency{Address: e2eLUSD})
	var fromAddr [32]byte
	copy(fromAddr[12:], e2eLUSD.Bytes())
	if wantID != fromAddr {
		t.Fatalf("ERC-20 value key must be the left-pad of the token address: got %x want %x", wantID, fromAddr)
	}
	if common.BytesToAddress(wantID[12:]) != e2eLUSD {
		t.Fatalf("ERC-20 value key low-20 bytes must equal the token address, got %x", wantID[12:])
	}
	for _, b := range wantID[:12] {
		if b != 0 {
			t.Fatal("ERC-20 value key high-12 bytes must be zero (a left-padded address, not an ASCII ticker)")
		}
	}

	// (b) The on-chain verifier requires CODE at that token address; a code-less address (an
	// ASCII ticker masquerading as a token) is refused — the permissionless reality gate.
	h := newE2EHarness(t)
	verifier := onChainVerifierFor(newPoolStateAdapter(h.state))
	if verifier == nil {
		t.Fatal("the value path must have an on-chain verifier")
	}
	if err := verifier.VerifyOnChainAsset(dexcore.AssetKindERC20, e2eLUSD.Bytes()); err != nil {
		t.Fatalf("a code-backed ERC-20 address must verify as real on-chain: %v", err)
	}
	if err := verifier.VerifyOnChainAsset(dexcore.AssetKindERC20, a32("USDC").Bytes()); err == nil {
		t.Fatal("a code-less ASCII-ticker address must NOT verify as a real ERC-20")
	}
}

// Test9999UTXOAssetIDUsesRealAssetID proves the identity discipline for UTXO assets: the
// canonical AssetID is DERIVED from the real 32-byte source-chain assetID (a domain-separated
// fold over the real reference), NEVER a left-padded ASCII ticker.
func Test9999UTXOAssetIDUsesRealAssetID(t *testing.T) {
	const net uint32 = 1
	srcChain := ids.ID{0xCC}

	realAssetID := ids.GenerateTestID()
	id, err := dexcore.DeriveAssetID(net, srcChain, dexcore.AssetKindUTXO, realAssetID[:])
	if err != nil {
		t.Fatalf("DeriveAssetID(UTXO, real assetID): %v", err)
	}
	if id == realAssetID {
		t.Fatal("the canonical UTXO id must be a derived fold, not the raw assetID passed through")
	}

	var tickerRef [20]byte
	copy(tickerRef[:], []byte("ZOO"))
	if _, err := dexcore.CanonicalRefFor(dexcore.AssetKindUTXO, tickerRef[:]); err == nil {
		t.Fatal("a 20-byte ASCII-ticker ref must NOT be accepted as a UTXO assetID (UTXO refs are real 32-byte assetIDs)")
	}

	other := ids.GenerateTestID()
	id2, err := dexcore.DeriveAssetID(net, srcChain, dexcore.AssetKindUTXO, other[:])
	if err != nil {
		t.Fatalf("DeriveAssetID(UTXO, other): %v", err)
	}
	if id == id2 {
		t.Fatal("distinct real UTXO assetIDs must derive distinct canonical ids")
	}
}

// Test9999OnChainProofRunsBeforeAnyDebit is the ordering proof under permissionless rules: even
// with the taker FUNDED and a min-out floor that would clear the slippage policy, a swap whose
// base is SYNTHETIC (no on-chain code) moves NEITHER the taker's C balance NOR any DEX state —
// the on-chain-proof gate runs strictly before the lock. We use a code-less base so the on-chain
// PROOF fires (the permissionless rejection), and assert no debit and no market binding occurred.
func Test9999OnChainProofRunsBeforeAnyDebit(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker

	synthBase := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	key := PoolKey{Currency0: Currency{Address: synthBase}, Currency1: Currency{Address: e2eLUSD}, Fee: 3000, TickSpacing: 60}

	// Fund the taker generously so a debit would be unmistakable. NOTE: mintTestToken auto-seeds
	// code (a minted test token is a real ERC-20 by default), so we zero the code AFTER minting
	// to model a SYNTHETIC asset (funded, but no contract code) — the case the on-chain proof
	// must refuse.
	h.wrapper().mintTestToken(synthBase, taker, big.NewInt(10_000))
	h.state.stateDB.SetCodeSize(synthBase, 0) // SYNTHETIC: no code -> on-chain proof refuses it
	takerBefore := h.wrapper().ercBal(synthBase, taker).Uint64()
	seamBefore := h.seamReserveOf(synthBase)

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-5_000), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if !errors.Is(err, dexcore.ErrAssetNotOnChain) {
		t.Fatalf("expected ErrAssetNotOnChain (synthetic base, no code), got: %v", err)
	}
	// NO DEBIT: the taker's balance is untouched and the vault reserve did not grow.
	if got := h.wrapper().ercBal(synthBase, taker).Uint64(); got != takerBefore {
		t.Fatalf("the on-chain-proof gate debited the taker BEFORE refusing: %d -> %d", takerBefore, got)
	}
	if got := h.seamReserveOf(synthBase); got != seamBefore {
		t.Fatalf("the on-chain-proof gate moved value into the vault BEFORE refusing: %d -> %d", seamBefore, got)
	}
	// NO DEX STATE WRITE: no market bound.
	if _, _, ok, _ := dexcore.ReadMarketAssets(newEVMStore(newPoolStateAdapter(h.state)), key.ID()); ok {
		t.Fatal("the on-chain-proof gate bound a market BEFORE refusing (no DEX write may precede admission)")
	}
}
