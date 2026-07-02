// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// asset_resolver_testhelp_test.go provides the test-only, PERMISSIONLESS AssetResolver the
// sync-swap harnesses install so the value path's admission is exercised against the real
// production model (never stubbed). It mirrors the production canonicalAssetResolver exactly:
// it RESOLVES the canonical AssetID for ANY well-formed reference on its bound network — it
// has NO membership set, NO Enabled flag, NO manifest. An asset is tradeable iff its identity
// resolves here AND it is proven real on-chain by the EXTCODESIZE verifier; a synthetic asset
// is refused at the on-chain proof (no code at its address), never by an allowlist.
//
// The "admit" helpers below therefore do NOT register membership (there is none). admitERC20
// SEEDS LIVE ON-CHAIN CODE for the token — that is what makes it tradeable under permissionless
// admission, and it is exactly what production requires (a deployed contract has bytecode).
// admitNative is a no-op: the native coin is always real. A token that is NOT code-seeded has
// no code and is refused at the live-reality gate, modelling a fabricated/synthetic asset.

// testAssetResolver is a PERMISSIONLESS AssetResolver bound to a fixed network identity. It
// derives the canonical AssetID with its OWN bound ids, identical to the production
// canonicalAssetResolver, and admits any well-formed reference. It holds an optional
// back-reference to the harness so the `admit` helpers can seed live on-chain code (the
// authoritative reality signal) for a token's address.
type testAssetResolver struct {
	networkID uint32
	chainID   ids.ID
	h         *settleHarness // optional; set when constructed via the harness, for code seeding
}

func newTestAssetResolver(networkID uint32, chainID ids.ID) *testAssetResolver {
	return &testAssetResolver{networkID: networkID, chainID: chainID}
}

// boundToHarness returns the resolver with a harness back-reference so admitERC20 can seed
// on-chain code through the harness's StateDB.
func (r *testAssetResolver) boundToHarness(h *settleHarness) *testAssetResolver {
	r.h = h
	return r
}

// ResolveAsset implements dexcore.AssetResolver PERMISSIONLESSLY: derive the canonical
// AssetID from the bound (networkID, chainID) and the per-asset (kind, ref). It returns an
// error ONLY when the reference is malformed (wrong shape, rejected by DeriveAssetID), never
// because the asset is "unregistered". Native decimals are the intrinsic 18; ERC-20/UTXO
// decimals are a live-chain fact (returned 0, proven by the verifier), matching production.
func (r *testAssetResolver) ResolveAsset(kind dexcore.AssetKind, ref []byte) (ids.ID, uint8, error) {
	id, err := dexcore.DeriveAssetID(r.networkID, r.chainID, kind, ref)
	if err != nil {
		return ids.Empty, 0, err
	}
	var decimals uint8
	if kind == dexcore.AssetKindEVMNative {
		decimals = 18
	}
	return id, decimals, nil
}

// admitNative is a no-op under permissionless admission: the native coin is the chain's own
// coin and is always real (no contract code needed). Kept so native-inclusive test setups
// read symmetrically with admitERC20. The decimals arg is ignored (native is intrinsically 18).
func (r *testAssetResolver) admitNative(_ testing.TB, _ uint8) {}

// admitERC20 makes an ERC-20 TRADEABLE under permissionless admission by seeding LIVE ON-CHAIN
// CODE at its address (the authoritative reality signal the value path's verifier checks) — it
// does NOT register membership (there is none). It requires the resolver to be bound to a
// harness (via the harness installer or boundToHarness). The decimals arg is ignored (decimals
// is a live-chain fact, not a resolver fact).
func (r *testAssetResolver) admitERC20(t testing.TB, addr common.Address, _ uint8) {
	t.Helper()
	if r.h == nil {
		t.Fatal("admitERC20: resolver is not bound to a harness (cannot seed on-chain code); construct via installAssetResolverFor or boundToHarness")
	}
	// A real, deployed ERC-20 has bytecode at its address; seed code so the on-chain verifier
	// admits it permissionlessly.
	r.h.state.stateDB.SetCodeSize(addr, 1)
}

// installAssetResolverFor installs a fresh PERMISSIONLESS test resolver bound to the harness
// identity and seeds LIVE on-chain code for the given ERC-20 token addresses (so the value
// path's OnChainAssetVerifier — the authoritative reality gate — admits them). It restores
// the prior global resolver on cleanup so tests do not leak install state. The resolver
// itself admits ANY well-formed reference; what makes a token tradeable is the code seeded
// here. A token a test deliberately leaves OUT of `tokens` (and does not code-seed) has no
// code and is refused at the live-reality gate — exactly as a fabricated/synthetic asset is.
// Returns the resolver (harness-bound, so further admitERC20 calls seed code).
func (h *settleHarness) installAssetResolverFor(t testing.TB, tokens ...common.Address) *testAssetResolver {
	t.Helper()
	r := newTestAssetResolver(h.networkID, h.cChainID).boundToHarness(h)
	for _, tok := range tokens {
		h.state.stateDB.SetCodeSize(tok, 1)
	}
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })
	return r
}
