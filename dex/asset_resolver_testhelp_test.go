// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"testing"

	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// asset_resolver_testhelp_test.go provides the test-only, registry-SHAPED AssetResolver
// the sync-swap harnesses install so the value path's C1 admission gate is exercised for
// real (never stubbed always-true). It admits ONLY the (kind, ref) pairs a test
// explicitly registers — exactly as the production chains/dexvm/registry resolver admits
// only assets registered against the running chain — so a fabricated/unregistered asset
// has no admission and a swap over it reverts.

// testAssetResolver is a fake AssetResolver bound to a fixed network identity. It mirrors
// the real registry: an asset is admissible iff it was registered (and not disabled). It
// derives the canonical AssetID with its OWN bound ids, identical to the real resolver.
type testAssetResolver struct {
	networkID uint32
	chainID   ids.ID
	enabled   map[ids.ID]uint8
	disabled  map[ids.ID]bool
}

func newTestAssetResolver(networkID uint32, chainID ids.ID) *testAssetResolver {
	return &testAssetResolver{
		networkID: networkID,
		chainID:   chainID,
		enabled:   map[ids.ID]uint8{},
		disabled:  map[ids.ID]bool{},
	}
}

// admitERC20 registers a real ERC-20 by its 20-byte address.
func (r *testAssetResolver) admitERC20(t testing.TB, addr common.Address, decimals uint8) {
	t.Helper()
	r.admit(t, dexcore.AssetKindERC20, addr.Bytes(), decimals)
}

// admitNative registers the C-Chain native coin (the native marker).
func (r *testAssetResolver) admitNative(t testing.TB, decimals uint8) {
	t.Helper()
	r.admit(t, dexcore.AssetKindEVMNative, dexcore.EVMNativeMarker, decimals)
}

func (r *testAssetResolver) admit(t testing.TB, kind dexcore.AssetKind, ref []byte, decimals uint8) ids.ID {
	t.Helper()
	id, err := dexcore.DeriveAssetID(r.networkID, r.chainID, kind, ref)
	if err != nil {
		t.Fatalf("testAssetResolver.admit derive: %v", err)
	}
	r.enabled[id] = decimals
	return id
}

func (r *testAssetResolver) ResolveEnabled(kind dexcore.AssetKind, ref []byte) (ids.ID, uint8, error) {
	id, err := dexcore.DeriveAssetID(r.networkID, r.chainID, kind, ref)
	if err != nil {
		return ids.Empty, 0, err
	}
	dec, ok := r.enabled[id]
	if !ok {
		return ids.Empty, 0, errors.New("test resolver: unknown asset (not registered)")
	}
	if r.disabled[id] {
		return ids.Empty, 0, errors.New("test resolver: asset disabled")
	}
	return id, dec, nil
}

// installAssetResolverFor installs a fresh test resolver bound to the harness identity,
// pre-admitting the given ERC-20 token addresses plus the native coin (the common case
// for the sync-swap e2e tests), and restores the prior global resolver on cleanup so
// tests do not leak install state into each other. Returns the resolver so a test can
// admit/disable more assets.
func (h *settleHarness) installAssetResolverFor(t testing.TB, tokens ...common.Address) *testAssetResolver {
	t.Helper()
	r := newTestAssetResolver(h.networkID, h.cChainID)
	r.admitNative(t, 18)
	for _, tok := range tokens {
		r.admitERC20(t, tok, 18)
		// A real registered ERC-20 is a DEPLOYED contract — give its address live on-chain
		// code so the value path's OnChainAssetVerifier (C1 live-reality gate) admits it.
		// This mirrors production: an asset admitted to the registry has bytecode at its
		// address. A token a test deliberately leaves OUT of this set has no code and is
		// refused at the live-reality gate (exercised by the C1 redteam tests).
		h.state.stateDB.SetCodeSize(tok, 1)
	}
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(r, h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })
	return r
}
