// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/luxfi/dex/pkg/dexcore"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// asset_resolver.go is the value-path wiring: it injects the canonical-identity
// AssetResolver into the 0x9999 cEVM value path. The resolver PROVES an asset's canonical
// identity on the node's bound network (permissionless, not an allowlist): it derives the
// canonical AssetID with the node's bound ids — pure canonical math, no manifest, no
// registered-asset set. The value path lives here in the precompile. The precompile depends
// only on the dexcore AssetResolver PORT (an abstraction it owns through the shared leaf),
// never on any registry/manifest package — so there is no upward dependency and no cycle.
// The EVM plugin boot constructs the canonical resolver and installs it here exactly like it
// installs the local D-Chain client (InstallDChainClient).
//
// THE PROPERTY THIS ENFORCES (PERMISSIONLESS + PUBLIC): any market over two REAL assets
// can be opened — permissionlessly. The left-padded address (assetID) NAMES an asset but
// does not let it TRADE: trading requires the asset to RESOLVE (well-formed canonical
// identity on the bound network) AND VERIFY ON-CHAIN (real contract code — the
// authoritative reality check). A swap whose base is a fabricated/synthetic asset RESOLVES
// to a well-formed id but REVERTS at the live-reality gate (OpenMarketChecked ->
// ErrAssetNotOnChain), because a synthetic address has no code. When the value path is live
// and no resolver was installed, the path FAILS CLOSED (ErrNoAssetResolver) rather than
// admitting an unbound left-padded address.

// installedAssetResolver is the package-level, identity-bound asset resolver the value
// path consults. nil until the EVM plugin installs one at boot. It is read on the hot
// swap path under an atomic load (the install is a one-shot boot event; the value never
// changes after, so an atomic.Pointer gives a race-free read without a hot-path mutex).
var installedAssetResolver atomic.Pointer[boundAssetResolver]

// boundAssetResolver is the installed resolver together with the network identity it was
// constructed for. The bound identity is CROSS-CHECKED against the runtime AtomicState's
// (networkID, cChainID) at swap time: a resolver built for a different network than the
// node actually runs is REFUSED (fail-closed, derive-don't-trust). This mirrors the
// startup RuntimeVerifier's identity binding, now applied on the value path.
type boundAssetResolver struct {
	resolver  dexcore.AssetResolver
	networkID uint32
	cChainID  ids.ID
}

var (
	// ErrAssetResolverIdentityMismatch is returned when the installed resolver's bound
	// network identity does not match the runtime AtomicState's (networkID, cChainID).
	// A resolver bound to the wrong chain must never admit assets for this one.
	ErrAssetResolverIdentityMismatch = errors.New("dex: installed asset resolver is bound to a different network/C-Chain than the running chain (refusing to admit)")
)

// InstallAssetResolver wires the permissionless canonical asset resolver into the value
// path, bound to the network identity (networkID, cChainID) the node runs. The EVM plugin
// calls this once at boot, alongside the network identity already supplied to the
// precompile at runtime. resolver must be non-nil; cChainID must be set. Installing a
// resolver bound to a (networkID, cChainID) that disagrees with the running chain is
// caught at swap time (ErrAssetResolverIdentityMismatch), not here, because the runtime
// identity is supplied per-call by the AtomicState capability.
//
// Idempotent re-install with the SAME identity is allowed (re-wiring on a benign
// re-init); a re-install with a DIFFERENT identity is refused (a real misconfiguration).
//
// Logs to stderr on success so operators see in the boot log that real-asset admission
// is active on the value path. Not safe for concurrent use; the host binary is the
// single caller during process startup.
func InstallAssetResolver(resolver dexcore.AssetResolver, networkID uint32, cChainID ids.ID) error {
	if resolver == nil {
		return fmt.Errorf("dex: asset resolver must not be nil")
	}
	if cChainID == ids.Empty {
		return fmt.Errorf("dex: asset resolver requires a non-empty C-Chain id")
	}
	next := &boundAssetResolver{resolver: resolver, networkID: networkID, cChainID: cChainID}
	if cur := installedAssetResolver.Load(); cur != nil {
		if cur.networkID != next.networkID || cur.cChainID != next.cChainID {
			return fmt.Errorf("dex: asset resolver already installed for network %d C-Chain %s; refusing re-install for network %d C-Chain %s",
				cur.networkID, cur.cChainID, next.networkID, next.cChainID)
		}
	}
	installedAssetResolver.Store(next)
	fmt.Fprintf(os.Stderr, "dex: 0x9999 real-asset admission active (resolver bound to network=%d C-Chain=%s)\n", networkID, cChainID)
	return nil
}

// AssetResolverInstalled reports whether a resolver has been installed (used by tests
// and by boot diagnostics).
func AssetResolverInstalled() bool { return installedAssetResolver.Load() != nil }

// resolverForRuntime returns the installed resolver IF its bound identity matches the
// runtime (networkID, cChainID), else an error. A nil installed resolver yields a nil
// resolver and nil error — the caller (RequireResolvedAsset) maps that to the fail-closed
// ErrNoAssetResolver. A bound/runtime identity mismatch is a hard refusal.
func resolverForRuntime(networkID uint32, cChainID ids.ID) (dexcore.AssetResolver, error) {
	b := installedAssetResolver.Load()
	if b == nil {
		return nil, nil // fail-closed downstream (no resolver -> ErrNoAssetResolver)
	}
	if b.networkID != networkID || b.cChainID != cChainID {
		return nil, fmt.Errorf("%w (resolver network=%d C-Chain=%s; running network=%d C-Chain=%s)",
			ErrAssetResolverIdentityMismatch, b.networkID, b.cChainID, networkID, cChainID)
	}
	return b.resolver, nil
}

// assetSideForCurrency maps a V4 currency to its real-asset (kind, ref) coordinates for
// admission: the zero address is the native coin (EVM_NATIVE + the native marker); any
// other address is an ERC-20 (its 20-byte contract address is the canonical ref). UTXO
// assets never appear as a V4 currency address, so the value path admits only the two
// EVM kinds — exactly matching dexcore.CanonicalRefFor.
func assetSideForCurrency(c Currency) dexcore.AssetSide {
	if c.Address == (common.Address{}) {
		return dexcore.AssetSide{Kind: dexcore.AssetKindEVMNative, Ref: append([]byte(nil), dexcore.EVMNativeMarker...)}
	}
	return dexcore.AssetSide{Kind: dexcore.AssetKindERC20, Ref: append([]byte(nil), c.Address.Bytes()...)}
}
