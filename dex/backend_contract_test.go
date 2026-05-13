// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"
)

// labeledEngine wraps EmbeddedEngine with a different brand. It exists only
// to exercise the backend-swap path from a test — it stands in for the real
// white-label backends (e.g. Partner DEX) that live in dependent repos.
type labeledEngine struct {
	*EmbeddedEngine
	brand string
}

func (l *labeledEngine) Brand() string { return l.brand }

// TestEngineContractAcrossBackends asserts both the default EmbeddedEngine
// and an alternate-brand wrapper satisfy the Engine interface with identical
// observable behavior. This is the contract that lets a smart contract
// compiled against the LP-9010 precompile run unchanged on any chain that
// configures a different backend — only the brand string differs.
func TestEngineContractAcrossBackends(t *testing.T) {
	upstream := NewEmbeddedEngine()
	whitelabel := &labeledEngine{EmbeddedEngine: NewEmbeddedEngine(), brand: "Partner DEX"}

	// Brand contract: each backend reports a non-empty, distinct identity.
	if upstream.Brand() == "" || whitelabel.Brand() == "" {
		t.Fatalf("brand must be non-empty: upstream=%q whitelabel=%q", upstream.Brand(), whitelabel.Brand())
	}
	if upstream.Brand() == whitelabel.Brand() {
		t.Fatalf("brands must differ: both=%q", upstream.Brand())
	}

	// Math parity: Initialize at the 1:1 sqrtPriceX96 = 2^96 must agree.
	sqrtPriceX96 := new(big.Int).Lsh(big.NewInt(1), 96)
	tu, errU := upstream.Initialize(sqrtPriceX96)
	tw, errW := whitelabel.Initialize(sqrtPriceX96)
	if (errU == nil) != (errW == nil) {
		t.Fatalf("Initialize error parity: upstream=%v whitelabel=%v", errU, errW)
	}
	if tu != tw {
		t.Fatalf("Initialize tick parity: upstream=%d whitelabel=%d", tu, tw)
	}

	// Quote parity on an empty pool.
	pool := &Pool{Liquidity: big.NewInt(0), SqrtPriceX96: sqrtPriceX96}
	qu := upstream.Quote(pool, big.NewInt(1000), true)
	qw := whitelabel.Quote(pool, big.NewInt(1000), true)
	if qu.Cmp(qw) != 0 {
		t.Fatalf("Quote parity: upstream=%s whitelabel=%s", qu, qw)
	}
}

// TestSetBackendNilRejected asserts the backend swap refuses a nil engine,
// preventing a downstream caller from accidentally clearing the engine and
// crashing on the first swap.
func TestSetBackendNilRejected(t *testing.T) {
	if err := SetBackend(nil); err == nil {
		t.Fatal("SetBackend(nil) must return an error")
	}
}

// TestSetBackendRejectsAfterPoolInit asserts the backend cannot be swapped
// after a pool has been initialized. This guards against mid-flight engine
// swaps that would race with live state.
func TestSetBackendRejectsAfterPoolInit(t *testing.T) {
	// Save and restore the default backend so this test doesn't bleed into
	// other tests' singleton state.
	original := Backend()
	defer func() { _ = SetBackend(original) }()

	// Reset to a clean engine for this test.
	if err := SetBackend(NewEmbeddedEngine()); err != nil {
		t.Fatalf("initial install: %v", err)
	}

	// Inject a synthetic pool. We cannot exercise the public Initialize path
	// without a full StateDB; mutating the package-private map is the precise
	// test of the guard.
	DEXPrecompile.poolManager.pools[[32]byte{0x01}] = &Pool{}

	if err := SetBackend(NewEmbeddedEngine()); err == nil {
		t.Fatal("SetBackend after pool init must return an error")
	}

	// Clean up so subsequent tests start fresh.
	delete(DEXPrecompile.poolManager.pools, [32]byte{0x01})
}

// TestPrecompileAddressIsStable pins the precompile address slot. If this
// value ever drifts, every contract on every Lux-derived chain breaks. The
// constant is part of the on-chain ABI surface.
func TestPrecompileAddressIsStable(t *testing.T) {
	const want = "0x0000000000000000000000000000000000009010"
	if Module.Address.Hex() != want {
		t.Fatalf("DEX precompile address drifted: got %s want %s", Module.Address.Hex(), want)
	}
}
