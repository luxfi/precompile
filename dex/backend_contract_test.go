// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// labeledEngine wraps a base Engine with a distinct brand. It exists only to
// exercise the backend-swap path from a test — it stands in for the real
// white-label backends (e.g. Hanzo DEX, Zoo DEX) that live in dependent repos.
// The base is the in-package mockEngine (pool_manager_test.go): the embedded
// AMM was removed because V4 is a CLOB, not an AMM, and the precompile holds no
// matcher of its own.
type labeledEngine struct {
	Engine
	brand string
}

func (l *labeledEngine) Brand() string { return l.brand }

// TestEngineContractAcrossBackends asserts two distinct backends satisfy the
// Engine interface with identical observable behavior except brand. This is the
// contract that lets a smart contract compiled against the LP-9010 precompile
// run unchanged on any chain that configures a different backend — only the
// brand string differs.
func TestEngineContractAcrossBackends(t *testing.T) {
	upstream := &labeledEngine{Engine: &mockEngine{}, brand: "Lux DEX"}
	whitelabel := &labeledEngine{Engine: &mockEngine{}, brand: "Hanzo DEX"}

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

// TestDefaultBackendIsInert asserts the package default is the inert engine: an
// unconfigured LP-9010 reverts ErrDEXBackendNotConfigured on every state-moving
// method and NEVER panics, NEVER fabricates a delta. V4 = CLOB, so the matcher
// lives only on the d-chain; the precompile must be dead until a venue wires the
// ZAP backend.
func TestDefaultBackendIsInert(t *testing.T) {
	e := newInertEngine()

	// Every state-moving method reverts with the sentinel.
	if _, err := e.Initialize(big.NewInt(1)); !errors.Is(err, ErrDEXBackendNotConfigured) {
		t.Fatalf("Initialize err = %v, want ErrDEXBackendNotConfigured", err)
	}
	if d, err := e.Swap(&PoolState{}, common.Address{}, SwapParams{AmountSpecified: big.NewInt(-1)}); !errors.Is(err, ErrDEXBackendNotConfigured) || !d.IsZero() {
		t.Fatalf("Swap = (%v,%v), want (zero, ErrDEXBackendNotConfigured)", d, err)
	}
	cd, fd, err := e.ModifyLiquidity(&PoolState{}, common.Address{}, ModifyLiquidityParams{LiquidityDelta: big.NewInt(1)})
	if !errors.Is(err, ErrDEXBackendNotConfigured) || !cd.IsZero() || !fd.IsZero() {
		t.Fatalf("ModifyLiquidity = (%v,%v,%v), want (zero,zero,ErrDEXBackendNotConfigured)", cd, fd, err)
	}
	if d, err := e.Donate(&PoolState{}, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrDEXBackendNotConfigured) || !d.IsZero() {
		t.Fatalf("Donate = (%v,%v), want (zero, ErrDEXBackendNotConfigured)", d, err)
	}

	// Quote is a read estimate: it returns a benign zero (no route), not an error.
	if q := e.Quote(&Pool{Liquidity: big.NewInt(0), SqrtPriceX96: big.NewInt(1)}, big.NewInt(1000), true); q.Sign() != 0 {
		t.Fatalf("inert Quote = %s, want 0", q)
	}

	// It is the package default.
	if _, ok := Backend().(*inertEngine); !ok {
		t.Fatalf("package default backend = %T, want *inertEngine", Backend())
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
	if err := SetBackend(&mockEngine{}); err != nil {
		t.Fatalf("initial install: %v", err)
	}

	// Inject a synthetic pool. We cannot exercise the public Initialize path
	// without a full StateDB; mutating the package-private map is the precise
	// test of the guard.
	DEXPrecompile.poolManager.pools[[32]byte{0x01}] = &Pool{}

	if err := SetBackend(&mockEngine{}); err == nil {
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
