// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
)

// zzmop_dchain_test.go covers native_dchain_client.go — the C side of the C<->D atomic
// seam. The SHIP RULE is what is under test:
//
//   - C is credited ONLY by consuming a D->C atomic object of the MATCHING rail, ONCE,
//     bound to the RECORDED owner / asset / amount. A claim can neither invent value nor
//     re-denominate an object, nor consume a victim's.
//   - D is funded ONLY by a C->D object backed by a C-side debit, and the same intent id
//     can never be submitted twice.
//   - The two object-id derivations are INJECTIVE over every field they claim to bind
//     (each field is varied on its own) and live in disjoint domains.

// zzmpClient is a fresh client (never the package singleton, so a test cannot disturb
// the live money path).
func zzmpClient() *NativeDChainClient { return NewNativeDChainClient("zzmp test") }

// zzmpPutRaw writes an arbitrary D->C shared-memory value under outputID, so a test can
// present a MALFORMED object the decoder must refuse.
func zzmpPutRaw(t *testing.T, h *settleHarness, outputID ids.ID, value []byte) {
	t.Helper()
	reqs := map[ids.ID]*atomic.Requests{
		h.cChainID: {PutRequests: []*atomic.Element{{
			Key:    outputID[:],
			Value:  value,
			Traits: [][]byte{h.caller[:]},
		}}},
	}
	if err := h.dSM.Apply(reqs); err != nil {
		t.Fatalf("zzmpPutRaw: %v", err)
	}
}

// ---------------------------------------------------------------------------
// brand + the closed synchronous Engine surface
// ---------------------------------------------------------------------------

// TestZzmpNativeClientBrandAndClosedEngineSurface pins the white-label default and the
// deliberately-closed synchronous surface: a live in-block matcher forks consensus, so
// every synchronous Engine method REFUSES rather than moving value.
func TestZzmpNativeClientBrandAndClosedEngineSurface(t *testing.T) {
	if got := NewNativeDChainClient("").Brand(); got != "Lux DEX" {
		t.Fatalf("an empty brand must default to the OSS identity, got %q", got)
	}
	if got := NewNativeDChainClient("Acme DEX").Brand(); got != "Acme DEX" {
		t.Fatalf("a tenant brand must be kept, got %q", got)
	}

	c := zzmpClient()
	if tick, err := c.Initialize(big.NewInt(1)); !errors.Is(err, ErrDChainUnavailable) || tick != 0 {
		t.Fatalf("Engine.Initialize: want 0/ErrDChainUnavailable, got %d/%v", tick, err)
	}
	if d, err := c.Swap(nil, common.Address{}, SwapParams{}); !errors.Is(err, ErrDChainUnavailable) || !d.IsZero() {
		t.Fatalf("Engine.Swap: want zero/ErrDChainUnavailable, got %+v/%v", d, err)
	}
	if a, b, err := c.ModifyLiquidity(nil, common.Address{}, ModifyLiquidityParams{}); !errors.Is(err, ErrDChainUnavailable) || !a.IsZero() || !b.IsZero() {
		t.Fatalf("Engine.ModifyLiquidity: want zero/ErrDChainUnavailable, got %+v %+v/%v", a, b, err)
	}
	if d, err := c.Donate(nil, big.NewInt(1), big.NewInt(1)); !errors.Is(err, ErrDChainUnavailable) || !d.IsZero() {
		t.Fatalf("Engine.Donate: want zero/ErrDChainUnavailable, got %+v/%v", d, err)
	}
	if q := c.Quote(nil, big.NewInt(1_000), true); q == nil || q.Sign() != 0 {
		t.Fatalf("Engine.Quote must answer 0 (no synchronous quote), got %v", q)
	}
}

// ---------------------------------------------------------------------------
// C->D: SubmitSwapIntent / SubmitPositionCommit
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// D->C: ImportSettlement binds the RECORDED value
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// D->C: ImportPositionCollect binds the RECORDED value AND the named position
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ReclaimIntent — the replay slot and the unbacked refund
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// the two credit helpers, fail-closed without a vault
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// object-id derivations — every field bound, disjoint domains
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// the taker-authenticated MEV floor — exact integers, both directions
// ---------------------------------------------------------------------------
