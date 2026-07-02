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

// swap_sync_fix3_deadlock_test.go proves the CRITICAL do-not-ship fund-lock is STRUCTURALLY
// unreachable after the decomplect. The fund-lock was: a plain swap() locked the taker's full
// input as a Deadline==0 async intent, and reclaimIntent PERMANENTLY refused a deadline-0
// intent (ErrReclaimNoDeadline) => permanent fund loss.
//
// The decomplect removes the fork: a plain swap() now ALWAYS settles synchronously through the
// on-chain router (no value gate, no async fall-through for normal swaps). A synchronous swap
// NEVER calls SubmitSwapIntent, so it can never create an intent record at all — Deadline==0
// or otherwise. The ONLY way to reach the async C->D intent primitive is an EXPLICIT DI01
// swap (a genuine cross-chain settlement), and even there a missing deadline is defaulted to a
// finite reclaim horizon. So the deadline-0 record is unreachable from every selector.
//
// These tests drive REAL swap() calls through the 0x9999 Run dispatch over the real atomic
// shared-memory + ERC-20 + registry harness (no stubs). Token layout (e2e): LETH = currency0
// (base), LUSD = currency1 (quote); "sell LETH for LUSD" is zeroForOne.

// wouldBeIntentID derives the intent id a SELL of amountIn LETH (the e2e market's base) would
// have minted IF it had taken the async path — so a test can assert that NO such record
// exists (Status == swapIntentNone) after a synchronous swap. The derivation mirrors
// SubmitSwapIntent's (same domain, ids, asset, amount, market, nonce).
func wouldBeIntentID(h *e2eHarness, amountIn uint64, nonce uint64) ids.ID {
	return DeriveIntentID(h.networkID, h.cChainID, h.dChainID, e2eTaker,
		assetID(Currency{Address: e2eLETH}), amountIn, h.key.ID(), nonce)
}

// swapDI01 drives an EXPLICIT DI01-tagged swap() (the async cross-chain C->D intent
// primitive) through the 0x9999 Run dispatch. This is the ONLY swap shape that routes to the
// async handler; a plain swap() is synchronous. deadline/nonce ride in the DI01 body. It
// returns the intent id the async path minted (Phase A returns the 32-byte id).
func swapDI01(t *testing.T, h *e2eHarness, taker common.Address, amountIn int64, deadline, nonce uint64) ids.ID {
	t.Helper()
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-amountIn), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeIntentHookData(deadline, nonce)) // DI01 -> async Phase A
	out, _, err := h.c.Run(h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err != nil {
		t.Fatalf("DI01 swap() (async intent): %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("a DI01 Phase-A swap must return a 32-byte intent id, got %d bytes", len(out))
	}
	var id ids.ID
	copy(id[:], out)
	return id
}

// Test9999PlainSwapCannotStrandFunds is the decisive proof of the decomplected invariant: a
// plain swap() NEVER takes the async fork, so it can never strand the taker's input in a
// locked intent. A plain swap() with no resting counterparty REVERTS in-process (no liquidity)
// and rolls back atomically — the taker's funds never leave their balance and NO intent record
// is created. (Before the decomplect this locked the input as an unreclaimable Deadline=0
// intent.)
func Test9999PlainSwapCannotStrandFunds(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker

	const principal int64 = 200
	h.mint(e2eLETH, taker, principal)
	takerBefore := h.ercBal(e2eLETH, taker)

	// A plain swap() (DM01 floor so the SELL-protection policy is satisfied and it reaches the
	// router) against an EMPTY book: no counterparty, so the synchronous router reverts with no
	// liquidity. Drive it over the EVM atomicity boundary so the revert is atomic.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-principal), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1))
	_, _, err := runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err == nil {
		t.Fatal("a plain swap() against an empty book must REVERT (no liquidity), not lock an intent")
	}
	if !errors.Is(err, dexcore.ErrNoLiquidity) {
		t.Fatalf("expected ErrNoLiquidity on an empty-book synchronous swap, got: %v", err)
	}

	// ATOMIC: the taker's full balance is intact (nothing was locked into the vault).
	if got := h.ercBal(e2eLETH, taker); got != takerBefore {
		t.Fatalf("a reverted synchronous swap must not move the taker's balance: %d -> %d", takerBefore, got)
	}
	if got := h.ercBal(e2eLETH, taker); got != principal {
		t.Fatalf("taker balance after revert = %d, want the full %d (no strand)", got, principal)
	}

	// STRUCTURAL: no async intent record exists for this swap (the synchronous path never
	// called SubmitSwapIntent). The would-be id (nonce 0, the plain-swap default) is absent.
	if rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), wouldBeIntentID(h, uint64(principal), 0)); rec.Status != swapIntentNone {
		t.Fatalf("a plain swap() created an async intent record (status=%d) — the async fork must be unreachable from a plain swap()", rec.Status)
	}
}

// Test9999PlainSwapIsSynchronousMintsNoIntent is the structural one-path proof for a swap that
// FILLS: a plain swap() that crosses a real maker creates NO async intent record (it settled
// synchronously, never calling SubmitSwapIntent), so there is no intent — and therefore no
// Deadline=0 lock — to strand.
func Test9999PlainSwapIsSynchronousMintsNoIntent(t *testing.T) {
	h := newE2EHarness(t)
	maker, taker := e2eMaker, e2eTaker

	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)

	h.mint(e2eLETH, taker, 80)
	if _, err := h.swap(t, taker, true, 80, sqrtX96For(1.0)); err != nil {
		t.Fatalf("plain swap() must fill synchronously: %v", err)
	}

	// NO intent record was created by the synchronous fill (would-be id at nonce 0 is absent).
	if rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), wouldBeIntentID(h, 80, 0)); rec.Status != swapIntentNone {
		t.Fatalf("a synchronous swap() created an async intent record (status=%d, want none)", rec.Status)
	}
}

// TestNoDeadlineZeroIntentOnValuePath proves the structural invariant: NO intent reachable
// from the swap selector can carry Deadline==0. A plain swap() mints no intent at all (it is
// synchronous), and the ONLY async path — an explicit DI01 swap — defaults a missing deadline
// to a finite horizon. The Deadline==0 record reclaimIntent refuses forever is unreachable.
func TestNoDeadlineZeroIntentOnValuePath(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker
	h.mint(e2eLETH, taker, 1_000)

	// (a) A plain swap() against an empty book reverts and mints NO intent — no Deadline==0
	// lock can exist because no intent exists.
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-100), SqrtPriceLimitX96: big.NewInt(0)}
	plain := buildSwapCalldata(h.key, params, EncodeMinOutHookData(1))
	_, _, _ = runWithEVMSnapshot(h.c, h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorSwap, plain), 5_000_000, false)
	if rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), wouldBeIntentID(h, 100, 0)); rec.Status != swapIntentNone {
		t.Fatalf("a plain swap() minted an intent (status=%d) — the synchronous path must never call SubmitSwapIntent", rec.Status)
	}

	// (b) An EXPLICIT DI01 intent that NAMES deadline 0 — defaulted to a finite horizon (a user
	// who passes 0 to the async primitive still gets a reclaim horizon, never a permanent lock).
	id := swapDI01(t, h, taker, 100, 0 /*deadline*/, 7 /*nonce*/)
	if rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), id); rec.Deadline == 0 {
		t.Fatal("a DI01 intent that named deadline 0 must still be defaulted to a finite horizon, got 0")
	}
}

// Test9999ReclaimAlwaysHasHorizon proves the async DI01 primitive's horizon is FINITE and
// bounded: a DI01 swap that supplies no deadline gets exactly block.timestamp + maxIntentTTL,
// and the locked principal is ALWAYS reclaimable after that known, finite wait (never never).
// (A plain swap() never reaches this path, but the cross-chain primitive that does must still
// guarantee exit — that is what we prove.)
func Test9999ReclaimAlwaysHasHorizon(t *testing.T) {
	h := newE2EHarness(t)
	taker := e2eTaker

	const t0 uint64 = 1_700_000_000
	h.state.blockTimestamp = t0

	const principal int64 = 200
	h.mint(e2eLETH, taker, principal)
	takerBefore := h.ercBal(e2eLETH, taker)

	// A DI01 swap with deadline 0 -> defaulted to t0 + maxIntentTTL.
	id := swapDI01(t, h, taker, principal, 0 /*deadline*/, 0 /*nonce*/)
	rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), id)
	wantDeadline := t0 + maxIntentTTL
	if rec.Deadline != wantDeadline {
		t.Fatalf("a no-deadline DI01 swap must default to block.timestamp + maxIntentTTL = %d, got %d", wantDeadline, rec.Deadline)
	}
	if rec.Remaining != uint64(principal) {
		t.Fatalf("the DI01 intent must lock the full principal, remaining=%d want %d", rec.Remaining, principal)
	}

	// BEFORE the horizon, reclaim is refused (a settlement may still land) — correct.
	h.state.blockTimestamp = rec.Deadline
	if _, _, err := h.c.Run(h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(id)), 5_000_000, false); !errors.Is(err, ErrReclaimBeforeDeadline) {
		t.Fatalf("reclaim AT the horizon must still be refused (ErrReclaimBeforeDeadline), got: %v", err)
	}

	// AFTER the horizon, reclaim ALWAYS succeeds and refunds the FULL principal — never stranded.
	h.state.blockTimestamp = rec.Deadline + 1
	out, _, err := h.c.Run(h.state, taker, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(id)), 5_000_000, false)
	if err != nil {
		t.Fatalf("the DI01 intent's locked principal MUST be reclaimable after the horizon: %v", err)
	}
	if refunded := new(big.Int).SetBytes(out).Uint64(); refunded != uint64(principal) {
		t.Fatalf("reclaim must refund the FULL locked principal, refunded=%d want %d", refunded, principal)
	}
	if got := h.ercBal(e2eLETH, taker); got != takerBefore {
		t.Fatalf("after reclaim the taker's LETH must be whole: %d, want %d (no funds lost)", got, takerBefore)
	}
	if maxIntentTTL == 0 {
		t.Fatal("maxIntentTTL must be a finite positive horizon")
	}
}

// guard against an unused import if a refactor drops the common ref.
var _ = common.Address{}
