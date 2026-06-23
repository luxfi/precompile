// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// swap_sync_fix3_deadlock_test.go is the proof for the CRITICAL do-not-ship fund-lock: a
// plain swap() — with the synchronous value router GATED OFF (the default until a node
// verifies quorum finality) — routes to the async Phase-A intent path, which LOCKS the
// taker's full input. Before this fix that lock carried Deadline==0, and reclaimIntent
// PERMANENTLY refused a deadline-0 intent (ErrReclaimNoDeadline) => the principal could
// never exit if D never settled = permanent fund loss. The fix stamps a FINITE reclaim
// horizon (block.timestamp + maxIntentTTL) on any intent that supplied no explicit
// deadline, so a normal user calling swap() can ALWAYS recover their funds.
//
// These tests drive a REAL swap() through the 0x9999 Run dispatch over the real atomic
// shared-memory harness (no stubs) and prove the lock is always reclaimable.

// swapNativeIntent drives a plain native swap() (empty hookData) through the 0x9999 Run
// dispatch with the value router gated OFF, so the dispatch routes it to the async Phase-A
// intent path. It returns the intent id the swap minted (Phase A returns the 32-byte id).
func swapNativeIntent(t *testing.T, h *settleHarness, amountIn int64) ids.ID {
	t.Helper()
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-amountIn), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.key, params, nil) // empty hookData -> Phase A intent
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err != nil {
		t.Fatalf("plain swap() (gate off -> async intent): %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Phase-A swap must return a 32-byte intent id, got %d bytes", len(out))
	}
	var id ids.ID
	copy(id[:], out)
	return id
}

// Test9999PlainSwapCannotStrandFunds is the decisive proof: a normal user calls swap()
// with the value router OFF; their full input is locked as an async intent; and that lock
// is ALWAYS recoverable via reclaimIntent after a bounded wait — the funds can never be
// permanently stranded. (Before the fix this reverted ErrReclaimNoDeadline forever.)
func Test9999PlainSwapCannotStrandFunds(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	// Value router OFF (the default, and the exact dangerous condition): a plain swap()
	// routes to the async Phase-A intent path that locks the taker's input.
	EnableValueSwaps(false)

	// The taker funds and swaps 200 native in.
	const principal int64 = 200
	h.fundCallerNative(principal)
	callerBefore := h.state.stateDB.GetBalance(h.caller).Uint64()

	intentID := swapNativeIntent(t, h, principal)

	// The input was locked into the vault (the taker's native balance dropped by the full
	// principal) — exactly the condition that, with a deadline-0 intent, would strand it.
	callerAfterLock := h.state.stateDB.GetBalance(h.caller).Uint64()
	if callerAfterLock != callerBefore-uint64(principal) {
		t.Fatalf("swap() must lock the full input: caller balance %d -> %d (want -%d)", callerBefore, callerAfterLock, principal)
	}

	// THE RECORD CARRIES A FINITE DEADLINE (not zero) — the structural fix.
	rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), intentID)
	if rec.Status != swapIntentOpen {
		t.Fatalf("the swap intent must be Open, got status %d", rec.Status)
	}
	if rec.Deadline == 0 {
		t.Fatal("FUND-LOCK REGRESSION: a plain swap() intent must carry a FINITE reclaim deadline, got 0 (permanently unreclaimable)")
	}
	if rec.Remaining != uint64(principal) {
		t.Fatalf("the intent must lock the full principal, remaining=%d want %d", rec.Remaining, principal)
	}

	// BEFORE the deadline, reclaim is refused (a settlement may still land) — correct.
	h.state.blockTimestamp = rec.Deadline // not strictly past yet
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false); !errors.Is(err, ErrReclaimBeforeDeadline) {
		t.Fatalf("reclaim AT the deadline must still be refused (ErrReclaimBeforeDeadline), got: %v", err)
	}

	// AFTER the deadline, reclaim ALWAYS succeeds and refunds the FULL principal — the funds
	// are never stranded.
	h.state.blockTimestamp = rec.Deadline + 1
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false)
	if err != nil {
		t.Fatalf("a plain swap()'s locked principal MUST be reclaimable after the horizon: %v", err)
	}
	if refunded := new(big.Int).SetBytes(out).Uint64(); refunded != uint64(principal) {
		t.Fatalf("reclaim must refund the FULL locked principal, refunded=%d want %d", refunded, principal)
	}
	// The taker's native balance is whole again (full round-trip, no loss).
	if got := h.state.stateDB.GetBalance(h.caller).Uint64(); got != callerBefore {
		t.Fatalf("after reclaim the taker's balance must be whole: %d, want %d (no funds lost)", got, callerBefore)
	}
}

// Test9999ReclaimAlwaysHasHorizon proves the horizon is FINITE and bounded: a plain
// swap()'s intent deadline is exactly block.timestamp + maxIntentTTL, so reclaim is
// guaranteed reachable after a known, finite wait (never never).
func Test9999ReclaimAlwaysHasHorizon(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	EnableValueSwaps(false)

	// Pin a known block time so the expected horizon is deterministic.
	const t0 uint64 = 1_700_000_000
	h.state.blockTimestamp = t0

	h.fundCallerNative(100)
	intentID := swapNativeIntent(t, h, 100)

	rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), intentID)
	wantDeadline := t0 + maxIntentTTL
	if rec.Deadline != wantDeadline {
		t.Fatalf("a no-deadline swap() must default to block.timestamp + maxIntentTTL = %d, got %d", wantDeadline, rec.Deadline)
	}
	// The horizon is in the FUTURE (reclaim is not immediately available — a settlement may
	// still land first) but is FINITE (reachable).
	if wantDeadline <= t0 {
		t.Fatal("the defaulted horizon must be strictly in the future")
	}
	if maxIntentTTL == 0 {
		t.Fatal("maxIntentTTL must be a finite positive horizon")
	}
}

// Test9999NoDeadlineZeroIntentOnValuePath proves the structural invariant: NO intent
// minted on the value path (whether by a plain swap() or an explicit DI01 with deadline 0)
// can ever carry Deadline==0. The deadline-0 record — the one reclaimIntent refuses
// forever — is unreachable from the swap selector.
func Test9999NoDeadlineZeroIntentOnValuePath(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	EnableValueSwaps(false)
	h.fundCallerNative(1_000)

	// (a) A plain swap() (empty hookData) — deadline defaulted, never 0.
	id1 := swapNativeIntent(t, h, 100)
	if rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), id1); rec.Deadline == 0 {
		t.Fatal("plain swap() minted a deadline-0 intent (permanently unreclaimable)")
	}

	// (b) An EXPLICIT DI01 intent that names deadline 0 — also defaulted to a finite
	// horizon (a user who passes 0 still gets a reclaim horizon, never a permanent lock).
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-100), SqrtPriceLimitX96: big.NewInt(0)}
	di01ZeroDeadline := EncodeIntentHookData(0, 7) // deadline 0, nonce 7 -> distinct id
	calldata := buildSwapCalldata(h.key, params, di01ZeroDeadline)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err != nil {
		t.Fatalf("DI01 deadline-0 swap: %v", err)
	}
	var id2 ids.ID
	copy(id2[:], out)
	if rec := loadSwapIntentRecord(newPoolStateAdapter(h.state), id2); rec.Deadline == 0 {
		t.Fatal("a DI01 intent that named deadline 0 must still be defaulted to a finite horizon, got 0")
	}
}

// guard against an unused import if a refactor drops the common ref.
var _ = common.Address{}
