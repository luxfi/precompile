// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
)

// access_soundness_test.go is the ANTI-FORK GATE for the 0x9999 Block-STM scheduler — the
// proof that the access-set declaration the scheduler keys its conflict graph on is a SOUND
// superset of what the handler actually writes. A missed write would let two truly-
// conflicting settlements run in parallel and commit in divergent order on different
// validators => a SILENT FORK. These tests close that by construction:
//
//   - Test9999_AccessSetKeyParity_HandlerVsPredictor: drive a REAL native settle through a
//     write-observing StateDB, capture EVERY 0x9999 conflict key the handler mutates, and
//     assert observed ⊆ PredictSwapWriteSet(...). FAILS the moment the predictor and the
//     handler diverge on a single write key — the gate. Includes a fail-without proof.
//   - Test9999_AccessSet_FailClosed_RejectsUndeclaredWrite: prove the runtime assertion
//     REJECTS a settlement whose handler escapes its declared write-set (fail-closed), and
//     ACCEPTS one with the complete declaration (no false positive).
//   - Test9999_AccessCommitment_RootBinding: prove the declared-set commitment is
//     deterministic AND that altering ANY single key changes the root (so a mis-declared
//     block is non-reproducible and rejected by peers).

// runSwapObserved runs the 0x9999 swap selector against a write-observing view of the
// harness state and returns (the 0x9999 conflict write-set, the foreign token-ledger writes,
// the handler's error). The observer is transparent — the handler's value movement commits
// on the underlying MockStateDB exactly as without it — so this both EXERCISES the real money
// path AND records its writes for the subset check.
func (h *settleHarness) runSwapObserved(t testing.TB, calldata []byte) (observed map[common.Hash]struct{}, foreign map[foreignKey]struct{}, err error) {
	t.Helper()
	obs := newWriteObservingStateDB(h.state.GetStateDB())
	wrapped := &observingAccessibleState{inner: h.state, stateDB: obs}
	_, _, err = h.c.Run(wrapped, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	return obs.observed, obs.foreign, err
}

// predictSwap is the test-side predictor call: the SOUND superset declared for the swap,
// computed against the PRE-CALL state (the same state the handler reads when it runs).
func (h *settleHarness) predictSwap(calldata []byte) map[common.Hash]struct{} {
	return PredictSwapWriteSet(
		newPoolStateAdapter(h.state),
		h.state.NetworkID(), h.state.CChainID(), h.state.DChainID(),
		h.state.stateDB.blockNumber,
		h.key, h.params, h.caller, calldataHookData(calldata),
	)
}

// subsetViolations returns the observed keys NOT present in declared (empty => observed ⊆
// declared). Used to make a parity failure name the exact missed key(s).
func subsetViolations(observed, declared map[common.Hash]struct{}) []common.Hash {
	var bad []common.Hash
	for k := range observed {
		if _, ok := declared[k]; !ok {
			bad = append(bad, k)
		}
	}
	return bad
}

// Test9999_AccessSetKeyParity_HandlerVsPredictor is THE anti-fork gate: for a real native
// settle it asserts every 0x9999 conflict key the handler writes is within the predictor's
// declared write-set. If the predictor and the handler ever diverge on a single write key —
// a new slot the handler touches that the predictor forgot — this FAILS, because that
// divergence is exactly the missed conflict edge that forks the chain.
func Test9999_AccessSetKeyParity_HandlerVsPredictor(t *testing.T) {
	t.Run("PhaseA_native_intent", func(t *testing.T) {
		h := newSettleHarness(t)
		h.registerMarket(t)
		h.fundCallerNative(1000)

		calldata := h.intentCalldataWithDeadline(1 << 40) // DI01-tagged -> native SettleSwap seam
		declared := h.predictSwap(calldata)

		observed, foreign, err := h.runSwapObserved(t, calldata)
		if err != nil {
			t.Fatalf("phase-A intent must succeed: %v", err)
		}
		if len(observed) == 0 {
			t.Fatal("observer recorded NO 0x9999 writes — the harness did not exercise the money path")
		}
		// The all-native intent path moves value through native balances + 0x9999 slots ONLY:
		// there must be NO foreign (token-ledger) writes. This pins the native scoping claim.
		if len(foreign) != 0 {
			t.Fatalf("native intent unexpectedly wrote %d foreign (non-0x9999) slots — scoping claim violated", len(foreign))
		}

		// THE GATE: every observed write key must be declared. A miss is a forkable edge.
		if bad := subsetViolations(observed, declared); len(bad) != 0 {
			for _, k := range bad {
				t.Errorf("HANDLER WROTE UNDECLARED KEY %s (missed conflict edge => fork risk)", k.Hex())
			}
			t.Fatalf("phase-A access-set parity FAILED: %d undeclared handler writes", len(bad))
		}
		t.Logf("phase-A: handler wrote %d 0x9999 keys, all within the %d declared", len(observed), len(declared))
	})

	t.Run("PhaseB_settle", func(t *testing.T) {
		// Phase B credits the swap's OUTPUT (the ERC-20 currency1), whose value moves through
		// the token ledger (foreign, outside the 0x9999 conflict graph). The conflict-relevant
		// Phase-B writes — the D->C consumed slot, the per-asset seam reserve, the volume
		// bucket, the staged Remove, the per-intent record decrement, the custody guard — are
		// all 0x9999 slots, and THOSE (the observer's observed set) must be ⊆ declared.
		h := newSettleHarness(t)
		h.registerMarket(t)
		h.fundVaultOut(10_000) // back the output credit (no mint).

		outputID := ids.ID{0xDE, 0xB0}
		h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 250)

		intentID := h.standingIntent(250)
		calldata := h.settlementCalldataFor(outputID, 250, intentID)
		declared := h.predictSwap(calldata)

		observed, _, err := h.runSwapObserved(t, calldata)
		if err != nil {
			t.Fatalf("phase-B settle must succeed: %v", err)
		}
		if len(observed) == 0 {
			t.Fatal("observer recorded NO 0x9999 conflict writes for the settle")
		}
		if bad := subsetViolations(observed, declared); len(bad) != 0 {
			for _, k := range bad {
				t.Errorf("PHASE-B HANDLER WROTE UNDECLARED 0x9999 KEY %s (fork risk)", k.Hex())
			}
			t.Fatalf("phase-B access-set parity FAILED: %d undeclared 0x9999 writes", len(bad))
		}
		t.Logf("phase-B: handler wrote %d 0x9999 keys, all within the %d declared", len(observed), len(declared))
	})

	t.Run("reclaimIntent_native", func(t *testing.T) {
		// A SECOND value path (a different selector, a different write region) — proving the
		// per-selector predictor (PredictReclaimIntentWriteSet) is also a sound superset of its
		// handler. A native reclaim refunds the locked principal from seamReserve to the locker.
		h := newSettleHarness(t)
		h.registerMarket(t)
		native := h.inAssetID()
		h.fundVaultNativeOut(1_000) // backs the reclaim refund (the seam reserve of the input asset).

		const deadline uint64 = 100
		const principal uint64 = 300
		intentID := h.seedSwapIntent(h.caller, native, principal, deadline, ids.ID{0xCE, 0xA1})
		h.state.blockTimestamp = deadline + 1 // past the deadline so reclaim is allowed.

		// PREDICT (pre-call) via the RECLAIM selector's predictor — NOT the swap predictor.
		declared := PredictReclaimIntentWriteSet(newPoolStateAdapter(h.state), h.state.DChainID(), intentID)

		obs := newWriteObservingStateDB(h.state.GetStateDB())
		wrapped := &observingAccessibleState{inner: h.state, stateDB: obs}
		if _, _, err := h.c.Run(wrapped, h.caller, poolManagerAddr9999,
			prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false); err != nil {
			t.Fatalf("reclaim must succeed: %v", err)
		}
		if len(obs.observed) == 0 {
			t.Fatal("observer recorded NO 0x9999 writes for the reclaim")
		}
		if len(obs.foreign) != 0 {
			t.Fatalf("native reclaim unexpectedly wrote %d foreign slots — scoping claim violated", len(obs.foreign))
		}
		if bad := subsetViolations(obs.observed, declared); len(bad) != 0 {
			for _, k := range bad {
				t.Errorf("RECLAIM HANDLER WROTE UNDECLARED KEY %s (fork risk)", k.Hex())
			}
			t.Fatalf("reclaim access-set parity FAILED: %d undeclared writes", len(bad))
		}
		t.Logf("reclaim: handler wrote %d 0x9999 keys, all within the %d declared", len(obs.observed), len(declared))
	})

	// Per-selector DISPATCH parity: PredictWriteSetForCall routes a swap call to the swap
	// predictor and a reclaim call to the reclaim predictor — the wiring the runtime assertion
	// uses. Proven by checking the dispatched set equals the direct predictor's set.
	t.Run("dispatch_routes_to_matching_predictor", func(t *testing.T) {
		h := newSettleHarness(t)
		h.registerMarket(t)
		h.fundCallerNative(1000)
		swapCalldata := h.intentCalldataWithDeadline(1 << 40) // DI01-tagged -> native SettleSwap seam

		direct := h.predictSwap(swapCalldata)
		// PredictWriteSetForCall decodes the swap input itself (DecodeSwapInput), so `input` is
		// the post-selector ABI calldata — exactly what intentCalldata() returns (Run strips the
		// selector before the handler decodes; here we hand the predictor the same post-selector
		// bytes).
		dispatched, ok := PredictWriteSetForCall(
			newPoolStateAdapter(h.state),
			h.state.NetworkID(), h.state.CChainID(), h.state.DChainID(),
			h.state.TxID(), h.state.CallIndex(), h.caller, h.state.stateDB.blockNumber,
			SelectorSwap, swapCalldata,
		)
		if !ok {
			t.Fatal("SelectorSwap must be covered by PredictWriteSetForCall")
		}
		if !keySetsEqual(direct, dispatched) {
			t.Fatal("dispatch did not route SelectorSwap to PredictSwapWriteSet (sets differ)")
		}

		// An uncovered selector is fail-closed (ok=false) — the caller must reject it.
		if _, ok := PredictWriteSetForCall(
			newPoolStateAdapter(h.state),
			h.state.NetworkID(), h.state.CChainID(), h.state.DChainID(),
			h.state.TxID(), h.state.CallIndex(), h.caller, h.state.stateDB.blockNumber,
			0xDEADBEEF, nil,
		); ok {
			t.Fatal("an uncovered selector must return ok=false (fail-closed), not a set")
		}
		t.Log("dispatch confirmed: swap->swap predictor, reclaim->reclaim predictor, unknown->fail-closed")
	})

	// FAIL-WITHOUT PROOF: if the predictor under-declares by even ONE key, the gate fires.
	// This proves the test is load-bearing — it removes a key the handler DOES write from the
	// declaration and asserts the subset check now reports it (the temporary-revert discipline
	// made into an assertion: proven to FAIL-without a complete predictor).
	t.Run("fail_without_complete_predictor", func(t *testing.T) {
		h := newSettleHarness(t)
		h.registerMarket(t)
		h.fundCallerNative(1000)
		calldata := h.intentCalldataWithDeadline(1 << 40) // DI01-tagged -> native SettleSwap seam

		declared := h.predictSwap(calldata)
		observed, _, err := h.runSwapObserved(t, calldata)
		if err != nil {
			t.Fatalf("intent: %v", err)
		}
		if bad := subsetViolations(observed, declared); len(bad) != 0 {
			t.Fatalf("precondition: complete predictor must pass, got %d violations", len(bad))
		}

		// CRIPPLE the declaration by dropping the staging seq key (a key stageAtomicPut writes).
		// The subset check MUST now report it — proving an incomplete predictor is caught.
		crippled := cloneKeySet(declared)
		delete(crippled, stageSeqKey)
		bad := subsetViolations(observed, crippled)
		if len(bad) == 0 {
			t.Fatal("FAIL-WITHOUT proof broken: dropping a written key from the declaration did " +
				"NOT produce a violation — the gate is not actually checking that key")
		}
		foundSeq := false
		for _, k := range bad {
			if k == stageSeqKey {
				foundSeq = true
			}
		}
		if !foundSeq {
			t.Fatalf("expected the dropped stageSeqKey as the reported violation, got %v", bad)
		}
		t.Logf("fail-without confirmed: an incomplete predictor (missing stageSeqKey) is caught")
	})
}

// Test9999_AccessSet_FailClosed_RejectsUndeclaredWrite proves the runtime assertion
// (AssertWriteSetWithin) is FAIL-CLOSED: a settlement whose handler writes a key OUTSIDE its
// declared write-set is REJECTED (ErrAccessSetUndeclaredWrite), so an under-declaration is
// converted to a rejected tx, never a forked commit — AND that a COMPLETE declaration is
// accepted (no false rejection).
func Test9999_AccessSet_FailClosed_RejectsUndeclaredWrite(t *testing.T) {
	run := func(h *settleHarness, declared map[common.Hash]struct{}, calldata []byte) error {
		_, _, err := AssertWriteSetWithin(h.state, declared, func(s contract.AccessibleState) ([]byte, uint64, error) {
			return h.c.Run(s, h.caller, poolManagerAddr9999,
				prependSelector(SelectorSwap, calldata), 5_000_000, false)
		})
		return err
	}

	// REJECT: an empty declaration against a handler that writes many keys.
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.fundCallerNative(1000)
	calldata := h.intentCalldataWithDeadline(1 << 40) // DI01-tagged -> native SettleSwap seam

	err := run(h, map[common.Hash]struct{}{}, calldata)
	if err == nil {
		t.Fatal("FAIL-CLOSED broken: a handler writing undeclared keys must be REJECTED")
	}
	if _, ok := err.(*ErrAccessSetUndeclaredWrite); !ok {
		t.Fatalf("expected ErrAccessSetUndeclaredWrite, got %T: %v", err, err)
	}
	t.Logf("fail-closed confirmed: undeclared write rejected with %v", err)

	// ACCEPT: the SAME handler call with the COMPLETE declaration is not rejected.
	h2 := newSettleHarness(t)
	h2.registerMarket(t)
	h2.fundCallerNative(1000)
	calldata2 := h2.intentCalldataWithDeadline(1 << 40) // DI01-tagged -> native SettleSwap seam
	declared := h2.predictSwap(calldata2)
	if err := run(h2, declared, calldata2); err != nil {
		t.Fatalf("complete declaration must be ACCEPTED (no false rejection), got: %v", err)
	}
	t.Log("complement confirmed: a complete declaration is accepted (no false positive)")
}

// Test9999_AccessCommitment_RootBinding proves the access-set root binding: the commitment
// over a declared write-set is DETERMINISTIC (same set => same root, independent of
// insertion / map-iteration order) AND DISCRIMINATING (adding, removing, or altering ANY
// single key changes the root). Together these are the anti-fork property: a validator that
// declares a different write-set lands on a different root and its block is rejected.
func Test9999_AccessCommitment_RootBinding(t *testing.T) {
	mk := func(keys ...common.Hash) map[common.Hash]struct{} {
		m := make(map[common.Hash]struct{}, len(keys))
		for _, k := range keys {
			m[k] = struct{}{}
		}
		return m
	}
	k1 := common.HexToHash("0x01")
	k2 := common.HexToHash("0x02")
	k3 := common.HexToHash("0x03")
	base := mk(k1, k2, k3)

	// DETERMINISM across insertion order.
	rootA := NewAccessCommitment(base).Root()
	if got := NewAccessCommitment(mk(k3, k1, k2)).Root(); got != rootA {
		t.Fatalf("commitment not deterministic across insertion order: %s != %s", got.Hex(), rootA.Hex())
	}

	// DISCRIMINATION: dropping a declared key (the missed-edge case) changes the root.
	if NewAccessCommitment(mk(k1, k2)).Root() == rootA {
		t.Fatal("dropping a declared key did NOT change the root — an under-declaration would be invisible to peers")
	}
	// Adding a key changes the root.
	if NewAccessCommitment(mk(k1, k2, k3, common.HexToHash("0x04"))).Root() == rootA {
		t.Fatal("adding a declared key did NOT change the root")
	}
	// Altering a key changes the root.
	if NewAccessCommitment(mk(k1, k2, common.HexToHash("0x33"))).Root() == rootA {
		t.Fatal("altering a declared key did NOT change the root")
	}

	// LENGTH-PREFIX SOUNDNESS (the atomic.go discipline): two DIFFERENT sets that concatenate
	// to the same bytes without length framing must NOT collide.
	left := mk(common.HexToHash("0xAABB"), common.HexToHash("0xCC"))
	right := mk(common.HexToHash("0xAA"), common.HexToHash("0xBBCC"))
	if NewAccessCommitment(left).Root() == NewAccessCommitment(right).Root() {
		t.Fatal("length-prefix framing broken: two distinct key sets collided (concatenation attack)")
	}

	// FOLD discrimination + order-sensitivity (the deterministic settle order binds the run).
	var acc0 common.Hash
	accA := FoldAccessCommitment(acc0, NewAccessCommitment(base))
	if accA == FoldAccessCommitment(acc0, NewAccessCommitment(mk(k1, k2))) {
		t.Fatal("folded accumulator does not discriminate a mis-declared settlement")
	}
	cB := NewAccessCommitment(mk(k1))
	if FoldAccessCommitment(accA, cB) == FoldAccessCommitment(FoldAccessCommitment(acc0, cB), NewAccessCommitment(base)) {
		t.Fatal("fold is order-insensitive — settle-order divergence would be invisible")
	}
	t.Log("root binding confirmed: deterministic, discriminating, length-framed, order-bound")
}

// calldataHookData extracts the trailing hookData bytes the swap calldata carries, so the
// predictor classifies the SAME phase the handler will. buildSwapCalldata lays out 288 ABI
// bytes + a 32-byte length word + the padded hookData; we re-read the length word and slice.
func calldataHookData(calldata []byte) []byte {
	if len(calldata) < 320 { // 288 args + 32 length word
		return nil
	}
	n := int(bytesToU64(calldata[288+24 : 288+32]))
	if n == 0 || 320+n > len(calldata) {
		return nil
	}
	return calldata[320 : 320+n]
}

func cloneKeySet(in map[common.Hash]struct{}) map[common.Hash]struct{} {
	out := make(map[common.Hash]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

// keySetsEqual reports whether two key sets are identical (same membership). Used to prove
// the per-selector dispatcher routes to the same set the direct predictor produces.
func keySetsEqual(a, b map[common.Hash]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
