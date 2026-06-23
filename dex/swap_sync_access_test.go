// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// swap_sync_access_test.go is the ANTI-FORK GATE for the SYNCHRONOUS value swap — the B7/B8
// proof that PredictSyncSwapWriteSet is a SOUND superset of what runSyncSwap actually writes.
// The live 0x9999 dispatch routes a plain swap() to runSyncSwap, which writes the swap counter
// AND the dexcore book/index/ledger rows — a DIFFERENT region than the async PredictSwapWriteSet
// models. If the scheduler keyed a sync swap's conflict graph on the async predictor it would
// MISS those edges -> a silent fork. These tests close that by construction:
//
//   - Test9999_SyncAccessSetKeyParity_HandlerVsPredictor: drive a REAL sync swap (maker resting,
//     taker crossing) through a write-observing StateDB, capture EVERY 0x9999 conflict key the
//     handler mutates, assert observed ⊆ PredictSyncSwapWriteSet. Includes a fail-without proof
//     keyed on swapCounterKey — the exact slot the async predictor omits.
//   - Test9999_SyncAccessSet_FailClosed: prove the runtime assertion REJECTS a sync swap whose
//     declared set is the WRONG (async) one, and ACCEPTS the correct sync declaration.
//   - Test9999_SyncDispatch_RoutesToSyncPredictor: prove the live per-selector dispatch routes a
//     value-enabled untagged swap to the SYNC predictor (not the async one).

// runSyncSwapObserved runs a real sync swap() through a write-observing view of the e2e harness
// state and returns (the 0x9999 conflict write-set, the foreign token-ledger writes, the
// handler error). The observer is transparent — the swap settles on the underlying state exactly
// as without it — so this EXERCISES the real money path AND records its writes for the subset
// check. The harness has value swaps enabled (newE2EHarness) and the real-asset resolver
// installed, so the dispatch routes the untagged swap to runSyncSwap.
func (h *e2eHarness) runSyncSwapObserved(t testing.TB, calldata []byte) (observed map[common.Hash]struct{}, foreign map[foreignKey]struct{}, err error) {
	t.Helper()
	obs := newWriteObservingStateDB(h.state.GetStateDB())
	wrapped := &observingAccessibleState{inner: h.state, stateDB: obs}
	_, _, err = h.c.Run(wrapped, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, calldata), 5_000_000, false)
	return obs.observed, obs.foreign, err
}

// predictSync is the test-side sync predictor call: the SOUND superset declared for the sync
// swap, computed against the PRE-CALL state (the same state the handler reads when it runs).
func (h *e2eHarness) predictSync(key PoolKey, params SwapParams) map[common.Hash]struct{} {
	return PredictSyncSwapWriteSet(newPoolStateAdapter(h.state), key, params, h.caller)
}

// Test9999_SyncAccessSetKeyParity_HandlerVsPredictor is THE anti-fork gate for the synchronous
// value path: for a REAL sync swap that crosses a resting maker it asserts every 0x9999 conflict
// key the handler writes is within PredictSyncSwapWriteSet's declared set. If the sync handler
// ever writes a slot the sync predictor forgot — the swap counter, a dexcore book/ledger row,
// the order index — this FAILS, because that divergence is the missed conflict edge that forks.
func Test9999_SyncAccessSetKeyParity_HandlerVsPredictor(t *testing.T) {
	// The taker (msg.sender) is the harness caller, so the swap's ledger rows and value legs
	// are derived against h.caller. We set the e2e taker = h.caller for this gate by routing the
	// swap through h.caller directly (runSyncSwapObserved uses h.caller as msg.sender).
	h := newE2EHarness(t)
	maker := e2eMaker
	taker := h.caller

	// A real maker BID rests (100 LETH @ 50, 5000 LUSD locked) — the counterparty the sync swap
	// will cross, so the handler touches the maker's order/ledger/index rows.
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)

	// The taker SELLs 80 LETH -> LUSD with a permissive price floor (satisfies the SELL
	// protection). zeroForOne (sell currency0=LETH for currency1=LUSD).
	h.mint(e2eLETH, taker, 80)
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: sqrtX96For(1.0)}
	calldata := buildSwapCalldata(h.key, params, nil)

	// PREDICT against the PRE-call state (the maker is resting; the predictor reads the live
	// index to enumerate it).
	declared := h.predictSync(h.key, params)

	// RUN the real sync swap through the observer.
	observed, foreign, err := h.runSyncSwapObserved(t, calldata)
	if err != nil {
		t.Fatalf("sync swap must settle: %v", err)
	}
	if len(observed) == 0 {
		t.Fatal("observer recorded NO 0x9999 writes — the harness did not exercise the sync money path")
	}
	// This is an all-ERC-20 market (LETH/LUSD), so the taker's VALUE legs move on the token
	// ledgers (foreign) — that is the expected native-scoping boundary; the 0x9999 conflict
	// keys (counter, dexcore rows, index) are what must be ⊆ declared.
	t.Logf("sync swap: %d 0x9999 conflict writes, %d foreign token-ledger writes", len(observed), len(foreign))

	// THE GATE: every observed 0x9999 write key must be declared. A miss is a forkable edge.
	if bad := subsetViolations(observed, declared); len(bad) != 0 {
		for _, k := range bad {
			t.Errorf("SYNC HANDLER WROTE UNDECLARED 0x9999 KEY %s (missed conflict edge => fork risk)", k.Hex())
		}
		t.Fatalf("sync access-set parity FAILED: %d undeclared handler writes (declared=%d, observed=%d)",
			len(bad), len(declared), len(observed))
	}
	t.Logf("sync parity: handler wrote %d 0x9999 keys, all within the %d declared", len(observed), len(declared))

	// FAIL-WITHOUT PROOF: the swap counter is the slot the ASYNC predictor (PredictSwapWriteSet)
	// never declares. Drop it from the SYNC declaration and the subset check MUST report it —
	// proving (a) the gate is load-bearing and (b) runSyncSwap genuinely writes swapCounterKey,
	// the exact edge the async predictor would have missed.
	crippled := cloneKeySet(declared)
	counterKey := swapCounterKey(h.key.ID())
	if _, ok := observed[counterKey]; !ok {
		t.Fatal("precondition broken: the sync swap did not write swapCounterKey — the counter " +
			"is the slot the async predictor omits; if the handler stopped writing it the B7/B8 " +
			"premise is gone")
	}
	delete(crippled, counterKey)
	bad := subsetViolations(observed, crippled)
	foundCounter := false
	for _, k := range bad {
		if k == counterKey {
			foundCounter = true
		}
	}
	if !foundCounter {
		t.Fatalf("FAIL-WITHOUT proof broken: dropping swapCounterKey did NOT surface a violation — "+
			"the gate is not checking the counter slot (declared=%d)", len(declared))
	}
	t.Logf("fail-without confirmed: dropping swapCounterKey (the async predictor's blind spot) is caught")

	// SECOND FAIL-WITHOUT: drop a dexcore book/ledger row class (the taker's available ledger
	// slot) and prove the gate catches that too — the dexcore rows are the OTHER region the
	// async predictor never models.
	takerAvailBase := newEVMStore(newPoolStateAdapter(h.state)).valueSlot(
		dexKeyBalance([32]byte(accountFromAddress(taker)), assetID(h.key.Currency0)), 0)
	if _, ok := observed[takerAvailBase]; ok {
		crippled2 := cloneKeySet(declared)
		delete(crippled2, takerAvailBase)
		if len(subsetViolations(observed, crippled2)) == 0 {
			t.Fatal("FAIL-WITHOUT(dexcore row) broken: dropping the taker base-available slot did " +
				"not surface a violation — the gate is not checking dexcore ledger rows")
		}
		t.Logf("fail-without(dexcore row) confirmed: dropping a taker ledger slot is caught")
	}
}

// Test9999_SyncAccessSet_FailClosed proves the runtime assertion is FAIL-CLOSED for the sync
// path: running the sync swap under the WRONG (async) declared set is REJECTED with
// ErrAccessSetUndeclaredWrite, and under the CORRECT sync set is accepted (no false rejection).
func Test9999_SyncAccessSet_FailClosed(t *testing.T) {
	mkHarness := func(t *testing.T) (*e2eHarness, SwapParams, []byte) {
		h := newE2EHarness(t)
		maker := e2eMaker
		h.mint(e2eLUSD, maker, 5000)
		h.deposit(t, maker, e2eLUSD, 5000)
		h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)
		h.mint(e2eLETH, h.caller, 80)
		params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: sqrtX96For(1.0)}
		calldata := buildSwapCalldata(h.key, params, nil)
		return h, params, calldata
	}
	run := func(h *e2eHarness, declared map[common.Hash]struct{}, calldata []byte) error {
		_, _, err := AssertWriteSetWithin(h.state, declared, func(s contract.AccessibleState) ([]byte, uint64, error) {
			return h.c.Run(s, h.caller, poolManagerAddr9999,
				prependSelector(SelectorSwap, calldata), 5_000_000, false)
		})
		return err
	}

	// REJECT: the ASYNC predictor's set is the WRONG region for a sync swap. The sync handler
	// writes the swap counter + dexcore rows the async set omits, so the assertion must reject.
	h, params, calldata := mkHarness(t)
	asyncDeclared := PredictSwapWriteSet(
		newPoolStateAdapter(h.state), h.state.NetworkID(), h.state.CChainID(), h.state.DChainID(),
		h.state.stateDB.blockNumber, h.key, params, h.caller, nil)
	if err := run(h, asyncDeclared, calldata); err == nil {
		t.Fatal("FAIL-CLOSED broken: a sync swap checked against the ASYNC write-set must be REJECTED")
	} else if _, ok := err.(*ErrAccessSetUndeclaredWrite); !ok {
		t.Fatalf("expected ErrAccessSetUndeclaredWrite, got %T: %v", err, err)
	}
	t.Log("fail-closed confirmed: sync swap under the async (wrong-region) set is rejected")

	// ACCEPT: the SAME swap under the CORRECT sync declaration is not rejected.
	h2, params2, calldata2 := mkHarness(t)
	syncDeclared := PredictSyncSwapWriteSet(newPoolStateAdapter(h2.state), h2.key, params2, h2.caller)
	if err := run(h2, syncDeclared, calldata2); err != nil {
		t.Fatalf("complete sync declaration must be ACCEPTED (no false rejection), got: %v", err)
	}
	t.Log("complement confirmed: the correct sync declaration is accepted (no false positive)")
}

// Test9999_SyncDispatch_RoutesToSyncPredictor proves the LIVE per-selector dispatch
// (PredictWriteSetForCall) routes a VALUE-ENABLED untagged swap to the SYNC predictor — the
// region the handler actually writes — not the async predictor. With value swaps enabled and an
// empty (untagged) hookData, the call is the synchronous router, so its declared set must equal
// PredictSyncSwapWriteSet, not PredictSwapWriteSet.
func Test9999_SyncDispatch_RoutesToSyncPredictor(t *testing.T) {
	h := newE2EHarness(t) // value swaps ENABLED
	maker := e2eMaker
	h.mint(e2eLUSD, maker, 5000)
	h.deposit(t, maker, e2eLUSD, 5000)
	h.placeArgs(t, maker, true, 50*uint64(priceMultiplierConst), 100)

	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-80), SqrtPriceLimitX96: sqrtX96For(1.0)}
	calldata := buildSwapCalldata(h.key, params, nil) // untagged -> sync route while value-enabled

	// PredictWriteSetForCall decodes the swap input itself (DecodeSwapInput), so `input` is the
	// post-selector ABI calldata — exactly what buildSwapCalldata returns (Run strips the
	// selector before the handler decodes; here we hand the dispatcher the same post-selector bytes).
	dispatched, ok := PredictWriteSetForCall(
		newPoolStateAdapter(h.state),
		h.state.NetworkID(), h.state.CChainID(), h.state.DChainID(),
		h.state.TxID(), h.state.CallIndex(), h.caller, h.state.stateDB.blockNumber,
		SelectorSwap, calldata,
	)
	if !ok {
		t.Fatal("SelectorSwap must be covered by PredictWriteSetForCall")
	}
	wantSync := PredictSyncSwapWriteSet(newPoolStateAdapter(h.state), h.key, params, h.caller)
	if !keySetsEqual(dispatched, wantSync) {
		t.Fatalf("value-enabled untagged swap did not route to the SYNC predictor "+
			"(dispatched=%d, sync=%d)", len(dispatched), len(wantSync))
	}
	t.Log("dispatch confirmed: a value-enabled untagged swap routes to PredictSyncSwapWriteSet")
}
