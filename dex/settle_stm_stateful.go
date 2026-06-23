// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// settle_stm_stateful.go is the COMPLETE, STATE-AWARE access-set predictor — the closure of
// the gap settle_stm.go's PURE predictor documents (settle_stm.go:42-49, 137-144). The pure
// predictor surfaces only the conflict axes a scheduler can derive from (key, params, caller)
// WITHOUT state; the keys it cannot statically know — a settlement object's consumed slot
// (keyed by the object id), the C->D replay slot (keyed by a derived intent/commit id), the
// per-intent record slots, the staging slots (seq-keyed), and the per-owner order index at
// the LIVE count — are derived HERE by reading the SAME stateKV the handler reads and
// calling the SAME helpers the handler calls, so the prediction is the EXACT write-set, not
// an approximation.
//
// THE SOUNDNESS RULE (no escape hatch on a WRITE): every key the handler can SetState (or
// move via a native balance op) for a given call MUST appear in the returned Writes. A
// missed write = a missed conflict edge = a silent fork. So this predictor is held to a
// strictly higher bar than the pure one: it is the SOUND SUPERSET the runtime assertion
// (AssertWriteSetWithin) checks the handler against and the set the root binding
// (AccessCommitment) commits. The pure PredictAccesses remains the scheduler's fast static
// pre-pass; this is the authority.
//
// SCOPE (documented honestly for the adversary): the assertion drives the NATIVE settlement
// path (the asset that moves via account balances). On that path every conflict key is a
// 0x9999-namespace slot or a native balanceSlot, all derivable here. The ERC-20 path's value
// movement additionally writes the TOKEN contract's own ledger (a different address, the
// erc20Vault sub-call) and, for a fee-on-transfer token, locks an amount that is only known
// post-transfer — neither is part of the 0x9999 Block-STM conflict graph (which is over
// 0x9999 slots + native balances), so the native scoping is the precise boundary of the
// by-construction guarantee. The fee-on-transfer intent-id divergence is exactly why the
// id-derived keys can only be made complete for native here.

// writeSet is a small set-builder so a predictor accumulates conflict keys without dup. The
// returned AccessSet's Writes are deduped; Reads are not part of the soundness check (a
// missed READ never forks — only a missed WRITE does — so the predictor declares the writes
// authoritatively and the reads for completeness/observability).
type writeSet struct {
	w map[common.Hash]struct{}
}

func newWriteSet() *writeSet { return &writeSet{w: make(map[common.Hash]struct{})} }

func (s *writeSet) add(keys ...common.Hash) {
	for _, k := range keys {
		s.w[k] = struct{}{}
	}
}

// set returns the accumulated write-set as the map the assertion and the commitment consume.
func (s *writeSet) set() map[common.Hash]struct{} { return s.w }

// PredictSwapWriteSet returns the EXACT set of conflict keys a native SettleSwap of
// (key, params, caller, hookData) will write, derived against the live stateKV so every
// id-keyed and index-keyed slot is named identically to the handler. It dispatches on the
// hookData phase (decodeSwapPhase — the SAME classifier the handler uses) so a Phase-A
// intent and a Phase-B settlement each declare their own write-set.
//
// It is the authority the runtime assertion checks `observed ⊆ this` against, so it MUST be
// a superset of every key the handler can touch on the native path. Where the handler's
// write depends on live state (the replay set already holding an id, the intent's recorded
// asset), this predictor reads that same state and includes the conditional write — a
// SUPERSET is always safe (an over-declaration only over-serializes), so where a branch is
// state-dependent we declare BOTH outcomes' keys.
//
// stagingSeqHint is the staging sequence the call will start writing at (== stageSeq(sdb)
// before the call); the staged Put/Remove records are seq-keyed, so the predictor names the
// exact staging slots the call will occupy.
func PredictSwapWriteSet(
	sdb stateKV,
	networkID uint32,
	cChainID, dChainID ids.ID,
	blockNumber uint64,
	key PoolKey,
	params SwapParams,
	caller common.Address,
	hookData []byte,
) map[common.Hash]struct{} {
	ws := newWriteSet()

	// EVERY 0x9999 money entrypoint takes the custody guard on enter AND clears it on exit
	// — two writes to the SAME slot, so one key. Declared unconditionally for both phases.
	ws.add(custodyGuardKey9999)

	_, out := swapAssetDirection(key, params)
	phase, _, _ := decodeSwapPhase(hookData)

	switch phase {
	case swapPhaseSettlement:
		// PHASE B — ImportSettlement consumes a D->C object and credits C (native: out leg).
		claim, derr := decodeSettlementBody(decodeSwapBody(hookData), key, params, caller)
		if derr != nil {
			// A malformed settlement body reverts in the handler before any write past the
			// custody guard; the guard key alone is the write-set. (The guard's enter+exit
			// both fire because the defer runs on the early return.)
			return ws.set()
		}
		predictImportSettlementWrites(ws, sdb, dChainID, blockNumber, key.ID(), out, caller, claim)

	default:
		// PHASE A — SubmitSwapIntent locks input (native: in leg) and stages a C->D object.
		predictSubmitSwapIntentWrites(ws, sdb, networkID, cChainID, dChainID, blockNumber, key, params, caller, hookData)
	}
	return ws.set()
}

// decodeSwapBody returns the post-tag settlement body for a DS01 hookData (the bytes
// decodeSettlementBody parses), mirroring decodeSwapPhase's body return for the settlement
// branch. For a non-settlement hookData it returns nil (the Phase-B predictor branch is only
// reached for a DS01 tag, so this is exact).
func decodeSwapBody(hookData []byte) []byte {
	_, body, _ := decodeSwapPhase(hookData)
	return body
}

// predictSubmitSwapIntentWrites declares the Phase-A native write-set: the seam-reserve
// accounting slot, the two native balance legs, the C->D replay slot, the five per-intent
// record slots, and the staged C->D Put slots — each keyed exactly as SubmitSwapIntent keys
// them, derived against the live state.
func predictSubmitSwapIntentWrites(
	ws *writeSet,
	sdb stateKV,
	networkID uint32,
	cChainID, dChainID ids.ID,
	blockNumber uint64,
	key PoolKey,
	params SwapParams,
	caller common.Address,
	hookData []byte,
) {
	in, _ := swapAssetDirection(key, params)

	// lockIntentInput (native): storeSeamReserve(in) + SubBalance(caller) + AddBalance(0x9999).
	// For native the locked amount == |AmountSpecified| (no fee-on-transfer), so the intent
	// id is derivable; the seam reserve and both balance legs are the value writes.
	ws.add(seamReserveKey(in))
	ws.add(balanceSlot(caller, nativeAssetID))
	ws.add(balanceSlot(poolManagerAddr9999, nativeAssetID))

	// The intent id is content-addressed over the FULL identity, with the locked amount the
	// id binds being the native lock magnitude. The handler derives it via DeriveIntentID;
	// we derive it identically so the replay slot + record slots are the exact keys.
	locked := nativeLockMagnitude(params)
	if locked == 0 {
		// A zero/invalid amount reverts in buildIntentRequest / SubmitSwapIntent before the
		// id-keyed writes; the value legs above are the upper bound of what could be touched.
		return
	}
	deadline, nonce := predictIntentDeadlineNonce(hookData, blockNumber)
	_ = deadline // the deadline rides the record's meta slot (declared below), not its own key
	intentID := DeriveIntentID(networkID, cChainID, dChainID, caller, in, locked, key.ID(), nonce)

	// markIntentSubmitted -> the C->D replay slot keyed by the intent id.
	ws.add(intentSubmittedKey(intentID))

	// putSwapIntentRecord -> the five per-intent record slots keyed by the intent id.
	ws.add(
		swapIntentSlot(intentID, swapIntentOwnerSuffix),
		swapIntentSlot(intentID, swapIntentAssetSuffix),
		swapIntentSlot(intentID, swapIntentMetaSuffix),
		swapIntentSlot(intentID, swapIntentRemainSuffix),
		swapIntentSlot(intentID, swapIntentLimitSuffix),
	)

	// stageAtomicPut -> the staged C->D Put record: the seq counter, the kind marker, and the
	// length+data slots for the packed object, all keyed by the live staging seq.
	predictStagePutWrites(ws, sdb, intentID, dChainID, railSwap, caller, in, locked)
}

// predictImportSettlementWrites declares the Phase-B native write-set: the D->C consumed
// slot, the seam-reserve accounting, the two native balance legs, the optional per-intent
// record decrement, the sharded volume bucket, the DEXFill log is not a state write, and the
// staged D->C Remove slots — each keyed exactly as ImportSettlement keys them.
func predictImportSettlementWrites(
	ws *writeSet,
	sdb stateKV,
	dChainID ids.ID,
	blockNumber uint64,
	marketID [32]byte,
	out [32]byte,
	caller common.Address,
	claim SettlementClaim,
) {
	var outputID ids.ID = claim.OutputID

	// markSettlementConsumed -> the D->C replay slot keyed by the object id.
	ws.add(settlementConsumedKey(outputID))

	// creditSettlementOutput (native): storeSeamReserve(out) + SubBalance(0x9999) +
	// AddBalance(recipient==caller). The credited asset is the swap's OUTPUT side (derived in
	// decodeSettlementBody as claim.Asset == out).
	ws.add(seamReserveKey(out))
	ws.add(balanceSlot(poolManagerAddr9999, nativeAssetID))
	ws.add(balanceSlot(caller, nativeAssetID))

	// The per-intent record is decremented ONLY for a same-asset refund (recAsset ==
	// intent.AssetIn). Whether this leg fires depends on the recorded object's asset, which
	// is not known until shared memory is read. A SUPERSET is safe, so we declare the record
	// slots the decrement could touch (keyed by the claim's intent id) unconditionally — an
	// over-declaration only over-serializes, never under-detects.
	if claim.IntentID != ([32]byte{}) {
		intentID := ids.ID(claim.IntentID)
		ws.add(
			swapIntentSlot(intentID, swapIntentOwnerSuffix),
			swapIntentSlot(intentID, swapIntentAssetSuffix),
			swapIntentSlot(intentID, swapIntentMetaSuffix),
			swapIntentSlot(intentID, swapIntentRemainSuffix),
			swapIntentSlot(intentID, swapIntentLimitSuffix),
		)
	}

	// accrueVolume -> the SHARDED volume bucket keyed by (poolID, epoch). The market is the
	// swap's pool id (key.ID(), threaded from PredictSwapWriteSet); the epoch is the block
	// number (epochOf), matching the handler. accrueVolume is a no-op for a zero credit, so a
	// declared volume bucket is a SUPERSET (safe — over-declaration only over-serializes).
	ws.add(volBucketKey(marketID, blockNumber))

	// stageAtomicRemove -> the staged D->C Remove record at the live staging seq.
	predictStageRemoveWrites(ws, sdb, dChainID, outputID)
}

// predictStagePutWrites declares the staged C->D Put slots a stageAtomicPut at the live seq
// will write: the seq counter (bumped), the kind marker, and the length+data words for the
// packed (version|dChainID|key|object) record. It computes the record exactly as packPut
// does so the slot count is exact.
func predictStagePutWrites(ws *writeSet, sdb stateKV, key ids.ID, dChainID ids.ID, rail Rail, owner common.Address, asset [32]byte, amount uint64) {
	seq := stageSeq(sdb)
	obj := encodeAtomicObject(rail, owner, asset, amount)
	rec := packPut(dChainID, key, obj)
	ws.add(stageSeqKey)
	ws.add(stageKindKey(seq))
	predictSlotRun(ws, stagePutPrefix, seq, len(rec))
}

// predictStageRemoveWrites declares the staged D->C Remove slots a stageAtomicRemove at the
// live seq will write: the seq counter, the kind marker, and the length+data words for the
// packed (version|dChainID|key) record.
func predictStageRemoveWrites(ws *writeSet, sdb stateKV, dChainID ids.ID, key ids.ID) {
	seq := stageSeq(sdb)
	rec := packRemove(dChainID, key)
	ws.add(stageSeqKey)
	ws.add(stageKindKey(seq))
	predictSlotRun(ws, stageRemovePrefix, seq, len(rec))
}

// predictSlotRun declares the consecutive 32-byte staging slots writeBytesToSlots writes for
// a record of n bytes: slot 0 (the length word) plus ceil(n/32) data words (slots 1..). This
// is the EXACT loop writeBytesToSlots runs, so the predicted slot set is identical.
func predictSlotRun(ws *writeSet, prefix []byte, seq uint64, n int) {
	ws.add(stageSlotKey(prefix, seq, 0))
	for i := 0; i*32 < n; i++ {
		ws.add(stageSlotKey(prefix, seq, i+1))
	}
}

// nativeLockMagnitude returns the native lock amount |AmountSpecified| for an exact-input
// swap, or 0 for an invalid amount — the SAME magnitude buildIntentRequest computes (it
// reverts on a non-positive / non-uint64 magnitude, so the predictor returns 0 there).
func nativeLockMagnitude(params SwapParams) uint64 {
	if params.AmountSpecified == nil || params.AmountSpecified.Sign() == 0 {
		return 0
	}
	mag := new(big.Int).Abs(params.AmountSpecified)
	if !mag.IsUint64() || mag.Sign() <= 0 {
		return 0
	}
	return mag.Uint64()
}

// predictIntentDeadlineNonce derives (deadline, nonce) from the Phase-A hookData the SAME way
// SettleSwap does: only a DI01-tagged body carries them; an untagged body yields (0,0), and a
// zero deadline is defaulted to blockTimestamp+maxIntentTTL by the handler — but the nonce
// (which is what the intent id binds) is what the predictor needs. The deadline rides the
// record's meta slot (already declared), not its own key, so only the nonce matters for the
// id derivation here.
func predictIntentDeadlineNonce(hookData []byte, blockNumber uint64) (deadline, nonce uint64) {
	_, body, tagged := decodeSwapPhase(hookData)
	if !tagged {
		return 0, 0
	}
	d, n, err := decodeIntentBody(body)
	if err != nil {
		return 0, 0
	}
	return d, n
}

// PredictReclaimIntentWriteSet returns the EXACT 0x9999 conflict keys a native
// reclaimIntent(intentID) writes: the custody guard, the reclaim one-time replay slot, the
// five per-intent record slots (the record is rewritten with remaining=0 + Status=Reclaimed),
// the seam-reserve accounting for the refunded asset, the two native balance legs (refund
// from 0x9999 to the locker), and the staged compensating C->D Remove of the original intent
// object — each keyed exactly as ReclaimIntent keys them, derived against the live state.
//
// It is the reclaim SELECTOR's predictor — the runtime assertion for a reclaimIntent call
// MUST use THIS, not PredictSwapWriteSet (which declares the swap's keys, a DIFFERENT set).
// This is the per-selector dispatch contract: each value selector's assertion uses its own
// matching predictor (see PredictWriteSetForCall).
func PredictReclaimIntentWriteSet(
	sdb stateKV,
	dChainID ids.ID,
	intentID ids.ID,
) map[common.Hash]struct{} {
	ws := newWriteSet()
	ws.add(custodyGuardKey9999)

	// markSwapIntentReclaimed -> the one-time reclaim replay slot.
	ws.add(swapIntentReclaimedKey(intentID))

	// putSwapIntentRecord (remaining=0, Status=Reclaimed) -> the five record slots.
	ws.add(
		swapIntentSlot(intentID, swapIntentOwnerSuffix),
		swapIntentSlot(intentID, swapIntentAssetSuffix),
		swapIntentSlot(intentID, swapIntentMetaSuffix),
		swapIntentSlot(intentID, swapIntentRemainSuffix),
		swapIntentSlot(intentID, swapIntentLimitSuffix),
	)

	// creditSettlementOutput refunds the LOCKED asset from seamReserve. The locked asset is
	// the record's AssetIn, read from live state (the same value ReclaimIntent reads). The
	// refund's native balance legs are 0x9999 -> the locker; for a native locked asset these
	// are the two balanceSlots, for an ERC-20 locked asset the value moves through the vault
	// (foreign). We declare the seam-reserve slot (always 0x9999) + both native balance legs
	// (the native case); an ERC-20 reclaim's token-ledger leg is foreign by construction.
	rec := loadSwapIntentRecord(sdb, intentID)
	ws.add(seamReserveKey(rec.AssetIn))
	if isNativeAsset(rec.AssetIn) {
		ws.add(balanceSlot(poolManagerAddr9999, nativeAssetID))
		ws.add(balanceSlot(rec.Owner, nativeAssetID))
	}

	// stageAtomicRemove of the original intent object (keyed by intentID) at the live seq.
	predictStageRemoveWrites(ws, sdb, dChainID, intentID)
	return ws.set()
}

// PredictModifyLiquidityWriteSet closes the per-owner index gap the pure
// PredictModifyLiquidityAccesses documents (settle_stm.go:137-144): it reads the LIVE owner
// order count and the order's index-presence flag from the stateKV and declares
// ownerOrdersAtKey(owner, count) IFF the order is not already indexed — exactly the branch
// appendOwnerOrder takes. This is the LP-rail analog of PredictSwapWriteSet: the SOUND
// superset the assertion checks an LP modifyLiquidity (ADD) against.
//
// It declares: the custody guard, the committed-positions accounting, the two native balance
// legs (commitPositionInput native), the C->D commit replay slot, the full resting-order
// record (storeRestingOrder's slots + the commit-object slot), the per-owner index (the
// count slot, the live-index slot, the presence flag), and the staged C->D Put slots — every
// key derived against the live state so the index slot is named at the count the handler will
// write to.
func PredictModifyLiquidityWriteSet(
	sdb stateKV,
	networkID uint32,
	cChainID, dChainID ids.ID,
	owner common.Address,
	poolID [32]byte,
	salt [32]byte,
	tickLower, tickUpper int24,
	lockedAsset [32]byte,
	lockedAmount uint64,
) map[common.Hash]struct{} {
	ws := newWriteSet()
	ws.add(custodyGuardKey9999)

	orderID := MakerOrderID(owner, poolID, salt, tickLower, tickUpper)

	// commitPositionInput (native): storeCommittedPositions(lockedAsset) + the two balance legs.
	ws.add(committedPositionsKey(lockedAsset))
	ws.add(balanceSlot(owner, nativeAssetID))
	ws.add(balanceSlot(poolManagerAddr9999, nativeAssetID))

	// The per-owner committed reserve (defense-in-depth accumulator).
	ws.add(lockedReserveKey(owner, lockedAsset))

	// storeRestingOrder -> the six order record slots + the commit-object slot.
	ws.add(
		orderSlot(orderID, orderMetaSuffix),
		orderSlot(orderID, orderOwnerSuffix),
		orderSlot(orderID, orderPoolSuffix),
		orderSlot(orderID, orderAssetSuffix),
		orderSlot(orderID, orderAmtSuffix),
		orderSlot(orderID, orderSaltSuffix),
		orderSlot(orderID, orderCommitObjSuffix),
	)

	// appendOwnerOrder -> the per-owner index. THE GAP: ownerOrdersAtKey(owner, count) is the
	// NEW slot at the LIVE count, which the pure predictor could not name. Here we read the
	// live count and the presence flag from the SAME state the handler reads and declare the
	// index write IFF the order is not already present — the exact branch appendOwnerOrder
	// takes. An already-indexed re-add writes NOTHING new to the index (idempotent), so we
	// declare the count + the live index slot ONLY for a first add.
	if sdb.GetState(poolManagerAddr9999, orderIndexedKey(orderID)) == (common.Hash{}) {
		count := loadOwnerOrderCount(sdb, owner)
		ws.add(ownerOrdersAtKey(owner, count))
		ws.add(ownerOrdersCountKey(owner))
		ws.add(orderIndexedKey(orderID))
	}

	// The C->D commit replay slot + staged C->D Put (railLP). The commit id is derived by the
	// handler via DerivePositionCommitID over the txID+callIndex (NOT chain-observable like the
	// swap nonce), so the predictor cannot statically name it for a value-bearing assertion on
	// the COMMIT id alone — but the replay set and the staged Put are keyed by the commit id,
	// which the handler computes from (txID, callIndex) the predictor DOES hold via the same
	// AtomicState. For the native LP assertion path we thread (txID, callIndex) through the
	// caller; here we leave the commit-id-keyed staging to the predictor variant that has them
	// (PredictModifyLiquidityWriteSetWithTx), and declare the structurally-derivable record +
	// index + accounting keys above. See the Red handoff: the LP commit-id staging slot is the
	// one remaining path requiring (txID, callIndex), provided by the with-tx variant below.
	return ws.set()
}

// PredictModifyLiquidityWriteSetWithTx is the COMPLETE LP-ADD predictor: it extends
// PredictModifyLiquidityWriteSet with the commit-id-keyed writes (the C->D replay slot and
// the staged C->D Put) that require the executing (txID, callIndex) — the inputs
// DerivePositionCommitID folds in. With these the LP-ADD native write-set is fully derived,
// with NO escape hatch on any write.
func PredictModifyLiquidityWriteSetWithTx(
	sdb stateKV,
	networkID uint32,
	cChainID, dChainID ids.ID,
	txID ids.ID,
	callIndex uint32,
	owner common.Address,
	poolID [32]byte,
	salt [32]byte,
	tickLower, tickUpper int24,
	lockedAsset [32]byte,
	lockedAmount uint64,
) map[common.Hash]struct{} {
	base := PredictModifyLiquidityWriteSet(sdb, networkID, cChainID, dChainID, owner, poolID, salt, tickLower, tickUpper, lockedAsset, lockedAmount)
	ws := &writeSet{w: base}

	commitID := DerivePositionCommitID(networkID, cChainID, dChainID, txID, callIndex, owner, lockedAsset, lockedAmount, poolID)
	ws.add(intentSubmittedKey(commitID))
	predictStagePutWrites(ws, sdb, commitID, dChainID, railLP, owner, lockedAsset, lockedAmount)
	return ws.set()
}

// ---------------------------------------------------------------------------
// The per-selector dispatch contract (the runtime assertion's wiring).
// ---------------------------------------------------------------------------

// PredictWriteSetForCall is the SINGLE dispatch point that maps a 0x9999 value selector to
// its matching write-set predictor — the contract the runtime assertion (AssertWriteSetWithin)
// wires to. It exists so the assertion uses the RIGHT declaration per call: a reclaimIntent
// must be checked against PredictReclaimIntentWriteSet, NOT the swap predictor (whose declared
// set is a different region), else the assertion would spuriously reject a correct reclaim.
//
// THE SOUNDNESS CONTRACT: every value selector that mutates 0x9999 state MUST have a case
// here returning a SOUND SUPERSET of its handler's write-set. A selector with no case returns
// ok=false, and the caller MUST fail-closed (reject the call) rather than run it unchecked —
// an unchecked value path is precisely the fork surface this whole layer closes. So a NEW
// value selector is inert until its predictor is added here: the dispatcher makes "did we
// forget to declare a path?" a compile-time-visible, fail-closed gap, not a silent fork.
//
// Decodes are done HERE (off the input) the SAME way each handler decodes, so the predictor
// reads the identical inputs. Returns (declared, true) for a covered selector; (nil, false)
// for an uncovered one (the caller rejects).
func PredictWriteSetForCall(
	sdb stateKV,
	networkID uint32,
	cChainID, dChainID ids.ID,
	txID ids.ID,
	callIndex uint32,
	caller common.Address,
	blockNumber uint64,
	selector uint32,
	input []byte,
) (map[common.Hash]struct{}, bool) {
	switch selector {
	case SelectorSwap:
		key, params, hookData, err := DecodeSwapInput(input)
		if err != nil {
			// A malformed swap reverts in the handler before any write past the custody guard.
			ws := newWriteSet()
			ws.add(custodyGuardKey9999)
			return ws.set(), true
		}
		// Route to the SAME predictor the live dispatch's handler uses (settle_module.go): an
		// untagged swap is the SYNCHRONOUS router (runSyncSwap, now UNCONDITIONAL — no value
		// gate), whose write region is the swap counter + dexcore book/index/ledger rows —
		// declared by PredictSyncSwapWriteSet. A tagged (DI01/DS01) swap is the async SettleSwap
		// seam — declared by PredictSwapWriteSet. Predicting the WRONG region would make the
		// runtime assertion either self-DoS (sync handler vs async set) or miss the sync edges
		// (async set used for a sync call), so the dispatch MUST mirror the handler's own routing
		// condition exactly.
		if isUntaggedSwap(hookData) {
			return PredictSyncSwapWriteSet(sdb, key, params, caller), true
		}
		return PredictSwapWriteSet(sdb, networkID, cChainID, dChainID, blockNumber, key, params, caller, hookData), true

	case SelectorReclaimIntent:
		if len(input) < 32 {
			ws := newWriteSet()
			ws.add(custodyGuardKey9999)
			return ws.set(), true
		}
		var intentID ids.ID
		copy(intentID[:], input[0:32])
		return PredictReclaimIntentWriteSet(sdb, dChainID, intentID), true

	default:
		// Uncovered selector: the caller MUST fail-closed (reject) rather than run it
		// unchecked. modifyLiquidity / collectPosition predictors exist
		// (PredictModifyLiquidityWriteSetWithTx) but need their decoded calldata params wired
		// in; until a case decodes them here, those selectors are not auto-dispatched. See the
		// Red handoff: this default is the explicit, fail-closed boundary of auto-coverage.
		return nil, false
	}
}
