// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
)

// native_dchain_client.go is the C SIDE of the native C<->D atomic settlement
// seam (Mode A, async atomic). It is the concrete realization of the on-ramp the
// DChainClient interface (dchain_client.go) describes: a marketable swap becomes a
// C->D atomic INTENT object (funds locked on C, an export written into shared
// memory for D to import), and a settled fill becomes a D->C atomic object the C
// side IMPORTS once and credits.
//
// THE SHIP SAFETY MODEL (the whole point, enforced here, decomplected into two
// orthogonal methods):
//
//   - SubmitSwapIntent / SubmitModifyLiquidity FUND D: they debit C value into the
//     0x9999 escrow and write a C->D atomic object into shared memory. They return
//     an intent/position id ONLY — never a live fill, never an output credit. D is
//     funded ONLY by consuming this object (its executeImport binds the recorded
//     owner/asset/amount; conservation + one-time replay are the dexvm's, already
//     done and tested).
//
//   - ImportSettlement CREDITS C: it consumes a D->C atomic object out of shared
//     memory EXACTLY ONCE (replay-rejected, rail/asset/owner/amount-bound to the
//     RECORDED value, sourceChain-bound), credits the C balance/refund, and applies
//     the shared-memory Remove atomically. A C balance is credited ONLY along this
//     path — there is no other C credit from a settlement. A "live matcher answer"
//     (a fill value a relayer hands the precompile) CANNOT credit C: nothing here
//     trusts a declared amount; the credit derives from a consumed D->C object.
//     PER-TAKER CAP (MEDIUM): the credit is additionally bound to the taker's OWN
//     intent record and capped by that intent's remaining locked principal, so an
//     over-export for taker X can never draw on other takers' pooled tokenIn in the
//     shared seam reserve — the swap-rail analog of the LP per-position bound.
//
//   - ReclaimIntent EXITS C (liveness): once a swap intent's deadline passes and D has
//     not settled it, the original locker reclaims the remaining locked principal from
//     the seam reserve (one-time, deadline-gated, conservation-preserving — a reclaim
//     and a late settlement can never both pay out, since both draw down the same
//     remaining-principal counter and reclaim makes the intent terminal). So locked
//     swap input can ALWAYS exit, with no dependence on D or the keeper.
//
// WHAT C ENFORCES vs RELIES ON D FOR: C enforces — with NO trust in D — the recorded-
// value bind, the rail gate, one-time consumption, the seam-reserve-only credit, the
// per-taker principal cap, AND deadline-gated reclaim liveness. C relies on D ONLY for
// WHICH fills occurred / their amounts (D is the matcher); the per-taker cap bounds the
// blast radius of a faulty/hostile D export to that one taker's own locked principal.
//
// CONSENSUS-SAFETY: every method is a pure deterministic function of (input,
// StateDB, shared-memory contents) — no live query whose result is not already a
// committed cross-chain object. Writing/consuming shared memory is the SAME
// platformvm import/export primitive the dexvm uses; it commits with the EVM block.

// NativeDChainClient moves value across the C<->D boundary via primary-network
// atomic shared memory. It holds NO mutable state of its own (the escrow,
// consumed-set, and intent records all live in StateDB / shared memory); it is a
// stateless set of operations over the host capabilities passed at call time.
type NativeDChainClient struct {
	// brand is the user-facing identity for error/log strings (white-label).
	brand string
}

// NewNativeDChainClient constructs the native C<->D client. brand defaults to the
// OSS "Lux DEX" identity; a tenant surface passes its own.
func NewNativeDChainClient(brand string) *NativeDChainClient {
	if brand == "" {
		brand = "Lux DEX"
	}
	return &NativeDChainClient{brand: brand}
}

// Brand identifies the client in logs / error wrapping (Engine surface).
func (c *NativeDChainClient) Brand() string { return c.brand }

var (
	ErrNativeNoAtomicMemory  = errors.New("dex: cross-chain atomic memory unavailable (single-chain dev / on-ramp closed)")
	ErrNativeBadAmount       = errors.New("dex: native intent amount out of range")
	ErrNativeFundsShort      = errors.New("dex: sender has insufficient balance to fund the C->D intent")
	ErrNativeERC20Vault      = errors.New("dex: ERC-20 intent requires an erc20Vault-capable StateDB")
	ErrNativeIntentReplay    = errors.New("dex: C->D intent id already submitted (replay)")
	ErrNativeNoSettlement    = errors.New("dex: no D->C settlement object found for the claimed id")
	ErrNativeSettleReplay    = errors.New("dex: D->C settlement object already consumed (replay)")
	ErrNativeSettleMalformed = errors.New("dex: D->C settlement object is malformed")
	ErrNativeSettleAsset     = errors.New("dex: D->C settlement object asset does not match the claim")
	ErrNativeSettleOwner     = errors.New("dex: D->C settlement object owner does not match the recipient")
	ErrNativeSettleAmount    = errors.New("dex: D->C settlement object amount does not match the claim")
	ErrNativeSettleUnbacked  = errors.New("dex: vault cannot back the D->C credited amount (no mint)")

	// LP-rail errors (C->D position commit / D->C collect-withdraw).
	ErrLPCommitReplay      = errors.New("dex: C->D position-commit id already submitted (replay)")
	ErrLPCollectUnbacked   = errors.New("dex: committed-positions reserve cannot back the D->C collect credit (no mint, no raid)")
	ErrLPCollectNoPosition = errors.New("dex: D->C collect names no open/closing position for the recorded owner (cross-rail object refused)")

	// ErrSettleWrongRail / ErrLPCollectWrongRail are the H1 rail gates: a D->C object
	// carries its lane in its wire (railSwap / railLP). ImportSettlement consumes ONLY
	// railSwap; ImportPositionCollect consumes ONLY railLP. Feeding the other rail's
	// object reverts here BEFORE any pot is touched — closing H1 in BOTH directions
	// (an LP-collect object cannot drain the swap pot; a swap-fill object cannot drain
	// the LP pot).
	ErrSettleWrongRail    = errors.New("dex: D->C object is not a swap-rail object (cross-rail consume refused)")
	ErrLPCollectWrongRail = errors.New("dex: D->C object is not an LP-rail object (cross-rail consume refused)")

	// ErrLPCollectExceedsPosition is the FIX-1/FIX-2 per-object, per-owner bound: a
	// collect's recorded amount may not exceed the named position record's remaining
	// committable backing (its LockedAmt). It binds the credit to a SPECIFIC position
	// the recorded owner holds and bounds it by that owner's OWN committed reserve, so
	// an over-export for one owner can never draw on another owner's committed
	// principal in the shared committedPositions pot.
	ErrLPCollectExceedsPosition = errors.New("dex: D->C collect amount exceeds the named position's committed backing (would draw on another owner's principal)")

	// Swap-rail per-intent gates (MEDIUM cap + HIGH reclaim deadline), the swap-rail
	// analogs of the LP per-position gates above.
	//
	// ErrSettleNoIntent: the settlement names no live (Open) intent for the recorded
	// owner — a swap settlement MUST draw against the taker's own submitted intent, so a
	// claim naming a zero / unknown / already-reclaimed intent (or one whose owner is not
	// the recorded object owner) is refused. The credit cannot float free of an intent.
	ErrSettleNoIntent = errors.New("dex: D->C settlement names no open intent for the recorded owner (unbound settlement refused)")
	// ErrSettleExceedsIntent: a SAME-ASSET refund (recAsset == intent.AssetIn) exceeds the
	// named intent's remaining locked principal — the per-taker cap, the exact same-asset
	// analog of ErrLPCollectExceedsPosition (the LP collects the same asset it committed).
	// Bounding the refund by the taker's OWN locked principal is what stops an over-refund
	// for taker X from drawing on other takers' pooled tokenIn of the input asset. (The
	// proceeds leg — the opposite asset — is not input-unit-capped; its no-mint guard is
	// the seam-reserve backing + one-time consumption + the intent binding.)
	ErrSettleExceedsIntent = errors.New("dex: D->C refund amount exceeds the intent's remaining locked principal (would draw on another taker's tokenIn)")
	// ErrSettlePastDeadline: a Phase-B settlement arrived after the intent's deadline.
	// Past the deadline the taker may reclaim the locked principal (ReclaimIntent), so a
	// late settlement is refused to keep settlement and reclaim mutually exclusive.
	ErrSettlePastDeadline = errors.New("dex: D->C settlement is past the intent's deadline (reclaim path applies)")
	// ErrSettlePriceLimit: a PROCEEDS settlement's realized price (out/spent) is WORSE than
	// the taker's OWN recorded slippage limit (intent.PriceLimit). This is the taker-
	// AUTHENTICATED MEV floor — it binds against the limit the taker recorded at submit, NOT
	// the keeper-relayed limit — so a keeper that zeroes the relay limit to sandwich the
	// taker cannot get the bad-price proceeds credited. The intent stays Open and its
	// principal remains reclaimable after the deadline.
	ErrSettlePriceLimit = errors.New("dex: D->C proceeds price violates the taker's recorded slippage limit (taker-authenticated MEV floor)")

	// Reclaim gates (HIGH liveness: locked swap input can always exit if D never settles).
	ErrReclaimNoIntent       = errors.New("dex: reclaimIntent names no open intent for the caller")
	ErrReclaimNotOwner       = errors.New("dex: reclaimIntent caller is not the intent's locker")
	ErrReclaimBeforeDeadline = errors.New("dex: reclaimIntent before the intent deadline (settlement may still land)")
	ErrReclaimNoDeadline     = errors.New("dex: reclaimIntent requires the intent to carry a deadline")
	ErrReclaimNothingLocked  = errors.New("dex: reclaimIntent has no remaining locked principal to refund")
	ErrReclaimReplay         = errors.New("dex: intent principal already reclaimed (replay)")
)

// --- Intent submission (C->D): FUND D, return an intent id, NEVER a fill. ------

// IntentRequest is the full C->D intent a swap creates. The 60-byte atomic object
// carries (account, assetIn, amountIn); the rest is routing metadata emitted as an
// event for the keeper that builds the D order.
type IntentRequest struct {
	Account      common.Address // taker — the C tx caller; bound as the object owner
	AssetIn      [32]byte       // full injective AssetID locked on C and credited on D
	AmountIn     uint64         // integer asset units locked
	AssetInAddr  common.Address // the ERC-20 token (address(0) for native) for the C lock
	MarketID     [32]byte       // D market the order targets
	MinAmountOut *big.Int       // taker slippage floor (routing only; D enforces at match)
	// PriceLimit is the taker's worst-acceptable CLOB price (quote-per-base, float64
	// bits) derived from the V4 SqrtPriceLimitX96 (priceLimitToCLOB). LimitIsUpper says
	// which side it bounds (true = a BUY ceiling, false = a SELL floor). The keeper carries
	// these onto the settling relay (RelayOrderTx.PriceLimit/LimitIsUpper) and the dexvm
	// settle path REFUSES a fill worse than the limit — the bounded sandwich/MEV guard.
	// Emitted in the routing event so the keeper does not re-derive them. 0 = no limit.
	PriceLimit   uint64
	LimitIsUpper bool
	Recipient    common.Address // where the D->C settlement must credit (object owner on return)
	Deadline     uint64         // order deadline (routing only)
	// Nonce is the taker's intent disambiguator, carried in the swap's DI01 hookData and
	// folded into DeriveIntentID. It makes the intent id CHAIN-OBSERVABLE (the off-chain
	// keeper derives the same id from the same calldata — the watch-correlation fix) and
	// distinguishes two otherwise-identical swaps. NOT value-bearing.
	Nonce uint64
}

// SubmitSwapIntent locks the taker's input on C and writes a C->D atomic intent
// object into shared memory. It returns the intentID (== the object's UTXO key);
// it does NOT match and does NOT return an output fill. The realized fill settles
// later through ImportSettlement once D matches and exports D->C.
//
// ORDERING (lock -> derive id -> replay-check -> export). The C value is debited into
// the 0x9999 escrow FIRST (real EVM SubBalance / observed-delta transferFrom); the
// object's amount equals the value ACTUALLY locked (observed delta for ERC-20), so D can
// never be funded beyond what C locked. The replay guard (isIntentSubmitted) is checked
// AFTER the lock, NOT before — this is deliberate and is NOT a CEI violation: the intent
// id IS the replay key, and it binds the observed-delta `locked` amount (DeriveIntentID
// takes `locked`, not the requested `AmountIn`), so the replay key is UNKNOWABLE until the
// lock has measured the real amount. Replay-safety is therefore provided by EVM REVERT
// ATOMICITY rather than check-ordering: a re-executed/reorged submit of the same intent
// recomputes the same id (the deterministic replay locks the same amount), hits
// isIntentSubmitted, and reverts — and the revert rolls back the lock in the SAME atomic
// step, so no double-debit ever persists. Deriving the id from the requested amount instead
// (to move the check earlier) would reintroduce the fee-on-transfer id divergence (the
// off-chain keeper and the chain would disagree on the id), so the observed-delta binding
// is the correct invariant and the post-lock replay check is its consequence.
func (c *NativeDChainClient) SubmitSwapIntent(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	req IntentRequest,
) (intentID ids.ID, err error) {
	sm := atomicState.AtomicMemory()
	if sm == nil {
		return ids.Empty, ErrNativeNoAtomicMemory
	}
	if req.AmountIn == 0 {
		return ids.Empty, ErrNativeBadAmount
	}
	stateDB := newPoolStateAdapter(state)

	// Lock the input into the 0x9999 escrow (the vault). This is the C-local debit
	// that BACKS the C->D object — D imports value C has already removed from the
	// caller, so no mint can occur on either side.
	locked, lockErr := lockIntentInput(stateDB, req.Account, req.AssetIn, req.AssetInAddr, req.AmountIn)
	if lockErr != nil {
		return ids.Empty, lockErr
	}

	// Derive the injective intent id (the shared-memory key) over the FULL identity.
	cChainID := atomicState.CChainID()
	// The D peer is the dexvm running as the primary network's D-Chain. The object is
	// keyed by intentID and PUT under the D chain's partition; the dexvm imports it
	// via Get(cChainID). The host resolves the D-Chain id at runtime from the chain
	// topology (consensus-context "D" alias) — always-on, zero per-net config; a
	// network with no dexvm yields ids.Empty and the seam stays closed (no mint).
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return ids.Empty, ErrNativeNoAtomicMemory
	}
	// CHAIN-OBSERVABLE id: derived from the taker's nonce (carried in the swap's own
	// calldata), NOT the post-landing txID — so the off-chain keeper derives the SAME id
	// from the SAME calldata and its watch correlates against the live chain. (The host's
	// per-tx CallIndex still scopes other precompiles; the swap id no longer needs it
	// because the user-supplied nonce disambiguates repeats and multi-swap-per-tx.)
	intentID = DeriveIntentID(
		atomicState.NetworkID(), cChainID, dChainID,
		req.Account, req.AssetIn, locked, req.MarketID, req.Nonce,
	)

	// Replay guard: the same intent id must not be submitted twice (a re-executed /
	// reorged C tx). Durable, consensus-shared (StateDB), CEI before the export.
	if isIntentSubmitted(stateDB, intentID) {
		return ids.Empty, ErrNativeIntentReplay
	}
	markIntentSubmitted(stateDB, intentID, state.GetBlockContext().Number().Uint64())

	// PERSIST the per-intent escrow record (the swap-rail analog of the LP RestingOrder).
	// It carries the owner (settlement authority + reclaim payee), the locked asset, the
	// remaining locked principal (== locked at submission), and the deadline. It is the
	// SINGLE record both ImportSettlement (per-taker cap) and ReclaimIntent (deadline
	// refund) consult — so a settlement is bounded by THIS taker's own principal and a
	// stranded intent is reclaimable to THIS taker after the deadline. owner==account is
	// the recorded D->C object owner D will mirror on the settlement object, so the
	// settlement's recorded-owner bind and this record's owner agree.
	// PriceLimit/LimitIsUpper are the taker's OWN slippage floor (from their V4
	// SqrtPriceLimitX96 via priceLimitToCLOB). Recording them HERE — at submit, bound to
	// the taker's authenticated intent — is what makes the Phase-B floor TAKER-authenticated
	// rather than keeper-asserted: ImportSettlement checks the realized proceeds price against
	// THIS recorded limit, so a malicious keeper that drops the relay limit cannot sandwich
	// the taker (the proceeds object whose price violates the recorded limit is refused). 0 =
	// no limit (preserves the unbounded behavior for a taker who set none).
	putSwapIntentRecord(stateDB, intentID, swapIntentRecord{
		Owner:        req.Account,
		AssetIn:      req.AssetIn,
		Remaining:    locked,
		Deadline:     req.Deadline,
		Status:       swapIntentOpen,
		PriceLimit:   req.PriceLimit,
		LimitIsUpper: req.LimitIsUpper,
	})

	// STAGE the C->D atomic object (rail=railSwap, owner=account, asset=assetIn,
	// amount=locked), keyed by intentID under the D chain's partition. We do NOT Apply
	// to shared memory here — a direct Apply commits OUTSIDE the EVM revert scope, so a
	// tx that reverts after this would leave a C->D object with no backing C debit (the
	// lock rolled back) => D funded without a C lock = MINT. Staging into StateDB is
	// revert-aware: a reverted tx discards the staged Put atomically with its rolled-
	// back lock. The host flushes staged Puts to shared memory at BLOCK ACCEPT, the
	// single cross-domain commit point. (See native_staging.go.) The railSwap tag makes
	// the swap's D->C settlement object (which D will export on this lane) consumable
	// ONLY by ImportSettlement.
	obj := encodeAtomicObject(railSwap, req.Account, req.AssetIn, locked)
	stageAtomicPut(stateDB, dChainID, intentID, obj)

	// Emit the routing metadata for the keeper that builds the D order. The staged
	// object backs the value; this only tells the keeper how to route it.
	emitNativeIntentEvent(stateDB, intentID, dChainID, req, locked)
	return intentID, nil
}

// SubmitPositionCommit is the C->D LP-COMMIT leg (intent kind DL01): it moves an
// LP's funds OUT of CSpendable and INTO the DCommitted state, and writes a C->D
// position-commit atomic object D imports to open a FUNDED position. It is the LP
// rail's analog of SubmitSwapIntent, on its OWN orthogonal pot (committedPositions)
// and its OWN id space (DerivePositionCommitID, positionCommitDomain) — so an LP
// commit can never be confused with a taker intent.
//
// THE NEVER-BOTH MOVE (CEI + conservation): the LP's C value is debited FIRST — real
// SubBalance / observed-delta transferFrom from the caller's CSpendable balance into
// the 0x9999 vault, recorded as committedPositions[asset] += locked — so the unit
// LEAVES the caller's spendable balance and becomes committed backing in one atomic
// step (never both spendable and committed). Then the C->D commit object (owner,
// assetIn, locked) is STAGED keyed by the position-commit id; at block accept the
// host flushes it to shared memory and D's executeImport consumes it to open the
// funded position. D is funded ONLY by consuming this object.
func (c *NativeDChainClient) SubmitPositionCommit(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	req IntentRequest,
) (positionID ids.ID, locked uint64, err error) {
	sm := atomicState.AtomicMemory()
	if sm == nil {
		return ids.Empty, 0, ErrNativeNoAtomicMemory
	}
	if req.AmountIn == 0 {
		return ids.Empty, 0, ErrNativeBadAmount
	}
	stateDB := newPoolStateAdapter(state)

	// Lock the LP principal into the COMMITTED-POSITIONS pot (the LP rail's own pot),
	// NOT the swap-rail seam reserve and NOT a depositor claim. This is the C-side
	// debit that BACKS the C->D commit object: D imports value C has already removed
	// from the caller's spendable balance, so no mint can occur on either side. locked
	// is the value ACTUALLY committed (observed delta for ERC-20) — the authoritative
	// amount the pot, the object, and the record all use, so none can overstate.
	locked, lockErr := commitPositionInput(stateDB, req.Account, req.AssetIn, req.AssetInAddr, req.AmountIn)
	if lockErr != nil {
		return ids.Empty, 0, lockErr
	}

	// Derive the injective position-commit id (the shared-memory key) over the FULL
	// identity, in the position-commit domain (disjoint from swap-intent ids).
	cChainID := atomicState.CChainID()
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return ids.Empty, 0, ErrNativeNoAtomicMemory
	}
	positionID = DerivePositionCommitID(
		atomicState.NetworkID(), cChainID, dChainID,
		atomicState.TxID(), atomicState.CallIndex(),
		req.Account, req.AssetIn, locked, req.MarketID,
	)

	// Replay guard: the same commit id must not be submitted twice (a re-executed /
	// reorged C tx). Durable, consensus-shared (StateDB), CEI before the export.
	if isIntentSubmitted(stateDB, positionID) {
		return ids.Empty, 0, ErrLPCommitReplay
	}
	markIntentSubmitted(stateDB, positionID, state.GetBlockContext().Number().Uint64())

	// STAGE the C->D commit object (rail=railLP, owner=account, asset=assetIn,
	// amount=locked) keyed by positionID under the D chain's partition (revert-aware —
	// discarded with the rolled-back lock if the tx reverts; flushed to shared memory
	// at block accept). The railLP tag makes the LP's D->C collect object (which D will
	// export on this lane via executeWithdraw) consumable ONLY by ImportPositionCollect.
	obj := encodeAtomicObject(railLP, req.Account, req.AssetIn, locked)
	stageAtomicPut(stateDB, dChainID, positionID, obj)

	// Emit the DL01 routing event (kind=position) for the keeper to OPEN the D
	// position against the committed collateral. The staged object backs the value.
	emitNativePositionCommitEvent(stateDB, positionID, dChainID, req, locked)
	return positionID, locked, nil
}

// SubmitModifyLiquidity is the on-ramp interface alias for an LP add: it routes to
// SubmitPositionCommit (the DL01 commit), returning the positionID. Kept so call
// sites that speak the modify-liquidity vocabulary reach the position rail.
func (c *NativeDChainClient) SubmitModifyLiquidity(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	req IntentRequest,
) (positionID ids.ID, err error) {
	positionID, _, err = c.SubmitPositionCommit(state, atomicState, req)
	return positionID, err
}

// ImportPositionCollect is the D->C LP-COLLECT/WITHDRAW leg: it consumes a D->C
// atomic object EXACTLY ONCE and credits C out of the COMMITTED-POSITIONS pot
// (DPendingCollect -> CSettled). It is the LP rail's analog of ImportSettlement, on
// the orthogonal committedPositions pot, with TWO additional gates that close H1-B
// and the per-owner blast radius:
//
//   - RAIL gate (H1-B): the recorded object's wire rail MUST be railLP. A swap-fill
//     D->C object (railSwap) is rejected here BEFORE any pot is touched, so a taker
//     holding a position can no longer route their swap-fill object through collect
//     to drain committedPositions. (This REPLACES the prior per-owner-ANY-position
//     gate, which armed permanently once an owner held one open position.)
//   - PER-OBJECT / PER-OWNER bound (FIX-1/FIX-2): the claim names a SPECIFIC position
//     record (claim.PositionID) the recorded owner must hold (Open/Closing), and the
//     credit is bounded by that record's remaining committed backing (LockedAmt) AND
//     decrements the owner's per-asset committed reserve. So an over-export for owner
//     X can never draw on owner Y's committed principal in the shared pot — the C leg
//     is bounded by X's OWN recorded commitment, independent of what D exports.
//
// The discipline otherwise mirrors ImportSettlement (CEI, one-time, recorded-value
// authoritative):
//
//  1. read the RECORDED object (Get under the D source chain); missing => revert.
//  2. RAIL gate: recorded rail == railLP (cross-rail object refused).
//  3. BIND asset == claimed, owner == recipient, amount == claimed (recorded value
//     authoritative — a claim cannot consume a victim's object or re-denominate it).
//  4. REPLAY guard: reject an already-consumed object id (shared D->C consumed set —
//     one object, one credit, globally, across the swap and LP rails). BEFORE the
//     per-object gate so a re-consume is always a replay, not a stale-backing reject.
//  5. PER-OBJECT/OWNER gate: the named position record exists, is owned by the
//     recorded owner, is Open/Closing, and recAmount <= its remaining LockedAmt.
//  6. MARK consumed (CEI) BEFORE moving value.
//  7. CREDIT C from committedPositions (NO MINT, NO RAID — the LP pot must back it).
//  8. DRIVE the record lifecycle: decrement LockedAmt + the owner's committed reserve
//     by the credited amount; Closed (terminal) when the record's LockedAmt hits 0.
//  9. STAGE the atomic Remove of the consumed object (flushed at block accept).
func (c *NativeDChainClient) ImportPositionCollect(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	claim SettlementClaim,
) (credited uint64, err error) {
	sm := atomicState.AtomicMemory()
	if sm == nil {
		return 0, ErrNativeNoAtomicMemory
	}
	stateDB := newPoolStateAdapter(state)

	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return 0, ErrNativeNoAtomicMemory
	}

	// (1) Read the RECORDED object. A missing object => never credit.
	key := claim.OutputID
	vals, gerr := sm.Get(dChainID, [][]byte{key[:]})
	if gerr != nil || len(vals) != 1 || len(vals[0]) == 0 {
		return 0, ErrNativeNoSettlement
	}
	recRail, recOwner, recAsset, recAmount, _, ok := decodeAtomicObject(vals[0])
	if !ok {
		return 0, ErrNativeSettleMalformed
	}

	// (2) RAIL gate (H1-B): consume ONLY railLP objects. A swap-fill object (railSwap)
	// is refused here — it can never reach the committedPositions pot.
	if recRail != railLP {
		return 0, ErrLPCollectWrongRail
	}

	// (3) BIND the credit to the RECORDED value (authoritative, not declared).
	if recAsset != claim.Asset {
		return 0, ErrNativeSettleAsset
	}
	if recOwner != claim.Recipient {
		return 0, ErrNativeSettleOwner
	}
	if recAmount != claim.Amount || recAmount == 0 {
		return 0, ErrNativeSettleAmount
	}

	// (4) REPLAY guard: one-time consumption across ALL D->C objects (shared set).
	// Checked BEFORE the per-object gate so re-consuming an already-spent object is
	// always caught as a replay — independent of the position's (now-decremented)
	// remaining backing.
	if isSettlementConsumed(stateDB, claim.OutputID) {
		return 0, ErrNativeSettleReplay
	}

	// (5) PER-OBJECT / PER-OWNER gate: bind the credit to the SPECIFIC position record
	// the claim names, owned by the recorded owner and still Open/Closing, and bound by
	// that record's OWN remaining committed backing. This is what stops an over-export
	// for owner X from drawing on owner Y's committed principal in the shared pot.
	order := loadRestingOrder(stateDB, claim.PositionID)
	if order.Status != OrderStatusOpen && order.Status != OrderStatusClosing {
		return 0, ErrLPCollectNoPosition
	}
	if order.Owner != recOwner {
		return 0, ErrLPCollectNoPosition
	}
	if order.LockedAmt == nil || order.LockedAmt.Cmp(new(big.Int).SetUint64(recAmount)) < 0 {
		return 0, ErrLPCollectExceedsPosition
	}

	// (6) MARK consumed BEFORE value movement (CEI; a failed credit rolls this back).
	markSettlementConsumed(stateDB, claim.OutputID, state.GetBlockContext().Number().Uint64())

	// (7) CREDIT C from the COMMITTED-POSITIONS pot — NO MINT, NO RAID. The transfer
	// token is derived from the RECORDED asset inside creditPositionCollect (FIX-5), so
	// the claim's AssetAddr cannot redirect the credit to a different token.
	if cerr := creditPositionCollect(stateDB, recOwner, recAsset, recAmount); cerr != nil {
		return 0, cerr
	}

	// (8) DRIVE the position lifecycle (FIX-3): the collected amount LEAVES the record's
	// committed backing AND the owner's per-asset committed reserve. When the record's
	// LockedAmt reaches 0 the position is fully collected -> Closed (terminal). A
	// partially-collected position stays Open/Closing (still collectable).
	collectPositionRecord(stateDB, claim.PositionID, order, recAsset, recAmount)

	// (9) STAGE the atomic Remove of the consumed object (revert-aware; flushed at
	// block accept atomically with the committed credit).
	stageAtomicRemove(stateDB, dChainID, key)
	return recAmount, nil
}

// collectPositionRecord applies a collect to the named position record and the
// owner's per-asset committed reserve: it subtracts the credited amount from the
// record's LockedAmt and from loadLockedReserve(owner,asset), and marks the record
// Closed (OrderStatusCancelled, the terminal "Closed" state in the None/Open/Closed
// lifecycle) once its LockedAmt reaches 0. The amount is already proven <= LockedAmt
// (the per-object gate), so neither subtraction underflows. This is the lifecycle
// half of FIX-1/2/3: a fully-collected position no longer satisfies the Open/Closing
// gate, so its object lane can never be reused, and the per-owner reserve stays the
// exact bound on what that owner can still pull.
func collectPositionRecord(stateDB stateKV, orderID [32]byte, order RestingOrder, asset [32]byte, amount uint64) {
	amt := new(big.Int).SetUint64(amount)
	order.LockedAmt = new(big.Int).Sub(order.LockedAmt, amt)
	if order.LockedAmt.Sign() == 0 {
		order.Status = OrderStatusCancelled // == Closed (terminal): fully collected.
	}
	storeRestingOrder(stateDB, orderID, order)

	// Decrement the owner's per-asset committed reserve (the defense-in-depth
	// accumulator) by the same amount — it stays == Σ the owner's live records'
	// LockedAmt, the per-owner bound D cannot exceed.
	reserve := loadLockedReserve(stateDB, order.Owner, asset)
	if reserve.Cmp(amt) < 0 {
		reserve = amt // never negative (defense in depth; the per-object gate bounds it).
	}
	storeLockedReserve(stateDB, order.Owner, asset, new(big.Int).Sub(reserve, amt))
}

// The cancel/collect KEEPER-ROUTING notifications are emitted DIRECTLY at their
// lifecycle sites — requestPositionWithdraw (position_commit.go) emits
// emitNativeCancelEvent on a REMOVE, and the position collect path emits
// emitNativeCollectEvent — so there is no standalone Submit{Cancel,Collect} client
// method (it had no production caller; the swap reclaim is the reclaimIntent selector,
// and the LP withdraw/collect is the collectPosition selector). One way to request
// each lifecycle op, at its own site — no redundant client wrapper.

// --- Settlement import (D->C): the ONLY path that credits C. -------------------

// SettlementClaim is what a settling C tx declares it wants to import. EVERY field
// is BOUND to the RECORDED D->C object — a mismatch reverts. The claim cannot
// invent value: it only names which committed object to consume and the recipient
// it must already credit.
type SettlementClaim struct {
	OutputID  ids.ID         // the D->C object's shared-memory UTXO key (sourceTxID|outputIndex-derived on D)
	Asset     [32]byte       // claimed output asset — MUST equal the recorded asset
	AssetAddr common.Address // ERC-20 token for the credit (address(0) for native) — IGNORED for the transfer token, which is derived from the recorded asset (FIX-5)
	Amount    uint64         // claimed output amount — MUST equal the recorded amount
	Recipient common.Address // claimed owner — MUST equal the recorded owner
	// PositionID is the LP-rail-only binding: the position RECORD id (MakerOrderID)
	// the collect draws against. ImportPositionCollect requires the recorded owner to
	// hold THIS specific position (Open/Closing) and bounds the credit by that
	// record's remaining committed backing — the per-object, per-owner gate (FIX-1/2).
	// The swap rail (ImportSettlement) leaves it zero; it consults no position record.
	PositionID [32]byte
	// IntentID is the SWAP-rail-only binding: the originating C->D intent id this
	// settlement draws against. ImportSettlement requires the recorded owner to hold
	// THIS specific Open intent and bounds the credit by that intent's remaining locked
	// principal (the per-taker cap, the swap-rail analog of the LP per-position bound),
	// and refuses a settlement past the intent's deadline. The LP rail leaves it zero.
	IntentID [32]byte
}

// ImportSettlement consumes a D->C atomic object EXACTLY ONCE and credits C. This
// is the sole C-credit path. The discipline mirrors the dexvm executeImport
// byte-for-byte (the symmetric leg):
//
//  1. read the RECORDED object from shared memory (Get under the D source chain);
//     a missing object reverts (never credit an unbacked claim).
//  2. BIND the credit to the RECORDED value — asset == claimed, owner == recipient,
//     amount == claimed — so a tx cannot consume a victim's object or re-denominate
//     it (the asset/owner-aliasing fix).
//  3. REPLAY guard: reject an already-consumed object id (one-time settlement).
//  4. MARK consumed (CEI, StateDB) BEFORE moving value.
//  5. CREDIT C from the 0x9999 vault (no mint — vault must back it).
//  6. APPLY the atomic Remove of the object under the D source chain, committing
//     the consumption with the EVM block.
//
// A "live matcher answer" cannot drive this: there is no parameter for a fill
// value; the credit is the RECORDED object's amount, and without a real object in
// shared memory step 1 reverts.
func (c *NativeDChainClient) ImportSettlement(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	claim SettlementClaim,
) (credited uint64, err error) {
	sm := atomicState.AtomicMemory()
	if sm == nil {
		return 0, ErrNativeNoAtomicMemory
	}
	stateDB := newPoolStateAdapter(state)

	// The D->C objects are written by the dexvm under the D chain's export, keyed by
	// the C chain partition; C reads them via Get(dChainID, key). Resolve the D
	// source chain (the object's origin) from the runtime chain topology.
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		// No dexvm on this network => no source chain to read from — the on-ramp is
		// not wired for atomic settlement.
		return 0, ErrNativeNoAtomicMemory
	}

	// (1) Read the RECORDED object. A missing object => never credit.
	key := claim.OutputID
	vals, gerr := sm.Get(dChainID, [][]byte{key[:]})
	if gerr != nil || len(vals) != 1 || len(vals[0]) == 0 {
		return 0, ErrNativeNoSettlement
	}
	recRail, recOwner, recAsset, recAmount, recSpent, ok := decodeAtomicObject(vals[0])
	if !ok {
		return 0, ErrNativeSettleMalformed
	}

	// (2) RAIL gate (H1-A): consume ONLY railSwap objects. An LP-collect object
	// (railLP) is refused here — it can never reach the swap rail's seamReserve pot,
	// so an LP cannot route their collect object through swap-settlement to drain the
	// swap pot and strand real swap settlements.
	if recRail != railSwap {
		return 0, ErrSettleWrongRail
	}

	// (3) BIND the credit to the RECORDED value (authoritative, not declared).
	if recAsset != claim.Asset {
		return 0, ErrNativeSettleAsset
	}
	if recOwner != claim.Recipient {
		return 0, ErrNativeSettleOwner
	}
	if recAmount != claim.Amount {
		return 0, ErrNativeSettleAmount
	}
	if recAmount == 0 {
		return 0, ErrNativeSettleAmount
	}

	// (4) REPLAY guard: one-time settlement, durable + consensus-shared.
	if isSettlementConsumed(stateDB, claim.OutputID) {
		return 0, ErrNativeSettleReplay
	}

	// (5) PER-INTENT / PER-TAKER gate (MEDIUM — the swap-rail analog of the LP per-
	// position bound). BIND the settlement to a SPECIFIC intent record the recorded owner
	// holds (Open), not past its deadline — so a credit can never float free of the
	// taker's own intent (no phantom settlement), and a late settlement is refused.
	intent := loadSwapIntentRecord(stateDB, claim.IntentID)
	if intent.Status != swapIntentOpen {
		return 0, ErrSettleNoIntent
	}
	if intent.Owner != recOwner {
		return 0, ErrSettleNoIntent
	}
	if intent.Deadline != 0 && state.GetBlockContext().Timestamp() > intent.Deadline {
		return 0, ErrSettlePastDeadline
	}
	// The PER-TAKER PRINCIPAL CAP is the EXACT LP-rail analog: it bounds a SAME-ASSET
	// return by the taker's OWN remaining locked principal. The LP collects the same
	// asset it committed; the swap's same-asset return is the REFUND of unfilled tokenIn
	// (recAsset == intent.AssetIn). For that leg, recAmount must not exceed the intent's
	// remaining locked principal — so an over-refund for taker X can never draw on OTHER
	// takers' pooled tokenIn of the input asset — and the credit decrements remaining.
	//
	// The PROCEEDS leg (recAsset != intent.AssetIn — the OPPOSITE asset the taker
	// receives) is NOT bounded by the input-asset principal: that is a different
	// dimension (output units legitimately differ from input units at any price != 1, so
	// an input-unit cap would wrongly refuse honest proceeds). Its no-mint protection is
	// the seamReserve backing (creditSettlementOutput) + one-time consumption + this
	// intent binding; WHICH fill amount occurred is D's matching authority (C never
	// matches), bounded to the documented single-venue proposer-trust surface.
	if recAsset == intent.AssetIn {
		if recAmount > intent.Remaining {
			return 0, ErrSettleExceedsIntent
		}
	}

	// (5b) TAKER-AUTHENTICATED MEV FLOOR (the swap-rail sandwich fix). On the PROCEEDS leg
	// (recAsset != intent.AssetIn — the OPPOSITE asset the taker receives), enforce the
	// taker's OWN recorded slippage limit against the REALIZED fill price, drawn from the
	// venue-attested witness (recSpent = matched input, recAmount = output). The binding
	// authority is intent.PriceLimit — recorded at SubmitSwapIntent from the taker's V4
	// SqrtPriceLimitX96 — NOT the keeper-relayed RelayOrderTx.PriceLimit. So a keeper that
	// zeroes the relay limit to let a sandwiched fill through (the dexvm settle path would
	// impose no D-side floor) STILL produces a proceeds object whose realized price C refuses
	// here: the taker is protected by their own intent, independent of the keeper.
	//
	// Why the proceeds leg only: the same-asset refund (recAsset == intent.AssetIn) is the
	// taker's unfilled principal coming back at par — no price is realized, so no floor
	// applies (it is bounded by the per-taker cap above). The floor binds exactly where a
	// price is realized: input converted to output.
	if recAsset != intent.AssetIn {
		if perr := enforceProceedsPriceFloor(intent.PriceLimit, intent.LimitIsUpper, recSpent, recAmount); perr != nil {
			return 0, perr
		}
	}

	// (6) MARK consumed BEFORE value movement (CEI for the replay slot). A failed
	// credit still leaves it unconsumed because the EVM revert rolls back this write.
	markSettlementConsumed(stateDB, claim.OutputID, state.GetBlockContext().Number().Uint64())

	// (7) CREDIT C from the vault — NO MINT (the vault must already hold the output;
	// it was funded by the tokenIn legs of prior intents and operator seeding). The
	// transfer token is derived from the RECORDED asset inside creditSettlementOutput
	// (FIX-5), so the claim's AssetAddr cannot redirect the credit to a different token.
	if cerr := creditSettlementOutput(stateDB, recOwner, recAsset, recAmount); cerr != nil {
		return 0, cerr
	}

	// (8) DECREMENT the intent's remaining locked principal ONLY for a same-asset refund
	// (the per-taker cap's accounting; recAmount <= remaining was proven above, so this
	// never underflows). A proceeds credit (different asset) does not touch the input
	// principal. The terminal Reclaimed state is reached only via ReclaimIntent.
	if recAsset == intent.AssetIn {
		intent.Remaining -= recAmount
		putSwapIntentRecord(stateDB, claim.IntentID, intent)
	}

	// (9) STAGE the atomic Remove of the consumed object under the D source chain. As
	// with the C->D Put, we do NOT Apply here: a direct Apply commits outside the EVM
	// revert scope, so a tx reverting after this would consume (remove) the D->C
	// object while the C credit + consumed-mark rolled back => the object is gone and
	// C was never credited = value LOSS. Staging is revert-aware; the host flushes the
	// Remove to shared memory at BLOCK ACCEPT atomically with the committed credit.
	stageAtomicRemove(stateDB, dChainID, key)
	return recAmount, nil
}

// enforceProceedsPriceFloor is the TAKER-AUTHENTICATED MEV floor: it refuses a swap
// PROCEEDS settlement whose realized fill price is worse than the limit the TAKER
// recorded at submit (priceLimit, limitIsUpper) — independent of any keeper-relayed
// limit. It is a PURE function of the recorded limit and the venue-attested witness
// (spent = matched input, out = proceeds output), so calling it before any state write
// preserves ImportSettlement's CEI ordering.
//
// PRICE DOMAIN. priceLimit is quote-per-base (currency1 per currency0) as IEEE-754
// float64 bits — the SAME CLOB price domain the dexvm matcher uses (Fill.Price) and the
// SAME value priceLimitToCLOB produced from the taker's V4 SqrtPriceLimitX96. The realized
// price is reconstructed in that domain from the integer witness:
//
//   - SELL (limitIsUpper == false; zeroForOne: base in -> quote out): spent = base in,
//     out = quote out, so realized quote/base = out/spent. The taker must receive AT LEAST
//     the limit per base — a FLOOR. Reject realized < limit.
//   - BUY  (limitIsUpper == true; !zeroForOne: quote in -> base out): spent = quote in,
//     out = base out, so realized quote/base = spent/out. The taker must pay AT MOST the
//     limit per base — a CEILING. Reject realized > limit.
//
// EDGE CASES (fail-secure):
//   - priceLimit == 0: the taker set no limit (or a V4 sentinel) — impose no floor, exactly
//     as priceLimitToCLOB's 0 = unbounded. The pre-existing behavior for limitless swaps.
//   - spent == 0 or out == 0 with a limit SET: the realized price is undefined (0 or
//     infinite). A proceeds leg under a real limit MUST carry both sides; absent them the
//     price is unprovable, so REJECT rather than credit an unverifiable fill. (D's
//     settleFromFills always sets spent > 0 on a proceeds export; a zero here is a malformed
//     or hostile object and the floor refuses it.)
//
// To avoid float division (and its divide-by-zero / rounding pitfalls) the comparison is
// cross-multiplied: out/spent >= limit  <=>  out >= limit*spent (SELL), and spent/out <=
// limit  <=>  spent <= limit*out (BUY). Both sides are non-negative float64 (the matcher's
// own domain), so this neither tightens nor loosens the floor relative to D.
//
// PROPOSER vs KEEPER. A hostile proposer UNDERSTATING spent would inflate the realized price
// (loosening this floor), but that same understatement inflates the refund and is
// independently bounded by the per-taker principal cap + seam-reserve conservation — the
// documented single-venue proposer-trust surface the fill attestation (the HIGH) covers.
// This floor's job is the KEEPER vector (a relay that drops the limit), against which it is
// sound: the keeper cannot touch the venue-signed spent/out witness.
func enforceProceedsPriceFloor(priceLimit uint64, limitIsUpper bool, spent, out uint64) error {
	if priceLimit == 0 {
		return nil // taker set no limit — unbounded, as recorded.
	}
	if spent == 0 || out == 0 {
		return ErrSettlePriceLimit // limit set but price unprovable — fail secure.
	}
	limit := math.Float64frombits(priceLimit)
	if !(limit > 0) || math.IsInf(limit, 0) || math.IsNaN(limit) {
		return nil // a degenerate recorded limit imposes nothing (mirrors priceLimitToCLOB).
	}
	spentF := float64(spent)
	outF := float64(out)
	if limitIsUpper {
		// BUY ceiling: realized quote/base = spent/out must not EXCEED the limit.
		if spentF > limit*outF {
			return ErrSettlePriceLimit
		}
		return nil
	}
	// SELL floor: realized quote/base = out/spent must not fall BELOW the limit.
	if outF < limit*spentF {
		return ErrSettlePriceLimit
	}
	return nil
}

// ReclaimIntent is the HIGH liveness fix: it lets the original locker reclaim a swap
// intent's remaining locked principal once the intent's deadline has passed and D has
// not settled it. Without this, a locked tokenIn whose intent D never settles (a
// dropped keeper, an unmatched order, a halted D) is STRANDED forever in seamReserve
// with no exit — settle_module's "funds can always exit" guarantee held for
// deposit/withdraw but not for swaps. This closes that gap symmetrically to the LP
// rail's collect path.
//
// DISCIPLINE (one-time, deadline-gated, conservation-preserving, fail-secure):
//
//  1. require the intent exists and is Open for the CALLER (the locker) — only the
//     locker may reclaim, and the refund goes only to them.
//  2. require the intent carried a deadline and the block timestamp is PAST it — before
//     the deadline a settlement may still legitimately land, so reclaim is refused
//     (settlement and reclaim are mutually exclusive by the deadline boundary).
//  3. require remaining principal > 0 (a fully-settled intent has nothing to refund).
//  4. REPLAY guard: reject an already-reclaimed intent (durable, consensus-shared).
//  5. MARK reclaimed + zero the remaining principal + set Status=Reclaimed BEFORE value
//     movement (CEI). The zeroed remaining makes any later settlement naming this intent
//     fail the per-taker cap (capped to 0) — so reclaim and a late settlement can never
//     BOTH pay out (conservation: the principal exits exactly once).
//  6. REFUND the remaining principal of the LOCKED asset from seamReserve to the locker
//     (creditSettlementOutput: NO MINT — the seam's own pot must back it; it does,
//     because the lock at SubmitSwapIntent added exactly this to seamReserve and no
//     settlement drew it down past `remaining`).
//  7. STAGE a compensating C->D Remove of the ORIGINAL intent object (keyed by intentID)
//     so a dexvm that has NOT yet imported the C->D object can never later fund a D order
//     from a reclaimed intent (double-fund). If D already imported it, the Remove is a
//     no-op on a missing key; the now-zero remaining still prevents a double payout.
func (c *NativeDChainClient) ReclaimIntent(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	caller common.Address,
	intentID ids.ID,
) (refunded uint64, err error) {
	sm := atomicState.AtomicMemory()
	if sm == nil {
		return 0, ErrNativeNoAtomicMemory
	}
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return 0, ErrNativeNoAtomicMemory
	}
	stateDB := newPoolStateAdapter(state)

	// (1) The intent must exist, be Open, and belong to the caller (the locker).
	intent := loadSwapIntentRecord(stateDB, intentID)
	if intent.Status != swapIntentOpen {
		return 0, ErrReclaimNoIntent
	}
	if intent.Owner != caller {
		return 0, ErrReclaimNotOwner
	}

	// (2) Deadline must exist and be PAST. Before it, a settlement may still land.
	if intent.Deadline == 0 {
		return 0, ErrReclaimNoDeadline
	}
	if state.GetBlockContext().Timestamp() <= intent.Deadline {
		return 0, ErrReclaimBeforeDeadline
	}

	// (3) Something must remain to refund (a fully-settled intent refunds nothing).
	if intent.Remaining == 0 {
		return 0, ErrReclaimNothingLocked
	}

	// (4) REPLAY guard: one-time reclaim (durable, consensus-shared). The record's
	// terminal Status is authoritative; this is the explicit single-claim slot.
	if isSwapIntentReclaimed(stateDB, intentID) {
		return 0, ErrReclaimReplay
	}

	// (5) MARK reclaimed + zero remaining + terminal status BEFORE value movement (CEI).
	// The zeroed remaining is what makes a late settlement naming this intent fail the
	// per-taker cap, so the principal can never be paid out twice.
	refunded = intent.Remaining
	blockNumber := state.GetBlockContext().Number().Uint64()
	markSwapIntentReclaimed(stateDB, intentID, blockNumber)
	intent.Remaining = 0
	intent.Status = swapIntentReclaimed
	putSwapIntentRecord(stateDB, intentID, intent)

	// (6) REFUND the locked principal of the LOCKED asset from seamReserve — NO MINT.
	// creditSettlementOutput draws ONLY seamReserve[assetIn] (the swap rail's own pot),
	// the exact pot SubmitSwapIntent credited, so the refund can never raid a depositor
	// or LP pot. The transfer token is derived from the recorded asset inside it (FIX-5).
	if cerr := creditSettlementOutput(stateDB, intent.Owner, intent.AssetIn, refunded); cerr != nil {
		return 0, cerr
	}

	// (7) STAGE a compensating C->D Remove of the original intent object so a dexvm that
	// has not yet imported it cannot later fund a D order from a reclaimed intent.
	stageAtomicRemove(stateDB, dChainID, intentID)

	emitNativeReclaimEvent(stateDB, intentID, intent.Owner, intent.AssetIn, refunded)
	return refunded, nil
}

// --- DChainClient interface conformance (the on-ramp seam). --------------------
//
// The narrow DChainClient methods (context-only) are the migration surface; the
// native value-moving work needs the host capabilities (StateDB + AtomicState)
// the V4 handler holds, so those are the methods above. The interface methods here
// keep the seam satisfiable for code paths that hold only a context — they refuse
// rather than move value without the host capabilities (fail-secure).

var _ Engine = (*NativeDChainClient)(nil)

// Initialize / Swap / ModifyLiquidity / Donate / Quote: the Engine surface the
// PoolManager calls. The native seam routes value through the 0x9999 handler
// (SettleSwap) using the methods above, NOT through a synchronous Engine.Swap
// (which forks). So the Engine methods here are the closed-on-ramp refusal: a node
// must use the 0x9999 native settle path, not the deprecated synchronous surface.
func (c *NativeDChainClient) Initialize(_ *big.Int) (int24, error) {
	return 0, ErrDChainUnavailable
}

func (c *NativeDChainClient) Swap(_ *PoolState, _ common.Address, _ SwapParams) (BalanceDelta, error) {
	// A synchronous in-block fill via a live query forks consensus (the whole reason
	// for the async atomic model). The native path is SettleSwap's two-phase intent/
	// settlement; this synchronous surface is never the value path.
	return ZeroBalanceDelta(), ErrDChainUnavailable
}

func (c *NativeDChainClient) ModifyLiquidity(_ *PoolState, _ common.Address, _ ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	return ZeroBalanceDelta(), ZeroBalanceDelta(), ErrDChainUnavailable
}

func (c *NativeDChainClient) Donate(_ *PoolState, _, _ *big.Int) (BalanceDelta, error) {
	return ZeroBalanceDelta(), ErrDChainUnavailable
}

func (c *NativeDChainClient) Quote(_ *Pool, _ *big.Int, _ bool) *big.Int {
	return big.NewInt(0)
}

// --- C-side value movement helpers (escrow lock / settlement credit). ----------

// lockIntentInput debits amount of the input asset from the caller into the 0x9999
// escrow vault, returning the value ACTUALLY locked (observed delta for ERC-20).
// Native moves via SubBalance(caller)/AddBalance(0x9999) with an observed-delta
// pre/post check; ERC-20 via the vault transferFrom observed delta. The locked
// value backs the C->D object's amount.
func lockIntentInput(stateDB StateDB, caller common.Address, assetID [32]byte, assetAddr common.Address, amount uint64) (uint64, error) {
	amt := new(big.Int).SetUint64(amount)
	if isNativeAsset(assetID) {
		u, of := uint256.FromBig(amt)
		if of {
			return 0, ErrNativeBadAmount
		}
		if stateDB.GetBalance(caller).Cmp(u) < 0 {
			return 0, ErrNativeFundsShort
		}
		// Lock the tokenIn into the SEAM RESERVE (the seam's own pot), not the depositor
		// pot. seamReserve[native] tracks the seam's slice of the vault's real native
		// balance; the other slices (settleVault depositor pot + makerLockedVault) are
		// untouched, so this lock can never appear as a depositor's withdrawable claim.
		before := loadSeamReserve(stateDB, assetID)
		stateDB.SubBalance(caller, u)
		stateDB.AddBalance(poolManagerAddr9999, u)
		storeSeamReserve(stateDB, assetID, new(big.Int).Add(before, amt))
		return amount, nil
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return 0, ErrNativeERC20Vault
	}
	delta, err := safeTransferTokenFrom(vault, assetAddr, caller, poolManagerAddr9999, amt)
	if err != nil {
		return 0, err
	}
	// Track the seam's holding of this asset (the seam reserve) so a later settlement
	// credit can be conservation-checked against the SEAM's own backing — never the
	// depositor pot. Observed delta is the true arrival (fee-on-transfer safe).
	before := loadSeamReserve(stateDB, assetID)
	storeSeamReserve(stateDB, assetID, new(big.Int).Add(before, delta))
	if !delta.IsUint64() {
		return 0, ErrNativeBadAmount
	}
	return delta.Uint64(), nil
}

// creditSettlementOutput releases amount of the output asset from the SEAM RESERVE
// to the recipient — NO MINT (the seam's own pot must already hold it). The credit is
// conservation-checked against seamReserve[a], NOT the total vault: it can never pay a
// taker out of a depositor's claim (settleVault) or a maker's locked reserve
// (makerLockedVault). Native via SubBalance(0x9999)/AddBalance(recipient); ERC-20 via
// the vault transfer.
//
// FIX-5 (defense in depth): the ERC-20 transfer token is DERIVED from the recorded
// asset id (assetAddress(assetID)) INSIDE this function — it does NOT trust a token
// address the caller passes. assetID is the recorded D->C object's asset (the value
// the seam reserve is denominated in), and assetAddress is its injective inverse, so
// the token credited is provably the one the reserve was debited for; a caller can
// no longer name a different token to transfer than the asset it claims to settle.
func creditSettlementOutput(stateDB StateDB, recipient common.Address, assetID [32]byte, amount uint64) error {
	amt := new(big.Int).SetUint64(amount)
	held := loadSeamReserve(stateDB, assetID)
	if held.Cmp(amt) < 0 {
		// NO MINT, and NO RAID: the SEAM's own reserve must back the output. A short
		// seam reserve reverts even if the vault holds depositor/maker funds of this asset.
		return ErrNativeSettleUnbacked
	}
	storeSeamReserve(stateDB, assetID, new(big.Int).Sub(held, amt))
	if isNativeAsset(assetID) {
		u, of := uint256.FromBig(amt)
		if of {
			return ErrNativeBadAmount
		}
		// Underflow guard (defense in depth): SubBalance is uint256-modular from a
		// precompile; the vault holdings (checked above) should never exceed the real
		// balance, so this only fires on a regression — fail loud, never wrap.
		if stateDB.GetBalance(poolManagerAddr9999).Cmp(u) < 0 {
			return ErrNativeSettleUnbacked
		}
		stateDB.SubBalance(poolManagerAddr9999, u)
		stateDB.AddBalance(recipient, u)
		return nil
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return ErrNativeERC20Vault
	}
	return safeTransferTokenTo(vault, assetAddress(assetID), recipient, amt)
}

// --- LP-rail value movement (commit into committedPositions / collect out of it). --

// commitPositionInput debits amount of the LP's input asset from the caller's
// CSpendable balance into the 0x9999 vault, recording it in the COMMITTED-POSITIONS
// pot (the LP rail's own pot), and returns the value ACTUALLY committed (observed
// delta for ERC-20). Native moves via SubBalance(caller)/AddBalance(0x9999) with a
// balance pre-check; ERC-20 via the vault transferFrom observed delta. The committed
// value backs the C->D commit object's amount AND represents the DCommitted state
// (the unit left the caller's spendable balance). Byte-for-byte the same discipline
// as lockIntentInput, but on committedPositions instead of seamReserve — the
// orthogonal-pot rule (an LP commit can never appear in the swap rail's reserve).
func commitPositionInput(stateDB StateDB, caller common.Address, assetID [32]byte, assetAddr common.Address, amount uint64) (uint64, error) {
	amt := new(big.Int).SetUint64(amount)
	if isNativeAsset(assetID) {
		u, of := uint256.FromBig(amt)
		if of {
			return 0, ErrNativeBadAmount
		}
		if stateDB.GetBalance(caller).Cmp(u) < 0 {
			return 0, ErrNativeFundsShort
		}
		before := loadCommittedPositions(stateDB, assetID)
		stateDB.SubBalance(caller, u)
		stateDB.AddBalance(poolManagerAddr9999, u)
		storeCommittedPositions(stateDB, assetID, new(big.Int).Add(before, amt))
		return amount, nil
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return 0, ErrNativeERC20Vault
	}
	delta, err := safeTransferTokenFrom(vault, assetAddr, caller, poolManagerAddr9999, amt)
	if err != nil {
		return 0, err
	}
	before := loadCommittedPositions(stateDB, assetID)
	storeCommittedPositions(stateDB, assetID, new(big.Int).Add(before, delta))
	if !delta.IsUint64() {
		return 0, ErrNativeBadAmount
	}
	return delta.Uint64(), nil
}

// creditPositionCollect releases amount of the collected asset from the COMMITTED-
// POSITIONS pot to the LP — NO MINT (the LP pot must already hold it), NO RAID (the
// credit is conservation-checked against committedPositions[a], never the swap-rail
// seamReserve, the depositor settleVault, or the legacy makerLockedVault). This is
// the CSettled credit (the collected unit re-enters the LP's CSpendable balance).
// Native via SubBalance(0x9999)/AddBalance(recipient); ERC-20 via the vault transfer.
//
// FIX-5 (defense in depth): the ERC-20 transfer token is DERIVED from the recorded
// asset id (assetAddress(assetID)) INSIDE this function — same discipline as
// creditSettlementOutput; the caller cannot redirect the credit to a different token.
func creditPositionCollect(stateDB StateDB, recipient common.Address, assetID [32]byte, amount uint64) error {
	amt := new(big.Int).SetUint64(amount)
	held := loadCommittedPositions(stateDB, assetID)
	if held.Cmp(amt) < 0 {
		// NO MINT, NO RAID: the LP pot's own reserve must back the collect. A short
		// committed-positions pot reverts even if other pots hold this asset.
		return ErrLPCollectUnbacked
	}
	storeCommittedPositions(stateDB, assetID, new(big.Int).Sub(held, amt))
	if isNativeAsset(assetID) {
		u, of := uint256.FromBig(amt)
		if of {
			return ErrNativeBadAmount
		}
		if stateDB.GetBalance(poolManagerAddr9999).Cmp(u) < 0 {
			return ErrLPCollectUnbacked
		}
		stateDB.SubBalance(poolManagerAddr9999, u)
		stateDB.AddBalance(recipient, u)
		return nil
	}
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return ErrNativeERC20Vault
	}
	return safeTransferTokenTo(vault, assetAddress(assetID), recipient, amt)
}
