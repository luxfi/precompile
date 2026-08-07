// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

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
	// PriceLimit is the taker's worst-acceptable CLOB price (quote-per-base, uint64
	// FIXED-POINT ×priceScale on the PriceInt grid) derived from the V4 SqrtPriceLimitX96
	// (priceLimitToCLOB). LimitIsUpper says which side it bounds (true = a BUY ceiling,
	// false = a SELL floor). The keeper carries these onto the settling relay
	// (RelayOrderTx.PriceLimit/LimitIsUpper) and the dexvm settle path REFUSES a fill worse
	// than the limit — the bounded sandwich/MEV guard. Emitted in the routing event so the
	// keeper does not re-derive them. 0 = no limit.
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

	// The D peer is the dexvm running as the primary network's D-Chain. The object is
	// keyed by intentID and PUT under the D chain's partition; the dexvm imports it
	// via Get(cChainID). The host resolves the D-Chain id at runtime from the chain
	// topology (consensus-context "D" alias) — always-on, zero per-net config; a
	// network with no dexvm yields ids.Empty and the seam stays closed (no mint).
	cChainID := atomicState.CChainID()
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return ids.Empty, ErrNativeNoAtomicMemory
	}

	// NATIVE-ZAP two-phase id binding: the locked principal is the REQUESTED amount. The
	// terminal ERC-20 pull (lockAssetIn Phase B) asserts the vault receives at least this
	// much or REVERTS the whole frame, so `locked == req.AmountIn` is authoritative — there
	// is no post-transfer observed delta to diverge on, so the off-chain keeper derives the
	// SAME id from the SAME calldata. CHAIN-OBSERVABLE id: over the taker's nonce (in the
	// swap's own calldata), NOT the post-landing txID.
	locked := req.AmountIn
	intentID = DeriveIntentID(
		atomicState.NetworkID(), cChainID, dChainID,
		req.Account, req.AssetIn, locked, req.MarketID, req.Nonce,
	)

	// Lock the input into the 0x9999 escrow (the vault) — the C-local debit that BACKS the
	// C->D object so D imports value C has already removed (no mint on either side). PHASE A
	// (the record callback) writes EVERY 0x9999 state — replay mark, escrow record, staged
	// C->D object, routing event — BEFORE the terminal asset pull, so none of those writes
	// can be dropped by the geth nested-call host bug (the fund-loss this dissolves). The
	// transferFrom is the frame's LAST external effect; an ERC-20 under-delivery reverts the
	// whole frame, the Phase-A writes included (all-or-nothing).
	if _, lockErr := lockAssetIn(stateDB, req.Account, req.AssetIn, req.AssetInAddr, req.AmountIn, func() error {
		// Replay guard: the same intent id must not be submitted twice (a re-executed /
		// reorged C tx). Durable, consensus-shared (StateDB), CEI before the export.
		if isIntentSubmitted(stateDB, intentID) {
			return ErrNativeIntentReplay
		}
		markIntentSubmitted(stateDB, intentID, state.GetBlockContext().Number().Uint64())

		// PERSIST the per-intent escrow record (the swap-rail analog of the LP RestingOrder):
		// owner (settlement authority + reclaim payee), locked asset, remaining principal
		// (== locked at submission), deadline. It is the SINGLE record both ImportSettlement
		// (per-taker cap) and ReclaimIntent (deadline refund) consult. PriceLimit/LimitIsUpper
		// are the taker's OWN slippage floor (from their V4 SqrtPriceLimitX96 via
		// priceLimitToCLOB), recorded HERE so the Phase-B floor is TAKER-authenticated, not
		// keeper-asserted. 0 = no limit (unbounded, as the taker set).
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
		// amount=locked) keyed by intentID under the D chain's partition. We do NOT Apply to
		// shared memory here — a direct Apply commits OUTSIDE the EVM revert scope, so a tx
		// that reverts after this would leave a C->D object with no backing C debit => MINT.
		// Staging into StateDB is revert-aware (discarded atomically with a rolled-back lock);
		// the host flushes staged Puts at BLOCK ACCEPT. The railSwap tag makes the swap's D->C
		// settlement object consumable ONLY by ImportSettlement.
		obj := encodeAtomicObject(railSwap, req.Account, req.AssetIn, locked)
		stageAtomicPut(stateDB, dChainID, intentID, obj)

		// Emit the routing metadata for the keeper that builds the D order.
		emitNativeIntentEvent(stateDB, intentID, dChainID, req, locked)
		return nil
	}); lockErr != nil {
		return ids.Empty, lockErr
	}
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

	// Derive the injective position-commit id (the shared-memory key) over the FULL
	// identity, in the position-commit domain (disjoint from swap-intent ids). The locked
	// principal is the REQUESTED amount: commitAssetIn's terminal ERC-20 pull asserts the
	// vault receives at least this much or REVERTS the whole frame, so `locked == req.AmountIn`
	// is authoritative (no post-transfer observed delta to overstate against).
	cChainID := atomicState.CChainID()
	dChainID := atomicState.DChainID()
	if dChainID == ids.Empty {
		return ids.Empty, 0, ErrNativeNoAtomicMemory
	}
	locked = req.AmountIn
	positionID = DerivePositionCommitID(
		atomicState.NetworkID(), cChainID, dChainID,
		atomicState.TxID(), atomicState.CallIndex(),
		req.Account, req.AssetIn, locked, req.MarketID,
	)

	// Lock the LP principal into the COMMITTED-POSITIONS pot (the LP rail's own pot) — the
	// C-side debit that BACKS the C->D commit object (D imports value C already removed, no
	// mint). PHASE A (the record callback) writes EVERY 0x9999 state — replay mark, staged
	// C->D commit object, routing event — BEFORE the terminal asset pull, so the geth nested-
	// call host bug cannot drop them. The transferFrom is the frame's LAST external effect;
	// an ERC-20 under-delivery reverts the whole frame (all-or-nothing).
	if _, lockErr := commitAssetIn(stateDB, req.Account, req.AssetIn, req.AssetInAddr, req.AmountIn, func() error {
		// Replay guard: the same commit id must not be submitted twice (a re-executed /
		// reorged C tx). Durable, consensus-shared (StateDB), CEI before the export.
		if isIntentSubmitted(stateDB, positionID) {
			return ErrLPCommitReplay
		}
		markIntentSubmitted(stateDB, positionID, state.GetBlockContext().Number().Uint64())

		// STAGE the C->D commit object (rail=railLP, owner=account, asset=assetIn,
		// amount=locked) keyed by positionID under the D chain's partition (revert-aware;
		// flushed at block accept). The railLP tag makes the LP's D->C collect object
		// consumable ONLY by ImportPositionCollect.
		obj := encodeAtomicObject(railLP, req.Account, req.AssetIn, locked)
		stageAtomicPut(stateDB, dChainID, positionID, obj)

		// Emit the DL01 routing event (kind=position) for the keeper to OPEN the D position.
		emitNativePositionCommitEvent(stateDB, positionID, dChainID, req, locked)
		return nil
	}); lockErr != nil {
		return ids.Empty, 0, lockErr
	}
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

	// (1) BIND to the object the TRANSACTION carried, and DECLARE the consumption into
	// the receipt — the SAME primitive the swap rail uses, so the two rails can never
	// drift and neither can forget the declaration Verify authenticates.
	key := claim.OutputID
	recRail, recOwner, recAsset, recAmount, _, berr := bindImportObject(stateDB, dChainID, key, claim.Object)
	if berr != nil {
		return 0, berr
	}

	// (2) RAIL gate (H1-B): consume ONLY railLP objects. A swap-fill object (railSwap)
	// is refused here — it can never reach the committedPositions pot.
	if recRail != railLP {
		return 0, ErrLPCollectWrongRail
	}

	// (3) BIND the credit to the OBJECT's value (authoritative, not declared).
	if recAsset != claim.Asset {
		return 0, ErrNativeSettleAsset
	}
	if recOwner != claim.Recipient {
		return 0, ErrNativeSettleOwner
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

	// (7) PHASE A — drive the position lifecycle + stage the Remove BEFORE the terminal
	// credit, so the geth nested-call host bug cannot drop these 0x9999 writes:
	//   - DRIVE the position lifecycle (FIX-3): the collected amount LEAVES the record's
	//     committed backing AND the owner's per-asset committed reserve; when the record's
	//     LockedAmt reaches 0 the position is fully collected -> Closed (terminal).
	//   - STAGE the atomic Remove of the consumed object (revert-aware; flushed at block accept
	//     atomically with the committed credit).
	collectPositionRecord(stateDB, claim.PositionID, order, recAsset, recAmount)
	stageAtomicRemove(stateDB, dChainID, key)

	// (8) PHASE B — CREDIT C from the COMMITTED-POSITIONS pot as the frame's TERMINAL effect:
	// NO MINT, NO RAID (the LP pot must back it). creditPositionCollect records the committed-
	// release (Phase A) then performs the native/ERC-20 payout terminally; nothing writes 0x9999
	// after it. The transfer token is derived from the RECORDED asset (FIX-5).
	if cerr := creditPositionCollect(stateDB, recOwner, recAsset, recAmount); cerr != nil {
		return 0, cerr
	}
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
	Asset     [32]byte       // claimed output asset — MUST equal the object's asset
	AssetAddr common.Address // ERC-20 token for the credit (address(0) for native) — IGNORED for the transfer token, which is derived from the object's asset (FIX-5)
	Recipient common.Address // claimed owner — MUST equal the object's owner
	// Object is the D->C atomic object's BYTES, carried by the transaction
	// (rail|owner|asset|amount|spent, exactly as D exported them). It is the
	// AUTHORITATIVE value: the credit is this object's amount, never a number the
	// claim states separately. Execution binds to these bytes WITHOUT reading shared
	// memory, so the transaction replays byte-identically forever; the host proves
	// the bytes are the recorded object at Block.Verify (settle_import.go), where a
	// forgery rejects the block instead of diverging a receipt.
	Object []byte
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

	// (1) BIND to the object the TRANSACTION carried, and DECLARE the consumption into
	// the receipt. No shared-memory read here: that read is what made this path
	// unsyncable, and it now happens once per block at Verify, against this declaration.
	key := claim.OutputID
	recRail, recOwner, recAsset, recAmount, recSpent, berr := bindImportObject(stateDB, dChainID, key, claim.Object)
	if berr != nil {
		return 0, berr
	}

	// (2) RAIL gate (H1-A): consume ONLY railSwap objects. An LP-collect object
	// (railLP) is refused here — it can never reach the swap rail's seamReserve pot,
	// so an LP cannot route their collect object through swap-settlement to drain the
	// swap pot and strand real swap settlements.
	if recRail != railSwap {
		return 0, ErrSettleWrongRail
	}

	// (3) BIND the credit to the OBJECT's value (authoritative, not declared). The
	// asset is derived from the swap direction and the recipient is the caller, so
	// these equalities are what stop a claim naming a victim's object or a
	// re-denominated asset — the same bindings as before, now against the carried
	// bytes that Verify proves are the recorded ones.
	if recAsset != claim.Asset {
		return 0, ErrNativeSettleAsset
	}
	if recOwner != claim.Recipient {
		return 0, ErrNativeSettleOwner
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

	// (7) PHASE A — record EVERY remaining 0x9999 state BEFORE the terminal credit, so the
	// geth nested-call host bug cannot drop them (the dropped-write fund-loss this dissolves):
	//   - DECREMENT the intent's remaining locked principal ONLY for a same-asset refund (the
	//     per-taker cap's accounting; recAmount <= remaining was proven above, so this never
	//     underflows). A proceeds credit (different asset) does not touch the input principal.
	//   - STAGE the atomic Remove of the consumed object under the D source chain. We do NOT
	//     Apply here (a direct Apply commits outside the EVM revert scope => value LOSS on a
	//     post-Apply revert); staging is revert-aware and flushed at BLOCK ACCEPT atomically
	//     with the committed credit.
	if recAsset == intent.AssetIn {
		intent.Remaining -= recAmount
		putSwapIntentRecord(stateDB, claim.IntentID, intent)
	}
	stageAtomicRemove(stateDB, dChainID, key)

	// (8) PHASE B — CREDIT C from the vault as the frame's TERMINAL effect: NO MINT (the seam
	// reserve must already hold the output, funded by prior tokenIn legs + operator seeding).
	// creditSettlementOutput records the seam-release (Phase A) then performs the native/ERC-20
	// payout terminally; nothing writes 0x9999 after it. The transfer token is derived from the
	// RECORDED asset (FIX-5), so claim.AssetAddr cannot redirect the credit.
	if cerr := creditSettlementOutput(stateDB, recOwner, recAsset, recAmount); cerr != nil {
		return 0, cerr
	}
	return recAmount, nil
}

// enforceProceedsPriceFloor is the TAKER-AUTHENTICATED MEV floor: it refuses a swap
// PROCEEDS settlement whose realized fill price is worse than the limit the TAKER
// recorded at submit (priceLimit, limitIsUpper) — independent of any keeper-relayed
// limit. It is a PURE function of the recorded limit and the venue-attested witness
// (spent = matched input, out = proceeds output), so calling it before any state write
// preserves ImportSettlement's CEI ordering.
//
// PRICE DOMAIN. priceLimit is quote-per-base (currency1 per currency0) as a uint64
// FIXED-POINT ×priceScale value — the SAME PriceInt grid the dexvm matcher uses
// (Fill.Price) and the SAME value priceLimitToCLOB produced from the taker's V4
// SqrtPriceLimitX96, so limit = priceLimit / priceScale exactly. The realized price is
// reconstructed from the integer witness:
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
// EXACT INTEGER COMPARISON (determinism + uint256 safety). limit = priceLimit / priceScale
// is a ratio of exact integers, and spent/out are uint256-domain token amounts that
// routinely exceed 2^53 — so the realized price MUST NOT be reconstructed in float64:
// float64(spent) silently drops the low bits above 2^53, mispricing the floor (it can
// ACCEPT a fill below the taker's floor, the exact MEV the floor exists to refuse). Instead
// the limit is carried as its exact numerator/denominator (priceLimit / priceScale) and
// cross-multiplied with the amounts as big.Ints:
//
//	SELL floor : out/spent >= limit  <=>  out*priceScale   >= priceLimit*spent ; reject if <
//	BUY ceiling: spent/out <= limit  <=>  spent*priceScale <= priceLimit*out   ; reject if >
//
// Every term is an exact integer, so the verdict is byte-identical on every validator (no
// float on the money path) and never truncates a uint256 amount.
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
	limNum := new(big.Int).SetUint64(priceLimit) // limit = priceLimit / priceScale
	limDen := big.NewInt(priceScale)
	spentBig := new(big.Int).SetUint64(spent) // exact, no 2^53 truncation.
	outBig := new(big.Int).SetUint64(out)
	if limitIsUpper {
		// BUY ceiling: realized quote/base = spent/out must not EXCEED the limit.
		// reject if spent*limDen > limNum*out
		lhs := new(big.Int).Mul(spentBig, limDen)
		rhs := new(big.Int).Mul(limNum, outBig)
		if lhs.Cmp(rhs) > 0 {
			return ErrSettlePriceLimit
		}
		return nil
	}
	// SELL floor: realized quote/base = out/spent must not fall BELOW the limit.
	// reject if out*limDen < limNum*spent
	lhs := new(big.Int).Mul(outBig, limDen)
	rhs := new(big.Int).Mul(limNum, spentBig)
	if lhs.Cmp(rhs) < 0 {
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

	// (6) PHASE A — stage the compensating C->D Remove + emit the reclaim event BEFORE the
	// terminal refund, so the geth nested-call host bug cannot drop these 0x9999 writes.
	// Staging a Remove of the original intent object stops a dexvm that has not yet imported
	// it from later funding a D order from a reclaimed intent (double-fund); if D already
	// imported it the Remove no-ops on a missing key and the now-zero remaining still prevents
	// a double payout.
	stageAtomicRemove(stateDB, dChainID, intentID)
	emitNativeReclaimEvent(stateDB, intentID, intent.Owner, intent.AssetIn, refunded)

	// (7) PHASE B — REFUND the locked principal from seamReserve as the frame's TERMINAL
	// effect: NO MINT (creditSettlementOutput draws ONLY seamReserve[assetIn], the exact pot
	// SubmitSwapIntent credited, so it can never raid a depositor/LP pot). The transfer token
	// is derived from the recorded asset (FIX-5). Nothing writes 0x9999 after it.
	if cerr := creditSettlementOutput(stateDB, intent.Owner, intent.AssetIn, refunded); cerr != nil {
		return 0, cerr
	}
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
//
// The escrow LOCK is lockAssetIn (native_zap.go) — the two-phase input lock that records
// seam accounting before the terminal ERC-20 pull (the geth nested-call fund-loss fix).
// The settlement CREDIT is creditSettlementOutput below (recordSeamRelease + terminal
// payout). The LP rail's analogs are commitAssetIn / creditPositionCollect.

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
	// PHASE A — debit the seam reserve (the conservation gate: NO MINT, the seam's own pot
	// must back the output; NO RAID, it is checked against seamReserve[a] only, never a
	// depositor/maker pot). Pure 0x9999 write, no nested call.
	if err := recordSeamRelease(stateDB, assetID, amount); err != nil {
		return err
	}
	if isNativeAsset(assetID) {
		// Native release is a plain balance op (Phase A) — no nested call.
		return moveNativeOutOfVault(stateDB, recipient, amount)
	}
	// PHASE B — terminal ERC-20 transfer. The token is DERIVED from the recorded asset id
	// (FIX-5: assetAddress is assetID's injective inverse), so a caller cannot redirect the
	// credit to a different token. Nothing writes 0x9999 storage after this.
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return ErrNativeERC20Vault
	}
	return pushERC20Terminal(vault, assetAddress(assetID), recipient, new(big.Int).SetUint64(amount))
}

// --- LP-rail value movement (commit into committedPositions / collect out of it). --

// The LP commit LOCK is commitAssetIn (native_zap.go) — the two-phase analog of lockAssetIn
// on the committedPositions pot (orthogonal to the swap-rail seam reserve). The collect
// CREDIT is creditPositionCollect below.

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
	// PHASE A — debit the LP committed-positions pot (NO MINT, NO RAID — orthogonal to the
	// swap-rail seam reserve and the depositor/maker pots). Pure 0x9999 write, no nested call.
	if err := recordCommittedRelease(stateDB, assetID, amount); err != nil {
		return err
	}
	if isNativeAsset(assetID) {
		return moveNativeOutOfVault(stateDB, recipient, amount)
	}
	// PHASE B — terminal ERC-20 transfer (token derived from the recorded asset id, FIX-5).
	vault, ok := stateDBERC20(stateDB)
	if !ok {
		return ErrNativeERC20Vault
	}
	return pushERC20Terminal(vault, assetAddress(assetID), recipient, new(big.Int).SetUint64(amount))
}
