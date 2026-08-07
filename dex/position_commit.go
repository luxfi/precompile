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

// position_commit.go is the C SIDE of the LP D-COMMITTED LIQUIDITY rail — the
// CTO-locked model where an LP's value is COMMITTED to a funded D position over the
// native C<->D atomic seam, never held as a C-side-only lock. It REPLACES the prior
// maker model (settle_maker.go's available->locked reclassification that kept funds
// on C): an LP add now MOVES value out of the caller's CSpendable balance into the
// DCommitted state via a C->D commit object D imports to open the position; a
// decrease/burn/cancel requests a D->C withdraw whose object C consumes to credit
// back (DPendingCollect -> CSettled).
//
// TWO VALUE STATES PER UNIT, NEVER BOTH (the locked invariant):
//
//	CSpendable   — a unit in the LP's normal EVM balance (spendable on C).
//	DCommitted   — a unit backing a live D position: it has LEFT the LP's balance,
//	               sits in the 0x9999 vault classified as committedPositions[asset],
//	               and a C->D commit object funds the position on D.
//	(transient)  DPendingCollect — a unit D has exported as a D->C object, not yet
//	               consumed on C; CSettled — consumed and credited back to CSpendable.
//
// THE SHIP RULE (LP extension, enforced structurally): a D position is funded ONLY by
// consuming a C->D commit object (SubmitPositionCommit -> dexvm executeImport); a C
// balance is credited (collect/withdraw) ONLY by consuming a D->C export object
// (ImportPositionCollect). No fill/fee VALUE a relayer hands the precompile can
// credit C — the credit is a RECORDED D->C object's amount, drawn from the LP rail's
// OWN committedPositions pot, and absent a real object in shared memory it reverts.
//
// ORTHOGONALITY: this rail composes the SAME atomic primitives (encodeAtomicObject,
// DerivePositionCommitID, stageAtomicPut/Remove, the consumed/submitted replay sets)
// and the SAME position RECORD storage (RestingOrder + the owner index in
// settle_maker.go), and it owns its OWN value pot (committedPositions, native_state.go)
// distinct from the swap rail's seamReserve, the depositor settleVault, and the
// legacy makerLockedVault. Each pot backs only its own credits (the FIX-3 discipline).

// OrderStatusClosing marks a position whose withdraw/collect was REQUESTED: a D->C
// object is expected and the recorded owner is still a legitimate collector (so
// ImportPositionCollect's per-object gate accepts a collect naming THIS record) until
// the position is fully drained, at which point collectPositionRecord flips it to
// Closed. It extends the OrderStatus lifecycle (None=0, Open=1=Committed,
// Cancelled=2=Closed, Closing=3).
const OrderStatusClosing OrderStatus = 3

var (
	// ErrLPNoAtomicState is returned when an LP commit/withdraw is attempted on a
	// StateDB without the cross-chain atomic capability (single-chain dev). Fail-secure:
	// the LP rail moves value ONLY as atomic objects, so it refuses rather than fall
	// back to a C-side-only lock (the exact model being replaced).
	ErrLPNoAtomicState = errors.New("dex: LP commit/withdraw requires the cross-chain atomic capability")
	// ErrLPNoPosition is returned when a withdraw/collect names no position for the
	// caller (nothing committed to withdraw).
	ErrLPNoPosition = errors.New("dex: no committed position for caller's (pool,salt,range)")
	// ErrLPBadCollectInput / ErrLPCollectBadAmount guard the collectPosition calldata.
	ErrLPBadCollectInput  = errors.New("dex: collectPosition input too short")
	ErrLPCollectBadAmount = errors.New("dex: collectPosition claim amount out of range")
	// ErrLPCommitWhileClosing forbids topping up a position whose withdraw is in flight
	// (Closing). The LP must let the D->C collect settle, or commit to a fresh
	// salt/range — re-arming a Closing record back to Open is the lifecycle hole FIX-3
	// closes.
	ErrLPCommitWhileClosing = errors.New("dex: cannot commit to a position with a withdraw in flight (closing); use a fresh range or collect first")
)

// orderCommitObjSuffix stores the C->D commit OBJECT id of a position record, so an
// auditor/keeper can correlate the C-side record (keyed by MakerOrderID) with the
// shared-memory commit object D imported (keyed by DerivePositionCommitID). Two ids,
// two purposes: the record id is re-derivable from (owner,pool,salt,range) for
// lifecycle ops; the object id is injective over the tx identity for replay safety.
var orderCommitObjSuffix = []byte("c") // commit object id (bytes32)

// runSettleModifyLiquidity is the 0x9999 LP-COMMIT kernel — the CTO-locked
// committed-liquidity path. ADD (delta>0) COMMITS the LP's funds to a D position via
// a C->D object; REMOVE (delta<0) REQUESTS a D->C withdraw (the funds return when the
// LP consumes the D->C object via collectPosition). PURE atomic-seam routing, no
// matching (matching/fee-accrual lives on D). 0x9996 PositionManager routes its
// lifecycle ops here. Replaces the prior C-side-only available->locked model.
func (s *SettleContract) runSettleModifyLiquidity(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot modifyLiquidity in read-only mode")
	}
	if gas < GasAddLiquidity {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasAddLiquidity

	key, params, hookData, err := DecodeModifyLiquidityInput(input)
	if err != nil {
		return nil, gasLeft, err
	}
	if params.LiquidityDelta == nil || params.LiquidityDelta.Sign() == 0 {
		return nil, gasLeft, ErrMakerZeroDelta
	}
	if !isWord(new(big.Int).Abs(params.LiquidityDelta)) {
		return nil, gasLeft, ErrMakerAmountRange
	}
	if params.TickLower >= params.TickUpper || params.TickLower < MinTick || params.TickUpper > MaxTick {
		return nil, gasLeft, ErrMakerBadTickRange
	}

	// The LP rail moves value ONLY as atomic objects — REQUIRE the cross-chain atomic
	// capability (fail-secure; never a C-side-only lock). A single-chain dev StateDB
	// reverts cleanly here, exactly as SettleSwap does.
	atomicState, ok := state.(contract.AtomicState)
	if !ok || atomicState.AtomicMemory() == nil {
		return nil, gasLeft, ErrLPNoAtomicState
	}

	stateDB := newPoolStateAdapter(state)

	poolID := key.ID()
	if loadMarket(stateDB, poolID).Status != MarketStatusActive {
		return nil, gasLeft, ErrMakerNoMarket
	}

	side := decodeMakerSide(hookData)
	lockedAsset := lockedAssetForSide(key, side)

	// GLOBAL non-reentrant guard (the SAME single 0x9999 custody slot deposit/withdraw/
	// swap take). Set BEFORE any value movement so a malicious ERC-20's transferFrom
	// callback cannot re-enter any custody op mid-commit.
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	orderID := MakerOrderID(caller, poolID, params.Salt, params.TickLower, params.TickUpper)

	if params.LiquidityDelta.Sign() > 0 {
		return s.commitPosition(state, atomicState, stateDB, caller, key, params, side, lockedAsset, orderID, gasLeft)
	}
	return s.requestPositionWithdraw(stateDB, caller, params, orderID, gasLeft)
}

// commitPosition handles the ADD leg: it COMMITS delta of the LP's CSpendable balance
// to a funded D position via a C->D commit object, records/tops-up the position, and
// returns (orderID, lockedAmt). The value LEAVES the caller's balance and becomes
// DCommitted (committedPositions[lockedAsset]); D is funded ONLY by importing the
// staged commit object.
func (s *SettleContract) commitPosition(
	state contract.AccessibleState, atomicState contract.AtomicState, stateDB *poolStateAdapter,
	caller common.Address, key PoolKey, params ModifyLiquidityParams, side MakerSide, lockedAsset [32]byte,
	orderID [32]byte, gasLeft uint64,
) ([]byte, uint64, error) {
	// A halted asset cannot commit new positions (cancel/withdraw is always allowed —
	// funds must stay releasable).
	if isHalted(stateDB, makeStorageKey(haltAssetPrefix, lockedAsset[:])) {
		return nil, gasLeft, ErrAssetHalted
	}
	delta := params.LiquidityDelta // validated >0 and isWord.
	if !delta.IsUint64() || delta.Sign() <= 0 {
		return nil, gasLeft, ErrMakerAmountRange
	}

	// COMMIT to D: SubmitPositionCommit debits the caller's CSpendable balance into
	// committedPositions, stages the C->D DL01 object, and emits the position-open
	// routing event. Returns the commit object id (the shared-memory key D imports).
	req := OrderRequest{
		Account:     caller,
		AssetIn:     lockedAsset,
		AmountIn:    delta.Uint64(),
		AssetInAddr: assetAddress(lockedAsset),
		MarketID:    key.ID(),
		Recipient:   caller,
		Deadline:    0,
	}
	commitObjID, committed, cerr := nativeClient.SubmitPositionCommit(state, atomicState, req)
	if cerr != nil {
		return nil, gasLeft, cerr
	}
	// `committed` is the value ACTUALLY committed (observed delta for ERC-20), the
	// authoritative amount the pot AND the C->D object carry — so the record below
	// never overstates the LP's committed principal (no fee-on-transfer drift).

	// Track the per-owner committed reserve (the LP's own committed total of this
	// asset) — the same fine-grained accumulator the prior model used for locked
	// reserve, now meaning "committed to D positions". Defense-in-depth bookkeeping
	// alongside the authoritative committedPositions[asset] pot.
	storeLockedReserve(stateDB, caller, lockedAsset,
		new(big.Int).Add(loadLockedReserve(stateDB, caller, lockedAsset), new(big.Int).SetUint64(committed)))

	// Record / top-up the position. A re-commit to the same (owner,pool,salt,range)
	// accumulates the committed amount (the increase-position semantic) ONLY while the
	// position is Open. A CLOSING position is mid-withdraw (a D->C collect object is
	// expected); re-committing to it would flip it back to Open and let new principal
	// share an in-flight withdraw's record — so re-commit while Closing is FORBIDDEN
	// (FIX-3): the LP must let the withdraw settle, or use a fresh salt/range. A fully
	// collected (Closed) or never-used (None) slot starts a brand-new position.
	existing := loadRestingOrder(stateDB, orderID)
	if existing.Status == OrderStatusClosing {
		return nil, gasLeft, ErrLPCommitWhileClosing
	}
	newAmt := new(big.Int).SetUint64(committed)
	if existing.Status == OrderStatusOpen {
		newAmt = new(big.Int).Add(existing.LockedAmt, newAmt)
	}
	storeRestingOrder(stateDB, orderID, RestingOrder{
		Owner:       caller,
		PoolID:      key.ID(),
		Side:        side,
		LockedAsset: lockedAsset,
		LockedAmt:   newAmt,
		TickLower:   params.TickLower,
		TickUpper:   params.TickUpper,
		Salt:        params.Salt,
		Status:      OrderStatusOpen,
	})
	// Store the commit object id on the record for keeper/audit correlation.
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderCommitObjSuffix), common.BytesToHash(commitObjID[:]))
	appendOwnerOrder(stateDB, caller, orderID)
	return encodeOrderResult(orderID, newAmt), gasLeft, nil
}

// requestPositionWithdraw handles the REMOVE/cancel/burn leg: it marks the position
// CLOSING and emits a D->C withdraw request (a routing event the keeper forwards to D
// to export the withdrawable principal + fees). It moves NO C value here — the value
// is on D; it returns when the LP consumes the resulting D->C object via
// collectPosition. Idempotent ownership-checked, exactly like the prior cancel.
func (s *SettleContract) requestPositionWithdraw(
	stateDB *poolStateAdapter, caller common.Address, params ModifyLiquidityParams, orderID [32]byte, gasLeft uint64,
) ([]byte, uint64, error) {
	order := loadRestingOrder(stateDB, orderID)
	if order.Status == OrderStatusNone {
		return nil, gasLeft, ErrMakerNotOwner // no such position for this caller's (pool,salt,range)
	}
	if order.Owner != caller {
		return nil, gasLeft, ErrMakerNotOwner
	}
	if order.Status == OrderStatusCancelled {
		return nil, gasLeft, ErrMakerAlreadyClosed
	}

	// Mark the position CLOSING — the recorded owner remains a legitimate collector
	// (the rail gate accepts it) until the D->C object lands and is collected. Emit
	// the withdraw request for the keeper; the funds return via collectPosition.
	order.Status = OrderStatusClosing
	storeRestingOrder(stateDB, orderID, order)
	emitNativeCancelEvent(stateDB, ids.ID(orderID), order.PoolID, caller)
	return encodeOrderResult(orderID, order.LockedAmt), gasLeft, nil
}

// runSettleCollectPosition is the 0x9999 LP D->C COLLECT/WITHDRAW handler — the
// Phase-B analog for the LP rail. It consumes a D->C atomic object EXACTLY ONCE and
// credits the caller out of the committedPositions pot (DPendingCollect -> CSettled).
// This is the SOLE C-credit path for an LP: collect, decrease, burn, and cancel all
// return funds through here, by consuming a D->C object D exported.
//
// CALLDATA (deterministic, fixed width, bounds-checked):
//
//	outputID[32]   // the D->C atomic object's shared-memory key (D's UTXO id)
//	asset[32]      // the claimed asset (address left-padded; native all-zero) —
//	               // EQUALITY-checked against the object's asset
//	positionID[32] // the position RECORD id (MakerOrderID) the collect draws against
//	               // — the object's owner must hold THIS position (Open/Closing) and
//	               // the credit is bounded by its remaining committed backing
//	object[69]     // THE OBJECT ITSELF: rail|owner|asset|amount|spent, as D exported
//	               // it. Carried by the tx so execution never reads shared memory and
//	               // the block replays identically; Verify proves it (settle_import.go).
//
// The recipient is the CALLER (day-1, no delegation). ImportPositionCollect binds the
// object's RAIL (must be railLP — a swap-fill object is refused), its
// owner/asset/amount, AND the named position record, so a claim cannot invent value,
// consume a victim's object, re-denominate it, consume a swap-rail object on the LP
// pot, or draw beyond the object owner's OWN committed backing.
func (s *SettleContract) runSettleCollectPosition(
	state contract.AccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, gas, errors.New("dex: cannot collectPosition in read-only mode")
	}
	if gas < GasNativeSettlement {
		return nil, 0, errors.New("dex: out of gas")
	}
	gasLeft := gas - GasNativeSettlement

	atomicState, ok := state.(contract.AtomicState)
	if !ok || atomicState.AtomicMemory() == nil {
		return nil, gasLeft, ErrLPNoAtomicState
	}
	// FIXED width: outputID(32) | asset(32) | positionID(32) | object(69). The object
	// rides in the CALLDATA for the same reason the swap rail's does — execution must
	// never read shared memory, or a node can never re-execute this block. There is no
	// separate `amount` word: the amount IS the object's amount.
	if len(input) != collectPositionInputLen {
		return nil, gasLeft, ErrLPBadCollectInput
	}
	var outputID ids.ID
	copy(outputID[:], input[0:32])
	var asset [32]byte
	copy(asset[:], input[32:64])
	var positionID [32]byte
	copy(positionID[:], input[64:96])
	object := append([]byte(nil), input[96:collectPositionInputLen]...)

	stateDB := newPoolStateAdapter(state)

	// GLOBAL non-reentrant guard (shared 0x9999 custody slot) — the credit's ERC-20
	// transfer can hand control to a malicious token; single-in-flight the whole
	// custody surface so two interleaved collects can't clobber the pot read-modify-write.
	if !enterCustodyKV(stateDB) {
		return nil, gasLeft, ErrCustodyReentrant
	}
	defer exitCustodyKV(stateDB)

	claim := SettlementClaim{
		OutputID:   outputID,
		Asset:      asset,
		AssetAddr:  assetAddress(asset), // routing only; the transfer token is derived from the object's asset (FIX-5).
		Recipient:  caller,              // day-1: no delegation; recipient is the caller.
		PositionID: positionID,
		Object:     object,
	}
	credited, ierr := nativeClient.ImportPositionCollect(state, atomicState, claim)
	if ierr != nil {
		return nil, gasLeft, ierr
	}
	out := make([]byte, 32)
	new(big.Int).SetUint64(credited).FillBytes(out)
	return out, gasLeft, nil
}

// EncodeCollectPositionInput builds collectPosition calldata (outputID, asset,
// amount, positionID) for the keeper's collect-tx builder and tests. The inverse of
// the decode in runSettleCollectPosition.
func EncodeCollectPositionInput(outputID ids.ID, asset [32]byte, positionID [32]byte, object []byte) []byte {
	out := make([]byte, collectPositionInputLen)
	copy(out[0:32], outputID[:])
	copy(out[32:64], asset[:])
	copy(out[64:96], positionID[:])
	copy(out[96:collectPositionInputLen], object)
	return out
}

// collectPositionInputLen is the fixed collectPosition calldata width:
// outputID(32) | asset(32) | positionID(32) | object(69).
const collectPositionInputLen = 32 + 32 + 32 + exportedOutputSize9999
