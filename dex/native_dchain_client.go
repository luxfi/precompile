// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
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
//     memory EXACTLY ONCE (replay-rejected, asset/owner/amount-bound to the
//     RECORDED value, sourceChain-bound), credits the C balance/refund, and applies
//     the shared-memory Remove atomically. A C balance is credited ONLY along this
//     path — there is no other C credit from a settlement. A "live matcher answer"
//     (a fill value a relayer hands the precompile) CANNOT credit C: nothing here
//     trusts a declared amount; the credit derives from a consumed D->C object.
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
	ErrLPCommitReplay        = errors.New("dex: C->D position-commit id already submitted (replay)")
	ErrLPCollectUnbacked     = errors.New("dex: committed-positions reserve cannot back the D->C collect credit (no mint, no raid)")
	ErrLPCollectNoPosition   = errors.New("dex: D->C collect names no open/closing position for the recorded owner (cross-rail object refused)")
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
	Recipient    common.Address // where the D->C settlement must credit (object owner on return)
	Deadline     uint64         // order deadline (routing only)
}

// SubmitSwapIntent locks the taker's input on C and writes a C->D atomic intent
// object into shared memory. It returns the intentID (== the object's UTXO key);
// it does NOT match and does NOT return an output fill. The realized fill settles
// later through ImportSettlement once D matches and exports D->C.
//
// LOCK-THEN-EXPORT (CEI + conservation): the C value is debited into the 0x9999
// escrow FIRST (real EVM SubBalance / observed-delta transferFrom), then the
// atomic object is written. The object's amount equals the value actually locked
// (observed delta for ERC-20), so D can never be funded beyond what C locked.
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
	dChainID := atomicState.ChainID() // resolved by the host to the D-Chain peer below
	// NOTE: ChainID() is THIS chain (C). The D peer is the configured target chain;
	// for the native seam the dexvm runs as the primary network's D-Chain. The
	// object is keyed by intentID and PUT under the D chain's partition; the dexvm
	// imports it via Get(cChainID). We resolve the D chain id from the settle config.
	dID := loadDChainTarget(stateDB)
	if dID != ids.Empty {
		dChainID = dID
	}
	intentID = DeriveIntentID(
		atomicState.NetworkID(), cChainID, dChainID,
		atomicState.TxID(), atomicState.CallIndex(),
		req.Account, req.AssetIn, locked, req.MarketID,
	)

	// Replay guard: the same intent id must not be submitted twice (a re-executed /
	// reorged C tx). Durable, consensus-shared (StateDB), CEI before the export.
	if isIntentSubmitted(stateDB, intentID) {
		return ids.Empty, ErrNativeIntentReplay
	}
	markIntentSubmitted(stateDB, intentID, state.GetBlockContext().Number().Uint64())

	// STAGE the C->D atomic object (owner=account, asset=assetIn, amount=locked),
	// keyed by intentID under the D chain's partition. We do NOT Apply to shared
	// memory here — a direct Apply commits OUTSIDE the EVM revert scope, so a tx that
	// reverts after this would leave a C->D object with no backing C debit (the lock
	// rolled back) => D funded without a C lock = MINT. Staging into StateDB is
	// revert-aware: a reverted tx discards the staged Put atomically with its rolled-
	// back lock. The host flushes staged Puts to shared memory at BLOCK ACCEPT, the
	// single cross-domain commit point. (See native_staging.go.)
	obj := encodeAtomicObject(req.Account, req.AssetIn, locked)
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
	dChainID := atomicState.ChainID()
	if dID := loadDChainTarget(stateDB); dID != ids.Empty {
		dChainID = dID
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

	// STAGE the C->D commit object (owner=account, asset=assetIn, amount=locked) keyed
	// by positionID under the D chain's partition (revert-aware — discarded with the
	// rolled-back lock if the tx reverts; flushed to shared memory at block accept).
	obj := encodeAtomicObject(req.Account, req.AssetIn, locked)
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
// the orthogonal committedPositions pot, with one ADDITIONAL gate: the recorded
// owner MUST have a position on C in Committed/Closing status (positionExists), so a
// swap-rail D->C object — which names no LP position — cannot be consumed here to
// drain the LP pot. The discipline otherwise mirrors ImportSettlement byte-for-byte:
//
//  1. read the RECORDED object (Get under the D source chain); missing => revert.
//  2. BIND asset == claimed, owner == recipient, amount == claimed (recorded value
//     authoritative — a claim cannot consume a victim's object or re-denominate it).
//  3. RAIL gate: the recorded owner must have an open/closing C position.
//  4. REPLAY guard: reject an already-consumed object id (shared D->C consumed set —
//     one object, one credit, globally, across the swap and LP rails).
//  5. MARK consumed (CEI) BEFORE moving value.
//  6. CREDIT C from committedPositions (NO MINT, NO RAID — the LP pot must back it).
//  7. STAGE the atomic Remove of the consumed object (flushed at block accept).
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

	dChainID := loadDChainTarget(stateDB)
	if dChainID == ids.Empty {
		return 0, ErrNativeNoAtomicMemory
	}

	// (1) Read the RECORDED object. A missing object => never credit.
	key := claim.OutputID
	vals, gerr := sm.Get(dChainID, [][]byte{key[:]})
	if gerr != nil || len(vals) != 1 || len(vals[0]) == 0 {
		return 0, ErrNativeNoSettlement
	}
	recOwner, recAsset, recAmount, ok := decodeAtomicObject(vals[0])
	if !ok {
		return 0, ErrNativeSettleMalformed
	}

	// (2) BIND the credit to the RECORDED value (authoritative, not declared).
	if recAsset != claim.Asset {
		return 0, ErrNativeSettleAsset
	}
	if recOwner != claim.Recipient {
		return 0, ErrNativeSettleOwner
	}
	if recAmount != claim.Amount || recAmount == 0 {
		return 0, ErrNativeSettleAmount
	}

	// (3) RAIL gate: the recorded owner must hold an open/closing position on C. This
	// closes the cross-rail consume (an LP cannot consume a swap-settlement object to
	// drain the LP pot — a swap object names no position record).
	if !ownerHasOpenPosition(stateDB, recOwner) {
		return 0, ErrLPCollectNoPosition
	}

	// (4) REPLAY guard: one-time consumption across ALL D->C objects (shared set).
	if isSettlementConsumed(stateDB, claim.OutputID) {
		return 0, ErrNativeSettleReplay
	}

	// (5) MARK consumed BEFORE value movement (CEI; a failed credit rolls this back).
	markSettlementConsumed(stateDB, claim.OutputID, state.GetBlockContext().Number().Uint64())

	// (6) CREDIT C from the COMMITTED-POSITIONS pot — NO MINT, NO RAID.
	if cerr := creditPositionCollect(stateDB, recOwner, recAsset, claim.AssetAddr, recAmount); cerr != nil {
		return 0, cerr
	}

	// (7) STAGE the atomic Remove of the consumed object (revert-aware; flushed at
	// block accept atomically with the committed credit).
	stageAtomicRemove(stateDB, dChainID, key)
	return recAmount, nil
}

// SubmitCancel submits a D cancel for a resting order/position. A cancel moves no
// C value by itself — the eventual refund of the cancelled order's locked funds
// returns via a D->C settlement object that ImportSettlement consumes. So a cancel
// is a routing notification (event) for the keeper; it never credits C here.
func (c *NativeDChainClient) SubmitCancel(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	orderID ids.ID,
	marketID [32]byte,
	owner common.Address,
) error {
	if atomicState.AtomicMemory() == nil {
		return ErrNativeNoAtomicMemory
	}
	stateDB := newPoolStateAdapter(state)
	emitNativeCancelEvent(stateDB, orderID, marketID, owner)
	return nil
}

// SubmitCollect submits a D collect (claim accrued fees / proceeds) for a position.
// Like cancel, collect moves no C value here — the collected value returns as a
// D->C settlement object ImportSettlement consumes. It is a routing notification.
func (c *NativeDChainClient) SubmitCollect(
	state contract.AccessibleState,
	atomicState contract.AtomicState,
	positionID ids.ID,
	marketID [32]byte,
	owner common.Address,
) error {
	if atomicState.AtomicMemory() == nil {
		return ErrNativeNoAtomicMemory
	}
	stateDB := newPoolStateAdapter(state)
	emitNativeCollectEvent(stateDB, positionID, marketID, owner)
	return nil
}

// --- Settlement import (D->C): the ONLY path that credits C. -------------------

// SettlementClaim is what a settling C tx declares it wants to import. EVERY field
// is BOUND to the RECORDED D->C object — a mismatch reverts. The claim cannot
// invent value: it only names which committed object to consume and the recipient
// it must already credit.
type SettlementClaim struct {
	OutputID  ids.ID         // the D->C object's shared-memory UTXO key (sourceTxID|outputIndex-derived on D)
	Asset     [32]byte       // claimed output asset — MUST equal the recorded asset
	AssetAddr common.Address // ERC-20 token for the credit (address(0) for native)
	Amount    uint64         // claimed output amount — MUST equal the recorded amount
	Recipient common.Address // claimed owner — MUST equal the recorded owner
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
	// source chain (the object's origin).
	dChainID := loadDChainTarget(stateDB)
	if dChainID == ids.Empty {
		// Without a configured D target there is no source chain to read from — the
		// on-ramp is not wired for atomic settlement.
		return 0, ErrNativeNoAtomicMemory
	}

	// (1) Read the RECORDED object. A missing object => never credit.
	key := claim.OutputID
	vals, gerr := sm.Get(dChainID, [][]byte{key[:]})
	if gerr != nil || len(vals) != 1 || len(vals[0]) == 0 {
		return 0, ErrNativeNoSettlement
	}
	recOwner, recAsset, recAmount, ok := decodeAtomicObject(vals[0])
	if !ok {
		return 0, ErrNativeSettleMalformed
	}

	// (2) BIND the credit to the RECORDED value (authoritative, not declared).
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

	// (3) REPLAY guard: one-time settlement, durable + consensus-shared.
	if isSettlementConsumed(stateDB, claim.OutputID) {
		return 0, ErrNativeSettleReplay
	}

	// (4) MARK consumed BEFORE value movement (CEI for the replay slot). A failed
	// credit still leaves it unconsumed because the EVM revert rolls back this write.
	markSettlementConsumed(stateDB, claim.OutputID, state.GetBlockContext().Number().Uint64())

	// (5) CREDIT C from the vault — NO MINT (the vault must already hold the output;
	// it was funded by the tokenIn legs of prior intents and operator seeding).
	if cerr := creditSettlementOutput(stateDB, recOwner, recAsset, claim.AssetAddr, recAmount); cerr != nil {
		return 0, cerr
	}

	// (6) STAGE the atomic Remove of the consumed object under the D source chain. As
	// with the C->D Put, we do NOT Apply here: a direct Apply commits outside the EVM
	// revert scope, so a tx reverting after this would consume (remove) the D->C
	// object while the C credit + consumed-mark rolled back => the object is gone and
	// C was never credited = value LOSS. Staging is revert-aware; the host flushes the
	// Remove to shared memory at BLOCK ACCEPT atomically with the committed credit.
	stageAtomicRemove(stateDB, dChainID, key)
	return recAmount, nil
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
func creditSettlementOutput(stateDB StateDB, recipient common.Address, assetID [32]byte, assetAddr common.Address, amount uint64) error {
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
	return safeTransferTokenTo(vault, assetAddr, recipient, amt)
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
func creditPositionCollect(stateDB StateDB, recipient common.Address, assetID [32]byte, assetAddr common.Address, amount uint64) error {
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
	return safeTransferTokenTo(vault, assetAddr, recipient, amt)
}
