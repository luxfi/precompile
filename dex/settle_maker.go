// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle_maker.go is the 0x9999 `modifyLiquidity` path — the MAKER / resting-order
// concern. It is PURE StateDB arithmetic with NO matching (matching lives on D;
// resting an order is a custody lock, not a trade). It composes the EXISTING
// single-concern reserve helpers from settle_custody.go (the depositor claim IS the
// maker's available balance in the 0x9999 vault) — it does NOT introduce a second
// custody ledger.
//
// THE MODEL:
//   - ADD  (liquidityDelta > 0): LOCK `delta` of the maker's reserve of one asset:
//       available -= delta ; locked += delta
//     and record a resting order. orderID = keccak(owner‖poolID‖salt‖tickLower‖tickUpper).
//   - REMOVE/cancel (liquidityDelta < 0): UNLOCK |delta| (clamped to locked):
//       locked -= min(|delta|, locked) ; available += min(|delta|, locked)
//     and mark the order CANCELLED.
//
// CONSERVATION: locked funds are still inside the 0x9999 vault (available + locked
// is invariant across a lock/unlock); nothing is minted, nothing strands. A
// resting maker's locked balance is released by cancel (here) or consumed by a
// swap settlement that the maker is the counterparty for (the receipt path, which
// already debits/credits the vault). The withdraw path drains AVAILABLE only —
// locked funds cannot be withdrawn out from under a resting order (claim clamps to
// available, defense in depth).
//
// REENTRANCY: this is a custody-moving entrypoint, so it takes the SAME global
// non-reentrant guard the deposit/withdraw path uses (a malicious ERC-20 cannot
// re-enter modifyLiquidity from inside an observed-delta window — though the lock
// itself moves no token, the guard is a uniform discipline for every custody op).

// --- Maker side. A resting order locks exactly ONE asset; which one is the
// maker's `side`. BID rests currency0 (the maker provides token0, wanting token1);
// ASK rests currency1. The side is carried in a tiny maker envelope in hookData
// (tag "M999", one side byte) so the locked asset is UNAMBIGUOUS and deterministic;
// absent the envelope the default is BID (locks currency0). This keeps the locked
// AssetID a pure function of (key, hookData), which PredictAccesses also derives.
type MakerSide uint8

const (
	MakerSideBid MakerSide = 0 // rests currency0 (the lower-address asset)
	MakerSideAsk MakerSide = 1 // rests currency1 (the higher-address asset)
)

// makerEnvelopeTag marks a modifyLiquidity hookData blob as a maker instruction.
// A non-conforming hookData (or none) defaults to MakerSideBid — there is no
// matcher to fall back to; resting is a pure custody lock either way.
var makerEnvelopeTag = [4]byte{'M', '9', '9', '9'}

// decodeMakerSide reads the maker side from a hookData envelope, defaulting to BID.
func decodeMakerSide(hookData []byte) MakerSide {
	if len(hookData) >= 5 && hookData[0] == makerEnvelopeTag[0] && hookData[1] == makerEnvelopeTag[1] &&
		hookData[2] == makerEnvelopeTag[2] && hookData[3] == makerEnvelopeTag[3] {
		if hookData[4] == byte(MakerSideAsk) {
			return MakerSideAsk
		}
	}
	return MakerSideBid
}

// lockedAssetForSide returns the injective AssetID a side rests.
func lockedAssetForSide(key PoolKey, side MakerSide) [32]byte {
	if side == MakerSideAsk {
		return assetID(key.Currency1)
	}
	return assetID(key.Currency0)
}

// --- Resting-order record + status.
type OrderStatus uint8

const (
	OrderStatusNone      OrderStatus = 0
	OrderStatusOpen      OrderStatus = 1
	OrderStatusCancelled OrderStatus = 2
)

// RestingOrder is a maker's locked resting order. owner+lockedAsset+lockedAmount
// are FULL WIDTH (AccountID/AssetID never truncated). tickLower/tickUpper/salt pin
// the position; status is the lifecycle witness for idempotent cancel.
type RestingOrder struct {
	Owner       common.Address
	PoolID      [32]byte
	Side        MakerSide
	LockedAsset [32]byte
	LockedAmt   *big.Int
	TickLower   int24
	TickUpper   int24
	Salt        [32]byte
	Status      OrderStatus
}

// resting-order storage. Each order is a few fine-grained slots; the per-owner
// index lets 0x9996 enumerate without scanning. No global hot write.
var (
	restingOrderPrefix  = []byte(settleStateNamespace + "ord") // restingOrder[orderID] -> record
	ownerOrdersPrefix   = []byte(settleStateNamespace + "own") // ownerOrders[owner][i] -> orderID, [count]
	lockedReservePrefix = []byte(settleStateNamespace + "lck") // lockedReserve[owner][asset] -> amount
)

// order record slot suffixes (one concern per slot).
var (
	orderMetaSuffix  = []byte("m") // status(1)|side(1)|tickLower(int24)|tickUpper(int24)
	orderOwnerSuffix = []byte("o") // owner (address)
	orderPoolSuffix  = []byte("p") // poolID (bytes32)
	orderAssetSuffix = []byte("a") // lockedAsset (bytes32)
	orderAmtSuffix   = []byte("v") // lockedAmount (uint256)
	orderSaltSuffix  = []byte("s") // salt (bytes32)
)

// MakerOrderID derives the resting order's id: keccak(owner‖poolID‖salt‖tickLower‖tickUpper).
// Deterministic + collision-resistant: two distinct (owner,pool,salt,range) tuples
// yield distinct ids; the same tuple re-derives the SAME id (so a cancel finds the
// order placed by an earlier tx, and a re-add to the same slot is detected).
func MakerOrderID(owner common.Address, poolID [32]byte, salt [32]byte, tickLower, tickUpper int24) [32]byte {
	buf := make([]byte, 0, 20+32+32+3+3)
	buf = append(buf, owner.Bytes()...)
	buf = append(buf, poolID[:]...)
	buf = append(buf, salt[:]...)
	var tl, tu [3]byte
	putInt24(tl[:], tickLower)
	putInt24(tu[:], tickUpper)
	buf = append(buf, tl[:]...)
	buf = append(buf, tu[:]...)
	var id [32]byte
	copy(id[:], crypto.Keccak256(buf))
	return id
}

func orderSlot(orderID [32]byte, suffix []byte) common.Hash {
	id := make([]byte, 0, 32+len(suffix))
	id = append(id, orderID[:]...)
	id = append(id, suffix...)
	return makeStorageKey(restingOrderPrefix, id)
}

func lockedReserveKey(owner common.Address, assetID [32]byte) common.Hash {
	id := make([]byte, 0, 20+32)
	id = append(id, owner.Bytes()...)
	id = append(id, assetID[:]...)
	return makeStorageKey(lockedReservePrefix, id)
}

func loadLockedReserve(stateDB stateKV, owner common.Address, assetID [32]byte) *big.Int {
	return new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, lockedReserveKey(owner, assetID)).Bytes())
}

func storeLockedReserve(stateDB stateKV, owner common.Address, assetID [32]byte, amount *big.Int) {
	var w common.Hash
	if amount != nil && amount.Sign() > 0 {
		amount.FillBytes(w[:])
	}
	stateDB.SetState(poolManagerAddr9999, lockedReserveKey(owner, assetID), w)
}

// --- per-owner order index (ownerOrders[owner] = [orderID...], with a count).
var ownerOrdersCountSuffix = []byte("n")

func ownerOrdersCountKey(owner common.Address) common.Hash {
	id := append(owner.Bytes(), ownerOrdersCountSuffix...)
	return makeStorageKey(ownerOrdersPrefix, id)
}

func ownerOrdersAtKey(owner common.Address, i uint64) common.Hash {
	id := make([]byte, 0, 20+8)
	id = append(id, owner.Bytes()...)
	var b [8]byte
	putU64(b[:], i)
	id = append(id, b[:]...)
	return makeStorageKey(ownerOrdersPrefix, id)
}

func loadOwnerOrderCount(stateDB stateKV, owner common.Address) uint64 {
	return new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, ownerOrdersCountKey(owner)).Bytes()).Uint64()
}

// orderIndexedSuffix flags whether an orderID is already present in its owner's
// index. A single SLOAD/SSTORE on this flag replaces the old O(n) presence scan, so
// appendOwnerOrder is O(1) state-touch and the cumulative cost of opening N distinct
// orders is O(N), not O(N^2). (The prior linear scan let an attacker force ~ (G/gas)^2
// validator SLOADs that the flat ADD gas did not bound — a compute-griefing vector.)
var orderIndexedSuffix = []byte("i")

func orderIndexedKey(orderID [32]byte) common.Hash {
	return orderSlot(orderID, orderIndexedSuffix)
}

// appendOwnerOrder adds orderID to the owner's index iff not already present. The
// orderID is deterministic, so a re-add of the same range must NOT grow the index;
// an O(1) membership flag (orderIndexedKey) enforces idempotency without scanning.
func appendOwnerOrder(stateDB stateKV, owner common.Address, orderID [32]byte) {
	if stateDB.GetState(poolManagerAddr9999, orderIndexedKey(orderID)) != (common.Hash{}) {
		return // already in the index (O(1), no scan).
	}
	n := loadOwnerOrderCount(stateDB, owner)
	stateDB.SetState(poolManagerAddr9999, ownerOrdersAtKey(owner, n), common.BytesToHash(orderID[:]))
	var cnt common.Hash
	new(big.Int).SetUint64(n + 1).FillBytes(cnt[:])
	stateDB.SetState(poolManagerAddr9999, ownerOrdersCountKey(owner), cnt)
	stateDB.SetState(poolManagerAddr9999, orderIndexedKey(orderID), common.Hash{31: 1})
}

// OwnerOrderIDs returns the orderIDs in a maker's index, in insertion order. Used
// by 0x9996 positionsOf / StateView getOpenOrders. Deterministic StateDB reads.
func OwnerOrderIDs(stateDB stateKV, owner common.Address) [][32]byte {
	n := loadOwnerOrderCount(stateDB, owner)
	ids := make([][32]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		var id [32]byte
		copy(id[:], stateDB.GetState(poolManagerAddr9999, ownerOrdersAtKey(owner, i)).Bytes())
		ids = append(ids, id)
	}
	return ids
}

func loadRestingOrder(stateDB stateKV, orderID [32]byte) RestingOrder {
	meta := stateDB.GetState(poolManagerAddr9999, orderSlot(orderID, orderMetaSuffix))
	var o RestingOrder
	o.Status = OrderStatus(meta[0])
	if o.Status == OrderStatusNone {
		return o
	}
	o.Side = MakerSide(meta[1])
	o.TickLower = decodeInt24(meta[2:5])
	o.TickUpper = decodeInt24(meta[5:8])
	o.Owner = common.BytesToAddress(stateDB.GetState(poolManagerAddr9999, orderSlot(orderID, orderOwnerSuffix)).Bytes())
	copy(o.PoolID[:], stateDB.GetState(poolManagerAddr9999, orderSlot(orderID, orderPoolSuffix)).Bytes())
	copy(o.LockedAsset[:], stateDB.GetState(poolManagerAddr9999, orderSlot(orderID, orderAssetSuffix)).Bytes())
	o.LockedAmt = new(big.Int).SetBytes(stateDB.GetState(poolManagerAddr9999, orderSlot(orderID, orderAmtSuffix)).Bytes())
	copy(o.Salt[:], stateDB.GetState(poolManagerAddr9999, orderSlot(orderID, orderSaltSuffix)).Bytes())
	return o
}

func storeRestingOrder(stateDB stateKV, orderID [32]byte, o RestingOrder) {
	var meta common.Hash
	meta[0] = byte(o.Status)
	meta[1] = byte(o.Side)
	putInt24(meta[2:5], o.TickLower)
	putInt24(meta[5:8], o.TickUpper)
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderMetaSuffix), meta)
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderOwnerSuffix), common.BytesToHash(o.Owner.Bytes()))
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderPoolSuffix), common.BytesToHash(o.PoolID[:]))
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderAssetSuffix), common.BytesToHash(o.LockedAsset[:]))
	var amt common.Hash
	if o.LockedAmt != nil && o.LockedAmt.Sign() > 0 {
		o.LockedAmt.FillBytes(amt[:])
	}
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderAmtSuffix), amt)
	stateDB.SetState(poolManagerAddr9999, orderSlot(orderID, orderSaltSuffix), common.BytesToHash(o.Salt[:]))
}

// maker-path errors.
var (
	ErrMakerZeroDelta     = errors.New("dex: modifyLiquidity delta must be non-zero")
	ErrMakerNoMarket      = errors.New("dex: modifyLiquidity on an unregistered market (initialize first)")
	ErrMakerBadTickRange  = errors.New("dex: modifyLiquidity tickLower must be < tickUpper, both in tick range")
	ErrMakerNotOwner      = errors.New("dex: modifyLiquidity cancel/remove: caller is not the order owner")
	ErrMakerAlreadyClosed = errors.New("dex: modifyLiquidity cancel: order already cancelled")
	ErrMakerAmountRange   = errors.New("dex: modifyLiquidity delta exceeds uint256")
)

// runSettleModifyLiquidity MOVED to position_commit.go — the LP D-committed rail
// (ADD commits to D via a C->D object; REMOVE requests a D->C withdraw). The storage
// helpers below (RestingOrder + the owner index + the per-owner reserve accumulator)
// are the POSITION RECORD that rail composes, kept here as the single record store.

// encodeOrderResult returns (orderID bytes32, remainingLocked uint256) ABI-packed.
func encodeOrderResult(orderID [32]byte, remaining *big.Int) []byte {
	out := make([]byte, 64)
	copy(out[0:32], orderID[:])
	if remaining != nil && remaining.Sign() > 0 {
		remaining.FillBytes(out[32:64])
	}
	return out
}

// enterCustodyKV / exitCustodyKV take the GLOBAL non-reentrant custody guard via the
// stateKV surface (the maker path holds a stateKV, not a *PoolManager). They read/
// write the 0x9999 namespace's custodyGuardKey9999 slot — the ONE flag across the
// 0x9999 deposit/withdraw/modifyLiquidity/collectPosition entrypoints, so a reentry
// through any of them trips it. (This is a DISTINCT slot from 0x9010's custodyGuardKey,
// which lives under 0x9010's own address; the two precompiles do not share a guard.)
func enterCustodyKV(stateDB stateKV) bool {
	if stateDB.GetState(poolManagerAddr9999, custodyGuardKey9999) != (common.Hash{}) {
		return false
	}
	stateDB.SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{31: 1})
	return true
}

func exitCustodyKV(stateDB stateKV) {
	stateDB.SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{})
}

// custodyGuardKey9999 is the 0x9999 namespace's single non-reentrant custody flag,
// stored under the 0x9999 PoolManager address (poolManagerAddr9999). Distinct from
// the 0x9010 custodyGuardKey (a different slot under 0x9010's own address); ONE slot
// for the whole 0x9999 custody entrypoint set (deposit/withdraw/modifyLiquidity/
// collectPosition).
var custodyGuardKey9999 = makeStorageKey([]byte(settleStateNamespace+"creg"), []byte{0x01})

var _ = contract.AccessibleState(nil)
