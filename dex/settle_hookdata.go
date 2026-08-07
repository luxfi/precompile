// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// settle_hookdata.go parses the PHASE SELECTOR carried in the V4 swap hookData for
// the native C<->D atomic seam. The V4 ABI is UNCHANGED — `swap(PoolKey,
// SwapParams, bytes hookData)` already passes a `bytes hookData`; the native model
// puts a small phase tag (and, for settlement, a D->C object reference) inside it.
// No selector change, no tuple change — only the CONTENTS of hookData.
//
// PHASES (the two-phase money path):
//
//	empty hookData               -> PHASE A (ORDER): lock input, create C->D object.
//	tag "DI01" + (empty)         -> PHASE A (ORDER), explicit, deadline 0 (none).
//	tag "DI01" + deadline[32]    -> PHASE A (ORDER) with an explicit deadline.
//	tag "DS02" + body            -> PHASE B (SETTLEMENT): consume a D->C object.
//	tag "DS01" + anything        -> RETIRED. Hard error, never re-read as Phase A.
//
// PHASE A body layout (optional, two recognized widths; absent => deadline 0, nonce 0):
//
//	deadline[32]                 // swap deadline as a block timestamp (uint256; fits uint64)
//	deadline[32] | nonce[32]     // + the order nonce (uint256; fits uint64)
//
// The deadline is persisted in the per-order escrow record so (a) Phase-B settlement
// past it is refused and (b) reclaimIntent can refund the locked principal once it
// passes and D has not settled. The NONCE is the taker's order disambiguator: it is
// folded into DeriveOrderID so the order id is CHAIN-OBSERVABLE (derivable off-chain
// before the txID exists — the watch-correlation fix) and so two otherwise-identical
// swaps get distinct ids. Both ride in hookData (the V4 SwapParams tuple is UNCHANGED) —
// neither is value-bearing, only routing/liveness/identity. A body with the deadline but
// no nonce derives the id with nonce 0 (back-compatible with a plain single-swap order).
//
// PHASE B body layout (deterministic, fixed width, bounds-checked):
//
//	outputID[32]   // the D->C atomic object's shared-memory key
//	orderID[32]   // the originating C->D order id this settlement draws against
//	object[69]     // THE OBJECT ITSELF: rail|owner|asset|amount|spent, exactly as D
//	               // exported it (native_wire.go encodeAtomicObjectSpent)
//
// WHY THE OBJECT RIDES IN THE CALLDATA (the change that makes this path syncable).
// The settlement's value used to be read from shared memory DURING EVM execution,
// while the matching Remove landed at block accept. A node re-executing that block
// later — bootstrapping, state-syncing, re-tracing — found the object gone and
// computed a different receipt than the network had accepted, so it could never sync
// past a settled swap. Carrying the object IN the transaction makes execution a pure
// function of the block, replayable byte-identically forever. The proof that these
// bytes are the real recorded object is a BLOCK rule now (see settle_import.go): the
// host authenticates every declared consumption against shared memory at Verify, and
// a forged object REJECTS THE BLOCK rather than diverging a receipt. This is the
// primary network's own ImportTx discipline — the object travels in the transaction,
// shared memory is consulted at Verify.
//
// There is NO separate `amount` field: the amount IS the object's amount. One
// declaration of a fact, never two that must be cross-checked.
//
// The output ASSET and RECIPIENT are NOT free wire fields: the asset is DERIVED
// from the swap direction (the pool's output side) and the recipient is the CALLER
// (day-1, no operator delegation). This keeps the claim from naming a victim's
// object or a re-denominated asset — ImportSettlement then binds these against the
// SUPPLIED object (which Verify proves is the recorded one), so even the derived
// values must match what D actually exported.
// The orderID binds the credit to the taker's OWN order record so it is capped by
// that taker's remaining locked principal (the per-taker cap, the swap-rail analog of
// the LP per-position bound).

// Phase tags. A hookData that does not begin with a known tag and is non-empty is
// rejected (a hook contract's opaque bytes will not collide with these 4-byte
// tags, and even if they did the inner decode rejects a non-conforming body).
var (
	orderPhaseTag      = [4]byte{'D', 'I', '0', '1'} // PHASE A explicit
	settlementPhaseTag = [4]byte{'D', 'S', '0', '2'} // PHASE B (object-carrying)

	// retiredSettlementTag is the OLD Phase-B tag, whose body named an object it did
	// not carry. It is retired, not merely superseded: the fallback for an unknown tag
	// is PHASE A, so a stale DS01 blob reaching this build would otherwise be silently
	// re-read as an ORDER and LOCK the sender's input instead of settling. That is the
	// one mixed-fleet outcome worse than a revert, so DS01 is refused explicitly and
	// loudly. It was never able to settle on any network — the seam has emitted zero
	// events on every net since genesis — so nothing is being broken here.
	retiredSettlementTag = [4]byte{'D', 'S', '0', '1'}
)

type swapPhase uint8

const (
	swapPhaseOrder swapPhase = iota
	swapPhaseSettlement
)

var (
	ErrSettleBodyMalformed = errors.New("dex: settlement hookData body is malformed")
	ErrSettleBadAmount     = errors.New("dex: settlement claim amount out of range")
	ErrUnknownSwapPhase    = errors.New("dex: swap hookData carries an unknown phase tag")
	ErrOrderBodyMalformed  = errors.New("dex: order hookData body is malformed")
	ErrOrderBadDeadline    = errors.New("dex: order deadline out of range")
	// ErrRetiredSwapPhase refuses the retired DS01 settlement tag. It is a distinct,
	// loud error precisely so a stale settle can never fall through to Phase A and
	// lock the sender's input.
	ErrRetiredSwapPhase = errors.New("dex: settlement hookData uses the retired DS01 phase tag")
)

// decodeSwapPhase classifies the hookData into a phase and returns the phase body —
// the bytes AFTER a recognized tag, and ONLY for a recognized tag. Empty hookData =>
// order with a nil body (the common case: a plain V4 swap). An explicit DI01 tag =>
// order with the post-tag body (which decodeOrderDeadline parses as an optional
// deadline). A DS01 tag => settlement with the post-tag body. Any OTHER non-empty,
// non-tagged blob (a hook contract's opaque bytes, including a legacy/foreign tag) =>
// order with a NIL body: Phase A ignores opaque hook data, so it never accidentally
// settles AND its arbitrary bytes are never mis-parsed as a deadline (the body is only
// meaningful behind the DI01 tag). taggedOrder reports whether the DI01 tag was seen
// so only an explicit order body is read for a deadline.
func decodeSwapPhase(hookData []byte) (phase swapPhase, body []byte, taggedOrder bool, err error) {
	if len(hookData) == 0 {
		return swapPhaseOrder, nil, false, nil
	}
	if len(hookData) >= 4 {
		switch {
		case bytes.Equal(hookData[:4], orderPhaseTag[:]):
			return swapPhaseOrder, hookData[4:], true, nil
		case bytes.Equal(hookData[:4], settlementPhaseTag[:]):
			return swapPhaseSettlement, hookData[4:], false, nil
		case bytes.Equal(hookData[:4], retiredSettlementTag[:]):
			// RETIRED. Refuse rather than fall through to the Phase-A default: a stale
			// settle silently becoming an order would LOCK the sender's input.
			return swapPhaseOrder, nil, false, ErrRetiredSwapPhase
		}
	}
	// Non-empty, non-tagged hookData: a Phase-A order whose opaque body is IGNORED
	// (nil body => no deadline parse). A hook-only swap that carries arbitrary bytes
	// still creates a (no-deadline) order; it never accidentally settles (settlement
	// requires the DS02 tag) and its bytes are never read as a deadline.
	return swapPhaseOrder, nil, false, nil
}

// settlementBodyLen is the fixed Phase-B body width: outputID(32) | orderID(32) |
// object(69).
const settlementBodyLen = 32 + 32 + exportedOutputSize9999

// decodeSettlementBody parses a Phase-B body into a SettlementClaim, DERIVING the
// asset from the swap output direction and the recipient from the caller, and
// carrying the SUPPLIED object bytes through untouched. The claim is bound against
// those bytes in ImportSettlement (which the host proves are the recorded object at
// Verify), and its credit is capped by the named order record's remaining principal.
func decodeSettlementBody(body []byte, key PoolKey, params SwapParams, caller common.Address) (SettlementClaim, error) {
	if len(body) != settlementBodyLen {
		return SettlementClaim{}, ErrSettleBodyMalformed
	}
	var outputID ids.ID
	copy(outputID[:], body[0:32])
	var orderID [32]byte
	copy(orderID[:], body[32:64])
	// Output asset = the pool's output side for this swap direction (the asset the
	// taker receives). Derived, not wire-supplied, so a claim cannot name a foreign
	// asset; ImportSettlement still equality-checks it against the object.
	_, outAsset := swapAssetDirection(key, params)
	return SettlementClaim{
		OutputID:  outputID,
		Asset:     outAsset,
		AssetAddr: assetAddress(outAsset),
		Recipient: caller, // day-1: no delegation; recipient is the caller.
		OrderID:   orderID,
		Object:    append([]byte(nil), body[64:settlementBodyLen]...),
	}, nil
}

// EncodeSettlementHookData builds a Phase-B hookData for tests and the keeper's
// settle-tx builder: tag + outputID + orderID + object. The inverse of
// decodeSettlementBody (asset/recipient are derived at decode, not encoded; the
// amount is inside the object and is never restated).
func EncodeSettlementHookData(outputID ids.ID, orderID ids.ID, object []byte) []byte {
	out := make([]byte, 0, 4+settlementBodyLen)
	out = append(out, settlementPhaseTag[:]...)
	out = append(out, outputID[:]...)
	out = append(out, orderID[:]...)
	out = append(out, object...)
	return out
}

// orderBodyLen is the Phase-A body width with a deadline only: deadline(32).
// orderBodyLenWithNonce adds the nonce word: deadline(32) | nonce(32). An empty body
// (the common plain-swap case) means deadline 0, nonce 0.
const (
	orderBodyLen          = 32
	orderBodyLenWithNonce = 64
)

// decodeOrderBody parses the OPTIONAL Phase-A order body into (deadline, nonce). An
// empty body => (0, 0) — the plain-swap default. A 32-byte body carries only a deadline
// (nonce 0). A 64-byte body carries deadline + nonce. Any other width, or a value that
// does not fit uint64, is malformed (a swap that carries garbage where a deadline/nonce
// should be reverts rather than silently dropping it and deriving a mismatched id /
// stranding funds with no reclaim horizon).
func decodeOrderBody(body []byte) (deadline, nonce uint64, err error) {
	switch len(body) {
	case 0:
		return 0, 0, nil
	case orderBodyLen:
		d := new(big.Int).SetBytes(body[0:32])
		if !d.IsUint64() {
			return 0, 0, ErrOrderBadDeadline
		}
		return d.Uint64(), 0, nil
	case orderBodyLenWithNonce:
		d := new(big.Int).SetBytes(body[0:32])
		n := new(big.Int).SetBytes(body[32:64])
		if !d.IsUint64() || !n.IsUint64() {
			return 0, 0, ErrOrderBadDeadline
		}
		return d.Uint64(), n.Uint64(), nil
	default:
		return 0, 0, ErrOrderBodyMalformed
	}
}

// EncodeOrderHookData builds an explicit Phase-A hookData: the tag, plus deadline and
// nonce words. A plain empty hookData also selects Phase A with deadline 0, nonce 0.
// The encoding is MINIMAL-WIDTH so the off-chain (zap/dexsession) and on-chain encoders
// produce byte-identical calldata for the same (deadline, nonce):
//   - deadline==0 && nonce==0 -> tag only (4 bytes)
//   - nonce==0                -> tag | deadline[32]
//   - else                    -> tag | deadline[32] | nonce[32]
func EncodeOrderHookData(deadline, nonce uint64) []byte {
	if deadline == 0 && nonce == 0 {
		out := make([]byte, 4)
		copy(out, orderPhaseTag[:])
		return out
	}
	var d [32]byte
	binary.BigEndian.PutUint64(d[24:32], deadline)
	if nonce == 0 {
		out := make([]byte, 0, 4+orderBodyLen)
		out = append(out, orderPhaseTag[:]...)
		out = append(out, d[:]...)
		return out
	}
	var n [32]byte
	binary.BigEndian.PutUint64(n[24:32], nonce)
	out := make([]byte, 0, 4+orderBodyLenWithNonce)
	out = append(out, orderPhaseTag[:]...)
	out = append(out, d[:]...)
	out = append(out, n[:]...)
	return out
}
