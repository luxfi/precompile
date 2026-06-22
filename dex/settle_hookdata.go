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
//	empty hookData               -> PHASE A (INTENT): lock input, create C->D object.
//	tag "DI01" + (empty)         -> PHASE A (INTENT), explicit, deadline 0 (none).
//	tag "DI01" + deadline[32]    -> PHASE A (INTENT) with an explicit deadline.
//	tag "DS01" + body            -> PHASE B (SETTLEMENT): consume a D->C object.
//
// PHASE A body layout (optional; absent => deadline 0 = no deadline):
//
//	deadline[32]   // swap deadline as a block timestamp (uint256; must fit uint64)
//
// The deadline is persisted in the per-intent escrow record so (a) Phase-B settlement
// past it is refused and (b) reclaimIntent can refund the locked principal once it
// passes and D has not settled. It rides in hookData (the V4 SwapParams tuple is
// UNCHANGED) — the deadline is not a value-bearing field, only a routing/liveness one.
//
// PHASE B body layout (deterministic, fixed width, bounds-checked):
//
//	outputID[32]   // the D->C atomic object's shared-memory key
//	amount[32]     // claimed output amount (uint256; must fit uint64 + == recorded)
//	intentID[32]   // the originating C->D intent id this settlement draws against
//
// The output ASSET and RECIPIENT are NOT free wire fields: the asset is DERIVED
// from the swap direction (the pool's output side) and the recipient is the CALLER
// (day-1, no operator delegation). This keeps the claim from naming a victim's
// object or a re-denominated asset — ImportSettlement then binds these against the
// RECORDED object, so even the derived values must match what D actually exported.
// The intentID binds the credit to the taker's OWN intent record so it is capped by
// that taker's remaining locked principal (the per-taker cap, the swap-rail analog of
// the LP per-position bound).

// Phase tags. A hookData that does not begin with a known tag and is non-empty is
// rejected (a hook contract's opaque bytes will not collide with these 4-byte
// tags, and even if they did the inner decode rejects a non-conforming body).
var (
	intentPhaseTag     = [4]byte{'D', 'I', '0', '1'} // PHASE A explicit
	settlementPhaseTag = [4]byte{'D', 'S', '0', '1'} // PHASE B
)

type swapPhase uint8

const (
	swapPhaseIntent swapPhase = iota
	swapPhaseSettlement
)

var (
	ErrSettleBodyMalformed = errors.New("dex: settlement hookData body is malformed")
	ErrSettleBadAmount     = errors.New("dex: settlement claim amount out of range")
	ErrUnknownSwapPhase    = errors.New("dex: swap hookData carries an unknown phase tag")
	ErrIntentBodyMalformed = errors.New("dex: intent hookData body is malformed")
	ErrIntentBadDeadline   = errors.New("dex: intent deadline out of range")
)

// decodeSwapPhase classifies the hookData into a phase and returns the phase body —
// the bytes AFTER a recognized tag, and ONLY for a recognized tag. Empty hookData =>
// intent with a nil body (the common case: a plain V4 swap). An explicit DI01 tag =>
// intent with the post-tag body (which decodeIntentDeadline parses as an optional
// deadline). A DS01 tag => settlement with the post-tag body. Any OTHER non-empty,
// non-tagged blob (a hook contract's opaque bytes, including a legacy/foreign tag) =>
// intent with a NIL body: Phase A ignores opaque hook data, so it never accidentally
// settles AND its arbitrary bytes are never mis-parsed as a deadline (the body is only
// meaningful behind the DI01 tag). taggedIntent reports whether the DI01 tag was seen
// so only an explicit intent body is read for a deadline.
func decodeSwapPhase(hookData []byte) (phase swapPhase, body []byte, taggedIntent bool) {
	if len(hookData) == 0 {
		return swapPhaseIntent, nil, false
	}
	if len(hookData) >= 4 {
		switch {
		case bytes.Equal(hookData[:4], intentPhaseTag[:]):
			return swapPhaseIntent, hookData[4:], true
		case bytes.Equal(hookData[:4], settlementPhaseTag[:]):
			return swapPhaseSettlement, hookData[4:], false
		}
	}
	// Non-empty, non-tagged hookData: a Phase-A intent whose opaque body is IGNORED
	// (nil body => no deadline parse). A hook-only swap that carries arbitrary bytes
	// still creates a (no-deadline) intent; it never accidentally settles (settlement
	// requires the DS01 tag) and its bytes are never read as a deadline.
	return swapPhaseIntent, nil, false
}

// settlementBodyLen is the fixed Phase-B body width: outputID(32) | amount(32) |
// intentID(32).
const settlementBodyLen = 32 + 32 + 32

// decodeSettlementBody parses a Phase-B body into a SettlementClaim, DERIVING the
// asset from the swap output direction and the recipient from the caller. The
// claim is then bound against the recorded D->C object in ImportSettlement, and its
// credit is capped by the named intent record's remaining principal.
func decodeSettlementBody(body []byte, key PoolKey, params SwapParams, caller common.Address) (SettlementClaim, error) {
	if len(body) != settlementBodyLen {
		return SettlementClaim{}, ErrSettleBodyMalformed
	}
	var outputID ids.ID
	copy(outputID[:], body[0:32])
	amount := new(big.Int).SetBytes(body[32:64])
	if !amount.IsUint64() || amount.Sign() <= 0 {
		return SettlementClaim{}, ErrSettleBadAmount
	}
	var intentID [32]byte
	copy(intentID[:], body[64:96])
	// Output asset = the pool's output side for this swap direction (the asset the
	// taker receives). Derived, not wire-supplied, so a claim cannot name a foreign
	// asset; ImportSettlement still equality-checks it against the recorded object.
	_, outAsset := swapAssetDirection(key, params)
	return SettlementClaim{
		OutputID:  outputID,
		Asset:     outAsset,
		AssetAddr: assetAddress(outAsset),
		Amount:    amount.Uint64(),
		Recipient: caller, // day-1: no delegation; recipient is the caller.
		IntentID:  intentID,
	}, nil
}

// EncodeSettlementHookData builds a Phase-B hookData for tests and the keeper's
// settle-tx builder: tag + outputID + amount + intentID. The inverse of
// decodeSettlementBody (asset/recipient are derived at decode, not encoded).
func EncodeSettlementHookData(outputID ids.ID, amount uint64, intentID ids.ID) []byte {
	out := make([]byte, 0, 4+settlementBodyLen)
	out = append(out, settlementPhaseTag[:]...)
	out = append(out, outputID[:]...)
	var amt [32]byte
	binary.BigEndian.PutUint64(amt[24:32], amount)
	out = append(out, amt[:]...)
	out = append(out, intentID[:]...)
	return out
}

// intentBodyLen is the fixed Phase-A body width when a deadline is present:
// deadline(32). An empty Phase-A body (the common plain-swap case) means no deadline.
const intentBodyLen = 32

// decodeIntentDeadline parses the OPTIONAL Phase-A intent body into a deadline. An
// empty body => deadline 0 (no deadline) — the plain-swap default. A non-empty body
// MUST be exactly the canonical width and fit uint64, else it is malformed (a swap
// that carries garbage where a deadline should be reverts rather than silently
// dropping the deadline and stranding funds with no reclaim horizon).
func decodeIntentDeadline(body []byte) (uint64, error) {
	if len(body) == 0 {
		return 0, nil
	}
	if len(body) != intentBodyLen {
		return 0, ErrIntentBodyMalformed
	}
	d := new(big.Int).SetBytes(body[0:32])
	if !d.IsUint64() {
		return 0, ErrIntentBadDeadline
	}
	return d.Uint64(), nil
}

// EncodeIntentHookData builds an explicit Phase-A hookData: the tag, plus a deadline
// word when deadline != 0. A plain empty hookData also selects Phase A with no
// deadline; this is for callers that want the tag (and optionally a deadline) explicit.
func EncodeIntentHookData(deadline uint64) []byte {
	if deadline == 0 {
		out := make([]byte, 4)
		copy(out, intentPhaseTag[:])
		return out
	}
	out := make([]byte, 0, 4+intentBodyLen)
	out = append(out, intentPhaseTag[:]...)
	var d [32]byte
	binary.BigEndian.PutUint64(d[24:32], deadline)
	out = append(out, d[:]...)
	return out
}
