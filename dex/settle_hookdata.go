// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"errors"

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
// PHASE A carries NO BODY. A crossing moves value: the beneficiary, asset and amount
// are everything it needs, and all three are derived from the call itself. There is
// no deadline (a claim is delivered when someone delivers it, and until then the
// value is C's), and no nonce (the transaction is the disambiguator — a claim id is
// derived from the source transaction and the call's index within it). Anything a
// hook contract puts in hookData for its own purposes is simply not read here.

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

// settlementBodyLen is the fixed Phase-B body width: claimID(32) | claim(60).
const settlementBodyLen = 32 + claimSize

// decodeSettlementBody parses a Phase-B body into a Claim, DERIVING the asset from
// the swap output direction and the beneficiary from the caller, and carrying the
// SUPPLIED object bytes through untouched. The claim is bound against those bytes in
// Import (which the host proves are the recorded object at Verify).
func decodeSettlementBody(body []byte, key PoolKey, params SwapParams, caller common.Address) (Claim, error) {
	if len(body) != settlementBodyLen {
		return Claim{}, ErrSettleBodyMalformed
	}
	var claimID ids.ID
	copy(claimID[:], body[0:32])
	// Output asset = the pool's output side for this swap direction (the asset the
	// caller receives). Derived, not wire-supplied, so a transaction cannot name a
	// foreign asset; Import still equality-checks it against the object.
	_, outAsset := swapAssetDirection(key, params)
	return Claim{
		ID:          claimID,
		Asset:       outAsset,
		Beneficiary: caller, // day-1: no delegation; the beneficiary is the caller.
		Object:      append([]byte(nil), body[32:settlementBodyLen]...),
	}, nil
}

// EncodeSettlementHookData builds a Phase-B hookData for tests and a client's
// import-tx builder: tag + claimID + claim. The inverse of decodeSettlementBody
// (asset/beneficiary are derived at decode, not encoded; the amount is inside the
// object and is never restated).
func EncodeSettlementHookData(claimID ids.ID, object []byte) []byte {
	out := make([]byte, 0, 4+settlementBodyLen)
	out = append(out, settlementPhaseTag[:]...)
	out = append(out, claimID[:]...)
	out = append(out, object...)
	return out
}


