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
// PHASE A body layout (optional, two recognized widths; absent => deadline 0, nonce 0):
//
//	deadline[32]                 // swap deadline as a block timestamp (uint256; fits uint64)
//	deadline[32] | nonce[32]     // + the intent nonce (uint256; fits uint64)
//
// The deadline is persisted in the per-intent escrow record so (a) Phase-B settlement
// past it is refused and (b) reclaimIntent can refund the locked principal once it
// passes and D has not settled. The NONCE is the taker's intent disambiguator: it is
// folded into DeriveIntentID so the intent id is CHAIN-OBSERVABLE (derivable off-chain
// before the txID exists — the watch-correlation fix) and so two otherwise-identical
// swaps get distinct ids. Both ride in hookData (the V4 SwapParams tuple is UNCHANGED) —
// neither is value-bearing, only routing/liveness/identity. A body with the deadline but
// no nonce derives the id with nonce 0 (back-compatible with a plain single-swap intent).
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

// isUntaggedSwap reports whether the hookData carries NEITHER cross-chain phase tag
// (DI01 intent / DS01 settlement) — i.e. it is a plain same-domain swap that routes
// through the synchronous on-chain router, not the async cross-chain settlement path.
// Empty hookData (the common case) is untagged; an opaque hook blob that is not one
// of the two recognized tags is also untagged (it is a normal swap whose hook bytes
// the router ignores). The two explicit cross-chain tags are the ONLY thing that
// routes a swap to the async settlement handler.
func isUntaggedSwap(hookData []byte) bool {
	if len(hookData) >= 4 {
		if bytes.Equal(hookData[:4], intentPhaseTag[:]) || bytes.Equal(hookData[:4], settlementPhaseTag[:]) {
			return false
		}
	}
	return true
}

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

// intentBodyLen is the Phase-A body width with a deadline only: deadline(32).
// intentBodyLenWithNonce adds the nonce word: deadline(32) | nonce(32). An empty body
// (the common plain-swap case) means deadline 0, nonce 0.
const (
	intentBodyLen          = 32
	intentBodyLenWithNonce = 64
)

// decodeIntentBody parses the OPTIONAL Phase-A intent body into (deadline, nonce). An
// empty body => (0, 0) — the plain-swap default. A 32-byte body carries only a deadline
// (nonce 0). A 64-byte body carries deadline + nonce. Any other width, or a value that
// does not fit uint64, is malformed (a swap that carries garbage where a deadline/nonce
// should be reverts rather than silently dropping it and deriving a mismatched id /
// stranding funds with no reclaim horizon).
func decodeIntentBody(body []byte) (deadline, nonce uint64, err error) {
	switch len(body) {
	case 0:
		return 0, 0, nil
	case intentBodyLen:
		d := new(big.Int).SetBytes(body[0:32])
		if !d.IsUint64() {
			return 0, 0, ErrIntentBadDeadline
		}
		return d.Uint64(), 0, nil
	case intentBodyLenWithNonce:
		d := new(big.Int).SetBytes(body[0:32])
		n := new(big.Int).SetBytes(body[32:64])
		if !d.IsUint64() || !n.IsUint64() {
			return 0, 0, ErrIntentBadDeadline
		}
		return d.Uint64(), n.Uint64(), nil
	default:
		return 0, 0, ErrIntentBodyMalformed
	}
}

// EncodeIntentHookData builds an explicit Phase-A hookData: the tag, plus deadline and
// nonce words. A plain empty hookData also selects Phase A with deadline 0, nonce 0.
// The encoding is MINIMAL-WIDTH so the off-chain (zap/dexsession) and on-chain encoders
// produce byte-identical calldata for the same (deadline, nonce):
//   - deadline==0 && nonce==0 -> tag only (4 bytes)
//   - nonce==0                -> tag | deadline[32]
//   - else                    -> tag | deadline[32] | nonce[32]
func EncodeIntentHookData(deadline, nonce uint64) []byte {
	if deadline == 0 && nonce == 0 {
		out := make([]byte, 4)
		copy(out, intentPhaseTag[:])
		return out
	}
	var d [32]byte
	binary.BigEndian.PutUint64(d[24:32], deadline)
	if nonce == 0 {
		out := make([]byte, 0, 4+intentBodyLen)
		out = append(out, intentPhaseTag[:]...)
		out = append(out, d[:]...)
		return out
	}
	var n [32]byte
	binary.BigEndian.PutUint64(n[24:32], nonce)
	out := make([]byte, 0, 4+intentBodyLenWithNonce)
	out = append(out, intentPhaseTag[:]...)
	out = append(out, d[:]...)
	out = append(out, n[:]...)
	return out
}
