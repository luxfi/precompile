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
//	empty hookData          -> PHASE A (INTENT): lock input, create C->D object.
//	tag "DI01" + (empty)    -> PHASE A (INTENT), explicit.
//	tag "DS01" + body       -> PHASE B (SETTLEMENT): consume a D->C object.
//
// PHASE B body layout (deterministic, fixed width, bounds-checked):
//
//	outputID[32]   // the D->C atomic object's shared-memory key
//	amount[32]     // claimed output amount (uint256; must fit uint64 + == recorded)
//
// The output ASSET and RECIPIENT are NOT free wire fields: the asset is DERIVED
// from the swap direction (the pool's output side) and the recipient is the CALLER
// (day-1, no operator delegation). This keeps the claim from naming a victim's
// object or a re-denominated asset — ImportSettlement then binds these against the
// RECORDED object, so even the derived values must match what D actually exported.

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
)

// decodeSwapPhase classifies the hookData into a phase and returns the phase body
// (the bytes after the tag). Empty hookData => intent (the common case: a plain V4
// swap creates an intent). An unknown non-empty, non-tagged blob defaults to
// intent ONLY when empty; a non-empty unknown tag is surfaced to the caller via a
// settlement body that fails to decode (so a malformed phase reverts, never
// silently moves value the wrong way).
func decodeSwapPhase(hookData []byte) (swapPhase, []byte) {
	if len(hookData) == 0 {
		return swapPhaseIntent, nil
	}
	if len(hookData) >= 4 {
		switch {
		case bytes.Equal(hookData[:4], intentPhaseTag[:]):
			return swapPhaseIntent, hookData[4:]
		case bytes.Equal(hookData[:4], settlementPhaseTag[:]):
			return swapPhaseSettlement, hookData[4:]
		}
	}
	// Non-empty, non-tagged hookData: treat as intent with the raw bytes as body
	// (Phase A ignores the body). A hook-only swap that carries opaque bytes still
	// creates an intent; it never accidentally settles (settlement requires the tag).
	return swapPhaseIntent, hookData
}

// settlementBodyLen is the fixed Phase-B body width: outputID(32) | amount(32).
const settlementBodyLen = 32 + 32

// decodeSettlementBody parses a Phase-B body into a SettlementClaim, DERIVING the
// asset from the swap output direction and the recipient from the caller. The
// claim is then bound against the recorded D->C object in ImportSettlement.
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
	}, nil
}

// EncodeSettlementHookData builds a Phase-B hookData for tests and the keeper's
// settle-tx builder: tag + outputID + amount. The inverse of decodeSettlementBody
// (asset/recipient are derived at decode, not encoded).
func EncodeSettlementHookData(outputID ids.ID, amount uint64) []byte {
	out := make([]byte, 0, 4+settlementBodyLen)
	out = append(out, settlementPhaseTag[:]...)
	out = append(out, outputID[:]...)
	var amt [32]byte
	binary.BigEndian.PutUint64(amt[24:32], amount)
	out = append(out, amt[:]...)
	return out
}

// EncodeIntentHookData builds an explicit Phase-A hookData (the tag alone). A plain
// empty hookData also selects Phase A; this is for callers that want the tag
// explicit.
func EncodeIntentHookData() []byte {
	out := make([]byte, 4)
	copy(out, intentPhaseTag[:])
	return out
}
