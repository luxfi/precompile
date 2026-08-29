// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_wire.go is the C<->D funding wire, and it is deliberately boring.
//
// MOVE ONCE, TRADE MANY. Value crosses the chain boundary exactly twice in its life
// — in, and out. Between those, D owns it outright and every order, match and trade
// is a local balance movement. A million trades cost zero crossings.
//
// So this subsystem has exactly ONE job: move ownership exactly once between chains.
// It knows nothing about orders, markets, sides, prices, sizes, executions,
// slippage, settlement or FIX. A claim is:
//
//	beneficiary(20) | asset(32) | amount(8)   = 60 bytes
//
// and that is the whole vocabulary. The same 60 bytes travel both directions: a C->D
// deposit and a D->C withdrawal are the same primitive pointed opposite ways, so
// there is one encoder, one decoder, and one golden vector pinning them against
// dex/pkg/dchain.
//
// WHY EACH FIELD EARNS ITS PLACE, AND WHY NOTHING ELSE DOES.
//
//   - beneficiary is the account the destination chain credits. Naming it in the
//     object is what makes delivery permissionless: anyone may hand a claim to the
//     destination, because handing it over can only credit the account it already
//     names. A relayer that refuses to deliver cannot strand anyone.
//   - asset and amount are the value. Nothing else is.
//
// There is ONE party field, not two. dexprotocol.Claim (dex/pkg/dexprotocol) names
// exactly one — Beneficiary — and PendingExport.Owner() returns claim.Beneficiary,
// so "owner" and "beneficiary" were already one fact under two names. Carrying both
// would store that fact twice for the two copies to be cross-checked against each
// other.
//
// The claim's SCOPE is not in its bytes because it is already in its address: the id
// binds (source, dest, sourceTx, index), the source chain owns the partition it is
// read from, and the destination owns the partition it is written under. Restating
// any of that inside the value would be a second copy of the addressing.
//
// WIDTH IS THE DISCRIMINATOR. 60 is the only canonical width; anything else is
// refused rather than reinterpreted, so a truncated or padded record can never
// decode into a credit.

// claimSize is the fixed funding-object width: beneficiary(20) | asset(32) |
// amount(8). IDENTICAL to dex/pkg/dchain claimSize.
const claimSize = 20 + 32 + 8

// encodeClaim serializes a funding object. beneficiary is the destination account
// (EVM address / D-Chain 20-byte owner); asset is the full injective AssetID (native
// = all-zero); amount is the integer asset unit count. Fixed width, big-endian, no
// padding — so two encoders agree byte-for-byte or the golden vector fails.
func encodeClaim(beneficiary common.Address, asset [32]byte, amount uint64) []byte {
	v := make([]byte, claimSize)
	copy(v[0:20], beneficiary[:])
	copy(v[20:52], asset[:])
	binary.BigEndian.PutUint64(v[52:60], amount)
	return v
}

// decodeClaim is the exact inverse. ok=false for any width but the canonical one, so
// a corrupt record is never reinterpreted into a credit. The consumer binds the
// credit to THIS recorded value, never to what the calling transaction declares.
func decodeClaim(v []byte) (beneficiary common.Address, asset [32]byte, amount uint64, ok bool) {
	if len(v) != claimSize {
		return common.Address{}, [32]byte{}, 0, false
	}
	copy(beneficiary[:], v[0:20])
	copy(asset[:], v[20:52])
	amount = binary.BigEndian.Uint64(v[52:60])
	return beneficiary, asset, amount, true
}

// DeriveClaimID computes a funding claim's deterministic id — the shared-memory key
// the object is written under, and the key the destination consumes:
//
//	SHA-256( claimDomain | source | dest | sourceTx | index )
//
// ONE derivation, BOTH directions, BOTH repos. dex/pkg/dchain reproduces it
// byte-for-byte; the golden vector pins them together.
//
// It is injective because a transaction id is unique on its chain and the index is
// unique within that transaction — so two claims minted by one transaction differ by
// index, and two minted by different transactions differ by sourceTx. (source, dest)
// scope the claim to one corridor, so an object minted for C->D can never be replayed
// as D->C. Every component is fixed width, so there is no concatenation ambiguity.
//
// The VALUE is deliberately not folded in. The id names WHICH claim; the object
// carries WHAT it moves, and the destination binds the credit to the object's bytes,
// which the block-level import rule proves are the recorded ones. Hashing the value
// into the id too would be a second copy of it, and a copy the consumer would then
// have to decide whether to trust over the first.
func DeriveClaimID(source, dest, sourceTx ids.ID, index uint32) ids.ID {
	h := sha256.New()
	h.Write([]byte(claimDomain))
	h.Write(source[:])
	h.Write(dest[:])
	h.Write(sourceTx[:])
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], index)
	h.Write(u4[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return ids.ID(out)
}

// claimDomain scopes the claim-id derivation so a funding-rail id can never collide
// with any other 32-byte shared-memory key.
//
// The literal is the hash input, not a label, so it does not track this identifier:
// changing a byte of it moves every claim id the rail has ever derived.
const claimDomain = "lux.dex.claim.v1"
