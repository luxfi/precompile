// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_wire.go is the C<->D ATOMIC OBJECT wire format for the 0x9999 native
// settlement seam. It is byte-for-byte the same shared-memory UTXO value the
// dexvm side reads/writes (chains/dexvm/atomic.go encodeExportedOutput /
// decodeExportedOutput): owner(20) | asset(32) | amount(8) = 60 bytes, fixed
// width, deterministic. Keeping the wire identical is what lets the D side import
// a C->D object NATIVELY (its executeImport binds the recorded owner/asset/amount)
// and lets C consume a D->C object the same way.
//
// THE TWO LEGS (the ship rule made concrete):
//   - C->D INTENT: C writes one of these into shared memory keyed by the D chain.
//     D's executeImport consumes it and credits a funded D order/position. D is
//     funded ONLY by consuming a C->D object.
//   - D->C SETTLEMENT: D writes one of these into shared memory keyed by the C
//     chain (its executeExport). C's ImportSettlement consumes it ONCE and credits
//     C value. C is credited ONLY by consuming a D->C object.
//
// The 60-byte object carries the VALUE-BEARING identity (owner/asset/amount) the
// atomic conservation binds. The richer order metadata (marketID, minAmountOut,
// recipient, deadline) is NOT value-bearing — it rides in the C->D intent EVENT
// (events.go) the keeper reads to build the D order. The atomic object alone moves
// value; the metadata only routes it.

// exportedOutputSize is the fixed shared-memory object width: owner(20) |
// asset(32) | amount(8). IDENTICAL to chains/dexvm/atomic.go exportedOutputSize.
const exportedOutputSize9999 = 20 + 32 + 8

// encodeAtomicObject serializes a cross-chain value object as the shared-memory
// value, byte-identical with the dexvm side: owner(20) | asset(32) | amount(8).
// owner is the account (EVM address / dexvm ShortID — both 20 bytes); asset is the
// full injective AssetID (assetID(Currency); native = all-zero); amount is the
// integer asset unit count.
func encodeAtomicObject(owner common.Address, asset [32]byte, amount uint64) []byte {
	v := make([]byte, exportedOutputSize9999)
	copy(v[0:20], owner[:])
	copy(v[20:52], asset[:])
	binary.BigEndian.PutUint64(v[52:60], amount)
	return v
}

// decodeAtomicObject is the inverse: it reads back the (owner, asset, amount) a
// consumed cross-chain object RECORDED in shared memory. ok=false for any value
// that is not EXACTLY the canonical width, so a corrupt/garbage record is never
// reinterpreted into a credit — the same defense the dexvm decodeExportedOutput
// applies. The consumer binds the credited owner/asset/amount to THIS recorded
// value, never to what the calling tx merely declares.
func decodeAtomicObject(v []byte) (owner common.Address, asset [32]byte, amount uint64, ok bool) {
	if len(v) != exportedOutputSize9999 {
		return common.Address{}, [32]byte{}, 0, false
	}
	copy(owner[:], v[0:20])
	copy(asset[:], v[20:52])
	amount = binary.BigEndian.Uint64(v[52:60])
	return owner, asset, amount, true
}

// DeriveIntentID computes the deterministic id of a C->D atomic intent object.
// It is the shared-memory UTXO key the object is PUT under (and that D's import
// consumes), and it is INJECTIVE over the full identity so two distinct intents —
// or the same logical intent across networks/chains/txs/calls — never collide:
//
//	SHA-256( domain | networkID | cChainID | dChainID | txID | callIndex |
//	         account | assetIn | amountIn | marketID )
//
// Every component is fixed width and length-stable (no concatenation ambiguity).
// callIndex disambiguates two swaps in one tx; (networkID, cChainID, dChainID)
// scope the object to exactly one rail; account/asset/amount/market bind the
// economic payload so the id cannot be reused for a different one.
func DeriveIntentID(
	networkID uint32,
	cChainID, dChainID ids.ID,
	txID ids.ID,
	callIndex uint32,
	account common.Address,
	assetIn [32]byte,
	amountIn uint64,
	marketID [32]byte,
) ids.ID {
	h := sha256.New()
	h.Write([]byte(nativeIntentDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], networkID)
	h.Write(u4[:])
	h.Write(cChainID[:])
	h.Write(dChainID[:])
	h.Write(txID[:])
	binary.BigEndian.PutUint32(u4[:], callIndex)
	h.Write(u4[:])
	h.Write(account[:])
	h.Write(assetIn[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], amountIn)
	h.Write(u8[:])
	h.Write(marketID[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return ids.ID(out)
}

// nativeIntentDomain scopes the intent-id derivation so an id minted for the DEX
// C->D atomic seam can never be confused with any other shared-memory object id.
const nativeIntentDomain = "lux.dex.native.intent.v1"

// DerivePositionCommitID computes the deterministic id of a C->D LP POSITION-COMMIT
// atomic object (intent kind DL01) — the C->D leg that FUNDS a D position. It is the
// shared-memory UTXO key the commit object is PUT under (and that D's import
// consumes). It is derived with its OWN domain (positionCommitDomain) so a
// position-commit id and a swap-intent id (DeriveIntentID, nativeIntentDomain) live
// in DISJOINT id spaces — a swap intent object can NEVER be consumed as a position
// commit, nor vice-versa, even with the same (account, asset, amount, market). The
// 60-byte object wire (owner|asset|amount) is IDENTICAL so D imports both natively;
// only the id DOMAIN (and the routing event KIND) distinguish the two rails.
//
//	SHA-256( positionCommitDomain | networkID | cChainID | dChainID | txID |
//	         callIndex | account | assetIn | amountIn | poolID )
//
// Every component is fixed width and length-stable; callIndex disambiguates two
// commits in one tx; (networkID, cChainID, dChainID) scope the object to one rail;
// account/asset/amount/pool bind the economic payload so the id cannot be reused.
func DerivePositionCommitID(
	networkID uint32,
	cChainID, dChainID ids.ID,
	txID ids.ID,
	callIndex uint32,
	account common.Address,
	assetIn [32]byte,
	amountIn uint64,
	poolID [32]byte,
) ids.ID {
	h := sha256.New()
	h.Write([]byte(positionCommitDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], networkID)
	h.Write(u4[:])
	h.Write(cChainID[:])
	h.Write(dChainID[:])
	h.Write(txID[:])
	binary.BigEndian.PutUint32(u4[:], callIndex)
	h.Write(u4[:])
	h.Write(account[:])
	h.Write(assetIn[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], amountIn)
	h.Write(u8[:])
	h.Write(poolID[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return ids.ID(out)
}

// positionCommitDomain scopes the position-commit-id derivation so a DL01 LP commit
// object id can never collide with a DI01 swap-intent object id (nativeIntentDomain)
// or any other shared-memory object id. This is the id-space half of the rail
// separation (the routing-event KIND is the other half).
const positionCommitDomain = "lux.dex.native.poscommit.v1"
