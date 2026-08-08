// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
)

// settle_import.go is THE ONE PLACE a D->C claim enters C.
//
// WHY IT EXISTS — EXECUTION MUST BE A PURE FUNCTION OF THE BLOCK.
//
// The previous shape read the object out of shared memory INSIDE EVM execution
// (sm.Get) while the matching Remove landed at block ACCEPT. Those two facts are
// irreconcilable: a node re-executing that block later — a bootstrapping node
// descending the chain through InsertBlockManual, a state-sync catch-up, an
// archive re-trace — finds the object GONE, computes a reverted receipt where the
// network computed a successful one, and dies with `invalid receipt root hash`.
// The seam worked live and wedged every node that tried to sync past it.
//
// THE MODEL (the primary network's own import discipline, which is why the owner
// pointed at it): the object's BYTES travel IN THE TRANSACTION, exactly as a
// platformvm/coreth ImportTx carries its imported inputs. Execution binds value to
// the bytes it was HANDED, so it replays byte-identically forever with no access
// to mutable peer-chain state. The proof that those bytes are the real recorded
// object is a BLOCK-level rule, checked at Verify against shared memory, where a
// mismatch REJECTS THE BLOCK instead of diverging a receipt.
//
// THE SHIP RULE DID NOT WEAKEN — IT MOVED. It is still true that "a C balance can
// be credited by 0x9999 ONLY by consuming a D->C atomic object". What changed is
// WHERE that is proven:
//
//	before:  execution reads shared memory      -> non-reproducible, unsyncable
//	after:   execution binds tx-carried bytes   -> reproducible forever
//	         + Block.Verify proves those bytes  -> a forged object kills the BLOCK
//
// The declaration is emitted as a LOG, so it is covered by the receipt root and is
// therefore consensus-agreed, byte-identical on every validator, and visible to
// the host WITHOUT re-reading state — including for a consumption made from a
// NESTED call, which a calldata scan would miss. The host enumerates it with
// DecodeSettleImports and authenticates each entry against shared memory.
//
// FORGERY IS NOT PROFITABLE. A transaction that supplies fabricated object bytes
// still executes (it must — execution cannot consult shared memory), but the block
// carrying it is rejected by every validator, including the producer, which
// verifies its own block before proposing it. The forger buys a rejected block, not
// value: nothing it credited is ever accepted.

// exportedObjectHashDomain domain-separates the object commitment so an object
// hash can never be confused with any other 32-byte digest on the seam (an
// order id, a pool id, a market id). The commitment is over the FULL canonical
// object bytes, so equality of hashes is equality of (rail, owner, asset, amount,
// spent) under keccak collision resistance.
var exportedObjectHashDomain = []byte("lux.dex.native.import.object.v1")

// SettleObjectHash is the CANONICAL commitment to a cross-chain object's bytes.
// It is the single definition both sides use: the precompile commits to the bytes
// the transaction supplied, and the host hashes the bytes it read out of shared
// memory. One function, so the two can never drift.
func SettleObjectHash(object []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(exportedObjectHashDomain, object))
}

// settleImportEventSig is DEXSettleImport(bytes32,bytes32,bytes32) — the block's
// DECLARATION that it consumed a specific cross-chain object:
//
//	topic0 = DEXSettleImport(bytes32,bytes32,bytes32)
//	topic1 = outputID       (indexed: the object's shared-memory key)
//	data   = sourceChainID | objectHash
//
// It is emitted by the consuming path itself, so a reverted consumption emits
// nothing (the EVM drops a reverted frame's logs) and the declaration set is
// exactly the set of consumptions the block committed.
var settleImportEventSig = common.BytesToHash(crypto.Keccak256([]byte("DEXSettleImport(bytes32,bytes32,bytes32)")))

// SettleImportTopic is the topic0 a host filters on to find the declarations.
func SettleImportTopic() common.Hash { return settleImportEventSig }

// SettleImport is ONE declared cross-chain consumption: "this block consumed the
// object at OutputID, exported by SourceChainID, whose bytes hash to ObjectHash".
// The host must prove each one against shared memory or reject the block.
type SettleImport struct {
	SourceChainID ids.ID
	OutputID      ids.ID
	ObjectHash    common.Hash
}

// emitSettleImportDeclaration writes the consumption into the receipt. Called by
// the ONE binding primitive below, so no consuming path can forget it.
func emitSettleImportDeclaration(stateDB StateDB, sourceChainID, outputID ids.ID, object []byte) {
	data := make([]byte, 0, 64)
	data = append(data, sourceChainID[:]...)
	h := SettleObjectHash(object)
	data = append(data, h[:]...)
	stateDB.AddLog(&ethtypes.Log{
		Address: poolManagerAddr9999,
		Topics: []common.Hash{
			settleImportEventSig,
			common.BytesToHash(outputID[:]),
		},
		Data: data,
	})
}

// settleImportDataLen is the fixed declaration payload width: sourceChainID(32) |
// objectHash(32).
const settleImportDataLen = 64

// DecodeSettleImports is the HOST's enumerator: it extracts every cross-chain
// consumption a block declared, from that block's logs. It is a PURE function of
// the logs — no state read, no calldata scan (so a consumption made from a nested
// call is found too), no chain context.
//
// It accepts ONLY logs emitted by 0x9999 itself carrying the declaration topic and
// the exact payload width; anything else is not a declaration and is ignored. A
// contract cannot forge one: the EVM stamps the emitting address on every log, and
// only the precompile executes at 0x9999.
func DecodeSettleImports(logs []*ethtypes.Log) []SettleImport {
	var out []SettleImport
	for _, l := range logs {
		if l == nil || l.Address != poolManagerAddr9999 {
			continue
		}
		if len(l.Topics) != 2 || l.Topics[0] != settleImportEventSig {
			continue
		}
		if len(l.Data) != settleImportDataLen {
			continue
		}
		var imp SettleImport
		copy(imp.OutputID[:], l.Topics[1][:])
		copy(imp.SourceChainID[:], l.Data[0:32])
		imp.ObjectHash = common.BytesToHash(l.Data[32:64])
		out = append(out, imp)
	}
	return out
}

// ErrImportObjectMalformed is returned when a transaction supplies object bytes
// that are not EXACTLY the canonical width. Refusing here (rather than decoding a
// short/long blob) is what stops a caller from steering the decode into a
// different (rail, owner, asset, amount) reading of the same bytes.
var ErrImportObjectMalformed = errors.New("dex: supplied cross-chain object is malformed")

// bindImportObject is THE binding primitive: it takes the object bytes the
// TRANSACTION supplied, refuses anything that is not canonical, and DECLARES the
// consumption into the receipt so the host can authenticate it at Verify.
//
// It deliberately does NOT read shared memory. The value a consumer credits is the
// value in these bytes; whether these bytes are the real recorded object is proven
// one level up, on the block. Every C-side consume path goes through here, so the
// declaration can never be omitted.
func bindImportObject(
	stateDB StateDB,
	sourceChainID, claimID ids.ID,
	object []byte,
) (beneficiary common.Address, asset [32]byte, amount uint64, err error) {
	beneficiary, asset, amount, ok := decodeClaim(object)
	if !ok {
		return common.Address{}, [32]byte{}, 0, ErrImportObjectMalformed
	}
	// A ZERO-AMOUNT object is not a value transfer, and refusing it HERE is what makes
	// "no object" a single clear refusal: an absent object that some caller zero-pads
	// to the canonical width decodes as a well-formed all-zero claim.
	if amount == 0 {
		return common.Address{}, [32]byte{}, 0, ErrImportAmount
	}
	emitSettleImportDeclaration(stateDB, sourceChainID, claimID, object)
	return beneficiary, asset, amount, nil
}
