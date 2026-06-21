// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"

	"github.com/luxfi/database"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"
)

// native_staging.go solves the CROSS-DOMAIN ATOMICITY problem of the native seam.
//
// THE PROBLEM (RED-found by self-review): a precompile's StateDB writes are covered
// by the EVM snapshot/revert, but a direct atomic.SharedMemory.Apply is NOT — it
// commits immediately, outside the tx's revert scope. If a tx reverts AFTER the
// precompile ran, an immediate Apply(Put) would leave a C->D object with NO backing
// C debit (the debit rolled back) => D funded without a C lock = MINT; an immediate
// Apply(Remove) would consume a D->C object while the C credit rolled back => value
// LOSS. The two domains have different commit semantics, so a direct Apply is wrong.
//
// THE FIX (mirrors the dexvm, which DEFERS its atomic ops to block accept via
// commitAtomic): the precompile NEVER calls Apply inside Run. It STAGES the atomic
// op into its OWN StateDB namespace — which IS snapshot/revert-aware, so a reverted
// tx discards the staged op atomically with its rolled-back balance changes. The
// host then FLUSHES the staged ops to shared memory at BLOCK ACCEPT
// (FlushStagedAtomic), the single cross-domain commit point where the committed
// StateDB and the shared-memory Apply land together — exactly the platformvm
// acceptor pattern the dexvm uses. (Mode A: D reads the C->D object after the block
// commits; nothing needs it mid-block, so deferral costs nothing.)
//
// STAGED RECORD LAYOUTS (in StateDB, under the 0x9999 namespace):
//   - C->D PUT:    stagePutPrefix | seq      -> dChainID(32) | key(32) | object(60)
//   - D->C REMOVE: stageRemovePrefix | seq   -> dChainID(32) | key(32)
//   - a monotonic per-block seq counter (stageSeqKey) orders them deterministically.
//
// Determinism: the seq counter increments in tx/call order (the same on every
// validator replaying the ordered block), so the flush order is identical network-
// wide and the resulting shared-memory state is consensus-agreed.

var (
	stageSeqKey       = makeStorageKey([]byte(settleStateNamespace+"stg.seq"), []byte{})
	stagePutPrefix    = []byte(settleStateNamespace + "stg.put")
	stageRemovePrefix = []byte(settleStateNamespace + "stg.rm")
)

func stageSeq(stateDB stateKV) uint64 {
	v := stateDB.GetState(poolManagerAddr9999, stageSeqKey)
	return bytesToU64(v[24:32])
}

func setStageSeq(stateDB stateKV, n uint64) {
	var w common.Hash
	putU64(w[24:32], n)
	stateDB.SetState(poolManagerAddr9999, stageSeqKey, w)
}

// stagePutKey / stageRemoveKey key a staged op by its sequence number. We store the
// variable-length record across consecutive 32-byte slots (the EVM word size) since
// a staged Put record is dChainID(32)|key(32)|object(60) = 124 bytes = 4 words.
func stageSlotKey(prefix []byte, seq uint64, word int) common.Hash {
	id := make([]byte, 0, 16)
	var s [8]byte
	putU64(s[:], seq)
	id = append(id, s[:]...)
	var wbuf [8]byte
	putU64(wbuf[:], uint64(word))
	id = append(id, wbuf[:]...)
	return makeStorageKey(prefix, id)
}

// stageRecordKindKey marks whether seq is a Put (1) or Remove (2) record, so the
// flush walks both kinds in one ordered pass.
var stageKindPrefix = []byte(settleStateNamespace + "stg.kind")

func stageKindKey(seq uint64) common.Hash {
	var s [8]byte
	putU64(s[:], seq)
	return makeStorageKey(stageKindPrefix, s[:])
}

const (
	stageKindPut    = 1
	stageKindRemove = 2
)

// stagedOpVersion is the only staged-op record version the flush accepts. A record
// with any other version is malformed and FAILS block accept (never skipped).
const stagedOpVersion byte = 1

// stageAtomicPut stages a C->D Put (revert-aware): version|dChainID|key|object. The
// object (encodeAtomicObject: owner|asset|amount) is the value bound at flush.
func stageAtomicPut(stateDB stateKV, dChainID ids.ID, key ids.ID, object []byte) {
	seq := stageSeq(stateDB)
	writeBytesToSlots(stateDB, stagePutPrefix, seq, packPut(dChainID, key, object))
	markStageKind(stateDB, seq, stageKindPut)
	setStageSeq(stateDB, seq+1)
}

// stageAtomicRemove stages a D->C Remove (revert-aware): version|dChainID|key.
func stageAtomicRemove(stateDB stateKV, dChainID ids.ID, key ids.ID) {
	seq := stageSeq(stateDB)
	writeBytesToSlots(stateDB, stageRemovePrefix, seq, packRemove(dChainID, key))
	markStageKind(stateDB, seq, stageKindRemove)
	setStageSeq(stateDB, seq+1)
}

func markStageKind(stateDB stateKV, seq uint64, kind byte) {
	var w common.Hash
	w[31] = kind
	stateDB.SetState(poolManagerAddr9999, stageKindKey(seq), w)
}

// packPut / packRemove are the fixed-width staged-record encodings. Each carries a
// leading version byte so a future layout change is an explicit new version (and an
// unknown version fails the flush rather than silently mis-decoding value).
//
//	Put:    version(1) | dChainID(32) | key(32) | object(60)
//	Remove: version(1) | dChainID(32) | key(32)
func packPut(dChainID, key ids.ID, object []byte) []byte {
	b := make([]byte, 1+32+32+len(object))
	b[0] = stagedOpVersion
	copy(b[1:33], dChainID[:])
	copy(b[33:65], key[:])
	copy(b[65:], object)
	return b
}

func packRemove(dChainID, key ids.ID) []byte {
	b := make([]byte, 1+32+32)
	b[0] = stagedOpVersion
	copy(b[1:33], dChainID[:])
	copy(b[33:65], key[:])
	return b
}

// writeBytesToSlots stores b across consecutive 32-byte StateDB slots: slot 0 holds
// the length (left-padded), slots 1.. hold the data words.
func writeBytesToSlots(stateDB stateKV, prefix []byte, seq uint64, b []byte) {
	var lenWord common.Hash
	putU64(lenWord[24:32], uint64(len(b)))
	stateDB.SetState(poolManagerAddr9999, stageSlotKey(prefix, seq, 0), lenWord)
	for i := 0; i*32 < len(b); i++ {
		var w common.Hash
		end := (i + 1) * 32
		if end > len(b) {
			end = len(b)
		}
		copy(w[:], b[i*32:end])
		stateDB.SetState(poolManagerAddr9999, stageSlotKey(prefix, seq, i+1), w)
	}
}

func readBytesFromSlots(stateDB stateKV, prefix []byte, seq uint64) []byte {
	lenWord := stateDB.GetState(poolManagerAddr9999, stageSlotKey(prefix, seq, 0))
	n := int(bytesToU64(lenWord[24:32]))
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	for i := 0; i*32 < n; i++ {
		w := stateDB.GetState(poolManagerAddr9999, stageSlotKey(prefix, seq, i+1))
		end := (i + 1) * 32
		if end > n {
			end = n
		}
		copy(out[i*32:end], w[:end-i*32])
	}
	return out
}

func bytesToU64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// AtomicStateReader is the EXPORTED read-only state surface the host needs to
// flush staged atomic ops at block accept. The cEVM's *state.StateDB satisfies it
// (its GetState(addr, key) returns the slot value). It is read-only because the
// flush MUST NOT mutate the accepted state (the state root is fixed at production);
// the deterministic seq window (parent->current) selects each block's ops instead.
type AtomicStateReader interface {
	GetState(addr common.Address, key common.Hash) common.Hash
}

// roStateKV adapts an AtomicStateReader to the internal stateKV (SetState is a
// no-op — the flush is read-only). The staging readers never call SetState.
type roStateKV struct{ r AtomicStateReader }

func (k roStateKV) GetState(addr common.Address, key common.Hash) common.Hash {
	return k.r.GetState(addr, key)
}
func (roStateKV) SetState(common.Address, common.Hash, common.Hash) {}

// Flush errors (each FAILS block accept — a malformed/regressed staged op must
// never be silently skipped, or value could move inconsistently with consensus).
var (
	ErrAtomicSeqRegression = errors.New("dex: staged atomic seq regressed (current < parent) — fatal")
	ErrStagedOpMalformed   = errors.New("dex: staged atomic op is malformed (version/length) — fatal")
)

// ReadStagedAtomicSeq reads the monotonic staging sequence at a state view. It is
// the CONSENSUS-DERIVED flush boundary: the parent block's seq and the accepted
// block's seq bracket exactly the ops THIS block staged, identically on every
// validator (the counter is part of the state root). A node-local marker is only a
// crash optimization, never the source of truth.
func ReadStagedAtomicSeq(state AtomicStateReader) uint64 {
	return stageSeq(roStateKV{r: state})
}

// CollectStagedAtomic reads ALL staged atomic ops (window [0, current)). Test-
// harness convenience; production uses CollectStagedAtomicRange over the parent->
// current window.
func CollectStagedAtomic(stateDB stateKV) map[ids.ID]*atomic.Requests {
	reqs, err := collectRange(stateDB, 0, stageSeq(stateDB))
	if err != nil {
		// Test-only path; a malformed op here is a test bug.
		panic(err)
	}
	return reqs
}

// CollectStagedAtomicRange reads staged atomic ops in the half-open window
// [fromSeq, toSeq) out of a (committed) state view, in deterministic seq order, and
// returns them as an atomic.Requests map ready for sm.Apply. It FAILS (returns an
// error the caller turns into a fatal block-accept error) on a malformed staged op
// — never silently skips one. fromSeq/toSeq are read from consensus state (parent
// and current seq), so every validator derives the identical request set.
//
// WHY A WINDOW (not clear-after-flush): the staged records live in EVM STATE (part
// of the state root, fixed at block production), so they CANNOT be cleared post-
// accept without changing the root. They are append-only consensus audit data; the
// parent->current seq window selects each block's ops.
//
// ATOMICITY: the staged ops live in StateDB, so a reverted tx's staging was already
// discarded by the EVM snapshot/revert — the window only ever yields ops from
// COMMITTED txs. Shared memory mutates iff the staging tx committed AND the block
// was accepted.
func CollectStagedAtomicRange(state AtomicStateReader, fromSeq, toSeq uint64) (map[ids.ID]*atomic.Requests, error) {
	return collectRange(roStateKV{r: state}, fromSeq, toSeq)
}

func collectRange(stateDB stateKV, fromSeq, toSeq uint64) (map[ids.ID]*atomic.Requests, error) {
	if toSeq <= fromSeq {
		return nil, nil
	}
	out := make(map[ids.ID]*atomic.Requests)
	forChain := func(id ids.ID) *atomic.Requests {
		r, ok := out[id]
		if !ok {
			r = &atomic.Requests{}
			out[id] = r
		}
		return r
	}
	for i := fromSeq; i < toSeq; i++ {
		kindWord := stateDB.GetState(poolManagerAddr9999, stageKindKey(i))
		switch kindWord[31] {
		case stageKindPut:
			rec := readBytesFromSlots(stateDB, stagePutPrefix, i)
			// version(1)|dChainID(32)|key(32)|object(>=60). Reject malformed (fatal).
			if len(rec) < 1+32+32+exportedOutputSize9999 || rec[0] != stagedOpVersion {
				return nil, ErrStagedOpMalformed
			}
			var dChainID, key ids.ID
			copy(dChainID[:], rec[1:33])
			copy(key[:], rec[33:65])
			object := rec[65:]
			// The object must be a well-formed atomic value (owner|asset|amount).
			if _, _, _, ok := decodeAtomicObject(object); !ok {
				return nil, ErrStagedOpMalformed
			}
			var owner common.Address
			copy(owner[:], object[0:20])
			req := forChain(dChainID)
			req.PutRequests = append(req.PutRequests, &atomic.Element{
				Key:    append([]byte(nil), key[:]...),
				Value:  append([]byte(nil), object...),
				Traits: [][]byte{append([]byte(nil), owner[:]...)},
			})
		case stageKindRemove:
			rec := readBytesFromSlots(stateDB, stageRemovePrefix, i)
			if len(rec) < 1+32+32 || rec[0] != stagedOpVersion {
				return nil, ErrStagedOpMalformed
			}
			var dChainID, key ids.ID
			copy(dChainID[:], rec[1:33])
			copy(key[:], rec[33:65])
			req := forChain(dChainID)
			req.RemoveRequests = append(req.RemoveRequests, append([]byte(nil), key[:]...))
		default:
			// A seq slot in the window with no recognizable kind is malformed.
			return nil, ErrStagedOpMalformed
		}
	}
	return out, nil
}

// FlushAcceptedAtomicOps is the HOST's block-accept cross-domain commit. It derives
// the flush window from CONSENSUS STATE — the parent block's staged seq and the
// accepted block's staged seq — collects that window's ops, and applies them to
// shared memory in the SAME database batch as the accepted EVM state commit, so the
// EVM state and the shared-memory mutation are ALL-OR-NOTHING (the platformvm
// acceptor pattern; never EVM-first-then-SM-later).
//
//	from := ReadStagedAtomicSeq(parentState)   // parent's high-water (consensus)
//	to   := ReadStagedAtomicSeq(currentState)  // accepted block's high-water
//	ops  := window [from, to)                  // exactly THIS block's staged ops
//	sm.Apply(ops, batch)                        // atomic with the state commit
//
// It REJECTS a seq regression (to < from) as fatal — that can only mean state
// corruption or a reorg the accept path must not paper over. batch may be nil in a
// single-chain dev harness; then the ops still apply (or no-op if sm is nil).
func FlushAcceptedAtomicOps(parentState, currentState AtomicStateReader, sm atomic.SharedMemory, batch database.Batch) error {
	from := ReadStagedAtomicSeq(parentState)
	to := ReadStagedAtomicSeq(currentState)
	if to < from {
		return ErrAtomicSeqRegression
	}
	reqs, err := CollectStagedAtomicRange(currentState, from, to)
	if err != nil {
		return err // malformed staged op — fatal block accept.
	}
	if len(reqs) == 0 || sm == nil {
		return nil
	}
	if batch != nil {
		return sm.Apply(reqs, batch)
	}
	return sm.Apply(reqs)
}

// ClearStagedAtomic zeroes the staged slots. It is the TEST-HARNESS reset (a mock
// StateDB has no immutable state-root constraint). Production does NOT clear staged
// records — they are immutable state history; the seq window (CollectStagedAtomic-
// Since) advances instead. Kept here only for the test harness.
func ClearStagedAtomic(stateDB stateKV) {
	seq := stageSeq(stateDB)
	for i := uint64(0); i < seq; i++ {
		kindWord := stateDB.GetState(poolManagerAddr9999, stageKindKey(i))
		var prefix []byte
		switch kindWord[31] {
		case stageKindPut:
			prefix = stagePutPrefix
		case stageKindRemove:
			prefix = stageRemovePrefix
		default:
			continue
		}
		// Clear the length word + data words + kind.
		lenWord := stateDB.GetState(poolManagerAddr9999, stageSlotKey(prefix, i, 0))
		n := int(bytesToU64(lenWord[24:32]))
		stateDB.SetState(poolManagerAddr9999, stageSlotKey(prefix, i, 0), common.Hash{})
		for w := 0; w*32 < n; w++ {
			stateDB.SetState(poolManagerAddr9999, stageSlotKey(prefix, i, w+1), common.Hash{})
		}
		stateDB.SetState(poolManagerAddr9999, stageKindKey(i), common.Hash{})
	}
	setStageSeq(stateDB, 0)
}
