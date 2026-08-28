// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"github.com/luxfi/database"
	"github.com/luxfi/geth/common"
)

// core_store.go is the bridge between dexcore (the shared deterministic DEX core,
// which reads/writes its ledger/book/router state over a generic key/value Store)
// and the cEVM 0x9999 storage namespace. It implements dexcore.Store —
// database.KeyValueReaderWriterDeleter + database.Iteratee — over the 0x9999
// account's EVM storage trie, so EVERY dexcore write is a 0x9999 StateDB write and
// is therefore committed by the cEVM block's own state root, in the SAME batch the
// EVM balance writes commit. That is what makes the joint C+D commit atomic and
// total: there is no second store and no shared-memory leg.
//
// THE TWO HARD PARTS, both grounded in existing 0x9999 patterns:
//
//  1. Arbitrary-length values over fixed 32-byte EVM slots: reuse the proven
//     writeBytesToSlots/readBytesFromSlots multi-slot record (native_staging.go) —
//     slot 0 holds the length, slots 1.. hold the data words. A length of 0 means
//     "absent" (dexcore never stores an empty value: a uint64 is 8 bytes, a row is
//     fixed-width, and a zeroed ledger row is DELETED), so present <=> length > 0.
//
//  2. Prefix iteration (EVM storage has none): dexcore iterates exactly ONE prefix —
//     order:<poolID:32> (the book rebuild). The adapter maintains an explicit
//     per-market order-id INDEX as a 0x9999 row, updated transparently whenever a
//     order:<poolID><orderID> key is Put/Deleted, so dexcore stays unaware. The
//     index is itself EVM state (committed by the block root, reverted by snapshots),
//     so it is consensus-shared and reorg-safe.

// coreStoreNamespace is the storage-key prefix for dexcore's KV rows under 0x9999.
// It is DISTINCT from the async-seam records (intent/settled/seam/cpos) so the two
// surfaces never collide on a slot; the synchronous router lives entirely in this
// region.
const coreStoreNamespace = settleStateNamespace + "core."

var (
	coreKVPrefix    = []byte(coreStoreNamespace + "kv.")   // per dexcore key -> value slots
	coreIndexPrefix = []byte(coreStoreNamespace + "oidx.") // per-market order-id index
	coreOrderPrefix = []byte("order:")                     // dexcore order-row key prefix
)

// evmStore implements dexcore.Store over the 0x9999 EVM storage trie via stateKV
// (GetState/SetState). It holds no state of its own — every byte lives in the trie.
type evmStore struct {
	sdb stateKV
}

// newEVMStore binds a dexcore Store to the 0x9999 storage of the given StateDB view.
func newEVMStore(sdb stateKV) *evmStore { return &evmStore{sdb: sdb} }

// --- value slot keying (multi-slot record per dexcore key) ---

// valueSlot returns the storage slot for word `word` of the value at dexcore key
// `key`. word 0 is the length word; words 1.. are the data. The slot is a blake3
// digest of (coreKVPrefix, key, word) so distinct keys/words never collide.
func (s *evmStore) valueSlot(key []byte, word int) common.Hash {
	id := make([]byte, 0, len(key)+8)
	id = append(id, key...)
	var w [8]byte
	putU64(w[:], uint64(word))
	id = append(id, w[:]...)
	return makeStorageKey(coreKVPrefix, id)
}

// Get returns the value at key, or database.ErrNotFound when absent (length 0).
func (s *evmStore) Get(key []byte) ([]byte, error) {
	lenWord := s.sdb.GetState(poolManagerAddr9999, s.valueSlot(key, 0))
	n, ok := slotLen(lenWord)
	if !ok {
		return nil, database.ErrNotFound
	}
	out := make([]byte, n)
	for i := 0; i*32 < n; i++ {
		w := s.sdb.GetState(poolManagerAddr9999, s.valueSlot(key, i+1))
		end := (i + 1) * 32
		if end > n {
			end = n
		}
		copy(out[i*32:end], w[:end-i*32])
	}
	return out, nil
}

// Has reports whether key has a present (non-empty) value.
func (s *evmStore) Has(key []byte) (bool, error) {
	lenWord := s.sdb.GetState(poolManagerAddr9999, s.valueSlot(key, 0))
	return bytesToU64(lenWord[24:32]) != 0, nil
}

// Put writes value at key across length+data slots and, when key is an order row,
// adds the order to its market's iteration index. dexcore never Puts an empty value
// (a zeroed ledger row is Deleted, not Put), so a present length is always > 0.
func (s *evmStore) Put(key []byte, value []byte) error {
	var lenWord common.Hash
	putU64(lenWord[24:32], uint64(len(value)))
	s.sdb.SetState(poolManagerAddr9999, s.valueSlot(key, 0), lenWord)
	for i := 0; i*32 < len(value); i++ {
		var w common.Hash
		end := (i + 1) * 32
		if end > len(value) {
			end = len(value)
		}
		copy(w[:], value[i*32:end])
		s.sdb.SetState(poolManagerAddr9999, s.valueSlot(key, i+1), w)
	}
	if poolID, orderID, ok := parseOrderKey(key); ok {
		s.indexAdd(poolID, orderID)
	}
	return nil
}

// Delete removes key by zeroing its length slot (present <=> length > 0; stale data
// slots are never read). When key is an order row, removes it from the market index.
func (s *evmStore) Delete(key []byte) error {
	var zero common.Hash
	s.sdb.SetState(poolManagerAddr9999, s.valueSlot(key, 0), zero)
	if poolID, orderID, ok := parseOrderKey(key); ok {
		s.indexRemove(poolID, orderID)
	}
	return nil
}

// --- per-market order-id index (the prefix-iteration backing) ---

// indexSlot returns the storage slot for word `word` of the order-id index of
// market poolID. word 0 holds the count; words 1.. hold 4 packed uint64 ids each
// (32 bytes / 8). The index is a packed, append-with-tombstone-compaction list.
func (s *evmStore) indexSlot(poolID [32]byte, word int) common.Hash {
	id := make([]byte, 0, 40)
	id = append(id, poolID[:]...)
	var w [8]byte
	putU64(w[:], uint64(word))
	id = append(id, w[:]...)
	return makeStorageKey(coreIndexPrefix, id)
}

// indexIDs reads the current order-id list for poolID.
func (s *evmStore) indexIDs(poolID [32]byte) []uint64 {
	countWord := s.sdb.GetState(poolManagerAddr9999, s.indexSlot(poolID, 0))
	n, ok := slotLen(countWord)
	if !ok {
		return nil
	}
	ids := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		word := i/4 + 1
		off := (i % 4) * 8
		w := s.sdb.GetState(poolManagerAddr9999, s.indexSlot(poolID, word))
		ids = append(ids, bytesToU64(w[off:off+8]))
	}
	return ids
}

// indexWrite persists the order-id list for poolID (count + packed words).
func (s *evmStore) indexWrite(poolID [32]byte, ids []uint64) {
	var countWord common.Hash
	putU64(countWord[24:32], uint64(len(ids)))
	s.sdb.SetState(poolManagerAddr9999, s.indexSlot(poolID, 0), countWord)
	// Write the packed data words. We must also clear any trailing words from a prior
	// longer list so a shrink doesn't leave stale ids readable past the new count —
	// but indexIDs reads exactly `count` ids, so trailing stale words are never read.
	for i := 0; i*4 < len(ids); i++ {
		var w common.Hash
		for j := 0; j < 4 && i*4+j < len(ids); j++ {
			putU64(w[j*8:j*8+8], ids[i*4+j])
		}
		s.sdb.SetState(poolManagerAddr9999, s.indexSlot(poolID, i+1), w)
	}
}

// indexAdd adds orderID to poolID's index (idempotent — a re-Put of the same row,
// which the EVM does across a tx's repeated executions, does not duplicate).
func (s *evmStore) indexAdd(poolID [32]byte, orderID uint64) {
	ids := s.indexIDs(poolID)
	for _, id := range ids {
		if id == orderID {
			return // already present
		}
	}
	s.indexWrite(poolID, append(ids, orderID))
}

// indexRemove removes orderID from poolID's index (no-op if absent).
func (s *evmStore) indexRemove(poolID [32]byte, orderID uint64) {
	ids := s.indexIDs(poolID)
	out := ids[:0:0]
	found := false
	for _, id := range ids {
		if id == orderID {
			found = true
			continue
		}
		out = append(out, id)
	}
	if !found {
		return
	}
	s.indexWrite(poolID, out)
}

// --- prefix iteration (the single prefix dexcore iterates: order:<poolID:32>) ---

// NewIteratorWithPrefix supports dexcore's ONLY iterated prefix: order:<poolID:32>.
// It reads the market's order-id index and yields each (order:<poolID><orderID>,
// value) pair. Any other prefix yields an empty iterator (dexcore iterates no other
// prefix; a non-order prefix is therefore correctly empty rather than a silent
// full-scan the EVM trie cannot provide).
func (s *evmStore) NewIteratorWithPrefix(prefix []byte) database.Iterator {
	if poolID, ok := parseOrderPrefix(prefix); ok {
		ids := s.indexIDs(poolID)
		return &evmOrderIterator{store: s, poolID: poolID, ids: ids, pos: -1}
	}
	return &database.IteratorError{Err: nil} // empty (no error): no rows under this prefix
}

// NewIteratorWithStartAndPrefix delegates to the prefix iterator. dexcore's book
// rebuild does not use a start key (it folds the whole market), so start is ignored;
// the order:<poolID> prefix fully determines the set.
func (s *evmStore) NewIteratorWithStartAndPrefix(_ []byte, prefix []byte) database.Iterator {
	return s.NewIteratorWithPrefix(prefix)
}

// NewIterator / NewIteratorWithStart are required by database.Iteratee but are NOT
// used by dexcore (which only ever iterates the order:<poolID> prefix). A full-
// keyspace scan over the EVM trie is not available and not needed, so these return
// an empty iterator rather than pretend to scan.
func (s *evmStore) NewIterator() database.Iterator { return &database.IteratorError{Err: nil} }
func (s *evmStore) NewIteratorWithStart(_ []byte) database.Iterator {
	return &database.IteratorError{Err: nil}
}

// evmOrderIterator yields the (key, value) pairs of one market's resting order rows
// in index order. It reads each row's value lazily on Value().
type evmOrderIterator struct {
	store  *evmStore
	poolID [32]byte
	ids    []uint64
	pos    int
	curKey []byte
	curVal []byte
	err    error
}

func (it *evmOrderIterator) Next() bool {
	it.pos++
	if it.pos >= len(it.ids) {
		it.curKey, it.curVal = nil, nil
		return false
	}
	it.curKey = orderRowKey(it.poolID, it.ids[it.pos])
	v, err := it.store.Get(it.curKey)
	if err != nil {
		// A row in the index with no value is a deleted-but-not-deindexed row; skip it
		// (defensive — Delete deindexes, so this is not a normal path). Advance.
		return it.Next()
	}
	it.curVal = v
	return true
}

func (it *evmOrderIterator) Error() error  { return it.err }
func (it *evmOrderIterator) Key() []byte   { return it.curKey }
func (it *evmOrderIterator) Value() []byte { return it.curVal }
func (it *evmOrderIterator) Release()      {}

// --- order-key parsing (the index trigger) ---

// orderRowKey rebuilds the dexcore order:<poolID:32><orderID:8> key for iteration.
func orderRowKey(poolID [32]byte, orderID uint64) []byte {
	k := make([]byte, len(coreOrderPrefix)+32+8)
	copy(k, coreOrderPrefix)
	copy(k[len(coreOrderPrefix):], poolID[:])
	putU64(k[len(coreOrderPrefix)+32:], orderID)
	return k
}

// parseOrderKey reports whether key is a dexcore order row (order:<poolID:32>
// <orderID:8>) and returns its (poolID, orderID).
func parseOrderKey(key []byte) (poolID [32]byte, orderID uint64, ok bool) {
	if len(key) != len(coreOrderPrefix)+32+8 {
		return poolID, 0, false
	}
	if string(key[:len(coreOrderPrefix)]) != string(coreOrderPrefix) {
		return poolID, 0, false
	}
	copy(poolID[:], key[len(coreOrderPrefix):len(coreOrderPrefix)+32])
	orderID = bytesToU64(key[len(coreOrderPrefix)+32:])
	return poolID, orderID, true
}

// parseOrderPrefix reports whether prefix is order:<poolID:32> and returns poolID.
func parseOrderPrefix(prefix []byte) (poolID [32]byte, ok bool) {
	if len(prefix) != len(coreOrderPrefix)+32 {
		return poolID, false
	}
	if string(prefix[:len(coreOrderPrefix)]) != string(coreOrderPrefix) {
		return poolID, false
	}
	copy(poolID[:], prefix[len(coreOrderPrefix):])
	return poolID, true
}
