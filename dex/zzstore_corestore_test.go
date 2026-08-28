// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/luxfi/database"
	"github.com/luxfi/geth/common"
)

// zzstore_corestore_test.go covers core_store.go — the dexcore Store over the
// 0x9999 EVM storage trie. Every byte dexcore writes lands in the block's state
// root through this file, so a length/offset mistake here is not a bug in a
// cache: it is a state root that differs between two honest nodes, i.e. a fork.
//
// The properties asserted, in order of how much they matter:
//
//  1. ROUND-TRIP EXACTNESS. Put(k,v) then Get(k) returns v, byte for byte, for
//     every length that straddles the 32-byte word boundary and for all-zero,
//     all-ones and random payloads.
//  2. SLOT INJECTIVITY. Two distinct (key, word) pairs never name the same slot,
//     and the value namespace never collides with the order-index namespace. A
//     collision is two dexcore rows sharing storage.
//  3. DETERMINISM. The same logical content written in a different ORDER leaves
//     an identical slot set. Iteration over a market yields the same sequence
//     every time. Both are consensus properties, not conveniences.
//  4. REFUSAL. Every truncation and every corruption of an order key is rejected
//     rather than half-parsed, and nothing panics on a short or nil key.

// zzstSeed is the ONE explicit deterministic seed for every randomised test in
// this file set. A consensus serializer test that varies run to run turns a real
// encoding fork into an intermittent CI failure nobody trusts, so the seed is
// fixed and written down. Change it only deliberately.
const zzstSeed int64 = 0x5EEDC0DE1234

// zzstFill writes deterministic pseudo-random bytes into b from rng.
func zzstFill(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
}

// zzstStore builds an evmStore over a fresh MockStateDB (which satisfies stateKV
// with the adapter-shaped SetState the store needs).
func zzstStore() (*MockStateDB, *evmStore) {
	sdb := NewMockStateDB()
	return sdb, newEVMStore(sdb)
}

// zzstFingerprint renders the 0x9999 storage a store produced as a canonical,
// order-independent string. Zero-valued slots are omitted because the EVM cannot
// distinguish a slot written to zero from one never written — which is exactly
// how Delete erases a row.
func zzstFingerprint(m *MockStateDB) string {
	lines := make([]string, 0, len(m.states[poolManagerAddr9999]))
	for k, v := range m.states[poolManagerAddr9999] {
		if v == (common.Hash{}) {
			continue
		}
		lines = append(lines, k.Hex()+"="+v.Hex())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// zzstIndexFingerprint renders the order-index words of one market — the count
// word plus the first 16 packed words, which covers 64 resting orders.
func zzstIndexFingerprint(m *MockStateDB, st *evmStore, poolID [32]byte) string {
	var b strings.Builder
	for w := 0; w <= 16; w++ {
		fmt.Fprintf(&b, "%d=%s ", w, m.GetState(poolManagerAddr9999, st.indexSlot(poolID, w)).Hex())
	}
	return b.String()
}

// zzstPoolID builds a recognisable 32-byte market id.
func zzstPoolID(n byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = n
	}
	return id
}

// =========================================================================
// 1. Round-trip exactness
// =========================================================================

func TestZzstStoreValueRoundTripEveryLength(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed))
	sdb, st := zzstStore()

	// 0..200 covers every 32-byte word boundary (32/64/96/128/160/192) and both
	// neighbours of each — where an off-by-one in the word loop lives — plus the
	// large multi-word records a book row can reach.
	lens := make([]int, 0, 210)
	for n := 0; n <= 200; n++ {
		lens = append(lens, n)
	}
	lens = append(lens, 255, 256, 257, 1024, 4096, 4097)

	for _, n := range lens {
		key := []byte(fmt.Sprintf("row/%d", n))
		val := make([]byte, n)
		zzstFill(rng, val)

		if err := st.Put(key, val); err != nil {
			t.Fatalf("Put(len=%d): %v", n, err)
		}

		got, err := st.Get(key)
		has, herr := st.Has(key)
		if herr != nil {
			t.Fatalf("Has(len=%d) returned an error: %v", n, herr)
		}

		if n == 0 {
			// present <=> length > 0: a zero-length value is ABSENT by construction.
			if !errors.Is(err, database.ErrNotFound) {
				t.Fatalf("Get of a zero-length Put: want ErrNotFound, got (%v, %v)", got, err)
			}
			if has {
				t.Fatalf("Has of a zero-length Put = true, want false")
			}
			continue
		}
		if err != nil {
			t.Fatalf("Get(len=%d): %v", n, err)
		}
		if !has {
			t.Fatalf("Has(len=%d) = false after Put", n)
		}
		if len(got) != n {
			t.Fatalf("Get(len=%d) returned %d bytes", n, len(got))
		}
		if !bytes.Equal(got, val) {
			t.Fatalf("Get(len=%d) round-trip differs:\n want %x\n  got %x", n, val, got)
		}
	}
	_ = sdb
}

func TestZzstStoreValueRoundTripExtremeBytes(t *testing.T) {
	_, st := zzstStore()

	cases := map[string][]byte{
		"one zero byte":      {0x00},
		"one 0xff byte":      {0xff},
		"all zero, 1 word":   make([]byte, 32),
		"all zero, 3 words":  make([]byte, 96),
		"all zero, ragged":   make([]byte, 33),
		"all ones, 1 word":   bytes.Repeat([]byte{0xff}, 32),
		"all ones, ragged":   bytes.Repeat([]byte{0xff}, 65),
		"zero then one word": append(make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)...),
		"one word then zero": append(bytes.Repeat([]byte{0xff}, 32), make([]byte, 32)...),
	}
	for name, want := range cases {
		key := []byte("x/" + name)
		if err := st.Put(key, want); err != nil {
			t.Fatalf("%s: Put: %v", name, err)
		}
		got, err := st.Get(key)
		if err != nil {
			t.Fatalf("%s: Get: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: round-trip differs:\n want %x\n  got %x", name, want, got)
		}
	}
}

// A shrink must not leak the previous, longer value. The store never clears the
// stale data slots — it relies on the length word alone — so this is the test
// that pins that reliance as correct.
func TestZzstStoreValueShrinkDoesNotLeakStaleTail(t *testing.T) {
	_, st := zzstStore()
	key := []byte("shrink")

	long := bytes.Repeat([]byte{0xAB}, 200)
	if err := st.Put(key, long); err != nil {
		t.Fatalf("Put long: %v", err)
	}
	short := []byte{0x01, 0x02, 0x03}
	if err := st.Put(key, short); err != nil {
		t.Fatalf("Put short: %v", err)
	}

	got, err := st.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, short) {
		t.Fatalf("shrink leaked the old tail: want %x, got %x", short, got)
	}

	// And a re-grow must read the NEW bytes in every word, not the survivors of
	// the first write.
	regrown := bytes.Repeat([]byte{0xCD}, 200)
	if err := st.Put(key, regrown); err != nil {
		t.Fatalf("Put regrown: %v", err)
	}
	got, err = st.Get(key)
	if err != nil {
		t.Fatalf("Get regrown: %v", err)
	}
	if !bytes.Equal(got, regrown) {
		t.Fatalf("regrow read stale words:\n want %x\n  got %x", regrown, got)
	}
}

func TestZzstStoreDeleteThenGetIsAbsent(t *testing.T) {
	_, st := zzstStore()
	key := []byte("gone")

	if err := st.Put(key, []byte("value")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(key); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}
	if has, _ := st.Has(key); has {
		t.Fatalf("Has after Delete = true")
	}
	// Deleting twice is a no-op, not an error.
	if err := st.Delete(key); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	// A re-Put after Delete must be fully readable again.
	if err := st.Put(key, []byte("back")); err != nil {
		t.Fatalf("re-Put: %v", err)
	}
	got, err := st.Get(key)
	if err != nil || !bytes.Equal(got, []byte("back")) {
		t.Fatalf("re-Put/Get = (%q, %v), want (\"back\", nil)", got, err)
	}
}

func TestZzstStoreAbsentKeyAndNilKeyDoNotPanic(t *testing.T) {
	_, st := zzstStore()

	for _, key := range [][]byte{nil, {}, []byte("never-written"), bytes.Repeat([]byte{0}, 1024)} {
		if _, err := st.Get(key); !errors.Is(err, database.ErrNotFound) {
			t.Fatalf("Get(%x) on absent key: want ErrNotFound, got %v", key, err)
		}
		has, err := st.Has(key)
		if err != nil || has {
			t.Fatalf("Has(%x) = (%v, %v), want (false, nil)", key, has, err)
		}
		if err := st.Delete(key); err != nil {
			t.Fatalf("Delete(%x): %v", key, err)
		}
	}
}

// =========================================================================
// 2. Slot injectivity — two rows must never share storage
// =========================================================================

// valueSlot appends a fixed-width 8-byte word number to the key, so the id length
// determines the split point and (key, word) is recoverable. This test states that
// as an assertion over adversarial neighbours: keys that are prefixes of each
// other, and keys whose tail is exactly a word number.
func TestZzstStoreValueSlotIsInjective(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 1))
	_, st := zzstStore()

	type ref struct {
		key  string
		word int
	}
	seen := map[common.Hash]ref{}

	// nil and []byte{} are the SAME key (both empty), so the list carries only one.
	keys := [][]byte{
		nil, []byte("a"), []byte("aa"), []byte("aaa"), []byte("ab"), []byte("b"),
		{'a', 0, 0, 0, 0, 0, 0, 0, 0},
		{'a', 0, 0, 0, 0, 0, 0, 0, 1},
		{'a', 0, 0, 0, 0, 0, 0, 0, 2},
		[]byte("order:"), orderRowKey(zzstPoolID(0x11), 1), orderRowKey(zzstPoolID(0x11), 2),
	}
	for i := 0; i < 64; i++ {
		k := make([]byte, 4+rng.Intn(37))
		zzstFill(rng, k)
		keys = append(keys, k)
	}

	// Distinct keys only — two spellings of the same key are meant to share a slot.
	distinct := keys[:0:0]
	dedupe := map[string]bool{}
	for _, k := range keys {
		if dedupe[string(k)] {
			continue
		}
		dedupe[string(k)] = true
		distinct = append(distinct, k)
	}
	keys = distinct

	for _, k := range keys {
		for w := 0; w < 6; w++ {
			slot := st.valueSlot(k, w)
			if prev, dup := seen[slot]; dup {
				t.Fatalf("valueSlot COLLISION: (%x, word %d) and (%q, word %d) share slot %s",
					k, w, prev.key, prev.word, slot.Hex())
			}
			seen[slot] = ref{key: string(k), word: w}
		}
	}
}

func TestZzstStoreIndexSlotIsInjective(t *testing.T) {
	_, st := zzstStore()
	seen := map[common.Hash]string{}
	for _, p := range []byte{0x00, 0x01, 0x02, 0xfe, 0xff} {
		poolID := zzstPoolID(p)
		for w := 0; w < 8; w++ {
			slot := st.indexSlot(poolID, w)
			ref := fmt.Sprintf("pool %x word %d", poolID[:2], w)
			if prev, dup := seen[slot]; dup {
				t.Fatalf("indexSlot COLLISION: %s and %s share slot %s", ref, prev, slot.Hex())
			}
			seen[slot] = ref
		}
	}
}

// The value namespace and the order-index namespace are separate regions of the
// same account. If they ever met, an index word would be read as a row length.
func TestZzstStoreValueAndIndexNamespacesNeverCollide(t *testing.T) {
	_, st := zzstStore()

	index := map[common.Hash]bool{}
	for _, p := range []byte{0x00, 0x01, 0x7f, 0xff} {
		poolID := zzstPoolID(p)
		for w := 0; w < 16; w++ {
			index[st.indexSlot(poolID, w)] = true
		}
	}
	for _, p := range []byte{0x00, 0x01, 0x7f, 0xff} {
		poolID := zzstPoolID(p)
		for id := uint64(0); id < 16; id++ {
			key := orderRowKey(poolID, id)
			for w := 0; w < 16; w++ {
				if index[st.valueSlot(key, w)] {
					t.Fatalf("value slot for (pool %x, order %d, word %d) collides with the order index",
						poolID[:2], id, w)
				}
			}
		}
	}
}

// =========================================================================
// 3. Determinism — the fork-shaped property
// =========================================================================

// Plain KV rows carry no ordering: writing the SAME content in a different order
// must leave an identical slot set, because each row is a self-contained record at
// a slot derived only from its key. Anything else would make the state root depend
// on how a block's writes happened to interleave.
func TestZzstStoreWriteOrderDoesNotChangeState(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 2))

	type row struct {
		key []byte
		val []byte
	}
	rows := make([]row, 0, 48)
	for i := 0; i < 48; i++ {
		k := make([]byte, 4+rng.Intn(20))
		zzstFill(rng, k)
		v := make([]byte, 1+rng.Intn(96))
		zzstFill(rng, v)
		rows = append(rows, row{key: k, val: v})
	}

	writeAll := func(order []int) string {
		sdb, st := zzstStore()
		for _, i := range order {
			if err := st.Put(rows[i].key, rows[i].val); err != nil {
				t.Fatalf("Put: %v", err)
			}
		}
		return zzstFingerprint(sdb)
	}

	forward := make([]int, len(rows))
	for i := range forward {
		forward[i] = i
	}
	want := writeAll(forward)

	reverse := make([]int, len(rows))
	for i := range reverse {
		reverse[i] = len(rows) - 1 - i
	}
	if got := writeAll(reverse); got != want {
		t.Fatalf("reverse write order produced a DIFFERENT slot set for order-free KV rows")
	}
	for trial := 0; trial < 8; trial++ {
		if got := writeAll(rng.Perm(len(rows))); got != want {
			t.Fatalf("shuffled write order (trial %d) produced a DIFFERENT slot set for order-free KV rows", trial)
		}
	}
}

// Order rows DO carry an order: the per-market index is an append list, so the
// insertion sequence is part of the state by design. Two properties follow, and
// both are consensus properties.
//
//  1. Replaying the SAME sequence is byte-identical, every time. (Every node
//     replays a block's transactions in the same order, so this is what makes two
//     honest nodes agree.)
//  2. A different insertion sequence holds the same SET of orders and yields a
//     self-consistent index — the book is complete however it was built.
func TestZzstStoreOrderRowsAreInsertionOrderedAndComplete(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 6))
	poolID := zzstPoolID(0xA1)

	const n = 21
	vals := make([][]byte, n)
	for i := range vals {
		vals[i] = make([]byte, 1+rng.Intn(70))
		zzstFill(rng, vals[i])
	}

	writeSeq := func(order []int) (*MockStateDB, *evmStore) {
		sdb, st := zzstStore()
		for _, i := range order {
			if err := st.Put(orderRowKey(poolID, uint64(i)), vals[i]); err != nil {
				t.Fatalf("Put: %v", err)
			}
		}
		return sdb, st
	}

	forward := make([]int, n)
	for i := range forward {
		forward[i] = i
	}

	// (1) Same sequence, 32 replays, byte-identical.
	base, _ := writeSeq(forward)
	want := zzstFingerprint(base)
	for trial := 0; trial < 32; trial++ {
		sdb, _ := writeSeq(forward)
		if zzstFingerprint(sdb) != want {
			t.Fatalf("replay %d of the same write sequence produced different storage — "+
				"the encoding is not deterministic", trial)
		}
	}

	// (2) Any sequence holds the whole book and an index that agrees with the rows.
	for trial := 0; trial < 8; trial++ {
		perm := rng.Perm(n)
		_, st := writeSeq(perm)
		ids := st.indexIDs(poolID)
		if len(ids) != n {
			t.Fatalf("trial %d: index holds %d ids, want %d", trial, len(ids), n)
		}
		seen := map[uint64]bool{}
		for pos, id := range ids {
			if seen[id] {
				t.Fatalf("trial %d: order %d indexed twice", trial, id)
			}
			seen[id] = true
			if id != uint64(perm[pos]) {
				t.Fatalf("trial %d: index[%d] = %d, want the %d-th inserted order %d",
					trial, pos, id, pos, perm[pos])
			}
			got, err := st.Get(orderRowKey(poolID, id))
			if err != nil || !bytes.Equal(got, vals[id]) {
				t.Fatalf("trial %d: order %d value = (%x, %v), want %x", trial, id, got, err, vals[id])
			}
		}
	}
}

// Encoding the same value twice must be byte-identical. Repeated many times so a
// map-ordered encoder (Go randomises map range order per iteration) cannot pass.
func TestZzstStorePutIsByteIdenticalAcrossRepeats(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 3))
	val := make([]byte, 137)
	zzstFill(rng, val)
	key := orderRowKey(zzstPoolID(0x5A), 42)

	var want string
	for i := 0; i < 64; i++ {
		sdb, st := zzstStore()
		if err := st.Put(key, val); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got := zzstFingerprint(sdb)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("Put produced different storage on repeat %d — encoding is not deterministic", i)
		}
	}
}

// Reaching a market state by churn (grow to 20 orders, delete back to 9) must be
// READ-INDISTINGUISHABLE from writing those 9 orders directly. The two stores do
// NOT hold identical bytes — Delete zeroes only the length word, and indexWrite
// leaves the trailing packed words of the longer list in place (core_store.go:164
// says so and relies on indexIDs reading exactly `count`). This test pins that
// reliance: everything a reader can reach is equal, and the residue is confined to
// slots no read path touches.
func TestZzstStoreChurnIsReadIndistinguishableFromDirectWrite(t *testing.T) {
	poolID := zzstPoolID(0x33)

	_, dst := zzstStore()
	for i := 0; i < 9; i++ {
		if err := dst.Put(orderRowKey(poolID, uint64(i)), []byte{byte(i)}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	_, cst := zzstStore()
	for i := 0; i < 20; i++ {
		if err := cst.Put(orderRowKey(poolID, uint64(i)), []byte{byte(i)}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	for i := 19; i >= 9; i-- {
		if err := cst.Delete(orderRowKey(poolID, uint64(i))); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	}

	da, ca := dst.indexIDs(poolID), cst.indexIDs(poolID)
	if len(da) != len(ca) {
		t.Fatalf("index lengths differ after churn: direct %v, churned %v", da, ca)
	}
	for i := range da {
		if da[i] != ca[i] {
			t.Fatalf("index[%d] differs after churn: direct %d, churned %d", i, da[i], ca[i])
		}
	}
	for i := 0; i < 30; i++ {
		key := orderRowKey(poolID, uint64(i))
		dv, derr := dst.Get(key)
		cv, cerr := cst.Get(key)
		if !errors.Is(derr, cerr) && (derr != nil || cerr != nil) {
			t.Fatalf("order %d: direct err %v, churned err %v", i, derr, cerr)
		}
		if !bytes.Equal(dv, cv) {
			t.Fatalf("order %d: direct %x, churned %x", i, dv, cv)
		}
		dh, _ := dst.Has(key)
		ch, _ := cst.Has(key)
		if dh != ch {
			t.Fatalf("order %d: Has direct %v, churned %v", i, dh, ch)
		}
	}
	// Iteration — the only surface dexcore rebuilds a book from — must match too.
	prefix := orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32]
	dk, dvals := zzstIterate(t, dst, prefix)
	ck, cvals := zzstIterate(t, cst, prefix)
	if len(dk) != len(ck) {
		t.Fatalf("iteration lengths differ after churn: %d vs %d", len(dk), len(ck))
	}
	for i := range dk {
		if !bytes.Equal(dk[i], ck[i]) || !bytes.Equal(dvals[i], cvals[i]) {
			t.Fatalf("iterated row %d differs after churn", i)
		}
	}
}

// =========================================================================
// 4. The order-id index and its iterator
// =========================================================================

func zzstIterate(t *testing.T, st *evmStore, prefix []byte) (keys [][]byte, vals [][]byte) {
	t.Helper()
	it := st.NewIteratorWithPrefix(prefix)
	defer it.Release()
	for it.Next() {
		keys = append(keys, append([]byte(nil), it.Key()...))
		vals = append(vals, append([]byte(nil), it.Value()...))
	}
	if err := it.Error(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
	return keys, vals
}

func TestZzstStoreOrderIterationYieldsExactlyTheMarket(t *testing.T) {
	_, st := zzstStore()
	poolA, poolB := zzstPoolID(0xAA), zzstPoolID(0xBB)

	// 17 orders crosses the packed-word boundary (4 ids per 32-byte word) four times.
	for i := uint64(0); i < 17; i++ {
		if err := st.Put(orderRowKey(poolA, i), []byte{byte(i), 0xA0}); err != nil {
			t.Fatalf("Put A/%d: %v", i, err)
		}
	}
	for i := uint64(100); i < 105; i++ {
		if err := st.Put(orderRowKey(poolB, i), []byte{byte(i), 0xB0}); err != nil {
			t.Fatalf("Put B/%d: %v", i, err)
		}
	}
	// A non-order row in the same store must not appear in either market.
	if err := st.Put([]byte("ledger:acct"), []byte{0xEE}); err != nil {
		t.Fatalf("Put ledger: %v", err)
	}

	keys, vals := zzstIterate(t, st, orderRowKey(poolA, 0)[:len(coreOrderPrefix)+32])
	if len(keys) != 17 {
		t.Fatalf("market A yielded %d rows, want 17", len(keys))
	}
	for i := uint64(0); i < 17; i++ {
		// Index order is insertion order, and it is EVM state, so it is the same on
		// every node. Assert the exact sequence, not just the set.
		if !bytes.Equal(keys[i], orderRowKey(poolA, i)) {
			t.Fatalf("row %d key = %x, want %x", i, keys[i], orderRowKey(poolA, i))
		}
		if !bytes.Equal(vals[i], []byte{byte(i), 0xA0}) {
			t.Fatalf("row %d value = %x, want %x", i, vals[i], []byte{byte(i), 0xA0})
		}
	}

	keysB, _ := zzstIterate(t, st, orderRowKey(poolB, 0)[:len(coreOrderPrefix)+32])
	if len(keysB) != 5 {
		t.Fatalf("market B yielded %d rows, want 5 — markets are not isolated", len(keysB))
	}
}

func TestZzstStoreIterationIsRepeatableAndOrdered(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0x77)
	ids := []uint64{9, 3, 40, 1, 0, 1 << 63, ^uint64(0), 7}
	for _, id := range ids {
		if err := st.Put(orderRowKey(poolID, id), []byte{0x01}); err != nil {
			t.Fatalf("Put %d: %v", id, err)
		}
	}
	prefix := orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32]

	var want [][]byte
	for trial := 0; trial < 32; trial++ {
		keys, _ := zzstIterate(t, st, prefix)
		if trial == 0 {
			want = keys
			if len(want) != len(ids) {
				t.Fatalf("yielded %d rows, want %d", len(want), len(ids))
			}
			for i, id := range ids {
				if !bytes.Equal(want[i], orderRowKey(poolID, id)) {
					t.Fatalf("row %d = %x, want order %d — index is not insertion-ordered", i, want[i], id)
				}
			}
			continue
		}
		if len(keys) != len(want) {
			t.Fatalf("trial %d yielded %d rows, want %d", trial, len(keys), len(want))
		}
		for i := range keys {
			if !bytes.Equal(keys[i], want[i]) {
				t.Fatalf("trial %d row %d differs — iteration order is not deterministic", trial, i)
			}
		}
	}
}

func TestZzstStoreIndexAddIsIdempotent(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0x12)
	key := orderRowKey(poolID, 5)

	// The EVM re-executes a tx; a row Put twice must not appear twice.
	for i := 0; i < 5; i++ {
		if err := st.Put(key, []byte{byte(i)}); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	ids := st.indexIDs(poolID)
	if len(ids) != 1 || ids[0] != 5 {
		t.Fatalf("index after 5 identical Puts = %v, want [5]", ids)
	}
	keys, vals := zzstIterate(t, st, key[:len(coreOrderPrefix)+32])
	if len(keys) != 1 {
		t.Fatalf("iteration yielded %d rows after repeated Put, want 1", len(keys))
	}
	if !bytes.Equal(vals[0], []byte{4}) {
		t.Fatalf("value = %x, want the last Put (0x04)", vals[0])
	}
}

func TestZzstStoreIndexRemoveCompactsAcrossWords(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0x21)

	const n = 18 // > 4 words of 4 packed ids
	for i := uint64(0); i < n; i++ {
		if err := st.Put(orderRowKey(poolID, i), []byte{byte(i)}); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	// Remove every third, from the back so the compaction rewrites several words.
	removed := map[uint64]bool{}
	for i := int(n) - 1; i >= 0; i -= 3 {
		if err := st.Delete(orderRowKey(poolID, uint64(i))); err != nil {
			t.Fatalf("Delete %d: %v", i, err)
		}
		removed[uint64(i)] = true
	}

	var want []uint64
	for i := uint64(0); i < n; i++ {
		if !removed[i] {
			want = append(want, i)
		}
	}
	got := st.indexIDs(poolID)
	if len(got) != len(want) {
		t.Fatalf("index after removals = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index[%d] = %d, want %d (order must be preserved by compaction)", i, got[i], want[i])
		}
	}

	// The rows themselves must agree with the index.
	keys, _ := zzstIterate(t, st, orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32])
	if len(keys) != len(want) {
		t.Fatalf("iteration yielded %d rows, index holds %d", len(keys), len(want))
	}

	// Draining the market must leave an empty index, not a stale tail.
	for _, id := range want {
		if err := st.Delete(orderRowKey(poolID, id)); err != nil {
			t.Fatalf("Delete %d: %v", id, err)
		}
	}
	if ids := st.indexIDs(poolID); len(ids) != 0 {
		t.Fatalf("drained market still indexes %v", ids)
	}
	if keys, _ := zzstIterate(t, st, orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32]); len(keys) != 0 {
		t.Fatalf("drained market still iterates %d rows", len(keys))
	}
}

func TestZzstStoreIndexRemoveOfAbsentIsNoOp(t *testing.T) {
	sdb, st := zzstStore()
	poolID := zzstPoolID(0x44)
	for i := uint64(0); i < 3; i++ {
		if err := st.Put(orderRowKey(poolID, i), []byte{byte(i)}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	before := zzstFingerprint(sdb)

	st.indexRemove(poolID, 999) // never added
	if after := zzstFingerprint(sdb); after != before {
		t.Fatalf("removing an absent order id mutated storage")
	}
	// And deleting a row of a DIFFERENT market must not touch this index.
	if err := st.Delete(orderRowKey(zzstPoolID(0x45), 0)); err != nil {
		t.Fatalf("Delete other market: %v", err)
	}
	if ids := st.indexIDs(poolID); len(ids) != 3 {
		t.Fatalf("index = %v after touching another market, want 3 ids", ids)
	}
}

// A non-order key must never touch an index. Delete and Put both gate on
// parseOrderKey; this pins that gate.
func TestZzstStoreNonOrderKeyNeverTouchesAnIndex(t *testing.T) {
	sdb, st := zzstStore()
	poolID := zzstPoolID(0x66)
	if err := st.Put(orderRowKey(poolID, 1), []byte{0x01}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before := zzstIndexFingerprint(sdb, st, poolID)

	// Right length, wrong prefix.
	bad := orderRowKey(poolID, 2)
	copy(bad, "ordeR:")
	// Right prefix, wrong length (one byte short of an order id).
	short := orderRowKey(poolID, 3)[:len(coreOrderPrefix)+32+7]
	// Right prefix and length, but a trailing byte too many.
	long := append(orderRowKey(poolID, 4), 0x00)

	for _, k := range [][]byte{bad, short, long} {
		if err := st.Put(k, []byte{0x02}); err != nil {
			t.Fatalf("Put %x: %v", k, err)
		}
		if err := st.Delete(k); err != nil {
			t.Fatalf("Delete %x: %v", k, err)
		}
	}

	if ids := st.indexIDs(poolID); len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("index = %v after non-order writes, want [1]", ids)
	}
	if after := zzstIndexFingerprint(sdb, st, poolID); after != before {
		t.Fatalf("non-order Put/Delete wrote into the market index:\n before %s\n  after %s", before, after)
	}
	// The market still iterates exactly its one real row.
	keys, _ := zzstIterate(t, st, orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32])
	if len(keys) != 1 || !bytes.Equal(keys[0], orderRowKey(poolID, 1)) {
		t.Fatalf("iteration after non-order writes = %x, want the single order 1", keys)
	}
}

// A row named by the index but with no value is skipped, not surfaced as an empty
// order. Delete de-indexes, so this is the defensive path — it exists precisely
// because a fork here would be silent.
func TestZzstStoreIteratorSkipsIndexedRowsWithNoValue(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0x88)

	// Write the index by hand with ids 0..5, but only give 2 and 5 a value.
	st.indexWrite(poolID, []uint64{0, 1, 2, 3, 4, 5})
	for _, id := range []uint64{2, 5} {
		// Put would re-index (idempotently); that is fine and keeps the order.
		if err := st.Put(orderRowKey(poolID, id), []byte{byte(id)}); err != nil {
			t.Fatalf("Put %d: %v", id, err)
		}
	}

	keys, vals := zzstIterate(t, st, orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32])
	if len(keys) != 2 {
		t.Fatalf("yielded %d rows, want the 2 that have values", len(keys))
	}
	if !bytes.Equal(keys[0], orderRowKey(poolID, 2)) || !bytes.Equal(vals[0], []byte{2}) {
		t.Fatalf("first surviving row = (%x, %x), want order 2", keys[0], vals[0])
	}
	if !bytes.Equal(keys[1], orderRowKey(poolID, 5)) || !bytes.Equal(vals[1], []byte{5}) {
		t.Fatalf("second surviving row = (%x, %x), want order 5", keys[1], vals[1])
	}

	// An index whose rows are ALL missing yields nothing and does not spin.
	empty := zzstPoolID(0x89)
	st.indexWrite(empty, []uint64{1, 2, 3, 4, 5, 6, 7, 8})
	if keys, _ := zzstIterate(t, st, orderRowKey(empty, 0)[:len(coreOrderPrefix)+32]); len(keys) != 0 {
		t.Fatalf("all-missing index yielded %d rows", len(keys))
	}
}

func TestZzstStoreIteratorSurfaceAfterExhaustion(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0x99)
	if err := st.Put(orderRowKey(poolID, 1), []byte{0x01}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	it := st.NewIteratorWithPrefix(orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32])
	if !it.Next() {
		t.Fatalf("Next = false with one row present")
	}
	if it.Next() {
		t.Fatalf("Next = true past the end")
	}
	if it.Key() != nil || it.Value() != nil {
		t.Fatalf("Key/Value after exhaustion = (%x, %x), want nil", it.Key(), it.Value())
	}
	if err := it.Error(); err != nil {
		t.Fatalf("Error after exhaustion = %v, want nil", err)
	}
	// Calling Next again past the end stays false and stays safe.
	if it.Next() {
		t.Fatalf("Next = true on a second call past the end")
	}
	it.Release()
	it.Release() // Release is a no-op and must tolerate repetition
}

// Every iteration surface that is NOT order:<poolID:32> yields an empty, non-error
// iterator. dexcore iterates exactly one prefix; an empty answer is correct here,
// a silent partial scan would not be.
func TestZzstStoreNonOrderPrefixesYieldEmptyIterators(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0xCC)
	if err := st.Put(orderRowKey(poolID, 1), []byte{0x01}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	valid := orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32]

	iters := map[string]database.Iterator{
		"NewIterator":                       st.NewIterator(),
		"NewIteratorWithStart":              st.NewIteratorWithStart([]byte("order:")),
		"nil prefix":                        st.NewIteratorWithPrefix(nil),
		"empty prefix":                      st.NewIteratorWithPrefix([]byte{}),
		"bare order prefix":                 st.NewIteratorWithPrefix(coreOrderPrefix),
		"one byte short":                    st.NewIteratorWithPrefix(valid[:len(valid)-1]),
		"one byte long":                     st.NewIteratorWithPrefix(append(append([]byte(nil), valid...), 0x00)),
		"full row key (prefix+8) not a set": st.NewIteratorWithPrefix(orderRowKey(poolID, 1)),
	}
	// Right length, wrong prefix bytes.
	wrong := append([]byte(nil), valid...)
	copy(wrong, "Order:")
	iters["wrong prefix bytes"] = st.NewIteratorWithPrefix(wrong)

	for name, it := range iters {
		if it.Next() {
			t.Fatalf("%s: Next = true, want an empty iterator", name)
		}
		if err := it.Error(); err != nil {
			t.Fatalf("%s: Error = %v, want nil (empty is not an error)", name, err)
		}
		if it.Key() != nil || it.Value() != nil {
			t.Fatalf("%s: Key/Value = (%x, %x), want nil", name, it.Key(), it.Value())
		}
		it.Release()
	}
}

// NewIteratorWithStartAndPrefix ignores start and is exactly the prefix iterator.
func TestZzstStoreIteratorWithStartDelegatesToPrefix(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0xDD)
	for i := uint64(0); i < 4; i++ {
		if err := st.Put(orderRowKey(poolID, i), []byte{byte(i)}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	prefix := orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32]

	for _, start := range [][]byte{nil, {}, orderRowKey(poolID, 2), []byte("zzz")} {
		it := st.NewIteratorWithStartAndPrefix(start, prefix)
		var n int
		for it.Next() {
			n++
		}
		it.Release()
		if n != 4 {
			t.Fatalf("start=%x yielded %d rows; start must be ignored (want 4)", start, n)
		}
	}
	// A non-order prefix is still empty regardless of start.
	it := st.NewIteratorWithStartAndPrefix(prefix, []byte("nope"))
	if it.Next() {
		t.Fatalf("non-order prefix with a start yielded a row")
	}
	it.Release()
}

// =========================================================================
// 5. Refusal — truncation and corruption of the order-key grammar
// =========================================================================

func TestZzstStoreParseOrderKeyRejectsEveryTruncation(t *testing.T) {
	poolID := zzstPoolID(0xEE)
	full := orderRowKey(poolID, 0x0102030405060708)

	// Every proper prefix must be refused — a half-parsed key would index the
	// wrong market.
	for n := 0; n < len(full); n++ {
		if _, _, ok := parseOrderKey(full[:n]); ok {
			t.Fatalf("parseOrderKey accepted a %d-byte truncation of a %d-byte key", n, len(full))
		}
	}
	// And every extension.
	for n := 1; n <= 8; n++ {
		if _, _, ok := parseOrderKey(append(append([]byte(nil), full...), make([]byte, n)...)); ok {
			t.Fatalf("parseOrderKey accepted a key %d bytes too long", n)
		}
	}
	// Right length, one corrupt prefix byte at every position.
	for i := 0; i < len(coreOrderPrefix); i++ {
		bad := append([]byte(nil), full...)
		bad[i] ^= 0xff
		if _, _, ok := parseOrderKey(bad); ok {
			t.Fatalf("parseOrderKey accepted a key with prefix byte %d corrupted", i)
		}
	}
	// The exact key round-trips.
	gotPool, gotID, ok := parseOrderKey(full)
	if !ok {
		t.Fatalf("parseOrderKey rejected a well-formed key")
	}
	if gotPool != poolID {
		t.Fatalf("poolID = %x, want %x", gotPool, poolID)
	}
	if gotID != 0x0102030405060708 {
		t.Fatalf("orderID = %#x, want 0x0102030405060708", gotID)
	}
}

func TestZzstStoreParseOrderPrefixRejectsEveryTruncation(t *testing.T) {
	poolID := zzstPoolID(0x5B)
	full := orderRowKey(poolID, 0)[:len(coreOrderPrefix)+32]

	for n := 0; n < len(full); n++ {
		if _, ok := parseOrderPrefix(full[:n]); ok {
			t.Fatalf("parseOrderPrefix accepted a %d-byte truncation", n)
		}
	}
	for n := 1; n <= 8; n++ {
		if _, ok := parseOrderPrefix(append(append([]byte(nil), full...), make([]byte, n)...)); ok {
			t.Fatalf("parseOrderPrefix accepted a prefix %d bytes too long", n)
		}
	}
	for i := 0; i < len(coreOrderPrefix); i++ {
		bad := append([]byte(nil), full...)
		bad[i] ^= 0xff
		if _, ok := parseOrderPrefix(bad); ok {
			t.Fatalf("parseOrderPrefix accepted a corrupt prefix byte at %d", i)
		}
	}
	got, ok := parseOrderPrefix(full)
	if !ok || got != poolID {
		t.Fatalf("parseOrderPrefix(%x) = (%x, %v), want (%x, true)", full, got, ok, poolID)
	}
}

// orderRowKey and parseOrderKey are inverse over the whole domain, including the
// id extremes where a signed/unsigned slip would show.
func TestZzstStoreOrderKeyRoundTripOverExtremes(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 4))

	pools := [][32]byte{zzstPoolID(0x00), zzstPoolID(0xff), zzstPoolID(0x01)}
	for i := 0; i < 8; i++ {
		var p [32]byte
		zzstFill(rng, p[:])
		pools = append(pools, p)
	}
	ids := []uint64{0, 1, 2, 127, 128, 255, 256, 1<<32 - 1, 1 << 32, 1 << 63, ^uint64(0), ^uint64(0) - 1}
	for i := 0; i < 16; i++ {
		ids = append(ids, rng.Uint64())
	}

	for _, p := range pools {
		for _, id := range ids {
			k := orderRowKey(p, id)
			if len(k) != len(coreOrderPrefix)+40 {
				t.Fatalf("orderRowKey length = %d, want %d", len(k), len(coreOrderPrefix)+40)
			}
			gotPool, gotID, ok := parseOrderKey(k)
			if !ok {
				t.Fatalf("parseOrderKey rejected orderRowKey(%x, %d)", p[:4], id)
			}
			if gotPool != p || gotID != id {
				t.Fatalf("round-trip lost data: (%x, %d) -> (%x, %d)", p[:4], id, gotPool[:4], gotID)
			}
			// The prefix half must recover the pool on its own.
			gotPool2, ok2 := parseOrderPrefix(k[:len(coreOrderPrefix)+32])
			if !ok2 || gotPool2 != p {
				t.Fatalf("parseOrderPrefix lost the pool id for (%x, %d)", p[:4], id)
			}
		}
	}
}

// Feeding every prefix of a valid order key to the live surfaces must never panic
// and must never silently index anything. A panic reachable from a dexcore Put is
// a chain halt.
func TestZzstStoreEveryKeyPrefixIsSafeOnLiveSurfaces(t *testing.T) {
	sdb, st := zzstStore()
	poolID := zzstPoolID(0x3C)
	full := orderRowKey(poolID, 7)

	for n := 0; n <= len(full); n++ {
		p := full[:n]
		if _, err := st.Get(p); err != nil && !errors.Is(err, database.ErrNotFound) {
			t.Fatalf("Get(prefix %d) = %v", n, err)
		}
		if _, err := st.Has(p); err != nil {
			t.Fatalf("Has(prefix %d) = %v", n, err)
		}
		if err := st.Put(p, []byte{byte(n)}); err != nil {
			t.Fatalf("Put(prefix %d) = %v", n, err)
		}
		it := st.NewIteratorWithPrefix(p)
		for it.Next() {
		}
		if err := it.Error(); err != nil {
			t.Fatalf("iterator(prefix %d) = %v", n, err)
		}
		it.Release()
		if err := st.Delete(p); err != nil {
			t.Fatalf("Delete(prefix %d) = %v", n, err)
		}
	}
	// Only the one full-length key was ever a real order row, and it was deleted,
	// so the market index must be empty.
	if ids := st.indexIDs(poolID); len(ids) != 0 {
		t.Fatalf("prefix sweep left %v in the market index", ids)
	}
	_ = sdb
}

// =========================================================================
// 6. Index encoding — packing, count word, and the read/write inverse
// =========================================================================

func TestZzstStoreIndexWriteReadRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(zzstSeed + 5))
	_, st := zzstStore()
	poolID := zzstPoolID(0x6E)

	// Lengths 0..33 cross the 4-ids-per-word boundary eight times.
	for n := 0; n <= 33; n++ {
		ids := make([]uint64, n)
		for i := range ids {
			ids[i] = rng.Uint64()
		}
		st.indexWrite(poolID, ids)
		got := st.indexIDs(poolID)
		if len(got) != n {
			t.Fatalf("n=%d: read back %d ids", n, len(got))
		}
		for i := range ids {
			if got[i] != ids[i] {
				t.Fatalf("n=%d: id[%d] = %d, want %d", n, i, got[i], ids[i])
			}
		}
	}

	// Extremes: 0 and max must survive the packing (a signed slip in the packer
	// would corrupt exactly these).
	edge := []uint64{0, ^uint64(0), 1, 1 << 63, (1 << 63) - 1, 0xdeadbeefcafebabe}
	st.indexWrite(poolID, edge)
	got := st.indexIDs(poolID)
	if len(got) != len(edge) {
		t.Fatalf("edge ids: read %d, want %d", len(got), len(edge))
	}
	for i := range edge {
		if got[i] != edge[i] {
			t.Fatalf("edge id[%d] = %#x, want %#x", i, got[i], edge[i])
		}
	}

	// An empty list reads back as nil, not as a stale tail from the longer write.
	st.indexWrite(poolID, nil)
	if ids := st.indexIDs(poolID); ids != nil {
		t.Fatalf("empty index read back as %v, want nil", ids)
	}
}

// A shrink followed by a grow must never resurrect an id from the earlier, longer
// list. indexIDs reads exactly `count` ids and indexWrite rewrites every word the
// new count reaches — this test is what makes that reliance load-bearing.
func TestZzstStoreIndexShrinkThenGrowHasNoGhosts(t *testing.T) {
	_, st := zzstStore()
	poolID := zzstPoolID(0x7E)

	long := make([]uint64, 20)
	for i := range long {
		long[i] = 1000 + uint64(i)
	}
	st.indexWrite(poolID, long)
	st.indexWrite(poolID, long[:2])

	grown := make([]uint64, 20)
	for i := range grown {
		grown[i] = 2000 + uint64(i)
	}
	st.indexWrite(poolID, grown)

	got := st.indexIDs(poolID)
	for i := range grown {
		if got[i] != grown[i] {
			t.Fatalf("id[%d] = %d, want %d — a ghost from the first write survived", i, got[i], grown[i])
		}
	}
}

// =========================================================================
// 7. A length read out of state is bounded before it sizes an allocation
// =========================================================================

// Get, indexIDs and readBytesFromSlots each read a length or a count out of a
// storage word and size an allocation with it. int(uint64) is negative above 2^63,
// and make takes a negative length as a panic — which from a precompile is a chain
// halt rather than a refusal. slotLen is the one bound: below it a record reads
// normally, above it the record reads as absent.
func TestZzstStoreBoundsALengthReadOutOfState(t *testing.T) {
	setLen := func(sdb *MockStateDB, st *evmStore, key []byte, n uint64) {
		var w common.Hash
		putU64(w[24:32], n)
		sdb.SetState(poolManagerAddr9999, st.valueSlot(key, 0), w)
	}

	// In range: a corrupt-but-addressable length returns a value of that length
	// (the unwritten data slots read as zero).
	for _, n := range []uint64{1, 31, 32, 33, 1000, 1 << 16} {
		sdb, st := zzstStore()
		key := []byte("corrupt")
		setLen(sdb, st, key, n)
		got, err := st.Get(key)
		if err != nil {
			t.Fatalf("Get with length %d: %v", n, err)
		}
		if uint64(len(got)) != n {
			t.Fatalf("Get with length %d returned %d bytes", n, len(got))
		}
	}

	// Out of range: the record is absent, and the read never allocates.
	for _, n := range []uint64{math.MaxInt32 + 1, 1 << 62, ^uint64(0)} {
		sdb, st := zzstStore()
		key := []byte("corrupt")
		setLen(sdb, st, key, n)
		zzstNoPanic(t, "Get", func() {
			got, err := st.Get(key)
			if !errors.Is(err, database.ErrNotFound) {
				t.Errorf("Get with length word %#x: want ErrNotFound, got (%d bytes, %v)", n, len(got), err)
			}
		})
	}

	// The order-id index answers the same way: a count it cannot address is no list.
	for _, n := range []uint64{math.MaxInt32 + 1, ^uint64(0)} {
		sdb, st := zzstStore()
		poolID := [32]byte{0xC0, 0x11}
		var w common.Hash
		putU64(w[24:32], n)
		sdb.SetState(poolManagerAddr9999, st.indexSlot(poolID, 0), w)
		zzstNoPanic(t, "indexIDs", func() {
			if got := st.indexIDs(poolID); got != nil {
				t.Errorf("indexIDs with count word %#x returned %d ids, want none", n, len(got))
			}
		})
	}

	// And so does the staging reader, which sizes its buffer the same way.
	for _, n := range []uint64{math.MaxInt32 + 1, ^uint64(0)} {
		sdb, _ := zzstStore()
		var w common.Hash
		putU64(w[24:32], n)
		sdb.SetState(poolManagerAddr9999, stageSlotKey(stagePutPrefix, 1, 0), w)
		zzstNoPanic(t, "readBytesFromSlots", func() {
			if got := readBytesFromSlots(sdb, stagePutPrefix, 1); got != nil {
				t.Errorf("readBytesFromSlots with length word %#x returned %d bytes, want none", n, len(got))
			}
		})
	}
}

// zzstNoPanic turns a panic escaping a consensus read into a named failure. A panic
// inside a precompile frame aborts the block, so it is never an acceptable answer to
// a malformed record.
func zzstNoPanic(t *testing.T, ctx string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PANIC escaped %s (a chain halt, not a refusal): %v", ctx, r)
		}
	}()
	fn()
}
