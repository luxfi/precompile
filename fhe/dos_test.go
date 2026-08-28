// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// allSelectors is every selector the precompile routes, paired with a body of EXACTLY the
// minimum length that handler accepts. Exactly the minimum, not merely enough: several
// tests truncate by one byte to check the length guard, and a body longer than the minimum
// would still be accepted and prove nothing.
var allSelectors = []struct {
	name string
	sel  string
	body []byte
}{
	{"add", "\x23\xb8\x72\xdd", make([]byte, 64)},
	{"sub", "\x51\xca\xb0\x91", make([]byte, 64)},
	{"mul", "\xc8\xa4\xac\x9c", make([]byte, 64)},
	{"div", "\x0f\x5e\x1b\x2a", make([]byte, 64)},
	{"rem", "\x1e\x19\x1a\x96", make([]byte, 64)},
	{"neg", "\xe4\x7e\xf3\xfc", make([]byte, 32)},
	{"scalarAdd", "\xf5\xa7\x96\xfb", make([]byte, 64)},
	{"scalarSub", "\xb6\x3a\x9e\x11", make([]byte, 64)},
	{"scalarMul", "\x3c\x96\x47\x95", make([]byte, 64)},
	{"scalarDiv", "\x7b\x8f\x4a\x2d", make([]byte, 64)},
	{"scalarRem", "\x52\x91\xa3\x21", make([]byte, 64)},
	{"lt", "\xa9\x05\x9c\xbb", make([]byte, 64)},
	{"le", "\x26\xa3\x31\x9e", make([]byte, 64)},
	{"gt", "\x4b\x64\xe4\x92", make([]byte, 64)},
	{"ge", "\x53\x1c\x19\xea", make([]byte, 64)},
	{"eq", "\x1c\xf4\x86\x63", make([]byte, 64)},
	{"ne", "\x14\x6e\x3a\x7e", make([]byte, 64)},
	{"min", "\x7a\x8f\x63\xb8", make([]byte, 64)},
	{"max", "\x6e\x32\x91\x28", make([]byte, 64)},
	{"and", "\xcd\x30\x32\x00", make([]byte, 64)},
	{"or", "\x5a\x6b\x26\xba", make([]byte, 64)},
	{"xor", "\xf6\x74\x70\x22", make([]byte, 64)},
	{"not", "\x6b\x3a\x00\x11", make([]byte, 32)},
	{"shl", "\x3e\x8c\x6c\x10", make([]byte, 33)},
	{"shr", "\x5f\x46\xe5\x15", make([]byte, 33)},
	{"rotl", "\x89\xa1\x9e\x6b", make([]byte, 33)},
	{"rotr", "\xd7\x25\x1c\xb9", make([]byte, 33)},
	{"select", "\x2e\x17\xde\x78", make([]byte, 96)},
	{"cast", "\xae\xd2\x44\x6b", make([]byte, 33)},
	{"asEuint64", "\xa5\x17\x5c\x89", make([]byte, 32)},
	{"asEaddress", "\xd4\x3f\x02\x80", make([]byte, 32)},
	{"asEbool", "\x8c\x3f\x5a\x42", make([]byte, 32)},
	{"asEuint4", "\x2d\xfa\x48\x63", make([]byte, 32)},
	{"asEuint8", "\x64\xc1\x51\x81", make([]byte, 32)},
	{"asEuint16", "\xf8\x91\x08\x50", make([]byte, 32)},
	{"asEuint32", "\x6c\xa9\xea\xe9", make([]byte, 32)},
	{"asEuint128", "\x7d\x6d\x81\x95", make([]byte, 32)},
	{"asEuint256", "\x9e\x5b\x2e\xf3", make([]byte, 32)},
	{"rand", "\x71\x5a\xd3\x11", make([]byte, 1)},    // type byte only
	{"verify", "\x45\xa9\x32\x18", make([]byte, 33)}, // type byte + one word
}

func call(sel string, body []byte) []byte {
	return append([]byte(sel), body...)
}

// countingDB is a StateDB that records whether anything was written. The embedded
// interface is nil: the FHE handlers touch only GetState and SetState, so any other method
// being reached would be a finding, and a nil-method panic reports it loudly.
type countingDB struct {
	contract.StateDB
	slots  map[common.Hash]common.Hash
	writes int
}

func newCountingDB() *countingDB {
	return &countingDB{slots: make(map[common.Hash]common.Hash)}
}

func (d *countingDB) GetState(_ common.Address, k common.Hash) common.Hash { return d.slots[k] }

func (d *countingDB) SetState(_ common.Address, k, v common.Hash) common.Hash {
	prev := d.slots[k]
	d.slots[k] = v
	d.writes++
	return prev
}

// stateOf is a minimal AccessibleState; the handlers only ask for the StateDB.
type stateOf struct {
	contract.AccessibleState
	db contract.StateDB
}

func (s *stateOf) GetStateDB() contract.StateDB { return s.db }

// TestRun_ReadOnlyRefusesEveryStateWriter is the STATICCALL regression.
//
// readOnly was threaded through Run and all forty-two handlers and read by none of them:
// `grep -c "if readOnly" fhe/*.go` over the non-test sources returned 0. Every operation
// except decrypt and sealOutput persists a ciphertext — a handle, a metadata word, one
// state slot per 32 bytes of ciphertext, and an ownership record — so a static call, which
// promises the callee mutates nothing, could grow the state trie.
func TestRun_ReadOnlyRefusesEveryStateWriter(t *testing.T) {
	c := &FHEContract{}

	for _, op := range allSelectors {
		t.Run(op.name, func(t *testing.T) {
			db := newCountingDB()
			state := &stateOf{db: db}

			_, _, err := c.Run(state, common.Address{1}, ContractAddress,
				call(op.sel, op.body), 1<<62, true)
			require.ErrorIs(t, err, ErrReadOnly,
				"%s writes state and must be refused under a static call", op.name)
			require.Zero(t, db.writes, "%s wrote state under a static call", op.name)
		})
	}
}

// TestRun_ReadOnlyPermitsPureReads proves the refusal is targeted, not a blanket ban: the
// two operations that only read are still reachable under a static call and fail for their
// own reason (the threshold ceremony), never with ErrReadOnly.
func TestRun_ReadOnlyPermitsPureReads(t *testing.T) {
	c := &FHEContract{}
	for name, sel := range map[string]string{
		"decrypt":    selectorDecrypt,
		"sealOutput": selectorSealOutput,
	} {
		t.Run(name, func(t *testing.T) {
			db := newCountingDB()
			_, _, err := c.Run(&stateOf{db: db}, common.Address{1}, ContractAddress,
				call(sel, make([]byte, 96)), 1<<62, true)
			require.NotErrorIs(t, err, ErrReadOnly,
				"%s only reads and must not be refused as a writer", name)
			require.Zero(t, db.writes)
		})
	}
}

// TestRun_UnknownSelectorIsTreatedAsAWriter proves the refusal fails closed: a selector
// nobody recognises is assumed to write, so a future handler added without revisiting this
// rule cannot silently become STATICCALL-reachable.
func TestRun_UnknownSelectorIsTreatedAsAWriter(t *testing.T) {
	c := &FHEContract{}
	_, _, err := c.Run(&stateOf{db: newCountingDB()}, common.Address{1},
		ContractAddress, call("\xde\xad\xbe\xef", make([]byte, 64)), 1<<62, true)
	require.ErrorIs(t, err, ErrReadOnly)

	// And outside a static call it is still refused, as not implemented.
	_, _, err = c.Run(&stateOf{db: newCountingDB()}, common.Address{1},
		ContractAddress, call("\xde\xad\xbe\xef", make([]byte, 64)), 1<<62, false)
	require.ErrorIs(t, err, ErrNotImplemented)
}

// =========================================================================
// Ciphertext framing
// =========================================================================

// frame builds a BitCiphertext encoding with the given declared numBits and per-bit
// declared lengths, writing only the bytes named. It is deliberately able to produce
// inconsistent encodings — that is the point.
func frame(numBits uint32, bits []uint32, payload []byte) []byte {
	out := make([]byte, 5)
	binary.LittleEndian.PutUint32(out[:4], numBits)
	out[4] = 1 // fheType
	for _, n := range bits {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint32(hdr, n)
		out = append(out, hdr...)
	}
	return append(out, payload...)
}

// TestWellFramed_RefusesAllocationBombs is the remote memory-exhaustion regression.
//
// BitCiphertext.UnmarshalBinary reads each declared count off the wire and allocates for it
// BEFORE checking that the input contains that many bytes:
//
//	bc.bits = make([]*Ciphertext, bc.numBits)   // numBits is a wire uint32
//	bitData := make([]byte, bitLen)             // bitLen is a wire uint32
//
// So five bytes of calldata request a 34 GB slice and nine request 4 GB — behind a flat
// 50,000 gas fee on verify, which is roughly 240 attempts per block. The framing is now
// validated against the bytes actually present before any of it reaches the library.
func TestWellFramed_RefusesAllocationBombs(t *testing.T) {
	// numBits alone: 4.29e9 pointers = ~34 GB.
	require.False(t, wellFramed(frame(0xFFFFFFFF, nil, nil)))
	require.False(t, wellFramed(frame(1<<31, nil, nil)))

	// A single bit declaring a 4 GB payload it does not carry.
	require.False(t, wellFramed(frame(1, []uint32{0xFFFFFFFF}, nil)))
	require.False(t, wellFramed(frame(1, []uint32{1 << 31}, []byte{1, 2, 3})))

	// A later bit overruns even though earlier ones are honest.
	require.False(t, wellFramed(frame(3, []uint32{0, 0, 0xFFFFFFFF}, nil)))

	// Anything past the widest supported type is refused before it is walked at all.
	require.False(t, wellFramed(frame(MaxCiphertextBits+1, nil, nil)))
	require.True(t, wellFramed(frame(0, nil, nil)), "zero bits is a complete encoding")

	// Truncated headers.
	for n := 0; n < 5; n++ {
		require.Falsef(t, wellFramed(make([]byte, n)), "a %d-byte frame is incomplete", n)
	}

	// The whole path refuses them too, rather than allocating.
	for _, bad := range [][]byte{
		frame(0xFFFFFFFF, nil, nil),
		frame(1, []uint32{0xFFFFFFFF}, nil),
		frame(MaxCiphertextBits+1, nil, nil),
	} {
		require.NotPanics(t, func() {
			require.Nil(t, deserializeBitCiphertext(bad))
			require.False(t, tfheVerify(bad, TypeEuint8))
		})
	}
}

// TestWellFramed_AcceptsHonestFrames proves the validator is not refusing everything: a
// frame whose declared lengths match the bytes present is accepted, at the boundary in both
// directions.
func TestWellFramed_AcceptsHonestFrames(t *testing.T) {
	require.True(t, wellFramed(frame(1, []uint32{3}, []byte{1, 2, 3})))
	require.True(t, wellFramed(frame(2, []uint32{1, 1}, nil)[:5+4+1+4+1]),
		"two one-byte bits, exactly the bytes required")

	// One byte short of the declared payload is refused; exactly enough is accepted.
	require.False(t, wellFramed(frame(1, []uint32{4}, []byte{1, 2, 3})))
	require.True(t, wellFramed(frame(1, []uint32{4}, []byte{1, 2, 3, 4})))

	// Trailing bytes beyond the declared frame are tolerated (the reader stops early).
	require.True(t, wellFramed(frame(1, []uint32{1}, []byte{9, 9, 9})))

	// The widest supported ciphertext is accepted.
	bits := make([]uint32, MaxCiphertextBits)
	require.True(t, wellFramed(frame(MaxCiphertextBits, bits, nil)))
}

// =========================================================================
// verify pricing
// =========================================================================

// TestVerify_GasScalesWithInputSize is the flat-fee regression for the one operation whose
// work is set by a caller-chosen length. verify deserializes the blob and then persists it
// to the state trie, one keccak and one SetState per 32 bytes — all for a constant 50,000
// gas. A longer blob must now cost more.
func TestVerify_GasScalesWithInputSize(t *testing.T) {
	c := &FHEContract{}
	const supplied = uint64(1) << 40

	charged := func(n int) uint64 {
		body := append([]byte{TypeEuint8}, make([]byte, n)...)
		db := newCountingDB()
		_, remaining, _ := c.Run(&stateOf{db: db}, common.Address{1},
			ContractAddress, call("\x45\xa9\x32\x18", body), supplied, false)
		require.LessOrEqual(t, remaining, supplied)
		return supplied - remaining
	}

	small := charged(32)
	large := charged(64 * 1024)
	require.Greater(t, large, small, "a larger verify payload must cost more gas")
	require.GreaterOrEqual(t, large-small, uint64(64*1024-32)*GasVerifyPerByte)

	// Monotonic across the range, not just at the ends.
	prev := uint64(0)
	for _, n := range []int{32, 64, 256, 1024, 4096, 16384} {
		got := charged(n)
		require.Greaterf(t, got, prev, "verify gas must increase with payload size at n=%d", n)
		prev = got
	}
}

// TestVerify_InsufficientGasRefusedBeforeWork proves the size-aware price is enforced up
// front: a caller that cannot cover it is refused and nothing is written.
func TestVerify_InsufficientGasRefusedBeforeWork(t *testing.T) {
	c := &FHEContract{}
	body := append([]byte{TypeEuint8}, make([]byte, 4096)...)
	need := GasEncrypt + uint64(4096)*GasVerifyPerByte

	db := newCountingDB()
	_, _, err := c.Run(&stateOf{db: db}, common.Address{1}, ContractAddress,
		call("\x45\xa9\x32\x18", body), need-1, false)
	require.ErrorIs(t, err, ErrInsufficientGas)
	require.Zero(t, db.writes, "a refused verify must not write state")
}

// =========================================================================
// silent failure
// =========================================================================

// TestRun_FailureIsAnErrorNotAZeroHandle is the silent-failure regression. Every perform*
// helper answers a failure with the zero handle; handlers returned that verbatim with a nil
// error, so an EVM caller received a 32-byte zero word that looked like a successful result
// and referred to no ciphertext at all. div and rem were the sharpest case: neither had a
// case in performFHEOperation's switch, so both fell to its default and charged 655,200,000
// gas for a guaranteed no-op that reported success.
func TestRun_FailureIsAnErrorNotAZeroHandle(t *testing.T) {
	c := &FHEContract{}

	for _, op := range allSelectors {
		t.Run(op.name, func(t *testing.T) {
			// Handles that resolve to nothing: every operation must either succeed with a
			// non-zero handle or report an error. It may never answer zero with nil.
			ret, _, err := c.Run(&stateOf{db: newCountingDB()}, common.Address{1},
				ContractAddress, call(op.sel, op.body), 1<<62, false)
			if err != nil {
				return
			}
			require.NotEqual(t, make([]byte, 32), ret,
				"%s reported success with the failure sentinel", op.name)
		})
	}
}

// allocBytes reports how many bytes f caused to be allocated.
func allocBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestWellFramed_BoundsAllocationNotJustTheResult closes a hole the mutation check found.
//
// Asserting that a bomb frame deserializes to nil is not enough: UnmarshalBinary ALSO
// returns nil for these inputs — after allocating for the declared counts and only then
// discovering the bytes are not there. The damage is the allocation, so the allocation is
// what has to be measured. Removing the call to wellFramed left every result-shaped
// assertion green.
//
// The declared counts here are large enough to dwarf the input by six orders of magnitude
// but small enough that an unguarded run allocates rather than killing the test process.
func TestWellFramed_BoundsAllocationNotJustTheResult(t *testing.T) {
	const budget = 1 << 20 // a 13-byte input has no business allocating a megabyte

	// 16.7M declared bits => 134 MB of pointers from 5 bytes of input.
	bits := frame(1<<24, nil, nil)
	require.Less(t, allocBytes(func() { _ = deserializeBitCiphertext(bits) }), uint64(budget),
		"a %d-byte frame declaring 2^24 bits must not allocate for them", len(bits))

	// One bit declaring a 64 MB payload from 9 bytes of input.
	payload := frame(1, []uint32{1 << 26}, nil)
	require.Less(t, allocBytes(func() { _ = deserializeBitCiphertext(payload) }), uint64(budget),
		"a %d-byte frame declaring a 64MB bit must not allocate for it", len(payload))

	// And through the operation that actually accepts caller bytes.
	require.Less(t, allocBytes(func() { _ = tfheVerify(payload, TypeEuint8) }), uint64(budget))
}

// TestWellFramed_RefusesOverWideEvenWhenByteConsistent closes the second hole. Every other
// over-wide frame in these tests is also byte-inconsistent, so the overrun check refused it
// and deleting the width cap changed nothing. This frame is internally consistent — every
// declared header is present — so only the cap can refuse it.
func TestWellFramed_RefusesOverWideEvenWhenByteConsistent(t *testing.T) {
	atCap := frame(MaxCiphertextBits, make([]uint32, MaxCiphertextBits), nil)
	require.True(t, wellFramed(atCap), "the widest supported ciphertext must be accepted")

	overCap := frame(MaxCiphertextBits+1, make([]uint32, MaxCiphertextBits+1), nil)
	require.True(t, len(overCap) == 5+4*(MaxCiphertextBits+1),
		"the over-wide frame must be byte-consistent, or the cap is not what refuses it")
	require.False(t, wellFramed(overCap),
		"a ciphertext wider than any supported type must be refused on width alone")

	// Far over the cap, still byte-consistent.
	require.False(t, wellFramed(frame(1024, make([]uint32, 1024), nil)))
}

// TestWellFramed_RefusesTruncatedBitHeaders closes a third hole the mutation check found.
// Once the width cap short-circuits the wildly over-wide frames, nothing else exercised the
// per-bit header bound: a frame declaring a plausible number of bits but carrying fewer
// headers than that walks straight off the end of the buffer. Every truncation point is
// swept, and the requirement is refusal without a panic — reading past the slice would
// panic inside a precompile, which no caller recovers.
func TestWellFramed_RefusesTruncatedBitHeaders(t *testing.T) {
	for _, declared := range []uint32{1, 2, 3, 17, MaxCiphertextBits} {
		full := frame(declared, make([]uint32, declared), nil)
		require.True(t, wellFramed(full), "the complete frame must be accepted")

		// Every proper prefix is refused, and none of them panics. The prefix is taken
		// with an exact capacity (full[:n:n]), because a sub-slice that keeps the parent's
		// spare capacity lets an out-of-bounds read succeed against the bytes that were
		// supposedly cut off — which hides exactly the defect this is testing for. Real
		// calldata has no slack beyond its length.
		for n := 0; n < len(full); n++ {
			trunc := full[:n:n]
			require.NotPanicsf(t, func() {
				require.Falsef(t, wellFramed(trunc),
					"a frame declaring %d bits was accepted with only %d bytes", declared, n)
			}, "wellFramed panicked on a %d-byte prefix of a %d-bit frame", n, declared)

			// The same truncation must not reach the library either.
			require.NotPanics(t, func() { require.Nil(t, deserializeBitCiphertext(trunc)) })
		}
	}
}

// TestBoolBit_AcceptsOnlySingleBitValues closes a hole the mutation check found: nothing
// asserted that a multi-bit ciphertext is refused as a boolean.
//
// boolBit reaches into the wire format to pull the one encrypted bit out of a TypeEbool
// value, because the pinned luxfi/fhe exposes no accessor for it. Without the width check
// it would happily return the FIRST bit of an eight-bit integer, so select(someEuint8, a, b)
// would silently branch on the low bit of an integer instead of refusing a value that is
// not a boolean at all — type confusion between an integer handle and a condition.
func TestBoolBit_AcceptsOnlySingleBitValues(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC}
	single := frame(1, []uint32{uint32(len(payload))}, payload)
	require.Equal(t, payload, boolBit(single), "a one-bit value yields its single bit verbatim")

	// Every other width is refused, at the boundaries either side of one.
	for _, width := range []uint32{0, 2, 4, 8, 16, 32, MaxCiphertextBits} {
		bits := make([]uint32, width)
		require.Nilf(t, boolBit(frame(width, bits, nil)),
			"a %d-bit value is not a boolean and must be refused as a condition", width)
	}

	// And malformed framing is refused rather than indexed into.
	for _, bad := range [][]byte{
		nil,
		make([]byte, 4),
		make([]byte, 8),
		frame(1, []uint32{99}, []byte{1, 2}), // declares more than it carries
		frame(0xFFFFFFFF, nil, nil),
	} {
		require.NotPanics(t, func() { require.Nil(t, boolBit(bad)) })
	}

	// A zero-length bit is well-framed and yields an empty slice, not a panic.
	require.NotPanics(t, func() { require.Empty(t, boolBit(frame(1, []uint32{0}, nil))) })
}

// TestRun_EveryHandlerRefusesAShortBody drives every selector with its body one byte short.
// Each handler must refuse on length before it touches an operand — a handler that read
// past its own bound would index into whatever the previous word left behind.
func TestRun_EveryHandlerRefusesAShortBody(t *testing.T) {
	c := &FHEContract{}
	for _, op := range allSelectors {
		t.Run(op.name, func(t *testing.T) {
			db := newCountingDB()
			short := op.body[:len(op.body)-1]
			_, _, err := c.Run(&stateOf{db: db}, common.Address{1}, ContractAddress,
				call(op.sel, short), 1<<62, false)
			require.ErrorIsf(t, err, ErrInvalidInput,
				"%s accepted a body of %d bytes", op.name, len(short))
			require.Zerof(t, db.writes, "%s wrote state on a refused call", op.name)
		})
	}
}

// TestRun_EveryHandlerRefusesInsufficientGas drives every selector with one gas unit, which
// is below the price of every operation in the schedule. Each must refuse on gas, and must
// do so before performing work it could not be paid for.
//
// One gas rather than zero: Run has a separate zero-gas floor, and routing through that
// would prove nothing about the per-handler check.
func TestRun_EveryHandlerRefusesInsufficientGas(t *testing.T) {
	c := &FHEContract{}
	for _, op := range allSelectors {
		t.Run(op.name, func(t *testing.T) {
			db := newCountingDB()
			_, remaining, err := c.Run(&stateOf{db: db}, common.Address{1}, ContractAddress,
				call(op.sel, op.body), 1, false)
			require.ErrorIsf(t, err, ErrInsufficientGas, "%s ran on one gas", op.name)
			require.Zerof(t, db.writes, "%s wrote state without being paid", op.name)
			require.LessOrEqual(t, remaining, uint64(1))
		})
	}
}

// TestRun_ZeroGasFloorPrecedesEverything proves the universal floor refuses before any
// selector is looked at, so a caller supplying nothing cannot reach a handler at all.
func TestRun_ZeroGasFloorPrecedesEverything(t *testing.T) {
	c := &FHEContract{}
	for _, op := range allSelectors {
		db := newCountingDB()
		_, remaining, err := c.Run(&stateOf{db: db}, common.Address{1}, ContractAddress,
			call(op.sel, op.body), 0, false)
		require.ErrorIsf(t, err, ErrInsufficientGas, "%s ran on zero gas", op.name)
		require.Zero(t, remaining)
		require.Zero(t, db.writes)
	}

	// The floor also applies to the two pure reads and to an unknown selector.
	for _, sel := range []string{selectorDecrypt, selectorSealOutput, "\xde\xad\xbe\xef"} {
		_, _, err := c.Run(&stateOf{db: newCountingDB()}, common.Address{1}, ContractAddress,
			call(sel, make([]byte, 96)), 0, false)
		require.ErrorIs(t, err, ErrInsufficientGas)
	}
}

// TestRun_RefusesWithoutAStateDB proves the precompile bails out cleanly when invoked with
// no state to read — a nil dereference inside a handler would panic the dispatch path, and
// a panic there is not recovered.
func TestRun_RefusesWithoutAStateDB(t *testing.T) {
	c := &FHEContract{}
	for _, op := range allSelectors {
		require.NotPanicsf(t, func() {
			_, _, err := c.Run(nil, common.Address{1}, ContractAddress,
				call(op.sel, op.body), 1<<62, false)
			require.ErrorIs(t, err, ErrInvalidInput)
		}, "%s panicked with no accessible state", op.name)

		require.NotPanicsf(t, func() {
			_, _, err := c.Run(&stateOf{db: nil}, common.Address{1}, ContractAddress,
				call(op.sel, op.body), 1<<62, false)
			require.ErrorIs(t, err, ErrInvalidInput)
		}, "%s panicked with a nil state db", op.name)
	}
}

// TestRun_ShortInputRefusedFHE covers calldata too short to carry a selector at all.
func TestRun_ShortInputRefusedFHE(t *testing.T) {
	c := &FHEContract{}
	for n := 0; n < 4; n++ {
		_, _, err := c.Run(&stateOf{db: newCountingDB()}, common.Address{1}, ContractAddress,
			make([]byte, n), 1<<62, false)
		require.ErrorIsf(t, err, ErrInvalidInput, "input of %d bytes", n)
	}
}
