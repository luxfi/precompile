// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCursorRefusesPastTheDeclaredEnd is the property the whole type exists
// for. A hand-written s[a:b] over this input succeeds and returns poison; the
// cursor refuses.
func TestCursorRefusesPastTheDeclaredEnd(t *testing.T) {
	in := Poisoned([]byte{1, 2, 3, 4}, 64)

	// The bug, spelled out: a slice expression does not save you here.
	require.NotPanics(t, func() {
		over := in[:20]
		require.Equal(t, byte(0xA5), over[10],
			"a hand-written slice reads attacker bytes past the declared end")
	})

	// The cursor refuses the same read.
	c := Read(in)
	_, err := c.Bytes(20)
	require.ErrorIs(t, err, ErrShort)
	require.ErrorIs(t, err, ErrInvalidInput, "callers refusing on ErrInvalidInput keep refusing")
	require.Equal(t, 4, c.Len(), "a refused read consumes nothing")

	// And every field reader refuses at the boundary rather than reading on.
	c = Read(in)
	_, err = c.Bytes(4)
	require.NoError(t, err)
	_, err = c.Byte()
	require.ErrorIs(t, err, ErrShort)
	_, err = c.Uint16()
	require.ErrorIs(t, err, ErrShort)
	_, err = c.Uint32()
	require.ErrorIs(t, err, ErrShort)
	_, err = c.Uint64()
	require.ErrorIs(t, err, ErrShort)
}

// TestCursorReturnsCappedSlices pins the tripwire: a field handed back cannot
// be re-sliced forward into the input's spare capacity.
func TestCursorReturnsCappedSlices(t *testing.T) {
	in := Poisoned([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 64)
	c := Read(in)
	got, err := c.Bytes(4)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3, 4}, got)
	require.Equal(t, len(got), cap(got), "a returned field has no spare capacity")
	require.Panics(t, func() { _ = got[:8] },
		"re-slicing a field past its length must fail loudly, not read the next field")

	rest := c.Rest()
	require.Equal(t, []byte{5, 6, 7, 8}, rest)
	require.Equal(t, len(rest), cap(rest), "Rest is capped too")
	require.Panics(t, func() { _ = rest[:len(rest)+1] })
}

// TestCursorReadsFieldsInOrder walks a whole wire format.
func TestCursorReadsFieldsInOrder(t *testing.T) {
	in := Poisoned([]byte{
		0x01,       // byte
		0x02, 0x03, // uint16
		0x00, 0x00, 0x00, 0x04, // uint32
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // uint64
		0xAA, 0xBB, // rest
	}, 32)
	c := Read(in)
	require.Equal(t, 17, c.Len())

	b, err := c.Byte()
	require.NoError(t, err)
	require.Equal(t, byte(0x01), b)

	u16, err := c.Uint16()
	require.NoError(t, err)
	require.Equal(t, uint16(0x0203), u16)

	u32, err := c.Uint32()
	require.NoError(t, err)
	require.Equal(t, uint32(4), u32)

	u64, err := c.Uint64()
	require.NoError(t, err)
	require.Equal(t, uint64(5), u64)

	require.Equal(t, 2, c.Len())
	require.Error(t, c.End())
	require.ErrorIs(t, c.End(), ErrTrailing)
	require.ErrorIs(t, c.End(), ErrInvalidInput)

	require.Equal(t, []byte{0xAA, 0xBB}, c.Rest())
	require.Equal(t, 0, c.Len())
	require.NoError(t, c.End())
	require.Empty(t, c.Rest(), "Rest at the end yields nothing")
}

// TestCursorRefusesADeclaredLengthLargerThanTheInput is the length-prefixed
// shape every parser here uses, and the one that reads attacker bytes when it
// is written by hand.
func TestCursorRefusesADeclaredLengthLargerThanTheInput(t *testing.T) {
	for _, claim := range []uint32{5, 1 << 20, 1 << 30, ^uint32(0)} {
		body := []byte{byte(claim >> 24), byte(claim >> 16), byte(claim >> 8), byte(claim), 1, 2, 3, 4}
		c := Read(Poisoned(body, 1<<16))
		n, err := c.Uint32()
		require.NoError(t, err)
		require.Equal(t, claim, n)
		_, err = c.Bytes(uint64(n))
		require.ErrorIs(t, err, ErrShort, "declared length %d exceeds the calldata", claim)
	}
}

// TestCursorLengthArithmeticDoesNotWrap pins that the bound is a subtraction
// on the trusted length, never an addition against the declared one. A guard
// written as `off+n > len` wraps for n near 2^64 and admits the read.
func TestCursorLengthArithmeticDoesNotWrap(t *testing.T) {
	c := Read(Poisoned([]byte{1, 2, 3, 4}, 1<<16))
	_, err := c.Bytes(1)
	require.NoError(t, err)
	for _, n := range []uint64{^uint64(0), ^uint64(0) - 3, 1 << 63, 1 << 40} {
		c2 := Read(Poisoned([]byte{1, 2, 3, 4}, 1<<16))
		_, err := c2.Bytes(1)
		require.NoError(t, err)
		_, err = c2.Bytes(n)
		require.ErrorIs(t, err, ErrShort, "n=%d must be refused, not wrapped", n)
	}
}

// TestZeroCursorRefusesEverything pins the fail-secure default.
func TestZeroCursorRefusesEverything(t *testing.T) {
	var c Cursor
	require.Equal(t, 0, c.Len())
	_, err := c.Byte()
	require.ErrorIs(t, err, ErrShort)
	_, err = c.Bytes(1)
	require.ErrorIs(t, err, ErrShort)
	require.NoError(t, c.End())
	require.Empty(t, c.Rest())

	// A zero-length read on an empty input is the one thing that succeeds,
	// and it yields nothing.
	got, err := c.Bytes(0)
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestCursorSentinelsAreDistinct guards the error identities the converted
// parsers depend on.
func TestCursorSentinelsAreDistinct(t *testing.T) {
	require.False(t, errors.Is(ErrShort, ErrTrailing))
	require.False(t, errors.Is(ErrTrailing, ErrShort))
	require.True(t, errors.Is(ErrShort, ErrInvalidInput))
	require.True(t, errors.Is(ErrTrailing, ErrInvalidInput))
	require.False(t, errors.Is(ErrInvalidInput, ErrShort))
}

// TestCursorFieldsBoundsTheCountBeforeAllocating is the property Fields
// exists for. A declared count must be refused against what the input can
// hold BEFORE it sizes anything — otherwise the refusal arrives after the
// allocation it was supposed to prevent.
func TestCursorFieldsBoundsTheCountBeforeAllocating(t *testing.T) {
	in := Poisoned([]byte{
		1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	}, 1<<16)

	c := Read(in)
	got, err := c.Fields(3, 4)
	require.NoError(t, err)
	require.Equal(t, [][]byte{{1, 1, 1, 1}, {2, 2, 2, 2}, {3, 3, 3, 3}}, got)
	require.Equal(t, 0, c.Len())
	for _, f := range got {
		require.Equal(t, len(f), cap(f), "each field is capped")
	}

	// A count the input cannot back is refused, and nothing is consumed.
	for _, n := range []uint64{4, 1 << 20, 1 << 32, ^uint64(0), ^uint64(0) / 2} {
		c := Read(in)
		_, err := c.Fields(n, 4)
		require.ErrorIs(t, err, ErrShort, "n=%d fields of 4 do not fit in %d bytes", n, len(in))
		require.Equal(t, len(in), c.Len(), "a refused read consumes nothing")
	}

	// The bound divides rather than multiplying: these counts times their
	// width wrap uint64, and a wrapped product compares as small.
	c = Read(in)
	_, err = c.Fields(1<<63, 4)
	require.ErrorIs(t, err, ErrShort, "n*w wrapping must not admit the read")
	_, err = c.Fields((^uint64(0)/32)+1, 32)
	require.ErrorIs(t, err, ErrShort)

	// Degenerate shapes.
	c = Read(in)
	zero, err := c.Fields(0, 4)
	require.NoError(t, err)
	require.Empty(t, zero)
	require.Equal(t, len(in), c.Len(), "zero fields consume nothing")

	nothing, err := c.Fields(1<<40, 0)
	require.NoError(t, err, "fields of zero width are the empty read")
	require.Empty(t, nothing)
	require.Equal(t, len(in), c.Len())
}
