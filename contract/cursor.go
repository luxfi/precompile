// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"encoding/binary"
	"fmt"
)

// ErrShort reports that the input ended before the wire format did: either
// fewer bytes remain than a fixed field needs, or a length read off the wire
// declares more bytes than the calldata holds.
//
// ErrTrailing reports bytes left over after the format was fully read.
//
// Both wrap ErrInvalidInput, so a caller that already refuses on
// errors.Is(err, ErrInvalidInput) keeps refusing exactly as before. They are
// built once at init, so returning one allocates nothing.
var (
	ErrShort    = fmt.Errorf("%w: shorter than the wire format requires", ErrInvalidInput)
	ErrTrailing = fmt.Errorf("%w: trailing bytes after the wire format", ErrInvalidInput)
)

// Cursor reads a wire format off calldata one field at a time. It is the one
// way a precompile parses its input.
//
// Why a type rather than hand-written slice expressions:
//
// A precompile's input is a window into the EVM memory store. instructions.go
// (opCall and its three siblings) takes it with Memory.GetPtr, which returns
// the two-index slice m.store[offset : offset+size], and nothing on the path
// to Run copies it. So len(input) is the size the caller declared and paid gas
// for, while cap(input) is the rest of EVM memory — which that same caller
// filled with MSTORE before making the call.
//
// A Go slice expression s[a:b] refuses only when b exceeds cap(s). Past len
// and within cap it succeeds silently. A parser that reaches past its input
// therefore does not panic and does not halt a validator: it reads bytes the
// attacker chose, hands them to a verifier, and returns a verdict computed
// over material the caller never declared and never paid for. That is a
// forgery surface, and it is invisible to any test whose fixture leaves the
// spare region zeroed.
//
// Every read below is bounded against Len, never against cap, and never by
// letting a slice expression refuse. Every returned slice is capped to its own
// length so a downstream re-slice cannot walk forward into the same region. A
// parser written on this type cannot have the bug, and it does not depend on
// how its fixtures were built.
//
// The zero Cursor is an empty input: every read refuses.
type Cursor struct {
	buf []byte
	off int // invariant: 0 <= off <= len(buf)
}

// Read starts a cursor at the front of b.
func Read(b []byte) *Cursor { return &Cursor{buf: b} }

// Len is the number of bytes not yet read. Never negative.
func (c *Cursor) Len() int { return len(c.buf) - c.off }

// Bytes consumes exactly n bytes and returns them, or refuses.
//
// n is uint64 because it is usually a length read off the wire, and a wire
// length converted to int is negative on a 32-bit build for anything above
// 2^31 — where a slice expression refuses but a hand-written `< len` guard
// passes. The comparison here is a subtraction on the trusted Len, never an
// addition against an attacker-chosen n, so nothing can wrap past it.
//
// The returned slice has cap == len. It is a window on the input, not a copy,
// but it cannot be re-sliced forward: a caller that asks for 32 bytes and then
// reads 64 gets a panic rather than 32 bytes of somebody else's memory. That
// tripwire should never fire, since the point of the cursor is that a caller
// receives exactly the field it named. Between a loud failure and a silent
// forgery, loud is the correct direction.
func (c *Cursor) Bytes(n uint64) ([]byte, error) {
	if n > uint64(c.Len()) {
		return nil, ErrShort
	}
	lo := c.off
	hi := lo + int(n)
	c.off = hi
	return c.buf[lo:hi:hi], nil
}

// Byte consumes one byte.
func (c *Cursor) Byte() (byte, error) {
	b, err := c.Bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// Uint16 consumes a big-endian uint16.
func (c *Cursor) Uint16() (uint16, error) {
	b, err := c.Bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// Uint32 consumes a big-endian uint32.
func (c *Cursor) Uint32() (uint32, error) {
	b, err := c.Bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// Uint64 consumes a big-endian uint64.
func (c *Cursor) Uint64() (uint64, error) {
	b, err := c.Bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// Rest consumes and returns everything left, capped to its own length.
// Use it where the format ends in an open field; use End where the format is
// pinned exactly.
func (c *Cursor) Rest() []byte {
	b, _ := c.Bytes(uint64(c.Len()))
	return b
}

// End refuses any bytes left over.
//
// Whether trailing bytes are refused is a property of the wire format, not of
// the parser: a format that admits them lets one signature be presented under
// many distinct calldatas. Formats that already document padding as accepted
// keep accepting it, and simply do not call End.
func (c *Cursor) End() error {
	if c.Len() != 0 {
		return ErrTrailing
	}
	return nil
}
