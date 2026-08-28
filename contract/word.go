// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"fmt"
	"math/big"
)

// ErrRange reports that a 256-bit word does not fit the width its wire format
// declares for it: a fee slot that must be a uint24 holding 2^24, a tick slot
// that must be an int24 holding 2^32, an amount that must be a uint64 holding
// 2^255.
//
// It wraps ErrInvalidInput, so a caller that already refuses on
// errors.Is(err, ErrInvalidInput) keeps refusing exactly as before.
var ErrRange = fmt.Errorf("%w: out of range for its declared width", ErrInvalidInput)

// one is the shift base for the range bounds below. Never mutated.
var one = big.NewInt(1)

// Unsigned narrows x to bits, or refuses.
//
// Why this exists rather than a bare x.Uint64():
//
// big.Int.Uint64 is documented "If x cannot be represented in a uint64, the
// result is undefined." Not truncated — undefined. Today it returns the low
// word, so a calldata word of 2^32+6 arrives downstream as 6 and a word of
// 2^255 arrives as 0. Neither is an error the caller can see, and a negative x
// yields its magnitude's low word, dropping the sign entirely. So on
// attacker-chosen input the narrowing is not a lossy conversion to reason
// about, it is a value substitution.
//
// The EVM word is 256 bits. Every place a wire format declares something
// narrower — uint24, uint64, an index, a length — the word that does not fit
// is malformed input, and the honest answer is to say so where the bytes
// become a value. One refusal at the edge, so nothing downstream has to
// remember which of its arguments were bounded.
//
// bits above 64 refuses everything: the result would not fit the return type,
// and failing closed on a caller's mistake is the direction that cannot be
// exploited. bits == 0 admits only zero, which is the honest reading of a
// zero-width field.
func Unsigned(x *big.Int, bits uint) (uint64, error) {
	if bits > 64 || x.Sign() < 0 || uint(x.BitLen()) > bits {
		return 0, ErrRange
	}
	return x.Uint64(), nil
}

// Signed narrows x to a two's-complement field of bits, or refuses.
//
// The admitted span is [-2^(bits-1), 2^(bits-1)-1] — the same span the wire
// format's sign extension can express, so a word that survives this is a word
// that round-trips through its own encoding. That round-trip is the property
// an identifier derived from the field depends on; see PoolKey.ID.
//
// BitLen alone cannot decide this: -2^(bits-1) and 2^(bits-1) share a bit
// length and only one of them is in range. So the bound is compared, not
// counted.
func Signed(x *big.Int, bits uint) (int64, error) {
	if bits == 0 || bits > 64 {
		return 0, ErrRange
	}
	hi := new(big.Int).Lsh(one, bits-1)
	if x.Cmp(hi) >= 0 || x.Cmp(hi.Neg(hi)) < 0 {
		return 0, ErrRange
	}
	return x.Int64(), nil
}
