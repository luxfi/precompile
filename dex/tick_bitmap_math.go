// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
)

// TickBitmapMath provides operations on the tick bitmap, matching
// Uniswap V4's TickBitmap.sol.
//
// The bitmap is a mapping from int16 (word position) to uint256 (256 bits).
// Each bit tracks whether a tick is initialized (has liquidity).
//
// Tick positions are compressed by tickSpacing before indexing.
// compress(tick) = tick / tickSpacing (floor division).

// Compress converts a raw tick to a compressed tick index for bitmap lookup.
// Uses floor division: negative ticks round toward negative infinity.
func Compress(tick, tickSpacing int32) int32 {
	if tick < 0 && tick%tickSpacing != 0 {
		return tick/tickSpacing - 1
	}
	return tick / tickSpacing
}

// TickBitmapPosition returns the word position and bit position for a given compressed tick.
// wordPos = compressed >> 8 (which 256-bit word)
// bitPos = compressed % 256 (which bit within that word)
func TickBitmapPosition(compressed int32) (wordPos int16, bitPos uint8) {
	wordPos = int16(compressed >> 8)
	bitPos = uint8(compressed & 0xFF) // equivalent to % 256 for int
	return
}

// FlipTick toggles the initialized state of a tick in the bitmap.
// tick must be aligned to tickSpacing.
func FlipTick(bitmap *TickBitmap, tick, tickSpacing int32) {
	if tick%tickSpacing != 0 {
		return // Only aligned ticks can be flipped
	}
	compressed := Compress(tick, tickSpacing)
	wordPos, bitPos := TickBitmapPosition(compressed)

	mask := new(big.Int).Lsh(bigOne, uint(bitPos))

	word := bitmap.Words[wordPos]
	if word == nil {
		word = new(big.Int)
	}
	bitmap.Words[wordPos] = new(big.Int).Xor(word, mask)
}

// NextInitializedTickWithinOneWord finds the next initialized tick within the same word.
//
// Parameters:
//   - tick: current tick
//   - tickSpacing: pool's tick spacing
//   - lte: if true, search to the left (less-than-or-equal, for zeroForOne swaps)
//     if false, search to the right (greater-than, for oneForZero swaps)
//
// Returns:
//   - next: the next initialized tick, or the boundary of the word if none found
//   - initialized: whether an initialized tick was found within this word
func NextInitializedTickWithinOneWord(
	bitmap *TickBitmap,
	tick, tickSpacing int32,
	lte bool,
) (next int32, initialized bool) {
	compressed := Compress(tick, tickSpacing)

	if lte {
		// Search leftward (decreasing ticks)
		wordPos, bitPos := TickBitmapPosition(compressed)
		word := bitmap.Words[wordPos]
		if word == nil {
			word = new(big.Int)
		}

		// Mask: all bits at and to the right of bitPos (including bitPos)
		// mask = (1 << (bitPos + 1)) - 1
		mask := new(big.Int).Sub(
			new(big.Int).Lsh(bigOne, uint(bitPos)+1),
			bigOne,
		)
		masked := new(big.Int).And(word, mask)

		if masked.Sign() != 0 {
			// Found an initialized tick
			// msBit = most significant bit of masked
			msBit := masked.BitLen() - 1
			next = (int32(wordPos)*256 + int32(msBit)) * tickSpacing
			return next, true
		}
		// No initialized tick in this word; return the left boundary
		next = int32(wordPos) * 256 * tickSpacing
		return next, false
	}

	// Search rightward (increasing ticks)
	// Start from the next compressed tick
	compressed++
	wordPos, bitPos := TickBitmapPosition(compressed)
	word := bitmap.Words[wordPos]
	if word == nil {
		word = new(big.Int)
	}

	// Mask: all bits at and to the left of bitPos (including bitPos)
	// mask = ~((1 << bitPos) - 1)
	lowMask := new(big.Int).Sub(
		new(big.Int).Lsh(bigOne, uint(bitPos)),
		bigOne,
	)
	// Invert within 256 bits
	fullMask := new(big.Int).Sub(new(big.Int).Lsh(bigOne, 256), bigOne)
	mask := new(big.Int).And(
		new(big.Int).Xor(lowMask, fullMask),
		fullMask,
	)
	masked := new(big.Int).And(word, mask)

	if masked.Sign() != 0 {
		// Find the least significant bit
		lsBit := lsb256(masked)
		next = (int32(wordPos)*256 + int32(lsBit)) * tickSpacing
		return next, true
	}
	// No initialized tick; return the right boundary of this word
	next = (int32(wordPos)*256 + 255) * tickSpacing
	return next, false
}

// lsb256 finds the index of the least significant bit of a positive big.Int.
func lsb256(x *big.Int) int {
	if x.Sign() <= 0 {
		return 0
	}
	// The position of the lowest set bit
	for i := range 256 {
		if x.Bit(i) != 0 {
			return i
		}
	}
	return 0
}
