// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"fmt"
	"math/big"
)

// TickMath implements tick <-> sqrtPrice conversions matching Uniswap V4's TickMath.sol.
//
// sqrtPriceX96 = sqrt(1.0001^tick) * 2^96
//
// The implementation uses the exact same magic constants and binary decomposition
// approach as Uniswap V4. Each tick is decomposed into powers of 2, and the
// corresponding sqrt ratio factors are multiplied/divided.

// GetSqrtRatioAtTick computes sqrtPriceX96 from a tick value.
// Returns sqrt(1.0001^tick) * 2^96 as a uint160 in *big.Int.
// tick must be in [MinTick, MaxTick].
func GetSqrtRatioAtTick(tick int32) (*big.Int, error) {
	if tick < MinTick || tick > MaxTick {
		return nil, fmt.Errorf("tick %d out of range [%d, %d]", tick, MinTick, MaxTick)
	}

	absTick := tick
	if absTick < 0 {
		absTick = -absTick
	}

	// Start with Q128 (1.0 in Q128.128 format)
	// We multiply by factors for each set bit in absTick.
	// These magic constants are from Uniswap V4's TickMath.sol.
	ratio := new(big.Int)

	if absTick&0x1 != 0 {
		ratio.SetString("fffcb933bd6fad37aa2d162d1a594001", 16)
	} else {
		ratio.SetString("100000000000000000000000000000000", 16)
	}

	mulShift := func(r *big.Int, factor string) {
		f, _ := new(big.Int).SetString(factor, 16)
		r.Mul(r, f)
		r.Rsh(r, 128)
	}

	if absTick&0x2 != 0 {
		mulShift(ratio, "fff97272373d413259a46990580e213a")
	}
	if absTick&0x4 != 0 {
		mulShift(ratio, "fff2e50f5f656932ef12357cf3c7fdcc")
	}
	if absTick&0x8 != 0 {
		mulShift(ratio, "ffe5caca7e10e4e61c3624eaa0941cd0")
	}
	if absTick&0x10 != 0 {
		mulShift(ratio, "ffcb9843d60f6159c9db58835c926644")
	}
	if absTick&0x20 != 0 {
		mulShift(ratio, "ff973b41fa98c081472e6896dfb254c0")
	}
	if absTick&0x40 != 0 {
		mulShift(ratio, "ff2ea16466c96a3843ec78b326b52861")
	}
	if absTick&0x80 != 0 {
		mulShift(ratio, "fe5dee046a99a2a811c461f1969c3053")
	}
	if absTick&0x100 != 0 {
		mulShift(ratio, "fcbe86c7900a88aedcffc83b479aa3a4")
	}
	if absTick&0x200 != 0 {
		mulShift(ratio, "f987a7253ac413176f2b074cf7815e54")
	}
	if absTick&0x400 != 0 {
		mulShift(ratio, "f3392b0822b70005940c7a398e4b70f3")
	}
	if absTick&0x800 != 0 {
		mulShift(ratio, "e7159475a2c29b7443b29c7fa6e889d9")
	}
	if absTick&0x1000 != 0 {
		mulShift(ratio, "d097f3bdfd2022b8845ad8f792aa5825")
	}
	if absTick&0x2000 != 0 {
		mulShift(ratio, "a9f746462d870fdf8a65dc1f90e061e5")
	}
	if absTick&0x4000 != 0 {
		mulShift(ratio, "70d869a156d2a1b890bb3df62baf32f7")
	}
	if absTick&0x8000 != 0 {
		mulShift(ratio, "31be135f97d08fd981231505542fcfa6")
	}
	if absTick&0x10000 != 0 {
		mulShift(ratio, "9aa508b5b7a84e1c677de54f3e99bc9")
	}
	if absTick&0x20000 != 0 {
		mulShift(ratio, "5d6af8dedb81196699c329225ee604")
	}
	if absTick&0x40000 != 0 {
		mulShift(ratio, "2216e584f5fa1ea926041bedfe98")
	}
	if absTick&0x80000 != 0 {
		mulShift(ratio, "48a170391f7dc42444e8fa2")
	}

	// If tick is positive, invert: ratio = type(uint256).max / ratio
	if tick > 0 {
		ratio.Div(maxU256, ratio)
	}

	// Convert from Q128.128 to Q96: shift right by 32 bits, rounding up
	// sqrtPriceX96 = (ratio >> 32) + (ratio % (1 << 32) == 0 ? 0 : 1)
	remainder := new(big.Int).And(ratio, new(big.Int).Sub(new(big.Int).Lsh(bigOne, 32), bigOne))
	ratio.Rsh(ratio, 32)
	if remainder.Sign() > 0 {
		ratio.Add(ratio, bigOne)
	}

	return ratio, nil
}

// GetTickAtSqrtRatio computes the greatest tick value such that
// getSqrtRatioAtTick(tick) <= sqrtPriceX96.
// sqrtPriceX96 must be in [MIN_SQRT_RATIO, MAX_SQRT_RATIO).
//
// Implementation matches Uniswap V4 TickMath.sol exactly: unsigned 256-bit
// arithmetic with two's complement interpretation for signed results.
func GetTickAtSqrtRatio(sqrtPriceX96 *big.Int) (int32, error) {
	if sqrtPriceX96.Cmp(MinSqrtRatio) < 0 || sqrtPriceX96.Cmp(MaxSqrtRatio) >= 0 {
		return 0, fmt.Errorf("sqrtPriceX96 %s out of range", sqrtPriceX96)
	}

	// ratio = sqrtPriceX96 << 32 (Q128.128 format)
	ratio := new(big.Int).Lsh(sqrtPriceX96, 32)

	// msb = most significant bit index
	msb := uint(msb256(ratio))

	// Normalize ratio to [2^127, 2^128)
	if msb >= 128 {
		ratio.Rsh(ratio, msb-127)
	} else {
		ratio.Lsh(ratio, 127-msb)
	}

	// log_2 as int256 (two's complement in 256 bits)
	// Integer part: (msb - 128) << 64 in two's complement uint256
	u256 := new(big.Int).Lsh(bigOne, 256)
	log2 := big.NewInt(int64(msb) - 128)
	log2.Lsh(log2, 64)
	if log2.Sign() < 0 {
		log2.Add(log2, u256) // Convert to two's complement unsigned
	}

	// Fractional log2 via repeated squaring (14 iterations matching V4)
	for i := uint(63); i >= 50; i-- {
		ratio.Mul(ratio, ratio)
		ratio.Rsh(ratio, 127)

		f := new(big.Int).Rsh(ratio, 128)
		// log_2 = log_2 | (f << i)
		log2.Or(log2, new(big.Int).Lsh(f, i))
		// ratio >>= f
		if f.Sign() > 0 {
			ratio.Rsh(ratio, uint(f.Uint64()))
		}

		if i == 50 {
			break
		}
	}

	// Keep log2 in uint256 range
	log2.And(log2, maxU256)

	// log_sqrt10001 = log_2 * 255738958999603826347141 (signed multiply in two's complement)
	// First convert log2 to signed
	log2Signed := uint256ToInt256(log2)

	factor, _ := new(big.Int).SetString("255738958999603826347141", 10)
	logSqrt10001 := new(big.Int).Mul(log2Signed, factor)

	// tickLow = int256(logSqrt10001 - 3402992956809132418596140100660247210) >> 128
	sub1, _ := new(big.Int).SetString("3402992956809132418596140100660247210", 10)
	tickLowVal := new(big.Int).Sub(logSqrt10001, sub1)
	tickLow := signedRsh128(tickLowVal)

	// tickHigh = int256(logSqrt10001 + 291339464771989622907027621153398088495) >> 128
	add1, _ := new(big.Int).SetString("291339464771989622907027621153398088495", 10)
	tickHighVal := new(big.Int).Add(logSqrt10001, add1)
	tickHigh := signedRsh128(tickHighVal)

	if tickLow == tickHigh {
		return tickLow, nil
	}

	sqrtAtHighTick, err := GetSqrtRatioAtTick(tickHigh)
	if err != nil {
		return tickLow, nil
	}
	if sqrtAtHighTick.Cmp(sqrtPriceX96) <= 0 {
		return tickHigh, nil
	}
	return tickLow, nil
}

// uint256ToInt256 interprets a uint256 value as a signed int256 (two's complement).
func uint256ToInt256(x *big.Int) *big.Int {
	result := new(big.Int).Set(x)
	// If bit 255 is set, the value is negative
	max := new(big.Int).Lsh(bigOne, 255)
	if result.Cmp(max) >= 0 {
		result.Sub(result, new(big.Int).Lsh(bigOne, 256))
	}
	return result
}

// signedRsh128 performs arithmetic right shift by 128 on a signed big.Int.
// Go's big.Int.Rsh is already an arithmetic right shift for signed values.
func signedRsh128(x *big.Int) int32 {
	return int32(new(big.Int).Rsh(x, 128).Int64())
}

// msb256 finds the index of the most significant bit of a positive big.Int.
func msb256(x *big.Int) int {
	if x.Sign() <= 0 {
		return 0
	}
	return x.BitLen() - 1
}

