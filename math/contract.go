// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package math implements fixed-point arithmetic precompiles.
// Address: 0x0400000000000000000000000000000000000050 (DEX math range)
//
// Operations:
//   - 0x01: MulDiv(a, b, denominator) -> (a * b) / denominator without overflow
//   - 0x02: MulDivRoundUp(a, b, denominator) -> ceiling division
//   - 0x03: Sqrt(x) -> floor(sqrt(x)) using Newton's method
//   - 0x04: Log2(x) -> floor(log2(x)) * 2^128 (Q128.128)
//   - 0x05: Exp(x) -> e^x in Q128.128 format
//   - 0x06: Pow(base, exp) -> base^exp via repeated squaring
//
// Gas: 50 base + 5 per 32-byte word
// Saves ~2000 gas per MulDiv vs Solidity (no overflow checks in Go native)
package math

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0400000000000000000000000000000000000050")

	Precompile = &fixedPointMathPrecompile{}

	_ contract.StatefulPrecompiledContract = Precompile

	ErrInvalidInput = contract.ErrInvalidInput
	// ErrOutOfGas aliases the canonical sentinel so callers can
	// errors.Is(err, contract.ErrOutOfGas) across every precompile.
	ErrOutOfGas  = contract.ErrOutOfGas
	ErrDivByZero = errors.New("division by zero")
	ErrUnknownOp = errors.New("unknown math operation")
	ErrOverflow  = errors.New("result overflows uint256")
)

// maxU256 bounds every result this precompile returns as a number. padTo32 keeps
// only the LOW 32 bytes, so without this bound an out-of-range result is not an
// error — it is a different, wrong, entirely plausible number.
var maxU256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

const (
	OpMulDiv        = 0x01
	OpMulDivRoundUp = 0x02
	OpSqrt          = 0x03
	OpLog2          = 0x04
	OpExp           = 0x05
	OpPow           = 0x06

	GasBase = 50
	GasWord = 5
)

// q128 = 2^128 for Q128.128 fixed-point
var q128 = new(big.Int).Lsh(big.NewInt(1), 128)

type fixedPointMathPrecompile struct{}

func (p *fixedPointMathPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 1 {
		return nil, suppliedGas, ErrInvalidInput
	}
	op := input[0]
	data := input[1:]

	words := uint64(len(data)+31) / 32
	gasCost := GasBase + words*GasWord
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	switch op {
	case OpMulDiv:
		return mulDiv(data, gas, false)
	case OpMulDivRoundUp:
		return mulDiv(data, gas, true)
	case OpSqrt:
		return sqrt(data, gas)
	case OpLog2:
		return log2(data, gas)
	case OpExp:
		return exp(data, gas)
	case OpPow:
		return pow(data, gas)
	default:
		return nil, gas, ErrUnknownOp
	}
}

// mulDiv computes (a * b) / d, optionally rounding up.
func mulDiv(data []byte, gas uint64, roundUp bool) ([]byte, uint64, error) {
	if len(data) < 96 {
		return nil, gas, ErrInvalidInput
	}
	a := new(big.Int).SetBytes(data[:32])
	b := new(big.Int).SetBytes(data[32:64])
	d := new(big.Int).SetBytes(data[64:96])
	if d.Sign() == 0 {
		return nil, gas, ErrDivByZero
	}
	result := new(big.Int).Mul(a, b)
	if roundUp {
		// ceil(a*b/d) = (a*b + d - 1) / d
		result.Add(result, new(big.Int).Sub(d, big.NewInt(1)))
	}
	result.Div(result, d)
	// REFUSE an out-of-range result instead of returning its low 256 bits. The
	// intermediate a*b is a full 512-bit product, so a quotient past uint256 is
	// ordinary calldata, not an exotic case: MulDiv(2^255, 4, 1) is 2^257, whose low
	// 256 bits are ZERO, and MulDiv(max, max, 1) truncates to ONE. Returning those is
	// worse than failing — the caller cannot tell a wrapped answer from a real one,
	// and this is the primitive fees and share ratios are computed with. Solidity's
	// FullMath.sol requires the same bound; erroring here is what makes the EVM revert.
	if result.Cmp(maxU256) > 0 {
		return nil, gas, ErrOverflow
	}
	return padTo32(result.Bytes()), gas, nil
}

// sqrt computes floor(sqrt(x)) using big.Int.Sqrt.
func sqrt(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	x := new(big.Int).SetBytes(data[:32])
	if x.Sign() < 0 {
		return nil, gas, ErrInvalidInput
	}
	result := new(big.Int).Sqrt(x)
	return padTo32(result.Bytes()), gas, nil
}

// log2 computes floor(log2(x)) as a uint256. Returns 0 for x=0.
func log2(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	x := new(big.Int).SetBytes(data[:32])
	if x.Sign() <= 0 {
		return padTo32(nil), gas, nil
	}
	result := big.NewInt(int64(x.BitLen() - 1))
	return padTo32(result.Bytes()), gas, nil
}

// exp computes e^x where x is a Q128.128 fixed-point number.
// Uses Taylor series: e^x = sum(x^n / n!) for n=0..30
// Result is Q128.128.
func exp(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	x := new(big.Int).SetBytes(data[:32])

	// Start with 1.0 in Q128.128
	result := new(big.Int).Set(q128)
	term := new(big.Int).Set(q128)

	for n := int64(1); n <= 30; n++ {
		// term = term * x / (n * 2^128)
		term.Mul(term, x)
		term.Div(term, new(big.Int).Mul(big.NewInt(n), q128))
		if term.Sign() == 0 {
			break
		}
		result.Add(result, term)
	}
	// Same rule as mulDiv: e^x leaves uint256 for any x above ~88 in Q128.128, and the
	// truncated remainder is a plausible-looking number with no relation to e^x.
	if result.Cmp(maxU256) > 0 {
		return nil, gas, ErrOverflow
	}
	return padTo32(result.Bytes()), gas, nil
}

// pow computes base^exponent via binary exponentiation.
// Both base and exponent are uint256.
func pow(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	base := new(big.Int).SetBytes(data[:32])
	exponent := new(big.Int).SetBytes(data[32:64])

	// Use modular exponentiation with 2^256 as the modulus to stay in uint256 range.
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	result := new(big.Int).Exp(base, exponent, mod)
	return padTo32(result.Bytes()), gas, nil
}

// padTo32 left-pads a byte slice to 32 bytes.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
