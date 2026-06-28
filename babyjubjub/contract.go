// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package babyjubjub implements Baby Jubjub twisted Edwards curve precompile
// on the Lux EVM.
//
// Address: 0x0500000000000000000000000000000000000007
//
// CURVE FORM — IMPORTANT:
//
// This precompile operates on Baby Jubjub in the REDUCED twisted Edwards
// form used by circom, iden3, Polygon zkEVM, and gnark-crypto:
//
//	a' x^2 + y^2 = 1 + d' x^2 y^2       over F_r  (r = BN254 scalar order)
//	a' = -1
//	d' = 12181644023421730124874158521699555681764249180949974110617291017600649128846
//	Base B' = (
//	    9671717474070082183213120605117400219616337014328744928644933853176787189663,
//	    16950150798460657717958625567821834550301663161624707787222815936182638968203
//	)
//
// EIP-2494 defines Baby Jubjub primarily in the STANDARD twisted Edwards
// form (a=168700, d=168696, base (5299..., 16950...)). The two forms are
// birationally equivalent via the scaling factor
//
//	f  =  6360561867910373094066688120553762416144456282423235903351243436111059670888
//	-f =  15527681003928902128179717624703512672403908117992798440346960750464748824729
//
// Standard (x, y) <-> Reduced (x', y'):
//
//	x'  =  x * (-f) mod r
//	y'  =  y
//
// Callers that produce points in EIP-2494 standard form MUST convert to
// reduced form before submitting to this precompile. The conversion is
// a single multiplication in F_r; see contract_test.go's EIP-2494
// conformance tests for worked examples.
//
// Operations:
//   - 0x01: PointAdd  — P1(64) + P2(64) -> P3(64)
//   - 0x02: ScalarMul — P(64) + scalar(32) -> P*s(64)
//   - 0x03: InCurve   — P(64) -> bool(32)
//
// Encoding: each point is (x, y) with each coordinate a 32-byte
// big-endian integer in [0, r).
//
// Used by: circom / iden3 / Polygon zkEVM / Semaphore / RLN / EdDSA on BN254.
package babyjubjub

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000007")

	BabyJubJubPrecompile = &babyJubJubPrecompile{}

	_ contract.StatefulPrecompiledContract = &babyJubJubPrecompile{}

	ErrInvalidInput = contract.ErrInvalidInput
	ErrInvalidOp    = errors.New("invalid babyjubjub operation")
	ErrNotOnCurve   = errors.New("point not on baby jubjub curve")
)

const (
	OpPointAdd  = 0x01
	OpScalarMul = 0x02
	OpInCurve   = 0x03

	PointLen = 64 // x(32) + y(32)

	GasPointAdd  = 2000
	GasScalarMul = 7000
	GasInCurve   = 500
)

var curve = twistededwards.GetEdwardsCurve()

type babyJubJubPrecompile struct{}

func (p *babyJubJubPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpPointAdd:
		return GasPointAdd
	case OpScalarMul:
		return GasScalarMul
	case OpInCurve:
		return GasInCurve
	default:
		return 0
	}
}

func (p *babyJubJubPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	switch input[0] {
	case OpPointAdd:
		return p.pointAdd(input[1:], gas)
	case OpScalarMul:
		return p.scalarMul(input[1:], gas)
	case OpInCurve:
		return p.inCurve(input[1:], gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

func decodePoint(data []byte) (twistededwards.PointAffine, error) {
	if len(data) < PointLen {
		return twistededwards.PointAffine{}, ErrInvalidInput
	}
	var x, y fr.Element
	x.SetBytes(data[:32])
	y.SetBytes(data[32:64])
	pt := twistededwards.PointAffine{X: x, Y: y}
	if !pt.IsOnCurve() {
		return twistededwards.PointAffine{}, ErrNotOnCurve
	}
	return pt, nil
}

func encodePoint(pt *twistededwards.PointAffine) []byte {
	result := make([]byte, PointLen)
	xBytes := pt.X.Bytes()
	yBytes := pt.Y.Bytes()
	copy(result[:32], xBytes[:])
	copy(result[32:], yBytes[:])
	return result
}

func (p *babyJubJubPrecompile) pointAdd(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 2*PointLen {
		return nil, gas, ErrInvalidInput
	}
	a, err := decodePoint(data[:PointLen])
	if err != nil {
		return nil, gas, err
	}
	b, err := decodePoint(data[PointLen : 2*PointLen])
	if err != nil {
		return nil, gas, err
	}
	a.Add(&a, &b)
	return encodePoint(&a), gas, nil
}

func (p *babyJubJubPrecompile) scalarMul(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < PointLen+32 {
		return nil, gas, ErrInvalidInput
	}
	pt, err := decodePoint(data[:PointLen])
	if err != nil {
		return nil, gas, err
	}
	var s fr.Element
	s.SetBytes(data[PointLen : PointLen+32])
	sBig := s.BigInt(new(big.Int))
	pt.ScalarMultiplication(&pt, sBig)
	return encodePoint(&pt), gas, nil
}

func (p *babyJubJubPrecompile) inCurve(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < PointLen {
		return nil, gas, ErrInvalidInput
	}
	var x, y fr.Element
	x.SetBytes(data[:32])
	y.SetBytes(data[32:64])
	pt := twistededwards.PointAffine{X: x, Y: y}
	result := make([]byte, 32)
	if pt.IsOnCurve() {
		result[31] = 1
	}
	return result, gas, nil
}
