// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package curve25519 implements raw Edwards25519 point operations precompile.
// Address: 0x0000000000000000000000000000000000009204 (Privacy range)
//
// Lower-level than x25519 (which is just Diffie-Hellman scalar mul on Montgomery form).
// This provides direct Edwards point add, scalar mul, and basepoint mul for
// advanced crypto protocols like ring signatures, Bulletproofs, and VRFs.
//
// Operations:
//   - 0x01: PointAdd     — P1(32) + P2(32) -> P3(32) (compressed Edwards points)
//   - 0x02: ScalarMul    — P(32) + scalar(32) -> P*s(32)
//   - 0x03: BasepointMul — scalar(32) -> B*s(32) (generator mul, constant-time)
//   - 0x04: VarTimeMultiScalarMul — n*(point(32) + scalar(32)) -> sum(32)
//
// Used by: ring signatures, Bulletproofs, VRFs, Ristretto255 primitives.
package curve25519

import (
	"errors"

	"filippo.io/edwards25519"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000009204")

	Curve25519Precompile = &curve25519Precompile{}

	_ contract.StatefulPrecompiledContract = &curve25519Precompile{}

	ErrInvalidInput = contract.ErrInvalidInput
	ErrInvalidOp    = errors.New("invalid curve25519 operation")
	ErrInvalidPoint = errors.New("invalid Edwards25519 point")
)

const (
	OpPointAdd     = 0x01
	OpScalarMul    = 0x02
	OpBasepointMul = 0x03
	OpMSM          = 0x04

	CompressedLen = 32
	ScalarLen     = 32

	GasPointAdd     = 1500
	GasScalarMul    = 5000
	GasBasepointMul = 5000
	GasMSMBase      = 5000
	GasMSMPerPair   = 4000
)

type curve25519Precompile struct{}

func (p *curve25519Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpPointAdd:
		return GasPointAdd
	case OpScalarMul:
		return GasScalarMul
	case OpBasepointMul:
		return GasBasepointMul
	case OpMSM:
		pairSize := CompressedLen + ScalarLen
		dataLen := len(input) - 1
		if dataLen < pairSize {
			return 0
		}
		n := dataLen / pairSize
		return GasMSMBase + uint64(n)*GasMSMPerPair
	default:
		return 0
	}
}

func (p *curve25519Precompile) Run(
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
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, gas, err
	}
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	switch input[0] {
	case OpPointAdd:
		return p.pointAdd(input[1:], gas)
	case OpScalarMul:
		return p.scalarMul(input[1:], gas)
	case OpBasepointMul:
		return p.basepointMul(input[1:], gas)
	case OpMSM:
		return p.msm(input[1:], gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

func decodePoint(data []byte) (*edwards25519.Point, error) {
	if len(data) < CompressedLen {
		return nil, ErrInvalidInput
	}
	pt, err := new(edwards25519.Point).SetBytes(data[:CompressedLen])
	if err != nil {
		return nil, ErrInvalidPoint
	}
	return pt, nil
}

func decodeScalar(data []byte) (*edwards25519.Scalar, error) {
	if len(data) < ScalarLen {
		return nil, ErrInvalidInput
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(data[:ScalarLen])
	if err != nil {
		return nil, ErrInvalidInput
	}
	return s, nil
}

func (p *curve25519Precompile) pointAdd(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 2*CompressedLen {
		return nil, gas, ErrInvalidInput
	}
	a, err := decodePoint(data[:CompressedLen])
	if err != nil {
		return nil, gas, err
	}
	b, err := decodePoint(data[CompressedLen : 2*CompressedLen])
	if err != nil {
		return nil, gas, err
	}
	result := new(edwards25519.Point).Add(a, b)
	return result.Bytes(), gas, nil
}

func (p *curve25519Precompile) scalarMul(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < CompressedLen+ScalarLen {
		return nil, gas, ErrInvalidInput
	}
	pt, err := decodePoint(data[:CompressedLen])
	if err != nil {
		return nil, gas, err
	}
	s, err := decodeScalar(data[CompressedLen : CompressedLen+ScalarLen])
	if err != nil {
		return nil, gas, err
	}
	result := new(edwards25519.Point).ScalarMult(s, pt)
	return result.Bytes(), gas, nil
}

func (p *curve25519Precompile) basepointMul(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < ScalarLen {
		return nil, gas, ErrInvalidInput
	}
	s, err := decodeScalar(data[:ScalarLen])
	if err != nil {
		return nil, gas, err
	}
	result := new(edwards25519.Point).ScalarBaseMult(s)
	return result.Bytes(), gas, nil
}

func (p *curve25519Precompile) msm(data []byte, gas uint64) ([]byte, uint64, error) {
	pairSize := CompressedLen + ScalarLen
	if len(data) == 0 || len(data)%pairSize != 0 {
		return nil, gas, ErrInvalidInput
	}
	n := len(data) / pairSize

	// Accumulate via VarTimeMultiScalarMult (uses Straus/Pippenger)
	points := make([]*edwards25519.Point, n)
	scalars := make([]*edwards25519.Scalar, n)
	for i := range n {
		offset := i * pairSize
		pt, err := decodePoint(data[offset : offset+CompressedLen])
		if err != nil {
			return nil, gas, err
		}
		s, err := decodeScalar(data[offset+CompressedLen : offset+pairSize])
		if err != nil {
			return nil, gas, err
		}
		points[i] = pt
		scalars[i] = s
	}

	result := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	return result.Bytes(), gas, nil
}
