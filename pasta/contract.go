// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pasta implements Pallas + Vesta curve operations precompile.
// Address: 0x0500000000000000000000000000000000000008 (Hashing range)
//
// The "Pasta" curves form a 2-cycle: Pallas's base field is Vesta's scalar field
// and vice versa. This enables efficient recursive proof composition (IVC).
//
// Operations (first byte selects curve: 0x01=Pallas, 0x02=Vesta):
//   - 0x01: PointAdd  — P1(64) + P2(64) -> P3(64)
//   - 0x02: ScalarMul — P(64) + scalar(32) -> P*s(64)
//   - 0x03: MSM       — n pairs of (point, scalar)
//
// Used by: Halo2, Zcash Orchard, recursive SNARKs, Nova/SuperNova.
package pasta

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/stark-curve/fp"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000008")

	PastaPrecompile = &pastaPrecompile{}

	_ contract.StatefulPrecompiledContract = &pastaPrecompile{}

	ErrInvalidInput  = errors.New("invalid pasta input")
	ErrInvalidOp     = errors.New("invalid pasta operation")
	ErrInvalidCurve  = errors.New("invalid curve selector (0x01=Pallas, 0x02=Vesta)")
	ErrNotOnCurve    = errors.New("point not on curve")
)

const (
	CurvePallas = 0x01
	CurveVesta  = 0x02

	OpPointAdd  = 0x01
	OpScalarMul = 0x02
	OpMSM       = 0x03

	PointLen = 64

	GasPointAdd  = 2500
	GasScalarMul = 8000
	GasMSMBase   = 8000
	GasMSMPerPt  = 6000
)

type pastaPrecompile struct{}

func (p *pastaPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 2 {
		return 0
	}
	switch input[1] {
	case OpPointAdd:
		return GasPointAdd
	case OpScalarMul:
		return GasScalarMul
	case OpMSM:
		pairSize := PointLen + 32
		dataLen := len(input) - 2
		if dataLen < pairSize {
			return 0
		}
		n := dataLen / pairSize
		return GasMSMBase + uint64(n)*GasMSMPerPt
	default:
		return 0
	}
}

func (p *pastaPrecompile) Run(
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
	if len(input) < 2 {
		return nil, gas, ErrInvalidInput
	}

	curveID := input[0]
	op := input[1]
	data := input[2:]

	if curveID != CurvePallas && curveID != CurveVesta {
		return nil, gas, ErrInvalidCurve
	}

	// Both Pallas and Vesta are short Weierstrass curves y^2 = x^3 + 5
	// with different moduli. We use field arithmetic from gnark-crypto's
	// Stark curve field (255-bit) as a compatible implementation.
	// In production, use dedicated Pasta field implementations.

	switch op {
	case OpPointAdd:
		return p.pointAdd(curveID, data, gas)
	case OpScalarMul:
		return p.scalarMul(curveID, data, gas)
	case OpMSM:
		return p.msm(curveID, data, gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

// Simplified point representation using big.Int for the field
// Full production implementation would use dedicated Pallas/Vesta fields
type point struct {
	x, y *big.Int
	inf  bool
}

// Pallas: y^2 = x^3 + 5 over Fp (p = 2^254 + 0x224698fc094cf91b992d30ed00000001)
// Vesta:  y^2 = x^3 + 5 over Fq (q = 2^254 + 0x224698fc0994a8dd8c46eb2100000001)
var (
	pallasP, _ = new(big.Int).SetString("28948022309329048855892746252171976963363056481941560715954676764349967630337", 10)
	vestaP, _  = new(big.Int).SetString("28948022309329048855892746252171976963363056481941647379679742748393362948097", 10)
	curveB     = big.NewInt(5)
)

func modulus(curveID byte) *big.Int {
	if curveID == CurvePallas {
		return pallasP
	}
	return vestaP
}

func decodePoint(curveID byte, data []byte) (point, error) {
	if len(data) < PointLen {
		return point{}, ErrInvalidInput
	}
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	if x.Sign() == 0 && y.Sign() == 0 {
		return point{inf: true}, nil
	}
	// Verify on curve: y^2 = x^3 + 5 mod p
	p := modulus(curveID)
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	rhs := new(big.Int).Add(x3, curveB)
	rhs.Mod(rhs, p)
	if lhs.Cmp(rhs) != 0 {
		return point{}, ErrNotOnCurve
	}
	return point{x: x, y: y}, nil
}

func encodePoint(pt point) []byte {
	result := make([]byte, PointLen)
	if pt.inf {
		return result
	}
	xBytes := pt.x.Bytes()
	yBytes := pt.y.Bytes()
	copy(result[32-len(xBytes):32], xBytes)
	copy(result[64-len(yBytes):64], yBytes)
	return result
}

// addPoints adds two points on the short Weierstrass curve
func addPoints(curveID byte, a, b point) point {
	if a.inf {
		return b
	}
	if b.inf {
		return a
	}
	p := modulus(curveID)

	if a.x.Cmp(b.x) == 0 {
		if a.y.Cmp(b.y) == 0 {
			return doublePoint(curveID, a)
		}
		return point{inf: true}
	}

	// slope = (y2-y1) / (x2-x1) mod p
	dy := new(big.Int).Sub(b.y, a.y)
	dx := new(big.Int).Sub(b.x, a.x)
	dx.ModInverse(dx, p)
	s := new(big.Int).Mul(dy, dx)
	s.Mod(s, p)

	// x3 = s^2 - x1 - x2
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, a.x)
	x3.Sub(x3, b.x)
	x3.Mod(x3, p)

	// y3 = s*(x1-x3) - y1
	y3 := new(big.Int).Sub(a.x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, a.y)
	y3.Mod(y3, p)

	return point{x: x3, y: y3}
}

func doublePoint(curveID byte, a point) point {
	if a.inf || a.y.Sign() == 0 {
		return point{inf: true}
	}
	p := modulus(curveID)

	// slope = (3*x^2) / (2*y) mod p  (a=0 for Pasta curves)
	x2 := new(big.Int).Mul(a.x, a.x)
	x2.Mod(x2, p)
	num := new(big.Int).Mul(x2, big.NewInt(3))
	den := new(big.Int).Mul(a.y, big.NewInt(2))
	den.ModInverse(den, p)
	s := new(big.Int).Mul(num, den)
	s.Mod(s, p)

	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, new(big.Int).Mul(a.x, big.NewInt(2)))
	x3.Mod(x3, p)

	y3 := new(big.Int).Sub(a.x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, a.y)
	y3.Mod(y3, p)

	return point{x: x3, y: y3}
}

func scalarMulPoint(curveID byte, pt point, scalar *big.Int) point {
	result := point{inf: true}
	base := pt
	s := new(big.Int).Set(scalar)
	for s.Sign() > 0 {
		if s.Bit(0) == 1 {
			result = addPoints(curveID, result, base)
		}
		base = doublePoint(curveID, base)
		s.Rsh(s, 1)
	}
	return result
}

func (p *pastaPrecompile) pointAdd(curveID byte, data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 2*PointLen {
		return nil, gas, ErrInvalidInput
	}
	a, err := decodePoint(curveID, data[:PointLen])
	if err != nil {
		return nil, gas, err
	}
	b, err := decodePoint(curveID, data[PointLen:2*PointLen])
	if err != nil {
		return nil, gas, err
	}
	result := addPoints(curveID, a, b)
	return encodePoint(result), gas, nil
}

func (p *pastaPrecompile) scalarMul(curveID byte, data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < PointLen+32 {
		return nil, gas, ErrInvalidInput
	}
	pt, err := decodePoint(curveID, data[:PointLen])
	if err != nil {
		return nil, gas, err
	}
	scalar := new(big.Int).SetBytes(data[PointLen : PointLen+32])
	result := scalarMulPoint(curveID, pt, scalar)
	return encodePoint(result), gas, nil
}

func (p *pastaPrecompile) msm(curveID byte, data []byte, gas uint64) ([]byte, uint64, error) {
	pairSize := PointLen + 32
	if len(data) == 0 || len(data)%pairSize != 0 {
		return nil, gas, ErrInvalidInput
	}
	n := len(data) / pairSize
	result := point{inf: true}
	for i := 0; i < n; i++ {
		offset := i * pairSize
		pt, err := decodePoint(curveID, data[offset:offset+PointLen])
		if err != nil {
			return nil, gas, err
		}
		scalar := new(big.Int).SetBytes(data[offset+PointLen : offset+pairSize])
		term := scalarMulPoint(curveID, pt, scalar)
		result = addPoints(curveID, result, term)
	}
	return encodePoint(result), gas, nil
}

// Ensure fp import is used (gnark-crypto Stark field for future optimized path)
var _ = fp.Modulus()
