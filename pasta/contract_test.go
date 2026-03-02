// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pasta

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0500000000000000000000000000000000000008"), ContractAddress)
}

// findPoint finds a valid point on the given curve (Pallas or Vesta)
func findPoint(curveID byte) point {
	mod := modulus(curveID)
	for xi := range int64(1000) {
		x := big.NewInt(xi)
		xCubed := new(big.Int).Exp(x, big.NewInt(3), mod)
		rhs := new(big.Int).Add(xCubed, curveB)
		rhs.Mod(rhs, mod)
		y := new(big.Int).ModSqrt(rhs, mod)
		if y != nil {
			return point{x: new(big.Int).Set(x), y: new(big.Int).Set(y)}
		}
	}
	panic("could not find point in first 1000 x values")
}

func TestPallas_PointAdd_Identity(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)
	identity := make([]byte, PointLen) // (0, 0) = infinity

	// P + O = P
	input := make([]byte, 2+2*PointLen)
	input[0] = CurvePallas
	input[1] = OpPointAdd
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], identity)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(ret, ptBytes), "P + identity should equal P")
}

func TestPallas_PointAdd_Commutative(t *testing.T) {
	p := &pastaPrecompile{}

	pt1 := findPoint(CurvePallas)
	pt2 := scalarMulPoint(CurvePallas, pt1, big.NewInt(2))
	pt1Bytes := encodePoint(pt1)
	pt2Bytes := encodePoint(pt2)

	// P1 + P2
	input1 := make([]byte, 2+2*PointLen)
	input1[0] = CurvePallas
	input1[1] = OpPointAdd
	copy(input1[2:], pt1Bytes)
	copy(input1[2+PointLen:], pt2Bytes)

	gas := p.RequiredGas(input1)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input1, gas, true)
	require.NoError(t, err)

	// P2 + P1
	input2 := make([]byte, 2+2*PointLen)
	input2[0] = CurvePallas
	input2[1] = OpPointAdd
	copy(input2[2:], pt2Bytes)
	copy(input2[2+PointLen:], pt1Bytes)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input2, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(ret1, ret2), "point addition must be commutative")
}

func TestPallas_ScalarMul_One(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)
	scalar := padBig(big.NewInt(1))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurvePallas
	input[1] = OpScalarMul
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(ret, ptBytes), "1*P should equal P")
}

func TestPallas_ScalarMul_Zero(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)
	scalar := padBig(big.NewInt(0))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurvePallas
	input[1] = OpScalarMul
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	identity := make([]byte, PointLen)
	require.True(t, bytes.Equal(ret, identity), "0*P should be infinity")
}

func TestPallas_ScalarMul_DoubleEqualsAdd(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)

	// 2*P via scalar mul
	mulInput := make([]byte, 2+PointLen+32)
	mulInput[0] = CurvePallas
	mulInput[1] = OpScalarMul
	copy(mulInput[2:], ptBytes)
	copy(mulInput[2+PointLen:], padBig(big.NewInt(2)))
	gas := p.RequiredGas(mulInput)
	mulResult, _, err := p.Run(nil, common.Address{}, ContractAddress, mulInput, gas, true)
	require.NoError(t, err)

	// P + P via point add
	addInput := make([]byte, 2+2*PointLen)
	addInput[0] = CurvePallas
	addInput[1] = OpPointAdd
	copy(addInput[2:], ptBytes)
	copy(addInput[2+PointLen:], ptBytes)
	gas = p.RequiredGas(addInput)
	addResult, _, err := p.Run(nil, common.Address{}, ContractAddress, addInput, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(mulResult, addResult), "2*P should equal P+P")
}

func TestPallas_ScalarMul_ResultOnCurve(t *testing.T) {
	pt := findPoint(CurvePallas)
	result := scalarMulPoint(CurvePallas, pt, big.NewInt(7))
	require.False(t, result.inf, "7*P should not be infinity")

	// Verify y^2 = x^3 + 5 mod p
	lhs := new(big.Int).Mul(result.y, result.y)
	lhs.Mod(lhs, pallasP)
	rhs := new(big.Int).Exp(result.x, big.NewInt(3), pallasP)
	rhs.Add(rhs, curveB)
	rhs.Mod(rhs, pallasP)
	require.Equal(t, 0, lhs.Cmp(rhs), "scalar mul result must be on Pallas curve")
}

func TestPallas_ScalarMul_RepeatedAddConsistency(t *testing.T) {
	pt := findPoint(CurvePallas)

	// 5*P via scalarMulPoint
	result := scalarMulPoint(CurvePallas, pt, big.NewInt(5))

	// 5*P via repeated addition
	acc := pt
	for i := 1; i < 5; i++ {
		acc = addPoints(CurvePallas, acc, pt)
	}

	require.Equal(t, 0, result.x.Cmp(acc.x), "x mismatch")
	require.Equal(t, 0, result.y.Cmp(acc.y), "y mismatch")
}

func TestVesta_PointAdd(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurveVesta)
	ptBytes := encodePoint(pt)
	identity := make([]byte, PointLen)

	input := make([]byte, 2+2*PointLen)
	input[0] = CurveVesta
	input[1] = OpPointAdd
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], identity)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(ret, ptBytes), "Vesta: P + O should equal P")
}

func TestVesta_ScalarMul(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurveVesta)
	ptBytes := encodePoint(pt)
	scalar := padBig(big.NewInt(3))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurveVesta
	input[1] = OpScalarMul
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, PointLen)
	require.False(t, isZero(ret), "3*P should not be zero on Vesta")
}

func TestVesta_DoubleEqualsAdd(t *testing.T) {
	pt := findPoint(CurveVesta)

	// P + P
	sum := addPoints(CurveVesta, pt, pt)
	// 2*P
	dbl := doublePoint(CurveVesta, pt)

	require.Equal(t, 0, sum.x.Cmp(dbl.x), "P+P.x should equal double(P).x")
	require.Equal(t, 0, sum.y.Cmp(dbl.y), "P+P.y should equal double(P).y")
}

func TestMSM_Pallas(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)

	// MSM: 3*P + 5*P = 8*P
	s3 := padBig(big.NewInt(3))
	s5 := padBig(big.NewInt(5))

	input := make([]byte, 2+2*(PointLen+32))
	input[0] = CurvePallas
	input[1] = OpMSM
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], s3)
	copy(input[2+PointLen+32:], ptBytes)
	copy(input[2+2*PointLen+32:], s5)

	gas := p.RequiredGas(input)
	msmResult, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	// Compare with 8*P
	mulInput := make([]byte, 2+PointLen+32)
	mulInput[0] = CurvePallas
	mulInput[1] = OpScalarMul
	copy(mulInput[2:], ptBytes)
	copy(mulInput[2+PointLen:], padBig(big.NewInt(8)))
	gas = p.RequiredGas(mulInput)
	expected, _, err := p.Run(nil, common.Address{}, ContractAddress, mulInput, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(msmResult, expected), "MSM(3*P + 5*P) should equal 8*P")
}

func TestMSM_SinglePair(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)
	s := padBig(big.NewInt(11))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurvePallas
	input[1] = OpMSM
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], s)

	gas := p.RequiredGas(input)
	msmResult, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	// Compare with ScalarMul(P, 11)
	smInput := make([]byte, 2+PointLen+32)
	smInput[0] = CurvePallas
	smInput[1] = OpScalarMul
	copy(smInput[2:], ptBytes)
	copy(smInput[2+PointLen:], s)
	gas = p.RequiredGas(smInput)
	smResult, _, err := p.Run(nil, common.Address{}, ContractAddress, smInput, gas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(msmResult, smResult), "MSM with 1 pair should match ScalarMul")
}

func TestInvalidCurve(t *testing.T) {
	p := &pastaPrecompile{}

	input := make([]byte, 2+2*PointLen)
	input[0] = 0xFF
	input[1] = OpPointAdd

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCurve)
}

func TestInvalidOperation(t *testing.T) {
	p := &pastaPrecompile{}

	input := make([]byte, 2+2*PointLen)
	input[0] = CurvePallas
	input[1] = 0xFF

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestPointAdd_InputTooShort(t *testing.T) {
	p := &pastaPrecompile{}

	input := make([]byte, 2+PointLen)
	input[0] = CurvePallas
	input[1] = OpPointAdd

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestScalarMul_InputTooShort(t *testing.T) {
	p := &pastaPrecompile{}

	input := make([]byte, 2+PointLen)
	input[0] = CurvePallas
	input[1] = OpScalarMul

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestPointNotOnCurve(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)

	bogus := make([]byte, PointLen)
	bogus[31] = 1 // x = 1
	bogus[63] = 1 // y = 1 (not on curve)

	input := make([]byte, 2+2*PointLen)
	input[0] = CurvePallas
	input[1] = OpPointAdd
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], bogus)

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotOnCurve)
}

func TestEmptyInput(t *testing.T) {
	p := &pastaPrecompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestInputTooShortForHeader(t *testing.T) {
	p := &pastaPrecompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{0x01}, 100000, true)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &pastaPrecompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"pointAdd", []byte{CurvePallas, OpPointAdd}, GasPointAdd},
		{"scalarMul", []byte{CurveVesta, OpScalarMul}, GasScalarMul},
		{"msm_1pair", func() []byte {
			b := make([]byte, 2+PointLen+32)
			b[0] = CurvePallas
			b[1] = OpMSM
			return b
		}(), GasMSMBase + 1*GasMSMPerPt},
		{"msm_3pairs", func() []byte {
			b := make([]byte, 2+3*(PointLen+32))
			b[0] = CurvePallas
			b[1] = OpMSM
			return b
		}(), GasMSMBase + 3*GasMSMPerPt},
		{"invalid_op", []byte{CurvePallas, 0xFF}, 0},
		{"too_short", []byte{0x01}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gas := p.RequiredGas(tc.input)
			require.Equal(t, tc.expected, gas)
		})
	}
}

func TestOutOfGas(t *testing.T) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)
	scalar := padBig(big.NewInt(42))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurvePallas
	input[1] = OpScalarMul
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], scalar)

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 10, true)
	require.Error(t, err)
}

func BenchmarkPallas_PointAdd(b *testing.B) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)

	input := make([]byte, 2+2*PointLen)
	input[0] = CurvePallas
	input[1] = OpPointAdd
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], ptBytes)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkPallas_ScalarMul(b *testing.B) {
	p := &pastaPrecompile{}

	pt := findPoint(CurvePallas)
	ptBytes := encodePoint(pt)
	scalar := padBig(big.NewInt(123456789))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurvePallas
	input[1] = OpScalarMul
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], scalar)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkVesta_ScalarMul(b *testing.B) {
	p := &pastaPrecompile{}

	pt := findPoint(CurveVesta)
	ptBytes := encodePoint(pt)
	scalar := padBig(big.NewInt(123456789))

	input := make([]byte, 2+PointLen+32)
	input[0] = CurveVesta
	input[1] = OpScalarMul
	copy(input[2:], ptBytes)
	copy(input[2+PointLen:], scalar)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

// --- Helpers ---

func padBig(v *big.Int) []byte {
	b := v.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
