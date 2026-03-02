// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package babyjubjub

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0500000000000000000000000000000000000007"), ContractAddress)
}

// Baby Jubjub generator point from the iden3 reference:
// Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553
// Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203
func getGenerator() twistededwards.PointAffine {
	var params = twistededwards.GetEdwardsCurve()
	return params.Base
}

func TestPointAdd_Identity(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	// identity point: (0, 1) for twisted Edwards
	var identity twistededwards.PointAffine
	identity.X.SetZero()
	identity.Y.SetOne()
	idBytes := encodeTestPoint(&identity)

	// G + O = G
	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], idBytes)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(ret, genBytes), "G + O should equal G")
}

func TestPointAdd_DoubleGenerator(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	// G + G = 2G
	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], genBytes)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, PointLen)

	// Verify via ScalarMul: 2*G
	twoG := scalarMulRef(&gen, big.NewInt(2))
	expected := encodeTestPoint(&twoG)
	require.True(t, bytes.Equal(ret, expected), "G+G should equal 2*G")
}

func TestScalarMul_One(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	// 1 * G = G
	scalar := padBig(big.NewInt(1))

	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.True(t, bytes.Equal(ret, genBytes), "1*G should equal G")
}

func TestScalarMul_Two(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	scalar := padBig(big.NewInt(2))

	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	// Compare with addition result
	addInput := make([]byte, 1+2*PointLen)
	addInput[0] = OpPointAdd
	copy(addInput[1:], genBytes)
	copy(addInput[1+PointLen:], genBytes)
	addGas := p.RequiredGas(addInput)
	addRet, _, err := p.Run(nil, common.Address{}, ContractAddress, addInput, addGas, true)
	require.NoError(t, err)

	require.True(t, bytes.Equal(ret, addRet), "2*G via ScalarMul should equal G+G")
}

func TestScalarMul_Zero(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	scalar := padBig(big.NewInt(0))

	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	// 0*G should be the identity (0, 1)
	var identity twistededwards.PointAffine
	identity.X.SetZero()
	identity.Y.SetOne()
	expected := encodeTestPoint(&identity)
	require.True(t, bytes.Equal(ret, expected), "0*G should be identity")
}

func TestInCurve_ValidPoint(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	input := make([]byte, 1+PointLen)
	input[0] = OpInCurve
	copy(input[1:], genBytes)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31], "generator should be on curve")
}

func TestInCurve_Identity(t *testing.T) {
	p := &babyJubJubPrecompile{}

	var identity twistededwards.PointAffine
	identity.X.SetZero()
	identity.Y.SetOne()
	idBytes := encodeTestPoint(&identity)

	input := make([]byte, 1+PointLen)
	input[0] = OpInCurve
	copy(input[1:], idBytes)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31], "identity point should be on curve")
}

func TestInCurve_InvalidPoint(t *testing.T) {
	p := &babyJubJubPrecompile{}

	// (1, 1) is not on the Baby Jubjub curve
	input := make([]byte, 1+PointLen)
	input[0] = OpInCurve
	input[32] = 1  // x = 1
	input[64] = 1  // y = 1

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), ret[31], "(1,1) should not be on curve")
}

func TestPointAdd_InputTooShort(t *testing.T) {
	p := &babyJubJubPrecompile{}

	input := make([]byte, 1+PointLen) // need 2*PointLen
	input[0] = OpPointAdd

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestScalarMul_InputTooShort(t *testing.T) {
	p := &babyJubJubPrecompile{}

	input := make([]byte, 1+PointLen) // need PointLen+32
	input[0] = OpScalarMul

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestPointAdd_PointNotOnCurve(t *testing.T) {
	p := &babyJubJubPrecompile{}

	// First point is valid (generator), second is (2, 3) -- not on curve
	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	bogus := make([]byte, PointLen)
	bogus[31] = 2  // x = 2
	bogus[63] = 3  // y = 3

	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], bogus)

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotOnCurve)
}

func TestInvalidOperation(t *testing.T) {
	p := &babyJubJubPrecompile{}

	input := []byte{0xFF, 0x00}
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEmptyInput(t *testing.T) {
	p := &babyJubJubPrecompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &babyJubJubPrecompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"pointAdd", []byte{OpPointAdd}, GasPointAdd},
		{"scalarMul", []byte{OpScalarMul}, GasScalarMul},
		{"inCurve", []byte{OpInCurve}, GasInCurve},
		{"invalid_op", []byte{0xFF}, 0},
		{"empty", []byte{}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gas := p.RequiredGas(tc.input)
			require.Equal(t, tc.expected, gas)
		})
	}
}

func TestOutOfGas(t *testing.T) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], genBytes)
	input[1+PointLen+31] = 5

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 10, true)
	require.Error(t, err)
}

func BenchmarkPointAdd(b *testing.B) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	input := make([]byte, 1+2*PointLen)
	input[0] = OpPointAdd
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], genBytes)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkScalarMul(b *testing.B) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)
	scalar := padBig(big.NewInt(123456789))

	input := make([]byte, 1+PointLen+32)
	input[0] = OpScalarMul
	copy(input[1:], genBytes)
	copy(input[1+PointLen:], scalar)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkInCurve(b *testing.B) {
	p := &babyJubJubPrecompile{}

	gen := getGenerator()
	genBytes := encodeTestPoint(&gen)

	input := make([]byte, 1+PointLen)
	input[0] = OpInCurve
	copy(input[1:], genBytes)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

// --- Helpers ---

func encodeTestPoint(pt *twistededwards.PointAffine) []byte {
	return encodePoint(pt)
}

func padBig(v *big.Int) []byte {
	b := v.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

func scalarMulRef(pt *twistededwards.PointAffine, s *big.Int) twistededwards.PointAffine {
	var sFr fr.Element
	sFr.SetBigInt(s)
	var result twistededwards.PointAffine
	result.ScalarMultiplication(pt, sFr.BigInt(new(big.Int)))
	return result
}
