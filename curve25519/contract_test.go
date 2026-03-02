// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package curve25519

import (
	"testing"

	"filippo.io/edwards25519"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0000000000000000000000000000000000009204"), ContractAddress)
}

// Edwards25519 basepoint (compressed, canonical encoding)
func basepoint() []byte {
	return edwards25519.NewGeneratorPoint().Bytes()
}

// identity is the neutral element (0, 1, 1, 0) in extended coordinates
func identity() []byte {
	return edwards25519.NewIdentityPoint().Bytes()
}

func TestPointAdd_Identity(t *testing.T) {
	p := &curve25519Precompile{}

	bp := basepoint()
	id := identity()

	// B + O = B
	input := make([]byte, 1+2*CompressedLen)
	input[0] = OpPointAdd
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], id)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, ret, bp, "B + identity should equal B")
}

func TestPointAdd_Commutative(t *testing.T) {
	p := &curve25519Precompile{}

	bp := basepoint()

	// Compute 2*B for a second distinct point
	scalar2 := scalarBytes(2)
	mulInput := make([]byte, 1+CompressedLen+ScalarLen)
	mulInput[0] = OpScalarMul
	copy(mulInput[1:], bp)
	copy(mulInput[1+CompressedLen:], scalar2)
	gas := p.RequiredGas(mulInput)
	pt2, _, err := p.Run(nil, common.Address{}, ContractAddress, mulInput, gas, true)
	require.NoError(t, err)

	// B + 2B
	addInput1 := make([]byte, 1+2*CompressedLen)
	addInput1[0] = OpPointAdd
	copy(addInput1[1:], bp)
	copy(addInput1[1+CompressedLen:], pt2)
	gas = p.RequiredGas(addInput1)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, addInput1, gas, true)
	require.NoError(t, err)

	// 2B + B
	addInput2 := make([]byte, 1+2*CompressedLen)
	addInput2[0] = OpPointAdd
	copy(addInput2[1:], pt2)
	copy(addInput2[1+CompressedLen:], bp)
	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, addInput2, gas, true)
	require.NoError(t, err)

	require.Equal(t, ret1, ret2, "point addition must be commutative")
}

func TestScalarMul_One(t *testing.T) {
	p := &curve25519Precompile{}

	bp := basepoint()
	scalar := scalarBytes(1)

	input := make([]byte, 1+CompressedLen+ScalarLen)
	input[0] = OpScalarMul
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, ret, bp, "1*B should equal B")
}

func TestBasepointMul(t *testing.T) {
	p := &curve25519Precompile{}

	scalar := scalarBytes(1)

	input := make([]byte, 1+ScalarLen)
	input[0] = OpBasepointMul
	copy(input[1:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, basepoint(), ret, "BasepointMul(1) should equal generator")
}

func TestBasepointMul_MatchesScalarMul(t *testing.T) {
	p := &curve25519Precompile{}

	scalar := scalarBytes(42)

	// BasepointMul(42)
	bpInput := make([]byte, 1+ScalarLen)
	bpInput[0] = OpBasepointMul
	copy(bpInput[1:], scalar)
	gas := p.RequiredGas(bpInput)
	bpResult, _, err := p.Run(nil, common.Address{}, ContractAddress, bpInput, gas, true)
	require.NoError(t, err)

	// ScalarMul(B, 42)
	smInput := make([]byte, 1+CompressedLen+ScalarLen)
	smInput[0] = OpScalarMul
	copy(smInput[1:], basepoint())
	copy(smInput[1+CompressedLen:], scalar)
	gas = p.RequiredGas(smInput)
	smResult, _, err := p.Run(nil, common.Address{}, ContractAddress, smInput, gas, true)
	require.NoError(t, err)

	require.Equal(t, bpResult, smResult, "BasepointMul(42) should equal ScalarMul(B, 42)")
}

func TestScalarMul_DoubleEqualsAdd(t *testing.T) {
	p := &curve25519Precompile{}

	bp := basepoint()

	// 2*B via ScalarMul
	mulInput := make([]byte, 1+CompressedLen+ScalarLen)
	mulInput[0] = OpScalarMul
	copy(mulInput[1:], bp)
	copy(mulInput[1+CompressedLen:], scalarBytes(2))
	gas := p.RequiredGas(mulInput)
	mulResult, _, err := p.Run(nil, common.Address{}, ContractAddress, mulInput, gas, true)
	require.NoError(t, err)

	// B + B via PointAdd
	addInput := make([]byte, 1+2*CompressedLen)
	addInput[0] = OpPointAdd
	copy(addInput[1:], bp)
	copy(addInput[1+CompressedLen:], bp)
	gas = p.RequiredGas(addInput)
	addResult, _, err := p.Run(nil, common.Address{}, ContractAddress, addInput, gas, true)
	require.NoError(t, err)

	require.Equal(t, mulResult, addResult, "2*B should equal B+B")
}

func TestMSM(t *testing.T) {
	p := &curve25519Precompile{}

	bp := basepoint()

	// MSM: 3*B + 5*B should equal 8*B
	s3 := scalarBytes(3)
	s5 := scalarBytes(5)

	input := make([]byte, 1+2*(CompressedLen+ScalarLen))
	input[0] = OpMSM
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], s3)
	copy(input[1+CompressedLen+ScalarLen:], bp)
	copy(input[1+2*CompressedLen+ScalarLen:], s5)

	gas := p.RequiredGas(input)
	msmResult, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	// 8*B via BasepointMul
	bpInput := make([]byte, 1+ScalarLen)
	bpInput[0] = OpBasepointMul
	copy(bpInput[1:], scalarBytes(8))
	gas = p.RequiredGas(bpInput)
	expected, _, err := p.Run(nil, common.Address{}, ContractAddress, bpInput, gas, true)
	require.NoError(t, err)

	require.Equal(t, msmResult, expected, "MSM(3*B + 5*B) should equal 8*B")
}

func TestMSM_SinglePair(t *testing.T) {
	p := &curve25519Precompile{}

	bp := basepoint()
	s := scalarBytes(7)

	input := make([]byte, 1+CompressedLen+ScalarLen)
	input[0] = OpMSM
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], s)

	gas := p.RequiredGas(input)
	msmResult, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	// Compare with ScalarMul
	smInput := make([]byte, 1+CompressedLen+ScalarLen)
	smInput[0] = OpScalarMul
	copy(smInput[1:], bp)
	copy(smInput[1+CompressedLen:], s)
	gas = p.RequiredGas(smInput)
	smResult, _, err := p.Run(nil, common.Address{}, ContractAddress, smInput, gas, true)
	require.NoError(t, err)

	require.Equal(t, msmResult, smResult, "MSM with 1 pair should match ScalarMul")
}

func TestPointAdd_InputTooShort(t *testing.T) {
	p := &curve25519Precompile{}

	input := make([]byte, 1+CompressedLen) // need 2*CompressedLen
	input[0] = OpPointAdd

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestScalarMul_InputTooShort(t *testing.T) {
	p := &curve25519Precompile{}

	input := make([]byte, 1+CompressedLen) // need CompressedLen+ScalarLen
	input[0] = OpScalarMul

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestBasepointMul_InputTooShort(t *testing.T) {
	p := &curve25519Precompile{}

	input := make([]byte, 1+16) // need ScalarLen
	input[0] = OpBasepointMul

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestMSM_BadAlignment(t *testing.T) {
	p := &curve25519Precompile{}

	input := make([]byte, 1+CompressedLen+16) // not a multiple of pair size
	input[0] = OpMSM

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
}

func TestInvalidPoint(t *testing.T) {
	p := &curve25519Precompile{}

	// Edwards25519 compressed encoding: y-coordinate in little-endian with sign
	// bit in the top bit of byte 31. Not all 32-byte values decode to valid
	// curve points. The value y=2 (little-endian: [2, 0, ..., 0]) is a known
	// non-square residue that the library rejects.
	bogus := make([]byte, CompressedLen)
	bogus[0] = 2 // y = 2 in little-endian

	input := make([]byte, 1+2*CompressedLen)
	input[0] = OpPointAdd
	copy(input[1:], basepoint())
	copy(input[1+CompressedLen:], bogus)

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestInvalidOperation(t *testing.T) {
	p := &curve25519Precompile{}

	input := []byte{0xFF, 0x00}
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEmptyInput(t *testing.T) {
	p := &curve25519Precompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &curve25519Precompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"pointAdd", []byte{OpPointAdd}, GasPointAdd},
		{"scalarMul", []byte{OpScalarMul}, GasScalarMul},
		{"basepointMul", []byte{OpBasepointMul}, GasBasepointMul},
		{"msm_1pair", func() []byte {
			b := make([]byte, 1+CompressedLen+ScalarLen)
			b[0] = OpMSM
			return b
		}(), GasMSMBase + 1*GasMSMPerPair},
		{"msm_4pairs", func() []byte {
			b := make([]byte, 1+4*(CompressedLen+ScalarLen))
			b[0] = OpMSM
			return b
		}(), GasMSMBase + 4*GasMSMPerPair},
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
	p := &curve25519Precompile{}

	bp := basepoint()
	input := make([]byte, 1+CompressedLen+ScalarLen)
	input[0] = OpScalarMul
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], scalarBytes(5))

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 10, true)
	require.Error(t, err)
}

func BenchmarkPointAdd(b *testing.B) {
	p := &curve25519Precompile{}

	bp := basepoint()
	input := make([]byte, 1+2*CompressedLen)
	input[0] = OpPointAdd
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], bp)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkScalarMul(b *testing.B) {
	p := &curve25519Precompile{}

	bp := basepoint()
	input := make([]byte, 1+CompressedLen+ScalarLen)
	input[0] = OpScalarMul
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], scalarBytes(123456789))
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkBasepointMul(b *testing.B) {
	p := &curve25519Precompile{}

	input := make([]byte, 1+ScalarLen)
	input[0] = OpBasepointMul
	copy(input[1:], scalarBytes(123456789))
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkMSM_8Pairs(b *testing.B) {
	p := &curve25519Precompile{}

	bp := basepoint()
	pairSize := CompressedLen + ScalarLen
	input := make([]byte, 1+8*pairSize)
	input[0] = OpMSM
	for i := range 8 {
		copy(input[1+i*pairSize:], bp)
		copy(input[1+i*pairSize+CompressedLen:], scalarBytes(int64(i+1)))
	}
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

// scalarBytes encodes a small integer as a 32-byte little-endian Edwards25519 scalar.
func scalarBytes(v int64) []byte {
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(func() []byte {
		b := make([]byte, 32)
		b[0] = byte(v & 0xff)
		b[1] = byte((v >> 8) & 0xff)
		b[2] = byte((v >> 16) & 0xff)
		b[3] = byte((v >> 24) & 0xff)
		return b
	}())
	if err != nil {
		panic(err)
	}
	return s.Bytes()
}
