// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestPrecompileAddress(t *testing.T) {
	require.Equal(t, common.HexToAddress("0x0500000000000000000000000000000000000006"), ContractAddress)
}

func TestCommit_BasicRoundTrip(t *testing.T) {
	p := &pedersenPrecompile{}

	// C(v=5, r=7) then verify
	value := padScalar(big.NewInt(5))
	blinding := padScalar(big.NewInt(7))

	// Commit
	commitInput := make([]byte, 1+64)
	commitInput[0] = OpCommit
	copy(commitInput[1:33], value)
	copy(commitInput[33:65], blinding)

	gas := p.RequiredGas(commitInput)
	commitResult, _, err := p.Run(nil, common.Address{}, ContractAddress, commitInput, gas, true)
	require.NoError(t, err)
	require.Len(t, commitResult, 32)

	// Verify
	verifyInput := make([]byte, 1+96)
	verifyInput[0] = OpVerify
	copy(verifyInput[1:33], commitResult)
	copy(verifyInput[33:65], value)
	copy(verifyInput[65:97], blinding)

	gas = p.RequiredGas(verifyInput)
	verifyResult, _, err := p.Run(nil, common.Address{}, ContractAddress, verifyInput, gas, true)
	require.NoError(t, err)
	require.Len(t, verifyResult, 32)
	require.Equal(t, byte(1), verifyResult[31], "commitment should verify")
}

func TestCommit_Determinism(t *testing.T) {
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(42))
	blinding := padScalar(big.NewInt(99))

	input := make([]byte, 1+64)
	input[0] = OpCommit
	copy(input[1:33], value)
	copy(input[33:65], blinding)

	gas := p.RequiredGas(input)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)

	require.Equal(t, ret1, ret2, "commitments must be deterministic")
}

func TestCommit_DifferentValues(t *testing.T) {
	p := &pedersenPrecompile{}

	blinding := padScalar(big.NewInt(99))

	c1 := commit(t, p, padScalar(big.NewInt(1)), blinding)
	c2 := commit(t, p, padScalar(big.NewInt(2)), blinding)

	require.False(t, bytes.Equal(c1, c2), "different values must produce different commitments")
}

func TestCommit_DifferentBlinding(t *testing.T) {
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(42))

	input1 := make([]byte, 1+64)
	input1[0] = OpCommit
	copy(input1[1:33], value)
	copy(input1[33:65], padScalar(big.NewInt(1)))

	input2 := make([]byte, 1+64)
	input2[0] = OpCommit
	copy(input2[1:33], value)
	copy(input2[33:65], padScalar(big.NewInt(2)))

	gas := p.RequiredGas(input1)
	ret1, _, err := p.Run(nil, common.Address{}, ContractAddress, input1, gas, true)
	require.NoError(t, err)

	ret2, _, err := p.Run(nil, common.Address{}, ContractAddress, input2, gas, true)
	require.NoError(t, err)

	require.False(t, bytes.Equal(ret1, ret2), "different blinding factors must produce different commitments")
}

func TestVerify_WrongValue(t *testing.T) {
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(5))
	blinding := padScalar(big.NewInt(7))
	wrongValue := padScalar(big.NewInt(6))

	// Commit with correct value
	c := commit(t, p, value, blinding)

	// Verify with wrong value
	verifyInput := make([]byte, 1+96)
	verifyInput[0] = OpVerify
	copy(verifyInput[1:33], c)
	copy(verifyInput[33:65], wrongValue)
	copy(verifyInput[65:97], blinding)

	gas := p.RequiredGas(verifyInput)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, verifyInput, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), ret[31], "verification with wrong value must fail")
}

func TestVerify_WrongBlinding(t *testing.T) {
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(5))
	blinding := padScalar(big.NewInt(7))
	wrongBlinding := padScalar(big.NewInt(8))

	c := commit(t, p, value, blinding)

	verifyInput := make([]byte, 1+96)
	verifyInput[0] = OpVerify
	copy(verifyInput[1:33], c)
	copy(verifyInput[33:65], value)
	copy(verifyInput[65:97], wrongBlinding)

	gas := p.RequiredGas(verifyInput)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, verifyInput, gas, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), ret[31], "verification with wrong blinding must fail")
}

func TestAdd_HomomorphicProperty(t *testing.T) {
	// Pedersen commitments are homomorphic: C(v1,r1) + C(v2,r2) should commit
	// to (v1+v2, r1+r2) on the raw curve points (before hashing).
	// Since commit() returns SHA256 of the curve point, we test Add on raw points.
	p := &pedersenPrecompile{}

	// Compute two raw G1 points: C1 = v1*G + r1*H, C2 = v2*G + r2*H
	v1, r1 := big.NewInt(10), big.NewInt(20)
	v2, r2 := big.NewInt(30), big.NewInt(40)

	pt1 := commitRawPoint(v1, r1)
	pt2 := commitRawPoint(v2, r2)

	pt1Bytes := pt1.Marshal()
	pt2Bytes := pt2.Marshal()

	// Add via precompile
	addInput := make([]byte, 1+128)
	addInput[0] = OpAdd
	copy(addInput[1:65], pt1Bytes)
	copy(addInput[65:129], pt2Bytes)

	gas := p.RequiredGas(addInput)
	addResult, _, err := p.Run(nil, common.Address{}, ContractAddress, addInput, gas, true)
	require.NoError(t, err)

	// Compute expected: (v1+v2)*G + (r1+r2)*H
	ptExpected := commitRawPoint(new(big.Int).Add(v1, v2), new(big.Int).Add(r1, r2))
	expectedBytes := ptExpected.Marshal()

	require.Equal(t, addResult, expectedBytes, "homomorphic addition failed")
}

func TestAdd_InputTooShort(t *testing.T) {
	p := &pedersenPrecompile{}

	input := make([]byte, 1+64) // need 128 bytes of point data
	input[0] = OpAdd

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestVectorCommit(t *testing.T) {
	p := &pedersenPrecompile{}

	// Vector commit with 2 values and a blinding factor
	n := byte(2)
	v1 := padScalar(big.NewInt(100))
	v2 := padScalar(big.NewInt(200))
	r := padScalar(big.NewInt(42))

	input := make([]byte, 1+1+2*32+32)
	input[0] = OpVectorCommit
	input[1] = n
	copy(input[2:34], v1)
	copy(input[34:66], v2)
	copy(input[66:98], r)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Len(t, ret, 32)
}

func TestVectorCommit_TooManyValues(t *testing.T) {
	p := &pedersenPrecompile{}

	input := make([]byte, 1+1+33*32+32)
	input[0] = OpVectorCommit
	input[1] = 33 // exceeds max 32

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTooManyVals)
}

func TestCommit_InputTooShort(t *testing.T) {
	p := &pedersenPrecompile{}

	input := make([]byte, 1+32) // need 64 bytes
	input[0] = OpCommit

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestVerify_InputTooShort(t *testing.T) {
	p := &pedersenPrecompile{}

	input := make([]byte, 1+64) // need 96 bytes
	input[0] = OpVerify

	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.Error(t, err)
}

func TestInvalidOperation(t *testing.T) {
	p := &pedersenPrecompile{}

	input := []byte{0xFF, 0x00}
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEmptyInput(t *testing.T) {
	p := &pedersenPrecompile{}

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestGasCost(t *testing.T) {
	p := &pedersenPrecompile{}

	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"commit", []byte{OpCommit}, GasCommit},
		{"verify", []byte{OpVerify}, GasVerify},
		{"add", []byte{OpAdd}, GasAdd},
		{"vector_2", []byte{OpVectorCommit, 2}, GasVectorBase + 2*GasVectorPerVal},
		{"vector_10", []byte{OpVectorCommit, 10}, GasVectorBase + 10*GasVectorPerVal},
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
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(5))
	blinding := padScalar(big.NewInt(7))

	input := make([]byte, 1+64)
	input[0] = OpCommit
	copy(input[1:33], value)
	copy(input[33:65], blinding)

	_, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 10, true)
	require.Error(t, err)
}

func BenchmarkCommit(b *testing.B) {
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(42))
	blinding := padScalar(big.NewInt(99))

	input := make([]byte, 1+64)
	input[0] = OpCommit
	copy(input[1:33], value)
	copy(input[33:65], blinding)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

func BenchmarkVerify(b *testing.B) {
	p := &pedersenPrecompile{}

	value := padScalar(big.NewInt(42))
	blinding := padScalar(big.NewInt(99))

	c := commit(b, p, value, blinding)

	input := make([]byte, 1+96)
	input[0] = OpVerify
	copy(input[1:33], c)
	copy(input[33:65], value)
	copy(input[65:97], blinding)
	gas := p.RequiredGas(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	}
}

// --- Helpers ---

func padScalar(v *big.Int) []byte {
	b := v.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(b):], b)
	return result
}

func commit(tb testing.TB, p *pedersenPrecompile, value, blinding []byte) []byte {
	tb.Helper()
	input := make([]byte, 1+64)
	input[0] = OpCommit
	copy(input[1:33], value)
	copy(input[33:65], blinding)
	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, gas, true)
	require.NoError(tb, err)
	return ret
}

func commitRawPoint(v, r *big.Int) bn254.G1Affine {
	var vFr, rFr fr.Element
	vFr.SetBigInt(v)
	rFr.SetBigInt(r)

	var vG, rH bn254.G1Affine
	vG.ScalarMultiplication(&genG, vFr.BigInt(new(big.Int)))
	rH.ScalarMultiplication(&genH, rFr.BigInt(new(big.Int)))

	var c bn254.G1Affine
	c.Add(&vG, &rH)
	return c
}
