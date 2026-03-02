// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package curve25519

import (
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

var addr0 = common.Address{}

// --- Edge Cases ---

func TestDeep_NilInput(t *testing.T) {
	p := Curve25519Precompile
	_, _, err := p.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestDeep_ZeroLengthInput(t *testing.T) {
	p := Curve25519Precompile
	_, _, err := p.Run(nil, addr0, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

// --- Gas Accounting ---

func TestDeep_GasExact_PointAdd(t *testing.T) {
	p := Curve25519Precompile
	bp := deepBasepoint()
	input := make([]byte, 1+2*CompressedLen)
	input[0] = OpPointAdd
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], bp)

	gas := p.RequiredGas(input)
	require.Equal(t, uint64(GasPointAdd), gas)
	_, remaining, err := p.Run(nil, addr0, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remaining)
}

func TestDeep_GasInsufficient(t *testing.T) {
	p := Curve25519Precompile
	input := make([]byte, 1+2*CompressedLen)
	input[0] = OpPointAdd
	copy(input[1:], deepBasepoint())
	copy(input[1+CompressedLen:], deepBasepoint())

	_, _, err := p.Run(nil, addr0, ContractAddress, input, GasPointAdd-1, true)
	require.Error(t, err)
}

func TestDeep_GasZero(t *testing.T) {
	p := Curve25519Precompile
	input := []byte{OpPointAdd}
	_, _, err := p.Run(nil, addr0, ContractAddress, input, 0, true)
	require.Error(t, err)
}

// --- MSM Tests ---

func TestDeep_MSM_SinglePair(t *testing.T) {
	p := Curve25519Precompile
	bp := deepBasepoint()
	scalar := make([]byte, ScalarLen)
	scalar[0] = 5

	input := make([]byte, 1+CompressedLen+ScalarLen)
	input[0] = OpMSM
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+10000, true)
	require.NoError(t, err)
	require.Len(t, ret, CompressedLen)

	// Should equal 5*B
	smInput := make([]byte, 1+CompressedLen+ScalarLen)
	smInput[0] = OpScalarMul
	copy(smInput[1:], bp)
	copy(smInput[1+CompressedLen:], scalar)
	smGas := p.RequiredGas(smInput)
	expected, _, err := p.Run(nil, addr0, ContractAddress, smInput, smGas+10000, true)
	require.NoError(t, err)
	require.Equal(t, expected, ret, "MSM(1 pair) must equal ScalarMul")
}

func TestDeep_MSM_GasScaling(t *testing.T) {
	p := Curve25519Precompile
	for n := 1; n <= 4; n++ {
		input := make([]byte, 1+n*(CompressedLen+ScalarLen))
		input[0] = OpMSM
		gas := p.RequiredGas(input)
		expected := GasMSMBase + uint64(n)*GasMSMPerPair
		require.Equal(t, expected, gas, "n=%d", n)
	}
}

// --- Correctness ---

func TestDeep_PointAdd_Associative(t *testing.T) {
	p := Curve25519Precompile
	bp := deepBasepoint()

	// B + B
	input := make([]byte, 1+2*CompressedLen)
	input[0] = OpPointAdd
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], bp)
	gas := p.RequiredGas(input)
	twoB, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)

	// (B+B) + B = 3B
	copy(input[1:], twoB)
	copy(input[1+CompressedLen:], bp)
	threeB_1, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)

	// B + (B+B) = 3B
	copy(input[1:], bp)
	copy(input[1+CompressedLen:], twoB)
	threeB_2, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)

	require.Equal(t, threeB_1, threeB_2, "point addition must be associative")
}

func TestDeep_BasepointMul_Identity(t *testing.T) {
	p := Curve25519Precompile

	// 1*B should equal the basepoint
	scalar := make([]byte, ScalarLen)
	scalar[0] = 1
	input := make([]byte, 1+ScalarLen)
	input[0] = OpBasepointMul
	copy(input[1:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	require.Equal(t, deepBasepoint(), ret)
}

// --- Concurrency ---

func TestDeep_Concurrent(t *testing.T) {
	p := Curve25519Precompile
	scalar := make([]byte, ScalarLen)
	scalar[0] = 42

	input := make([]byte, 1+ScalarLen)
	input[0] = OpBasepointMul
	copy(input[1:], scalar)
	gas := p.RequiredGas(input)

	var wg sync.WaitGroup
	results := make([][]byte, 50)
	for i := range 50 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
			require.NoError(t, err)
			results[idx] = ret
		}(i)
	}
	wg.Wait()
	for i := 1; i < 50; i++ {
		require.Equal(t, results[0], results[i])
	}
}

// --- Fuzz ---

func FuzzCurve25519(f *testing.F) {
	bp := deepBasepoint()
	seed := make([]byte, 1+CompressedLen+ScalarLen)
	seed[0] = OpScalarMul
	copy(seed[1:], bp)
	seed[1+CompressedLen] = 7
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	p := Curve25519Precompile
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		gas := p.RequiredGas(input)
		p.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}

func deepBasepoint() []byte {
	return edwards25519.NewGeneratorPoint().Bytes()
}
