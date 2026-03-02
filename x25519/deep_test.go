// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package x25519

import (
	"crypto/rand"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

var addr0 = common.Address{}

// --- Edge Cases ---

func TestEdge_NilInput(t *testing.T) {
	p := X25519Precompile
	_, _, err := p.Run(nil, addr0, ContractAddress, nil, 100000, true)
	require.Error(t, err)
}

func TestEdge_EmptyInput(t *testing.T) {
	p := X25519Precompile
	_, _, err := p.Run(nil, addr0, ContractAddress, []byte{}, 100000, true)
	require.Error(t, err)
}

func TestEdge_OpOnly(t *testing.T) {
	p := X25519Precompile
	for _, op := range []byte{OpScalarMult, OpBasepoint, 0xFF} {
		_, _, err := p.Run(nil, addr0, ContractAddress, []byte{op}, 100000, true)
		require.Error(t, err, "op=0x%02x with no data should error", op)
	}
}

func TestEdge_InvalidOp(t *testing.T) {
	p := X25519Precompile
	input := make([]byte, 1+32)
	input[0] = 0xFF
	_, _, err := p.Run(nil, addr0, ContractAddress, input, 100000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestEdge_AllZerosScalar(t *testing.T) {
	p := X25519Precompile
	// Basepoint mul with zero scalar
	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)
	// Result should be the low-order point (all zeros)
	require.Len(t, ret, 32)
}

// --- Cryptographic Correctness ---

func TestBasepoint_KnownVector(t *testing.T) {
	p := X25519Precompile
	// Scalar = 1 should give the basepoint
	scalar := make([]byte, 32)
	scalar[0] = 1

	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], scalar)

	gas := p.RequiredGas(input)
	ret, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)

	// Compare with stdlib
	expected, err := curve25519.X25519(scalar, curve25519.Basepoint)
	require.NoError(t, err)
	require.Equal(t, expected, ret)
}

func TestScalarMult_RoundTrip(t *testing.T) {
	p := X25519Precompile

	// Generate random scalar
	scalar := make([]byte, 32)
	_, err := rand.Read(scalar)
	require.NoError(t, err)

	// Basepoint mul
	bpInput := make([]byte, 1+32)
	bpInput[0] = OpBasepoint
	copy(bpInput[1:], scalar)

	gas := p.RequiredGas(bpInput)
	pubKey, _, err := p.Run(nil, addr0, ContractAddress, bpInput, gas+1000, true)
	require.NoError(t, err)

	// Verify against stdlib
	expected, err := curve25519.X25519(scalar, curve25519.Basepoint)
	require.NoError(t, err)
	require.Equal(t, expected, pubKey)
}

func TestScalarMult_DH(t *testing.T) {
	p := X25519Precompile

	// Alice and Bob generate keypairs
	alicePriv := make([]byte, 32)
	bobPriv := make([]byte, 32)
	_, _ = rand.Read(alicePriv)
	_, _ = rand.Read(bobPriv)

	// Alice public
	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], alicePriv)
	gas := p.RequiredGas(input)
	alicePub, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)

	// Bob public
	copy(input[1:], bobPriv)
	bobPub, _, err := p.Run(nil, addr0, ContractAddress, input, gas+1000, true)
	require.NoError(t, err)

	// Alice computes shared secret: alicePriv * bobPub
	smInput := make([]byte, 1+64)
	smInput[0] = OpScalarMult
	copy(smInput[1:33], alicePriv)
	copy(smInput[33:65], bobPub)
	smGas := p.RequiredGas(smInput)
	aliceShared, _, err := p.Run(nil, addr0, ContractAddress, smInput, smGas+1000, true)
	require.NoError(t, err)

	// Bob computes shared secret: bobPriv * alicePub
	copy(smInput[1:33], bobPriv)
	copy(smInput[33:65], alicePub)
	bobShared, _, err := p.Run(nil, addr0, ContractAddress, smInput, smGas+1000, true)
	require.NoError(t, err)

	require.Equal(t, aliceShared, bobShared, "DH shared secrets must match")
}

// --- Gas Accounting ---

func TestGas_ExactRequired(t *testing.T) {
	p := X25519Precompile
	scalar := make([]byte, 32)
	scalar[0] = 42

	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	copy(input[1:], scalar)

	gas := p.RequiredGas(input)
	_, remaining, err := p.Run(nil, addr0, ContractAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, uint64(0), remaining)
}

func TestGas_Insufficient(t *testing.T) {
	p := X25519Precompile
	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	input[1] = 1
	gas := p.RequiredGas(input)
	_, _, err := p.Run(nil, addr0, ContractAddress, input, gas-1, true)
	require.Error(t, err)
}

func TestGas_Zero(t *testing.T) {
	p := X25519Precompile
	input := make([]byte, 1+32)
	input[0] = OpBasepoint
	_, _, err := p.Run(nil, addr0, ContractAddress, input, 0, true)
	require.Error(t, err)
}

// --- Concurrency ---

func TestConcurrent(t *testing.T) {
	p := X25519Precompile
	scalar := make([]byte, 32)
	scalar[0] = 7

	input := make([]byte, 1+32)
	input[0] = OpBasepoint
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

func FuzzX25519(f *testing.F) {
	f.Add([]byte{OpBasepoint, 1})
	f.Add([]byte{OpScalarMult, 1, 2})
	f.Add([]byte{0xFF})
	f.Add([]byte{})

	p := X25519Precompile
	f.Fuzz(func(t *testing.T, input []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input len=%d: %v", len(input), r)
			}
		}()
		gas := p.RequiredGas(input)
		p.Run(nil, addr0, ContractAddress, input, gas+100000, true)
	})
}
