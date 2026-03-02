// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package stableswap

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	expected := "0x0400000000000000000000000000000000000060"
	require.Equal(t, expected, ContractAddress.Hex())
}

// encodeGetD builds input for OpGetD: [op] [n:4] [amp:32] [balances:n*32]
func encodeGetD(n int, amp *big.Int, balances []*big.Int) []byte {
	buf := make([]byte, 1+4+32+n*32)
	buf[0] = OpGetD
	binary.BigEndian.PutUint32(buf[1:5], uint32(n))
	copy(buf[5:37], padTo32(amp.Bytes()))
	for i, b := range balances {
		copy(buf[37+i*32:37+(i+1)*32], padTo32(b.Bytes()))
	}
	return buf
}

func TestGetD_Balanced(t *testing.T) {
	// Two tokens, both with 1e18, A=100
	// D should equal sum of balances for perfectly balanced pool
	bal := big.NewInt(1e18)
	input := encodeGetD(2, big.NewInt(100), []*big.Int{bal, bal})

	result, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100000, false)
	require.NoError(t, err)

	d := new(big.Int).SetBytes(result)
	expectedD := new(big.Int).Add(bal, bal)
	// D should be very close to sum (within rounding)
	diff := new(big.Int).Sub(d, expectedD)
	diff.Abs(diff)
	require.True(t, diff.Cmp(big.NewInt(2)) <= 0, "D should be ~2e18, got %s (diff %s)", d, diff)
}

func TestGetD_Unbalanced(t *testing.T) {
	// Unbalanced pool: 1e18 and 2e18, A=100
	b0 := big.NewInt(1e18)
	b1 := new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))
	input := encodeGetD(2, big.NewInt(100), []*big.Int{b0, b1})

	result, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100000, false)
	require.NoError(t, err)

	d := new(big.Int).SetBytes(result)
	sum := new(big.Int).Add(b0, b1)
	// D should be close to but slightly less than the sum for unbalanced pools
	require.True(t, d.Cmp(sum) <= 0, "D should be <= sum for unbalanced pool")
	require.True(t, d.Sign() > 0, "D should be positive")
}

func TestGetDy_Swap(t *testing.T) {
	// Swap 0.1e18 of token 0 for token 1 in a balanced 2-token pool
	bal := big.NewInt(1e18)
	dx := big.NewInt(1e17) // 0.1e18

	// Build GetDy input: [op] [i:4] [j:4] [dx:32] [n:4] [amp:32] [bal0:32] [bal1:32]
	n := 2
	input := make([]byte, 1+4+4+32+4+32+n*32)
	input[0] = OpGetDy
	binary.BigEndian.PutUint32(input[1:5], 0)
	binary.BigEndian.PutUint32(input[5:9], 1)
	copy(input[9:41], padTo32(dx.Bytes()))
	binary.BigEndian.PutUint32(input[41:45], uint32(n))
	copy(input[45:77], padTo32(big.NewInt(100).Bytes()))
	copy(input[77:109], padTo32(bal.Bytes()))
	copy(input[109:141], padTo32(bal.Bytes()))

	result, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100000, false)
	require.NoError(t, err)

	dy := new(big.Int).SetBytes(result)
	// For a balanced StableSwap pool with A=100, swapping 0.1e18 should yield close to 0.1e18
	require.True(t, dy.Cmp(big.NewInt(0)) > 0, "dy should be positive")
	require.True(t, dy.Cmp(dx) <= 0, "dy should be <= dx for stable pool")
	// Should be within 1% for a well-amplified stable pool
	minDy := new(big.Int).Mul(dx, big.NewInt(99))
	minDy.Div(minDy, big.NewInt(100))
	require.True(t, dy.Cmp(minDy) >= 0, "dy should be within 1%% of dx, got %s", dy)
}

func TestGetDy_InvalidIndex(t *testing.T) {
	bal := big.NewInt(1e18)
	n := 2
	input := make([]byte, 1+4+4+32+4+32+n*32)
	input[0] = OpGetDy
	binary.BigEndian.PutUint32(input[1:5], 0)
	binary.BigEndian.PutUint32(input[5:9], 0) // i == j -> invalid
	copy(input[9:41], padTo32(big.NewInt(1e17).Bytes()))
	binary.BigEndian.PutUint32(input[41:45], uint32(n))
	copy(input[45:77], padTo32(big.NewInt(100).Bytes()))
	copy(input[77:109], padTo32(bal.Bytes()))
	copy(input[109:141], padTo32(bal.Bytes()))

	_, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100000, false)
	require.ErrorIs(t, err, ErrInvalidIndex)
}

func TestAddLiquidity_Initial(t *testing.T) {
	// First deposit into empty pool
	n := 2
	amt := big.NewInt(1e18)
	// [op] [n:4] [amp:32] [totalSupply:32] [amounts:n*32] [balances:n*32]
	input := make([]byte, 1+4+32+32+2*n*32)
	input[0] = OpAddLiquidity
	binary.BigEndian.PutUint32(input[1:5], uint32(n))
	copy(input[5:37], padTo32(big.NewInt(100).Bytes()))
	// totalSupply = 0 (initial deposit)
	copy(input[69:101], padTo32(amt.Bytes()))
	copy(input[101:133], padTo32(amt.Bytes()))
	// balances = 0 (empty pool)

	result, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100000, false)
	require.NoError(t, err)

	lpMinted := new(big.Int).SetBytes(result)
	// D1 for balanced pool with 1e18 each should be ~2e18
	expectedD := new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))
	diff := new(big.Int).Sub(lpMinted, expectedD)
	diff.Abs(diff)
	require.True(t, diff.Cmp(big.NewInt(2)) <= 0, "initial LP should be ~2e18, got %s", lpMinted)
}

func TestRemoveLiquidity(t *testing.T) {
	n := 2
	bal := big.NewInt(1e18)
	totalSupply := new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))
	lpAmount := big.NewInt(1e18) // remove half

	// [op] [n:4] [lpAmount:32] [totalSupply:32] [balances:n*32]
	input := make([]byte, 1+4+32+32+n*32)
	input[0] = OpRemoveLiquidity
	binary.BigEndian.PutUint32(input[1:5], uint32(n))
	copy(input[5:37], padTo32(lpAmount.Bytes()))
	copy(input[37:69], padTo32(totalSupply.Bytes()))
	copy(input[69:101], padTo32(bal.Bytes()))
	copy(input[101:133], padTo32(bal.Bytes()))

	result, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	require.Len(t, result, 64)

	amt0 := new(big.Int).SetBytes(result[:32])
	amt1 := new(big.Int).SetBytes(result[32:64])
	// Removing half LP from balanced pool should return half of each balance
	expected := new(big.Int).Div(bal, big.NewInt(2))
	require.Equal(t, 0, expected.Cmp(amt0), "expected %s, got %s", expected, amt0)
	require.Equal(t, 0, expected.Cmp(amt1), "expected %s, got %s", expected, amt1)
}

func TestInvariantPreserved(t *testing.T) {
	// D before and after swap should be equal (minus rounding)
	bal := big.NewInt(1e18)
	amp := big.NewInt(100)
	n := 2

	// Get D before
	inputD := encodeGetD(n, amp, []*big.Int{bal, bal})
	resultD, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, inputD, 100000, false)
	require.NoError(t, err)
	dBefore := new(big.Int).SetBytes(resultD)

	// Simulate swap: add 0.1e18 to token0
	dx := big.NewInt(1e17)
	inputSwap := make([]byte, 1+4+4+32+4+32+n*32)
	inputSwap[0] = OpGetDy
	binary.BigEndian.PutUint32(inputSwap[1:5], 0)
	binary.BigEndian.PutUint32(inputSwap[5:9], 1)
	copy(inputSwap[9:41], padTo32(dx.Bytes()))
	binary.BigEndian.PutUint32(inputSwap[41:45], uint32(n))
	copy(inputSwap[45:77], padTo32(amp.Bytes()))
	copy(inputSwap[77:109], padTo32(bal.Bytes()))
	copy(inputSwap[109:141], padTo32(bal.Bytes()))

	resultSwap, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, inputSwap, 100000, false)
	require.NoError(t, err)
	dy := new(big.Int).SetBytes(resultSwap)

	// New balances: bal+dx, bal-dy
	newBal0 := new(big.Int).Add(bal, dx)
	newBal1 := new(big.Int).Sub(bal, dy)

	// Get D after
	inputDAfter := encodeGetD(n, amp, []*big.Int{newBal0, newBal1})
	resultDAfter, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, inputDAfter, 100000, false)
	require.NoError(t, err)
	dAfter := new(big.Int).SetBytes(resultDAfter)

	// D should be preserved (within rounding tolerance)
	diff := new(big.Int).Sub(dBefore, dAfter)
	diff.Abs(diff)
	require.True(t, diff.Cmp(big.NewInt(10)) <= 0, "invariant D should be preserved: before=%s, after=%s, diff=%s", dBefore, dAfter, diff)
}

func TestGasInsufficient(t *testing.T) {
	input := encodeGetD(2, big.NewInt(100), []*big.Int{big.NewInt(1e18), big.NewInt(1e18)})
	_, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, input, 1, false)
	require.Error(t, err)
}

func TestInvalidInput(t *testing.T) {
	// Empty
	_, _, err := Precompile.Run(nil, ContractAddress, ContractAddress, nil, 100000, false)
	require.ErrorIs(t, err, ErrInvalidInput)

	// Unknown op
	_, _, err = Precompile.Run(nil, ContractAddress, ContractAddress, []byte{0xFF}, 100000, false)
	require.ErrorIs(t, err, ErrUnknownOp)
}
