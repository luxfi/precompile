// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package math

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	expected := "0x0400000000000000000000000000000000000050"
	require.Equal(t, expected, ContractAddress.Hex())
}

func TestMulDiv(t *testing.T) {
	p := Precompile
	tests := []struct {
		name    string
		a, b, d *big.Int
		want    *big.Int
		wantErr error
	}{
		{
			name: "basic",
			a:    big.NewInt(10),
			b:    big.NewInt(20),
			d:    big.NewInt(5),
			want: big.NewInt(40),
		},
		{
			name: "large product no overflow",
			a:    new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
			b:    new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
			d:    new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
			want: new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
		},
		{
			name:    "div by zero",
			a:       big.NewInt(1),
			b:       big.NewInt(1),
			d:       big.NewInt(0),
			wantErr: ErrDivByZero,
		},
		{
			name: "zero numerator",
			a:    big.NewInt(0),
			b:    big.NewInt(100),
			d:    big.NewInt(7),
			want: big.NewInt(0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, 1+96)
			input[0] = OpMulDiv
			copy(input[1:33], padTo32(tc.a.Bytes()))
			copy(input[33:65], padTo32(tc.b.Bytes()))
			copy(input[65:97], padTo32(tc.d.Bytes()))

			result, gas, err := p.Run(nil, addr0, ContractAddress, input, 100000, false)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.True(t, gas < 100000, "gas should be consumed")
			got := new(big.Int).SetBytes(result)
			require.Equal(t, 0, tc.want.Cmp(got), "expected %s, got %s", tc.want, got)
		})
	}
}

func TestMulDivRoundUp(t *testing.T) {
	p := Precompile
	// 10 * 3 / 7 = 4.28... -> ceil = 5
	input := make([]byte, 1+96)
	input[0] = OpMulDivRoundUp
	copy(input[1:33], padTo32(big.NewInt(10).Bytes()))
	copy(input[33:65], padTo32(big.NewInt(3).Bytes()))
	copy(input[65:97], padTo32(big.NewInt(7).Bytes()))

	result, _, err := p.Run(nil, addr0, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	got := new(big.Int).SetBytes(result)
	require.Equal(t, big.NewInt(5), got)
}

func TestSqrt(t *testing.T) {
	p := Precompile
	tests := []struct {
		name string
		x    *big.Int
		want *big.Int
	}{
		{"zero", big.NewInt(0), big.NewInt(0)},
		{"one", big.NewInt(1), big.NewInt(1)},
		{"four", big.NewInt(4), big.NewInt(2)},
		{"non-perfect", big.NewInt(10), big.NewInt(3)},
		{"large", new(big.Int).Exp(big.NewInt(10), big.NewInt(40), nil), new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, 1+32)
			input[0] = OpSqrt
			copy(input[1:33], padTo32(tc.x.Bytes()))

			result, _, err := p.Run(nil, addr0, ContractAddress, input, 100000, false)
			require.NoError(t, err)
			got := new(big.Int).SetBytes(result)
			require.Equal(t, 0, tc.want.Cmp(got), "sqrt(%s): expected %s, got %s", tc.x, tc.want, got)
		})
	}
}

func TestLog2(t *testing.T) {
	p := Precompile
	tests := []struct {
		name string
		x    *big.Int
		want int64
	}{
		{"one", big.NewInt(1), 0},
		{"two", big.NewInt(2), 1},
		{"three", big.NewInt(3), 1},
		{"256", big.NewInt(256), 8},
		{"max_u64", new(big.Int).SetUint64(^uint64(0)), 63},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, 1+32)
			input[0] = OpLog2
			copy(input[1:33], padTo32(tc.x.Bytes()))

			result, _, err := p.Run(nil, addr0, ContractAddress, input, 100000, false)
			require.NoError(t, err)
			got := new(big.Int).SetBytes(result)
			require.Equal(t, 0, big.NewInt(tc.want).Cmp(got), "expected %d, got %s", tc.want, got)
		})
	}
}

func TestLog2Zero(t *testing.T) {
	input := make([]byte, 1+32)
	input[0] = OpLog2
	// x = 0 (all zeros)

	result, _, err := Precompile.Run(nil, addr0, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	got := new(big.Int).SetBytes(result)
	require.Equal(t, 0, big.NewInt(0).Cmp(got), "log2(0) should return 0")
}

func TestPow(t *testing.T) {
	p := Precompile
	// 2^10 = 1024
	input := make([]byte, 1+64)
	input[0] = OpPow
	copy(input[1:33], padTo32(big.NewInt(2).Bytes()))
	copy(input[33:65], padTo32(big.NewInt(10).Bytes()))

	result, _, err := p.Run(nil, addr0, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	got := new(big.Int).SetBytes(result)
	require.Equal(t, big.NewInt(1024), got)
}

func TestExp(t *testing.T) {
	// e^0 in Q128.128 = 2^128 (= 1.0)
	input := make([]byte, 1+32)
	input[0] = OpExp
	// x = 0

	result, _, err := Precompile.Run(nil, addr0, ContractAddress, input, 100000, false)
	require.NoError(t, err)
	got := new(big.Int).SetBytes(result)
	// e^0 = 1.0 in Q128.128 = 2^128
	require.Equal(t, 0, q128.Cmp(got), "e^0 should be 1.0 in Q128.128")
}

func TestGasInsufficient(t *testing.T) {
	input := []byte{OpMulDiv}
	input = append(input, make([]byte, 96)...)
	_, _, err := Precompile.Run(nil, addr0, ContractAddress, input, 1, false)
	require.Error(t, err)
}

func TestInvalidInput(t *testing.T) {
	// Empty input
	_, _, err := Precompile.Run(nil, addr0, ContractAddress, nil, 100000, false)
	require.ErrorIs(t, err, ErrInvalidInput)

	// Unknown op
	_, _, err = Precompile.Run(nil, addr0, ContractAddress, []byte{0xFF}, 100000, false)
	require.ErrorIs(t, err, ErrUnknownOp)

	// MulDiv with too little data
	_, _, err = Precompile.Run(nil, addr0, ContractAddress, []byte{OpMulDiv, 0x01}, 100000, false)
	require.ErrorIs(t, err, ErrInvalidInput)

	// Sqrt with too little data
	_, _, err = Precompile.Run(nil, addr0, ContractAddress, []byte{OpSqrt}, 100000, false)
	require.ErrorIs(t, err, ErrInvalidInput)
}

var addr0 = ContractAddress
