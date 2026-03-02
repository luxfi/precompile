// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package stableswap implements Curve-style StableSwap AMM as a precompile.
// Address: 0x0400000000000000000000000000000000000060 (DEX extended range)
//
// Implements the StableSwap invariant:
//
//	An^n * sum(x_i) + D = A * D^(n+1) / (n^n * prod(x_i))
//
// Operations:
//   - 0x01: GetDy(i, j, dx, balances, amp) -> output amount for swap i->j
//   - 0x02: AddLiquidity(amounts, balances, amp, totalSupply) -> LP tokens minted
//   - 0x03: RemoveLiquidity(lpAmount, balances, totalSupply) -> underlying amounts
//   - 0x04: GetD(balances, amp) -> invariant D
//
// Gas: 5,000 base (vs ~50,000 in Solidity -- 10x savings)
// Used for: LUSD/USDC, LETH/stETH, any pegged-asset pools
package stableswap

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0400000000000000000000000000000000000060")

	Precompile = &stableSwapPrecompile{}

	_ contract.StatefulPrecompiledContract = Precompile

	ErrInvalidInput  = errors.New("invalid stableswap input")
	ErrInvalidIndex  = errors.New("invalid token index")
	ErrZeroLiquidity = errors.New("zero liquidity")
	ErrConvergence   = errors.New("newton method did not converge")
	ErrUnknownOp     = errors.New("unknown stableswap operation")
)

const (
	OpGetDy           = 0x01
	OpAddLiquidity    = 0x02
	OpRemoveLiquidity = 0x03
	OpGetD            = 0x04

	GasBase = 5000

	maxIterations = 256
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type stableSwapPrecompile struct{}

func (p *stableSwapPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasBase)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	switch input[0] {
	case OpGetDy:
		return getDy(input[1:], gas)
	case OpAddLiquidity:
		return addLiquidity(input[1:], gas)
	case OpRemoveLiquidity:
		return removeLiquidity(input[1:], gas)
	case OpGetD:
		return getD(input[1:], gas)
	default:
		return nil, gas, ErrUnknownOp
	}
}

// Input layout for GetDy:
//
//	[0:4]   i (uint32)
//	[4:8]   j (uint32)
//	[8:40]  dx (uint256)
//	[40:44] n (uint32, number of tokens)
//	[44:76] amp (uint256)
//	[76:]   balances (n * 32 bytes)
func getDy(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 76 {
		return nil, gas, ErrInvalidInput
	}
	i := binary.BigEndian.Uint32(data[0:4])
	j := binary.BigEndian.Uint32(data[4:8])
	dx := new(big.Int).SetBytes(data[8:40])
	n := int(binary.BigEndian.Uint32(data[40:44]))
	amp := new(big.Int).SetBytes(data[44:76])

	if n < 2 || len(data) < 76+n*32 {
		return nil, gas, ErrInvalidInput
	}
	if int(i) >= n || int(j) >= n || i == j {
		return nil, gas, ErrInvalidIndex
	}

	balances := make([]*big.Int, n)
	for k := range n {
		off := 76 + k*32
		balances[k] = new(big.Int).SetBytes(data[off : off+32])
	}

	d, err := computeD(balances, amp, n)
	if err != nil {
		return nil, gas, err
	}

	// Compute new balance for token j after adding dx to token i
	newBalances := make([]*big.Int, n)
	for k := range n {
		newBalances[k] = new(big.Int).Set(balances[k])
	}
	newBalances[int(i)].Add(newBalances[int(i)], dx)

	y, err := computeY(newBalances, amp, n, int(j), d)
	if err != nil {
		return nil, gas, err
	}

	// dy = balances[j] - y - 1 (subtract 1 for rounding)
	dy := new(big.Int).Sub(balances[int(j)], y)
	dy.Sub(dy, one)
	if dy.Sign() < 0 {
		dy.SetInt64(0)
	}
	return padTo32(dy.Bytes()), gas, nil
}

// Input layout for AddLiquidity:
//
//	[0:4]   n (uint32)
//	[4:36]  amp (uint256)
//	[36:68] totalSupply (uint256)
//	[68:]   amounts (n * 32) + balances (n * 32)
func addLiquidity(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 68 {
		return nil, gas, ErrInvalidInput
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	amp := new(big.Int).SetBytes(data[4:36])
	totalSupply := new(big.Int).SetBytes(data[36:68])

	if n < 2 || len(data) < 68+2*n*32 {
		return nil, gas, ErrInvalidInput
	}

	amounts := make([]*big.Int, n)
	balances := make([]*big.Int, n)
	for k := range n {
		off := 68 + k*32
		amounts[k] = new(big.Int).SetBytes(data[off : off+32])
	}
	for k := range n {
		off := 68 + n*32 + k*32
		balances[k] = new(big.Int).SetBytes(data[off : off+32])
	}

	d0, err := computeD(balances, amp, n)
	if err != nil {
		return nil, gas, err
	}

	newBalances := make([]*big.Int, n)
	for k := range n {
		newBalances[k] = new(big.Int).Add(balances[k], amounts[k])
	}
	d1, err := computeD(newBalances, amp, n)
	if err != nil {
		return nil, gas, err
	}

	if totalSupply.Sign() == 0 {
		// First deposit: mint D1 tokens
		return padTo32(d1.Bytes()), gas, nil
	}

	// mint = totalSupply * (D1 - D0) / D0
	diff := new(big.Int).Sub(d1, d0)
	mint := new(big.Int).Mul(totalSupply, diff)
	mint.Div(mint, d0)
	return padTo32(mint.Bytes()), gas, nil
}

// Input layout for RemoveLiquidity:
//
//	[0:4]   n (uint32)
//	[4:36]  lpAmount (uint256)
//	[36:68] totalSupply (uint256)
//	[68:]   balances (n * 32)
func removeLiquidity(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 68 {
		return nil, gas, ErrInvalidInput
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	lpAmount := new(big.Int).SetBytes(data[4:36])
	totalSupply := new(big.Int).SetBytes(data[36:68])

	if n < 2 || len(data) < 68+n*32 {
		return nil, gas, ErrInvalidInput
	}
	if totalSupply.Sign() == 0 {
		return nil, gas, ErrZeroLiquidity
	}

	balances := make([]*big.Int, n)
	for k := range n {
		off := 68 + k*32
		balances[k] = new(big.Int).SetBytes(data[off : off+32])
	}

	// Return proportional share: amounts[i] = balances[i] * lpAmount / totalSupply
	result := make([]byte, n*32)
	for k := range n {
		amt := new(big.Int).Mul(balances[k], lpAmount)
		amt.Div(amt, totalSupply)
		b := padTo32(amt.Bytes())
		copy(result[k*32:(k+1)*32], b)
	}
	return result, gas, nil
}

// Input layout for GetD:
//
//	[0:4]  n (uint32)
//	[4:36] amp (uint256)
//	[36:]  balances (n * 32)
func getD(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 36 {
		return nil, gas, ErrInvalidInput
	}
	n := int(binary.BigEndian.Uint32(data[0:4]))
	amp := new(big.Int).SetBytes(data[4:36])
	if n < 2 || len(data) < 36+n*32 {
		return nil, gas, ErrInvalidInput
	}

	balances := make([]*big.Int, n)
	for k := range n {
		off := 36 + k*32
		balances[k] = new(big.Int).SetBytes(data[off : off+32])
	}

	d, err := computeD(balances, amp, n)
	if err != nil {
		return nil, gas, err
	}
	return padTo32(d.Bytes()), gas, nil
}

// computeD solves for D using Newton's method on the StableSwap invariant:
//
//	A * n^n * S + D = A * D * n^n + D^(n+1) / (n^n * prod(x_i))
//
// where S = sum(x_i).
func computeD(balances []*big.Int, amp *big.Int, n int) (*big.Int, error) {
	s := new(big.Int)
	for _, b := range balances {
		s.Add(s, b)
	}
	if s.Sign() == 0 {
		return big.NewInt(0), nil
	}

	nn := big.NewInt(int64(n))
	ann := new(big.Int).Mul(amp, nn) // A * n

	d := new(big.Int).Set(s)
	for range maxIterations {
		// dP = D^(n+1) / (n^n * prod(x_i))
		// Computed iteratively: dP = D, then dP = dP * D / (n * x_i) for each i
		dP := new(big.Int).Set(d)
		for _, x := range balances {
			if x.Sign() == 0 {
				return nil, ErrZeroLiquidity
			}
			// dP = dP * D / (x * n)
			dP.Mul(dP, d)
			dP.Div(dP, new(big.Int).Mul(x, nn))
		}

		prevD := new(big.Int).Set(d)

		// numerator   = (A*n*S + n*dP) * D
		// denominator = (A*n - 1) * D + (n+1) * dP
		num := new(big.Int).Mul(ann, s)
		num.Add(num, new(big.Int).Mul(nn, dP))
		num.Mul(num, d)

		denom := new(big.Int).Sub(ann, one)
		denom.Mul(denom, d)
		nPlus1 := new(big.Int).Add(nn, one)
		denom.Add(denom, new(big.Int).Mul(nPlus1, dP))

		d.Div(num, denom)

		// Check convergence: |d - prevD| <= 1
		diff := new(big.Int).Sub(d, prevD)
		diff.Abs(diff)
		if diff.Cmp(one) <= 0 {
			return d, nil
		}
	}
	return nil, ErrConvergence
}

// computeY solves for the new balance of token j given:
// - updated balances (with token j excluded)
// - A, n, D
// Uses Newton's method on the StableSwap invariant, solving for x_j.
func computeY(balances []*big.Int, amp *big.Int, n int, j int, d *big.Int) (*big.Int, error) {
	nn := big.NewInt(int64(n))
	ann := new(big.Int).Mul(amp, nn)

	// c = D^(n+1) / (n^n * A * n * prod(x_i, i != j))
	c := new(big.Int).Set(d)
	s := new(big.Int)
	for k := range n {
		if k == j {
			continue
		}
		x := balances[k]
		if x.Sign() == 0 {
			return nil, ErrZeroLiquidity
		}
		s.Add(s, x)
		c.Mul(c, d)
		c.Div(c, new(big.Int).Mul(x, nn))
	}
	c.Mul(c, d)
	c.Div(c, new(big.Int).Mul(ann, nn))

	b := new(big.Int).Add(s, new(big.Int).Div(d, ann))

	y := new(big.Int).Set(d)
	for range maxIterations {
		prevY := new(big.Int).Set(y)

		// y_next = (y^2 + c) / (2*y + b - D)
		yy := new(big.Int).Mul(y, y)
		yy.Add(yy, c)

		denom := new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), y), b)
		denom.Sub(denom, d)
		if denom.Sign() == 0 {
			return nil, ErrConvergence
		}

		y.Div(yy, denom)

		diff := new(big.Int).Sub(y, prevY)
		diff.Abs(diff)
		if diff.Cmp(one) <= 0 {
			return y, nil
		}
	}
	return nil, ErrConvergence
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
