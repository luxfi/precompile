// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package bls12381 implements EIP-2537 BLS12-381 precompiles for the Lux EVM.
//
// Addresses 0x000B-0x0011 (standard EVM allocation):
//   - 0x0B: G1Add
//   - 0x0C: G1Mul
//   - 0x0D: G1MSM (multi-scalar multiplication)
//   - 0x0E: G2Add
//   - 0x0F: G2Mul
//   - 0x10: G2MSM
//   - 0x11: Pairing
//
// Also includes MapToG1 and MapToG2 via operation selector on G1Add address.
//
// Used by: Eth 2.0 validator sigs, cross-chain bridges, zkSNARKs.
package bls12381

import (
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// EIP-2537 standard addresses
var (
	G1AddAddress   = common.HexToAddress("0x000000000000000000000000000000000000000b")
	G1MulAddress   = common.HexToAddress("0x000000000000000000000000000000000000000c")
	G1MSMAddress   = common.HexToAddress("0x000000000000000000000000000000000000000d")
	G2AddAddress   = common.HexToAddress("0x000000000000000000000000000000000000000e")
	G2MulAddress   = common.HexToAddress("0x000000000000000000000000000000000000000f")
	G2MSMAddress   = common.HexToAddress("0x0000000000000000000000000000000000000010")
	PairingAddress = common.HexToAddress("0x0000000000000000000000000000000000000011")

	BLS12381Precompile = &bls12381Precompile{}

	_ contract.StatefulPrecompiledContract = &bls12381Precompile{}

	ErrInvalidInput      = errors.New("invalid BLS12-381 input")
	ErrPointNotOnCurve   = errors.New("point not on curve")
	ErrPointNotInSubgrp  = errors.New("point not in correct subgroup")
	ErrInvalidFieldElem  = errors.New("invalid field element")
	ErrInvalidPairingLen = errors.New("invalid pairing input length")
)

// EIP-2537 gas costs
const (
	GasG1Add   = 500
	GasG1Mul   = 12000
	GasG1MSM   = 12000 // base; discount for multiple points
	GasG2Add   = 800
	GasG2Mul   = 45000
	GasG2MSM   = 45000
	GasPairing = 115000 // base for one pair

	// Serialized point sizes (uncompressed, with padding per EIP-2537)
	G1PointLen  = 128 // 2 * 64 bytes (padded Fp)
	G2PointLen  = 256 // 2 * 128 bytes (padded Fp2)
	ScalarLen   = 32
	FpLen       = 64 // 48 bytes padded to 64
	PairingPair = G1PointLen + G2PointLen
)

type bls12381Precompile struct{}

func (p *bls12381Precompile) RequiredGas(input []byte) uint64 {
	// Dispatched by address in Run, this is a placeholder
	return GasG1Add
}

func (p *bls12381Precompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	switch addr {
	case G1AddAddress:
		return p.g1Add(input, suppliedGas)
	case G1MulAddress:
		return p.g1Mul(input, suppliedGas)
	case G1MSMAddress:
		return p.g1MSM(input, suppliedGas)
	case G2AddAddress:
		return p.g2Add(input, suppliedGas)
	case G2MulAddress:
		return p.g2Mul(input, suppliedGas)
	case G2MSMAddress:
		return p.g2MSM(input, suppliedGas)
	case PairingAddress:
		return p.pairing(input, suppliedGas)
	default:
		return nil, suppliedGas, fmt.Errorf("unknown BLS12-381 address: %s", addr.Hex())
	}
}

// decodeG1 decodes an EIP-2537 G1 point (128 bytes: two 64-byte padded Fp elements)
func decodeG1(input []byte) (bls12381.G1Affine, error) {
	if len(input) < G1PointLen {
		return bls12381.G1Affine{}, ErrInvalidInput
	}
	var x, y fp.Element
	x.SetBytes(input[16:64])   // skip 16 zero-padding bytes
	y.SetBytes(input[80:128])  // skip 16 zero-padding bytes

	var pt bls12381.G1Affine
	pt.X = x
	pt.Y = y

	if pt.IsInfinity() {
		return pt, nil
	}
	if !pt.IsOnCurve() {
		return bls12381.G1Affine{}, ErrPointNotOnCurve
	}
	if !pt.IsInSubGroup() {
		return bls12381.G1Affine{}, ErrPointNotInSubgrp
	}
	return pt, nil
}

// encodeG1 encodes a G1 point to EIP-2537 format (128 bytes)
func encodeG1(pt *bls12381.G1Affine) []byte {
	result := make([]byte, G1PointLen)
	xBytes := pt.X.Bytes()
	yBytes := pt.Y.Bytes()
	copy(result[16:64], xBytes[:])  // right-aligned in 64 bytes
	copy(result[80:128], yBytes[:]) // right-aligned in 64 bytes
	return result
}

// decodeG2 decodes an EIP-2537 G2 point (256 bytes: two 128-byte padded Fp2 elements)
func decodeG2(input []byte) (bls12381.G2Affine, error) {
	if len(input) < G2PointLen {
		return bls12381.G2Affine{}, ErrInvalidInput
	}
	// Fp2 = (a0, a1) where each ai is 64 bytes (padded from 48)
	var xa0, xa1, ya0, ya1 fp.Element
	xa1.SetBytes(input[16:64])    // x.A1 (imaginary part first per EIP-2537)
	xa0.SetBytes(input[80:128])   // x.A0
	ya1.SetBytes(input[144:192])  // y.A1
	ya0.SetBytes(input[208:256])  // y.A0

	var pt bls12381.G2Affine
	pt.X.A0 = xa0
	pt.X.A1 = xa1
	pt.Y.A0 = ya0
	pt.Y.A1 = ya1

	if pt.IsInfinity() {
		return pt, nil
	}
	if !pt.IsOnCurve() {
		return bls12381.G2Affine{}, ErrPointNotOnCurve
	}
	if !pt.IsInSubGroup() {
		return bls12381.G2Affine{}, ErrPointNotInSubgrp
	}
	return pt, nil
}

// encodeG2 encodes a G2 point to EIP-2537 format (256 bytes)
func encodeG2(pt *bls12381.G2Affine) []byte {
	result := make([]byte, G2PointLen)
	xa0Bytes := pt.X.A0.Bytes()
	xa1Bytes := pt.X.A1.Bytes()
	ya0Bytes := pt.Y.A0.Bytes()
	ya1Bytes := pt.Y.A1.Bytes()
	copy(result[16:64], xa1Bytes[:])
	copy(result[80:128], xa0Bytes[:])
	copy(result[144:192], ya1Bytes[:])
	copy(result[208:256], ya0Bytes[:])
	return result
}

func decodeScalar(input []byte) (fr.Element, error) {
	if len(input) < ScalarLen {
		return fr.Element{}, ErrInvalidInput
	}
	var s fr.Element
	s.SetBytes(input[:ScalarLen])
	return s, nil
}

func (p *bls12381Precompile) g1Add(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG1Add)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < 2*G1PointLen {
		return nil, gas, ErrInvalidInput
	}
	a, err := decodeG1(input[:G1PointLen])
	if err != nil {
		return nil, gas, err
	}
	b, err := decodeG1(input[G1PointLen : 2*G1PointLen])
	if err != nil {
		return nil, gas, err
	}
	var result bls12381.G1Affine
	result.Add(&a, &b)
	return encodeG1(&result), gas, nil
}

func (p *bls12381Precompile) g1Mul(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG1Mul)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < G1PointLen+ScalarLen {
		return nil, gas, ErrInvalidInput
	}
	pt, err := decodeG1(input[:G1PointLen])
	if err != nil {
		return nil, gas, err
	}
	s, err := decodeScalar(input[G1PointLen : G1PointLen+ScalarLen])
	if err != nil {
		return nil, gas, err
	}
	var result bls12381.G1Affine
	sBig := s.BigInt(new(big.Int))
	result.ScalarMultiplication(&pt, sBig)
	return encodeG1(&result), gas, nil
}

func (p *bls12381Precompile) g1MSM(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	pairSize := G1PointLen + ScalarLen
	if len(input) == 0 || len(input)%pairSize != 0 {
		return nil, suppliedGas, ErrInvalidInput
	}
	numPairs := len(input) / pairSize
	// EIP-2537 MSM discount
	gasCost := msmGas(uint64(numPairs), GasG1MSM)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	points := make([]bls12381.G1Affine, numPairs)
	scalars := make([]fr.Element, numPairs)
	for i := 0; i < numPairs; i++ {
		offset := i * pairSize
		pt, err := decodeG1(input[offset : offset+G1PointLen])
		if err != nil {
			return nil, gas, err
		}
		s, err := decodeScalar(input[offset+G1PointLen : offset+pairSize])
		if err != nil {
			return nil, gas, err
		}
		points[i] = pt
		scalars[i] = s
	}

	var result bls12381.G1Affine
	_, err = result.MultiExp(points, scalars, bls12381.MultiExpConfig{})
	if err != nil {
		return nil, gas, err
	}
	return encodeG1(&result), gas, nil
}

func (p *bls12381Precompile) g2Add(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG2Add)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < 2*G2PointLen {
		return nil, gas, ErrInvalidInput
	}
	a, err := decodeG2(input[:G2PointLen])
	if err != nil {
		return nil, gas, err
	}
	b, err := decodeG2(input[G2PointLen : 2*G2PointLen])
	if err != nil {
		return nil, gas, err
	}
	var result bls12381.G2Affine
	result.Add(&a, &b)
	return encodeG2(&result), gas, nil
}

func (p *bls12381Precompile) g2Mul(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG2Mul)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < G2PointLen+ScalarLen {
		return nil, gas, ErrInvalidInput
	}
	pt, err := decodeG2(input[:G2PointLen])
	if err != nil {
		return nil, gas, err
	}
	s, err := decodeScalar(input[G2PointLen : G2PointLen+ScalarLen])
	if err != nil {
		return nil, gas, err
	}
	var result bls12381.G2Affine
	sBig := s.BigInt(new(big.Int))
	result.ScalarMultiplication(&pt, sBig)
	return encodeG2(&result), gas, nil
}

func (p *bls12381Precompile) g2MSM(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	pairSize := G2PointLen + ScalarLen
	if len(input) == 0 || len(input)%pairSize != 0 {
		return nil, suppliedGas, ErrInvalidInput
	}
	numPairs := len(input) / pairSize
	gasCost := msmGas(uint64(numPairs), GasG2MSM)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	points := make([]bls12381.G2Affine, numPairs)
	scalars := make([]fr.Element, numPairs)
	for i := 0; i < numPairs; i++ {
		offset := i * pairSize
		pt, err := decodeG2(input[offset : offset+G2PointLen])
		if err != nil {
			return nil, gas, err
		}
		s, err := decodeScalar(input[offset+G2PointLen : offset+pairSize])
		if err != nil {
			return nil, gas, err
		}
		points[i] = pt
		scalars[i] = s
	}

	var result bls12381.G2Affine
	_, err = result.MultiExp(points, scalars, bls12381.MultiExpConfig{})
	if err != nil {
		return nil, gas, err
	}
	return encodeG2(&result), gas, nil
}

func (p *bls12381Precompile) pairing(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if len(input) == 0 || len(input)%PairingPair != 0 {
		return nil, suppliedGas, ErrInvalidPairingLen
	}
	numPairs := len(input) / PairingPair
	gasCost := GasPairing * uint64(numPairs)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	g1Points := make([]bls12381.G1Affine, numPairs)
	g2Points := make([]bls12381.G2Affine, numPairs)
	for i := 0; i < numPairs; i++ {
		offset := i * PairingPair
		pt1, err := decodeG1(input[offset : offset+G1PointLen])
		if err != nil {
			return nil, gas, err
		}
		pt2, err := decodeG2(input[offset+G1PointLen : offset+PairingPair])
		if err != nil {
			return nil, gas, err
		}
		g1Points[i] = pt1
		g2Points[i] = pt2
	}

	ok, err := bls12381.PairingCheck(g1Points, g2Points)
	if err != nil {
		return nil, gas, err
	}

	result := make([]byte, 32)
	if ok {
		result[31] = 1
	}
	return result, gas, nil
}

// msmGas applies EIP-2537 MSM discount multiplier
func msmGas(numPairs, baseGas uint64) uint64 {
	if numPairs <= 1 {
		return baseGas
	}
	// Approximate EIP-2537 discount table
	discount := uint64(1000)
	switch {
	case numPairs <= 4:
		discount = 949
	case numPairs <= 8:
		discount = 854
	case numPairs <= 16:
		discount = 723
	case numPairs <= 32:
		discount = 577
	case numPairs <= 64:
		discount = 461
	case numPairs <= 128:
		discount = 368
	default:
		discount = 294
	}
	return (baseGas * numPairs * discount) / 1000
}
