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
// Used by: Eth 2.0 validator sigs, cross-chain bridges, zkSNARKs.
package bls12381

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
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

	// blsOps is the shared operation implementation used by all 7 precompile structs.
	blsOps = &blsOperations{}

	ErrInvalidInput      = contract.ErrInvalidInput
	ErrPointNotOnCurve   = errors.New("point not on curve")
	ErrPointNotInSubgrp  = errors.New("point not in correct subgroup")
	ErrInvalidFieldElem  = errors.New("invalid field element")
	ErrInvalidPairingLen = errors.New("invalid pairing input length")
)

// EIP-2537 gas costs, "Gas schedule" section.
const (
	GasG1Add = 375
	GasG2Add = 600

	// A multiplication is a multi-scalar multiplication over one pair, so it
	// is priced by the same constant with the k = 1 discount, which is 1000.
	GasG1Mul = 12000
	GasG1MSM = 12000
	GasG2Mul = 22500
	GasG2MSM = 22500

	// EIP-2537 pairing check: 32600 per pair plus a 37700 base.
	GasPairingBase    = 37700
	GasPairingPerPair = 32600

	// msmMultiplier is the denominator the MSM discounts are expressed over.
	msmMultiplier = 1000

	// Serialized point sizes (uncompressed, with padding per EIP-2537)
	G1PointLen  = 128 // 2 * 64 bytes (padded Fp)
	G2PointLen  = 256 // 2 * 128 bytes (padded Fp2)
	ScalarLen   = 32
	FpLen       = 64 // 48 bytes padded to 64
	FpBytes     = 48 // an Fp element before padding
	PadLen      = FpLen - FpBytes
	PairingPair = G1PointLen + G2PointLen
)

// msmDiscountG1 and msmDiscountG2 are the EIP-2537 discount tables, indexed by
// k-1 for k in 1..128. Beyond 128 pairs the discount stops improving and the
// max_discount below applies. G1 and G2 are priced separately.
var (
	msmDiscountG1 = [128]uint64{
		1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687,
		682, 677, 673, 669, 665, 661, 658, 654, 651, 648, 645, 642, 640, 637, 635,
		632, 630, 627, 625, 623, 621, 619, 617, 615, 613, 611, 609, 608, 606, 604,
		603, 601, 599, 598, 596, 595, 593, 592, 591, 589, 588, 586, 585, 584, 582,
		581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567, 566, 565,
		564, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550,
		549, 548, 547, 547, 546, 545, 544, 543, 542, 541, 540, 540, 539, 538, 537,
		536, 536, 535, 534, 533, 532, 532, 531, 530, 529, 528, 528, 527, 526, 525,
		525, 524, 523, 522, 522, 521, 520, 520, 519,
	}
	msmDiscountG2 = [128]uint64{
		1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732,
		724, 717, 711, 704, 699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655,
		652, 649, 646, 643, 640, 637, 634, 632, 629, 627, 624, 622, 620, 618, 615,
		613, 611, 609, 607, 606, 604, 602, 600, 598, 597, 595, 593, 592, 590, 589,
		587, 586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571, 570, 569,
		568, 567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553,
		552, 552, 551, 550, 549, 548, 547, 546, 545, 545, 544, 543, 542, 541, 541,
		540, 539, 538, 537, 537, 536, 535, 535, 534, 533, 532, 532, 531, 530, 530,
		529, 528, 528, 527, 526, 526, 525, 524, 524,
	}
)

// max_discount, applied for k > 128.
const (
	msmMaxDiscountG1 = 519
	msmMaxDiscountG2 = 524
)

// blsOperations holds all the BLS12-381 arithmetic. Stateless, thread-safe.
type blsOperations struct{}

// decodeFp decodes one 64-byte EIP-2537 field element: 16 zero bytes of
// padding followed by a 48-byte big-endian value below the modulus.
//
// Both halves are required. Padding that is not zero would let one field
// element be written many ways, and a value at or above the modulus would be
// reduced into a second encoding of a point that already has one -- the
// difference between a canonical encoding and a malleable one.
func decodeFp(input []byte) (fp.Element, error) {
	if len(input) != FpLen {
		return fp.Element{}, ErrInvalidInput
	}
	for _, b := range input[:PadLen] {
		if b != 0 {
			return fp.Element{}, ErrInvalidFieldElem
		}
	}
	var raw [FpBytes]byte
	copy(raw[:], input[PadLen:])
	e, err := fp.BigEndian.Element(&raw)
	if err != nil {
		return fp.Element{}, ErrInvalidFieldElem
	}
	return e, nil
}

// decodeG1 decodes an EIP-2537 G1 point (128 bytes: two 64-byte padded Fp elements).
func decodeG1(input []byte) (bls12381.G1Affine, error) {
	if len(input) != G1PointLen {
		return bls12381.G1Affine{}, ErrInvalidInput
	}

	x, err := decodeFp(input[:FpLen])
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	y, err := decodeFp(input[FpLen : 2*FpLen])
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	var pt bls12381.G1Affine
	pt.X = x
	pt.Y = y

	// EIP-2537 encodes the point at infinity as all zeros, which is not a
	// solution of the curve equation. gnark's IsOnCurve happens to admit it
	// too, by way of a zero Z in Jacobian form, so this branch changes no
	// output today -- it is here so the convention lives in this file rather
	// than in a dependency's internals.
	if pt.IsInfinity() {
		return pt, nil
	}
	if !pt.IsOnCurve() {
		return bls12381.G1Affine{}, ErrPointNotOnCurve
	}
	// On the curve is not enough: BLS12-381 has a cofactor, so a point can sit
	// on E(Fp) outside the r-order subgroup where the pairing is not bilinear
	// and a signature check is not a signature check.
	if !pt.IsInSubGroup() {
		return bls12381.G1Affine{}, ErrPointNotInSubgrp
	}
	return pt, nil
}

// encodeG1 encodes a G1 point to EIP-2537 format (128 bytes).
func encodeG1(pt *bls12381.G1Affine) []byte {
	result := make([]byte, G1PointLen)
	for i, c := range [2]fp.Element{pt.X, pt.Y} {
		b := c.Bytes()
		copy(result[i*FpLen+PadLen:(i+1)*FpLen], b[:])
	}
	return result
}

// decodeG2 decodes an EIP-2537 G2 point (256 bytes: two 128-byte padded Fp2 elements).
func decodeG2(input []byte) (bls12381.G2Affine, error) {
	if len(input) != G2PointLen {
		return bls12381.G2Affine{}, ErrInvalidInput
	}

	// EIP-2537 "Encoding": an Fp2 element el = c0 + c1*v is written
	// encode(c0) || encode(c1), so the real part comes first, for x and then
	// for y. Writing the pair the other way round produces a G2 encoding that
	// no other implementation reads, and that this one rejects as off-curve.
	var e [4]fp.Element
	for i := range e {
		v, err := decodeFp(input[i*FpLen : (i+1)*FpLen])
		if err != nil {
			return bls12381.G2Affine{}, err
		}
		e[i] = v
	}

	var pt bls12381.G2Affine
	pt.X.A0, pt.X.A1 = e[0], e[1]
	pt.Y.A0, pt.Y.A1 = e[2], e[3]

	// EIP-2537 encodes the point at infinity as all zeros, which is not a
	// solution of the curve equation. gnark's IsOnCurve happens to admit it
	// too, by way of a zero Z in Jacobian form, so this branch changes no
	// output today -- it is here so the convention lives in this file rather
	// than in a dependency's internals.
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

// encodeG2 encodes a G2 point to EIP-2537 format (256 bytes), c0 before c1.
func encodeG2(pt *bls12381.G2Affine) []byte {
	result := make([]byte, G2PointLen)
	for i, c := range [4]fp.Element{pt.X.A0, pt.X.A1, pt.Y.A0, pt.Y.A1} {
		b := c.Bytes()
		copy(result[i*FpLen+PadLen:(i+1)*FpLen], b[:])
	}
	return result
}

func decodeScalar(input []byte) (fr.Element, error) {
	if len(input) != ScalarLen {
		return fr.Element{}, ErrInvalidInput
	}
	var s fr.Element
	s.SetBytes(input[:ScalarLen])
	return s, nil
}

func (o *blsOperations) g1Add(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG1Add)
	if err != nil {
		return nil, 0, err
	}
	if len(input) != 2*G1PointLen {
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

func (o *blsOperations) g1Mul(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG1Mul)
	if err != nil {
		return nil, 0, err
	}
	if len(input) != G1PointLen+ScalarLen {
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

func (o *blsOperations) g1MSM(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	pairSize := G1PointLen + ScalarLen

	// EIP-2537 prices an MSM from a floor division of the input length and
	// never rejects; the routine below is what refuses a length that is not a
	// whole number of pairs, once the gas has been taken.
	numPairs := len(input) / pairSize
	gas, err := contract.DeductGas(suppliedGas, G1MSMGas(uint64(numPairs)))
	if err != nil {
		return nil, 0, err
	}
	if len(input) == 0 || len(input)%pairSize != 0 {
		return nil, gas, ErrInvalidInput
	}

	points := make([]bls12381.G1Affine, numPairs)
	scalars := make([]fr.Element, numPairs)
	for i := range numPairs {
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

	// CPU is the single source of truth: gnark-crypto's MultiExp. The accel
	// MSM result was trusted without being independently re-verified (an MSM
	// has no cheap verification), so a GPU result differing from gnark by even
	// one bit -- or computed under the wrong curve, since the accel MSM call
	// carries no curve binding through to the kernel -- would have produced a
	// different precompile output on accel-equipped validators, a consensus
	// split. Re-introducing accel requires a BLS12-381 G1 MSM kernel proven
	// bit-identical to MultiExp.
	var result bls12381.G1Affine
	_, err = result.MultiExp(points, scalars, ecc.MultiExpConfig{})
	if err != nil {
		return nil, gas, err
	}
	return encodeG1(&result), gas, nil
}

func (o *blsOperations) g2Add(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG2Add)
	if err != nil {
		return nil, 0, err
	}
	if len(input) != 2*G2PointLen {
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

func (o *blsOperations) g2Mul(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	gas, err := contract.DeductGas(suppliedGas, GasG2Mul)
	if err != nil {
		return nil, 0, err
	}
	if len(input) != G2PointLen+ScalarLen {
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

func (o *blsOperations) g2MSM(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	pairSize := G2PointLen + ScalarLen
	numPairs := len(input) / pairSize
	gas, err := contract.DeductGas(suppliedGas, G2MSMGas(uint64(numPairs)))
	if err != nil {
		return nil, 0, err
	}
	if len(input) == 0 || len(input)%pairSize != 0 {
		return nil, gas, ErrInvalidInput
	}

	points := make([]bls12381.G2Affine, numPairs)
	scalars := make([]fr.Element, numPairs)
	for i := range numPairs {
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
	_, err = result.MultiExp(points, scalars, ecc.MultiExpConfig{})
	if err != nil {
		return nil, gas, err
	}
	return encodeG2(&result), gas, nil
}

func (o *blsOperations) pairing(input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	numPairs := len(input) / PairingPair
	gas, err := contract.DeductGas(suppliedGas, PairingGas(len(input)))
	if err != nil {
		return nil, 0, err
	}
	if len(input) == 0 || len(input)%PairingPair != 0 {
		return nil, gas, ErrInvalidPairingLen
	}

	g1Points := make([]bls12381.G1Affine, numPairs)
	g2Points := make([]bls12381.G2Affine, numPairs)
	for i := range numPairs {
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

// PairingGas computes the EIP-2537 pairing gas cost for the given input length.
// Exported for use in tests and gas estimation.
// The pair count is a floor division, so a length that is not a whole number
// of pairs is still priced; the pairing routine is what rejects it.
func PairingGas(inputLen int) uint64 {
	numPairs := uint64(inputLen) / uint64(PairingPair)
	return GasPairingBase + GasPairingPerPair*numPairs
}

// msmGas prices a multi-scalar multiplication over numPairs pairs:
// k * multiplication_cost * discount(k) / multiplier, floor divided, per the
// EIP-2537 "Gas schedule clarifications for G1/G2 MSM" section.
func msmGas(numPairs, baseGas uint64, discounts *[128]uint64, maxDiscount uint64) uint64 {
	if numPairs == 0 {
		return 0
	}
	discount := maxDiscount
	if numPairs <= uint64(len(discounts)) {
		discount = discounts[numPairs-1]
	}
	return numPairs * baseGas * discount / msmMultiplier
}

// G1MSMGas and G2MSMGas expose the EIP-2537 MSM schedule for gas estimation.
func G1MSMGas(numPairs uint64) uint64 {
	return msmGas(numPairs, GasG1MSM, &msmDiscountG1, msmMaxDiscountG1)
}

func G2MSMGas(numPairs uint64) uint64 {
	return msmGas(numPairs, GasG2MSM, &msmDiscountG2, msmMaxDiscountG2)
}
