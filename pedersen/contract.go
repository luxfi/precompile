// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pedersen implements Pedersen hash/commitment precompile over BN254.
// Address: 0x0500000000000000000000000000000000000006 (Hashing range)
//
// Pedersen commitments are homomorphic: C(v1) + C(v2) = C(v1+v2).
// They are hiding and binding under DLOG hardness (NOT post-quantum).
//
// Operations:
//   - 0x01: Commit    — value(32) + blinding(32) -> commitment(32)
//   - 0x02: Verify    — commitment(32) + value(32) + blinding(32) -> bool(32)
//   - 0x03: Add       — c1(32) + c2(32) -> c1+c2(32)
//   - 0x04: VectorCommit — n(1) + values(n*32) + blinding(32) -> commitment(32)
//
// Used by: Zcash, Aztec, commitment schemes, range proofs.
package pedersen

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000006")

	PedersenPrecompile = &pedersenPrecompile{}

	_ contract.StatefulPrecompiledContract = &pedersenPrecompile{}

	ErrInvalidInput = contract.ErrInvalidInput
	ErrInvalidOp    = errors.New("invalid pedersen operation")
	ErrTooManyVals  = errors.New("too many values for vector commitment (max 32)")
)

const (
	OpCommit       = 0x01
	OpVerify       = 0x02
	OpAdd          = 0x03
	OpVectorCommit = 0x04

	GasCommit       = 6000
	GasVerify       = 7000
	GasAdd          = 500
	GasVectorBase   = 6000
	GasVectorPerVal = 3000
)

// Generators derived deterministically
var (
	genG  bn254.G1Affine // base generator
	genH  bn254.G1Affine // blinding generator
	genVi [32]bn254.G1Affine
)

func init() {
	_, _, g1Gen, _ := bn254.Generators()
	genG = g1Gen
	genH = hashToG1("Lux_Pedersen_H_Generator")
	for i := range 32 {
		genVi[i] = hashToG1("Lux_Pedersen_Gen_" + string(rune('A'+i)))
	}

	// Verify all generators are distinct (G, H, V_0..V_31)
	all := make([]bn254.G1Affine, 0, 34)
	all = append(all, genG, genH)
	all = append(all, genVi[:]...)
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[i].Equal(&all[j]) {
				panic("pedersen: duplicate generator detected at init")
			}
		}
	}
}

type pedersenPrecompile struct{}

func (p *pedersenPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpCommit:
		return GasCommit
	case OpVerify:
		return GasVerify
	case OpAdd:
		return GasAdd
	case OpVectorCommit:
		if len(input) < 2 {
			return 0
		}
		n := int(input[1])
		return GasVectorBase + uint64(n)*GasVectorPerVal
	default:
		return 0
	}
}

func (p *pedersenPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	switch input[0] {
	case OpCommit:
		return p.commit(input[1:], gas)
	case OpVerify:
		return p.verify(input[1:], gas)
	case OpAdd:
		return p.add(input[1:], gas)
	case OpVectorCommit:
		return p.vectorCommit(input[1:], gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

// commitTo computes sha256(v*G + r*H) from 64 bytes of value || blinding.
// It is the one place the commitment is defined; commit and verify both go
// through it, so an opening can never be checked against a different formula
// than the one that produced it. The multipliers are reduced modulo r, which is
// exactly the order of G and H, so every 32-byte word names one scalar.
func commitTo(data []byte) []byte {
	var v, r fr.Element
	v.SetBytes(data[:32])
	r.SetBytes(data[32:64])

	var vG, rH bn254.G1Affine
	vG.ScalarMultiplication(&genG, v.BigInt(new(big.Int)))
	rH.ScalarMultiplication(&genH, r.BigInt(new(big.Int)))

	var c bn254.G1Affine
	c.Add(&vG, &rH)

	h := sha256.Sum256(c.Marshal())
	return h[:]
}

// commit: C = v*G + r*H
func (p *pedersenPrecompile) commit(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	return commitTo(data[:64]), gas, nil
}

// verify: check C == v*G + r*H
func (p *pedersenPrecompile) verify(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 96 {
		return nil, gas, ErrInvalidInput
	}
	result := make([]byte, 32)
	if equal(data[:32], commitTo(data[32:96])) {
		result[31] = 1
	}
	return result, gas, nil
}

// add: C1 + C2 homomorphic addition (on compressed hashes -- re-serialize from raw points)
// For the precompile, we work with raw G1 points (64 bytes each)
func (p *pedersenPrecompile) add(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 128 {
		return nil, gas, ErrInvalidInput
	}
	var p1, p2 bn254.G1Affine
	if err := p1.Unmarshal(data[:64]); err != nil {
		return nil, gas, ErrInvalidInput
	}
	if err := p2.Unmarshal(data[64:128]); err != nil {
		return nil, gas, ErrInvalidInput
	}
	var sum bn254.G1Affine
	sum.Add(&p1, &p2)
	return sum.Marshal(), gas, nil
}

// vectorCommit: C = sum(v_i * G_i) + r * H
func (p *pedersenPrecompile) vectorCommit(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 1 {
		return nil, gas, ErrInvalidInput
	}
	n := int(data[0])
	if n > 32 {
		return nil, gas, ErrTooManyVals
	}
	if len(data) < 1+n*32+32 {
		return nil, gas, ErrInvalidInput
	}

	var sum bn254.G1Jac
	for i := range n {
		var vi fr.Element
		vi.SetBytes(data[1+i*32 : 1+(i+1)*32])
		var viG bn254.G1Affine
		viG.ScalarMultiplication(&genVi[i], vi.BigInt(new(big.Int)))
		var viGJac bn254.G1Jac
		viGJac.FromAffine(&viG)
		sum.AddAssign(&viGJac)
	}

	// Blinding factor
	var r fr.Element
	r.SetBytes(data[1+n*32 : 1+n*32+32])
	var rH bn254.G1Affine
	rH.ScalarMultiplication(&genH, r.BigInt(new(big.Int)))
	var rHJac bn254.G1Jac
	rHJac.FromAffine(&rH)
	sum.AddAssign(&rHJac)

	var result bn254.G1Affine
	result.FromJacobian(&sum)
	cBytes := result.Marshal()
	h := sha256.Sum256(cBytes)
	return h[:], gas, nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func hashToG1(seed string) bn254.G1Affine {
	seedBytes := []byte(seed)
	for counter := byte(0); ; counter++ {
		data := append(seedBytes, counter)
		hash := sha256.Sum256(data)
		var x fp.Element
		x.SetBytes(hash[:])
		var x2, x3, rhs fp.Element
		x2.Square(&x)
		x3.Mul(&x2, &x)
		var three fp.Element
		three.SetInt64(3)
		rhs.Add(&x3, &three)
		var y fp.Element
		if y.Sqrt(&rhs) != nil {
			var pt bn254.G1Affine
			pt.X = x
			pt.Y = y
			if pt.IsOnCurve() && !pt.IsInfinity() {
				return pt
			}
		}
		if counter == 255 {
			panic("pedersen: failed to derive independent generator after 256 tries")
		}
	}
}
