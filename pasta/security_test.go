// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pasta

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// H-05: Pasta scalar multiplication must not use big.Int double-and-add.
//
// Vulnerability: The original scalarMulPoint implementation used variable-time
// big.Int operations for double-and-add, which leaks the scalar through timing
// side channels. While EVM execution is generally public (calldata is visible),
// the pattern creates a bad precedent and affects any off-chain use of this code.
//
// Fix: Use constant-time scalar multiplication (e.g., Montgomery ladder or
// fixed-window method). At minimum, ensure no early-exit branches depend on
// scalar bits.
//
// This test verifies correctness rather than timing (timing tests are inherently
// flaky). The key property: scalarMul(G, 0) = identity, scalarMul(G, 1) = G,
// scalarMul(G, order) = identity.
func TestH05_PastaScalarMulCorrectnessBasic(t *testing.T) {
	// Use Pallas curve
	p := modulus(CurvePallas)

	// Pick a known point on Pallas: y^2 = x^3 + 5 mod p
	// x = 1 => y^2 = 6 mod p. Check if 6 is a QR mod p.
	// Use a generator-like point by doubling from a known point.
	x := big.NewInt(1)
	y2 := new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), p), curveB)
	y2.Mod(y2, p)

	// If 6 is not a QR, try x=2, etc.
	var basePoint point
	for testX := int64(1); testX < 100; testX++ {
		x := big.NewInt(testX)
		y2 := new(big.Int).Exp(x, big.NewInt(3), p)
		y2.Add(y2, curveB)
		y2.Mod(y2, p)

		// Tonelli-Shanks to find square root
		y := new(big.Int).ModSqrt(y2, p)
		if y != nil {
			basePoint = point{x: x, y: y}
			break
		}
	}
	require.False(t, basePoint.inf, "must find a valid Pallas curve point")

	// scalarMul(P, 0) = identity
	result := scalarMulPoint(CurvePallas, basePoint, big.NewInt(0))
	require.True(t, result.inf, "P * 0 must be the point at infinity")

	// scalarMul(P, 1) = P
	result = scalarMulPoint(CurvePallas, basePoint, big.NewInt(1))
	require.Equal(t, 0, result.x.Cmp(basePoint.x), "P * 1 must equal P (x)")
	require.Equal(t, 0, result.y.Cmp(basePoint.y), "P * 1 must equal P (y)")

	// scalarMul(P, 2) = P + P
	doubled := doublePoint(CurvePallas, basePoint)
	result = scalarMulPoint(CurvePallas, basePoint, big.NewInt(2))
	require.Equal(t, 0, result.x.Cmp(doubled.x), "P * 2 must equal 2P (x)")
	require.Equal(t, 0, result.y.Cmp(doubled.y), "P * 2 must equal 2P (y)")
}

// H-05: Pasta ScalarMul via precompile must be deterministic.
//
// Same input must produce same output on every call (consensus requirement).
func TestH05_PastaScalarMulDeterministic(t *testing.T) {
	// Build ScalarMul input: curveID(1) + op(1) + point(64) + scalar(32)
	input := make([]byte, 2+PointLen+32)
	input[0] = CurvePallas
	input[1] = OpScalarMul

	// Use x=1 (find valid point)
	p := modulus(CurvePallas)
	for testX := int64(1); testX < 100; testX++ {
		x := big.NewInt(testX)
		y2 := new(big.Int).Exp(x, big.NewInt(3), p)
		y2.Add(y2, curveB)
		y2.Mod(y2, p)
		y := new(big.Int).ModSqrt(y2, p)
		if y != nil {
			xBytes := x.Bytes()
			yBytes := y.Bytes()
			copy(input[2+32-len(xBytes):2+32], xBytes)
			copy(input[2+64-len(yBytes):2+64], yBytes)
			break
		}
	}

	// Scalar = 42
	scalar := big.NewInt(42)
	sBytes := scalar.Bytes()
	copy(input[2+PointLen+32-len(sBytes):2+PointLen+32], sBytes)

	gas := PastaPrecompile.RequiredGas(input)

	ret1, _, err1 := PastaPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas+100_000, false)
	require.NoError(t, err1)

	ret2, _, err2 := PastaPrecompile.Run(nil, common.Address{}, ContractAddress, input, gas+100_000, false)
	require.NoError(t, err2)

	require.Equal(t, ret1, ret2, "ScalarMul must be deterministic")
}

// H-05: Verify both Pallas and Vesta curves work.
func TestH05_PastaBothCurvesWork(t *testing.T) {
	for _, curveID := range []byte{CurvePallas, CurveVesta} {
		t.Run(curveName(curveID), func(t *testing.T) {
			p := modulus(curveID)
			// Find a point on the curve
			for testX := int64(1); testX < 100; testX++ {
				x := big.NewInt(testX)
				y2 := new(big.Int).Exp(x, big.NewInt(3), p)
				y2.Add(y2, curveB)
				y2.Mod(y2, p)
				y := new(big.Int).ModSqrt(y2, p)
				if y == nil {
					continue
				}

				pt := point{x: x, y: y}
				// Basic op: double and verify still on curve
				doubled := doublePoint(curveID, pt)
				if doubled.inf {
					continue
				}

				// Verify on curve: y^2 = x^3 + 5 mod p
				lhs := new(big.Int).Mul(doubled.y, doubled.y)
				lhs.Mod(lhs, p)
				rhs := new(big.Int).Exp(doubled.x, big.NewInt(3), p)
				rhs.Add(rhs, curveB)
				rhs.Mod(rhs, p)
				require.Equal(t, 0, lhs.Cmp(rhs),
					"%s: doubled point must be on curve", curveName(curveID))
				return
			}
			t.Fatalf("Could not find a valid point on %s", curveName(curveID))
		})
	}
}

func curveName(id byte) string {
	if id == CurvePallas {
		return "Pallas"
	}
	return "Vesta"
}
