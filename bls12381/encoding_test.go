// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// The generator coordinates published in the EIP-2537 "Curve parameters"
// section. They pin the byte order of an encoded point independently of the
// vector files: an Fp2 element el = c0 + c1*v is written encode(c0) ||
// encode(c1), so c0 comes first for x and then again for y.
const (
	g1GenX = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
	g1GenY = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"

	g2GenXc0 = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
	g2GenXc1 = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
	g2GenYc0 = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
	g2GenYc1 = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
)

// padded renders 48-byte field elements in EIP-2537's 64-byte slots.
func padded(elems ...string) string {
	var b bytes.Buffer
	for _, e := range elems {
		b.WriteString("00000000000000000000000000000000")
		b.WriteString(e)
	}
	return b.String()
}

// TestEncoding_GeneratorsMatchTheSpec is the direct check on component order.
// A G2 encoding that writes c1 before c0 round-trips through this package
// perfectly and is unreadable to every other implementation of the EIP.
func TestEncoding_GeneratorsMatchTheSpec(t *testing.T) {
	_, _, g1, g2 := gnark.Generators()

	require.Equal(t, padded(g1GenX, g1GenY), hex.EncodeToString(encodeG1(&g1)))
	require.Equal(t, padded(g2GenXc0, g2GenXc1, g2GenYc0, g2GenYc1), hex.EncodeToString(encodeG2(&g2)))

	// And the decoder reads its own output back to the same points.
	backG1, err := decodeG1(encodeG1(&g1))
	require.NoError(t, err)
	require.True(t, backG1.Equal(&g1))

	backG2, err := decodeG2(encodeG2(&g2))
	require.NoError(t, err)
	require.True(t, backG2.Equal(&g2))
}

// TestDecode_RequiresExactPointWidth covers the point decoders directly. Every
// caller slices to the exact width, so nothing reaching them through an
// operation can be the wrong size; the guard is what keeps that true if a
// caller is ever added.
func TestDecode_RequiresExactPointWidth(t *testing.T) {
	_, _, g1, g2 := gnark.Generators()

	for _, n := range []int{0, G1PointLen - 1, G1PointLen + 1, 2 * G1PointLen} {
		body := make([]byte, n)
		copy(body, encodeG1(&g1))
		_, err := decodeG1(body)
		require.ErrorIsf(t, err, ErrInvalidInput, "decodeG1 accepted %d bytes", n)
	}
	for _, n := range []int{0, G2PointLen - 1, G2PointLen + 1, 2 * G2PointLen} {
		body := make([]byte, n)
		copy(body, encodeG2(&g2))
		_, err := decodeG2(body)
		require.ErrorIsf(t, err, ErrInvalidInput, "decodeG2 accepted %d bytes", n)
	}
}

// TestDecode_AllZeroIsTheInfinityPoint pins the EIP-2537 convention: (0, 0) is
// not on either curve, and a 128- or 256-byte run of zeros stands for the
// point at infinity instead.
func TestDecode_AllZeroIsTheInfinityPoint(t *testing.T) {
	g1, err := decodeG1(make([]byte, G1PointLen))
	require.NoError(t, err)
	require.True(t, g1.IsInfinity())
	require.Equal(t, make([]byte, G1PointLen), encodeG1(&g1))

	g2, err := decodeG2(make([]byte, G2PointLen))
	require.NoError(t, err)
	require.True(t, g2.IsInfinity())
	require.Equal(t, make([]byte, G2PointLen), encodeG2(&g2))
}

// TestDecodeFp_Canonicality covers the field-element decoder on its own.
func TestDecodeFp_Canonicality(t *testing.T) {
	modulus := fp.Modulus()

	slot := func(v *big.Int) []byte {
		out := make([]byte, FpLen)
		v.FillBytes(out[PadLen:])
		return out
	}

	t.Run("wrong_width", func(t *testing.T) {
		for _, n := range []int{0, FpBytes, FpLen - 1, FpLen + 1} {
			_, err := decodeFp(make([]byte, n))
			require.ErrorIsf(t, err, ErrInvalidInput, "accepted a %d-byte slot", n)
		}
	})

	t.Run("padding_must_be_zero", func(t *testing.T) {
		for i := range PadLen {
			in := slot(big.NewInt(1))
			in[i] = 1
			_, err := decodeFp(in)
			require.ErrorIsf(t, err, ErrInvalidFieldElem, "accepted padding byte %d", i)
		}
	})

	t.Run("value_must_be_below_the_modulus", func(t *testing.T) {
		// p-1 is the largest legal value and must survive unchanged.
		pMinus1 := new(big.Int).Sub(modulus, big.NewInt(1))
		below, err := decodeFp(slot(pMinus1))
		require.NoError(t, err)
		require.Equal(t, pMinus1, below.BigInt(new(big.Int)))

		// p and p+1 are not legal. Reducing them instead of refusing would
		// give 0 and 1 a second encoding apiece, and every point built on
		// them a second encoding too.
		for _, over := range []*big.Int{modulus, new(big.Int).Add(modulus, big.NewInt(1))} {
			_, err := decodeFp(slot(over))
			require.ErrorIsf(t, err, ErrInvalidFieldElem, "accepted %s", over)
		}
	})

	t.Run("zero_is_legal", func(t *testing.T) {
		e, err := decodeFp(make([]byte, FpLen))
		require.NoError(t, err)
		require.True(t, e.IsZero())
	})
}

// TestDecode_RejectsOnCurveButOutsideTheSubgroup is the classic BLS failure:
// the point satisfies the curve equation, so an on-curve check passes, but it
// lies outside the r-order subgroup where the pairing is bilinear. Accepting
// one turns a signature check into no check at all.
func TestDecode_RejectsOnCurveButOutsideTheSubgroup(t *testing.T) {
	t.Run("g1", func(t *testing.T) {
		pt := g1OffSubgroup(t)
		require.True(t, pt.IsOnCurve())
		require.False(t, pt.IsInSubGroup())

		_, err := decodeG1(encodeG1(&pt))
		require.ErrorIs(t, err, ErrPointNotInSubgrp)

		// Every operation that takes a G1 point refuses it.
		enc := encodeG1(&pt)
		for name, in := range map[string][]byte{
			"g1add":   append(bytes.Clone(enc), make([]byte, G1PointLen)...),
			"g1mul":   append(bytes.Clone(enc), make([]byte, ScalarLen)...),
			"g1msm":   append(bytes.Clone(enc), make([]byte, ScalarLen)...),
			"pairing": append(bytes.Clone(enc), make([]byte, G2PointLen)...),
		} {
			_, _, err := run[name](in, katGas)
			require.ErrorIsf(t, err, ErrPointNotInSubgrp, "%s accepted it", name)
		}
	})

	t.Run("g2", func(t *testing.T) {
		pt := g2OffSubgroup(t)
		require.True(t, pt.IsOnCurve())
		require.False(t, pt.IsInSubGroup())

		_, err := decodeG2(encodeG2(&pt))
		require.ErrorIs(t, err, ErrPointNotInSubgrp)

		enc := encodeG2(&pt)
		for name, in := range map[string][]byte{
			"g2add":   append(bytes.Clone(enc), make([]byte, G2PointLen)...),
			"g2mul":   append(bytes.Clone(enc), make([]byte, ScalarLen)...),
			"g2msm":   append(bytes.Clone(enc), make([]byte, ScalarLen)...),
			"pairing": append(make([]byte, G1PointLen), enc...),
		} {
			_, _, err := run[name](in, katGas)
			require.ErrorIsf(t, err, ErrPointNotInSubgrp, "%s accepted it", name)
		}
	})
}

// g1OffSubgroup finds a point on E(Fp) outside the r-order subgroup by
// solving the curve equation for an x that yields one; the cofactor is not 1,
// so such points exist and a random x reaches one about half the time.
func g1OffSubgroup(t *testing.T) gnark.G1Affine {
	t.Helper()
	b := new(fp.Element).SetUint64(4) // y^2 = x^3 + 4
	for i := uint64(1); i < 1000; i++ {
		var x, y2 fp.Element
		x.SetUint64(i)
		y2.Square(&x).Mul(&y2, &x).Add(&y2, b)
		if y := new(fp.Element).Sqrt(&y2); y != nil {
			pt := gnark.G1Affine{X: x, Y: *y}
			if pt.IsOnCurve() && !pt.IsInSubGroup() {
				return pt
			}
		}
	}
	t.Fatal("no G1 point outside the subgroup found")
	return gnark.G1Affine{}
}

// g2OffSubgroup does the same over the twist, y^2 = x^3 + 4(1+u).
func g2OffSubgroup(t *testing.T) gnark.G2Affine {
	t.Helper()
	var b gnark.E2
	b.A0.SetUint64(4)
	b.A1.SetUint64(4)
	for i := uint64(1); i < 1000; i++ {
		var x, y2 gnark.E2
		x.A0.SetUint64(i)
		x.A1.SetUint64(1)
		y2.Square(&x).Mul(&y2, &x).Add(&y2, &b)
		if y := new(gnark.E2).Sqrt(&y2); y != nil {
			pt := gnark.G2Affine{X: x, Y: *y}
			if pt.IsOnCurve() && !pt.IsInSubGroup() {
				return pt
			}
		}
	}
	t.Fatal("no G2 point outside the subgroup found")
	return gnark.G2Affine{}
}

// TestMSM_OutOfGas: the fee is taken before any point is decoded, so a caller
// who cannot pay for k pairs never reaches the arithmetic.
func TestMSM_OutOfGas(t *testing.T) {
	for _, tc := range []struct {
		name     string
		op       func([]byte, uint64) ([]byte, uint64, error)
		pairSize int
		gas      func(uint64) uint64
	}{
		{"g1msm", blsOps.g1MSM, G1PointLen + ScalarLen, G1MSMGas},
		{"g2msm", blsOps.g2MSM, G2PointLen + ScalarLen, G2MSMGas},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []uint64{1, 2, 5} {
				in := make([]byte, uint64(tc.pairSize)*k)
				need := tc.gas(k)

				_, remaining, err := tc.op(in, need-1)
				require.ErrorIsf(t, err, contract.ErrOutOfGas, "k=%d", k)
				require.Zero(t, remaining)

				_, remaining, err = tc.op(in, need)
				require.NoError(t, err)
				require.Zero(t, remaining)
			}
		})
	}
}

// TestOperations_RejectTrailingBytes: EIP-2537 fixes the input width of every
// fixed-size operation, so a longer body is a different query and must not
// silently produce the shorter one's answer.
func TestOperations_RejectTrailingBytes(t *testing.T) {
	_, _, g1, g2 := gnark.Generators()
	one := make([]byte, ScalarLen)
	one[ScalarLen-1] = 1

	exact := map[string][]byte{
		"g1add":   append(encodeG1(&g1), encodeG1(&g1)...),
		"g1mul":   append(encodeG1(&g1), one...),
		"g2add":   append(encodeG2(&g2), encodeG2(&g2)...),
		"g2mul":   append(encodeG2(&g2), one...),
		"g1msm":   append(encodeG1(&g1), one...),
		"g2msm":   append(encodeG2(&g2), one...),
		"pairing": append(encodeG1(&g1), encodeG2(&g2)...),
	}

	for name, in := range exact {
		t.Run(name, func(t *testing.T) {
			_, _, err := run[name](in, katGas)
			require.NoError(t, err, "the exact-width input must be accepted")

			for _, extra := range []int{1, 16, 64} {
				_, _, err := run[name](append(bytes.Clone(in), make([]byte, extra)...), katGas)
				require.Errorf(t, err, "accepted %d trailing bytes", extra)
			}
			_, _, err = run[name](in[:len(in)-1], katGas)
			require.Error(t, err, "accepted a truncated input")
		})
	}
}

// TestOperations_DoNotMutateTheirInput: a precompile is called with a slice of
// EVM memory.
func TestOperations_DoNotMutateTheirInput(t *testing.T) {
	_, _, g1, g2 := gnark.Generators()
	one := make([]byte, ScalarLen)
	one[ScalarLen-1] = 1

	for name, in := range map[string][]byte{
		"g1add":   append(encodeG1(&g1), encodeG1(&g1)...),
		"g1mul":   append(encodeG1(&g1), one...),
		"g2mul":   append(encodeG2(&g2), one...),
		"pairing": append(encodeG1(&g1), encodeG2(&g2)...),
	} {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(in)
			_, _, err := run[name](in, katGas)
			require.NoError(t, err)
			require.Equal(t, before, in)
		})
	}
}
