// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"bytes"
	"encoding/binary"
	"testing"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// opWidths is the exact body width every operation accepts, excluding the
// selector. EIP-4844 structures are fixed size, so a longer body is a
// different query and must not silently answer the shorter one.
var opWidths = map[byte]int{
	OpBlobToCommitment: BlobSize,
	OpComputeProof:     BlobSize + FieldElementSize,
	OpVerifyProof:      CommitmentSize + 2*FieldElementSize + ProofSize,
	OpVerifyBlobProof:  BlobSize + CommitmentSize + ProofSize,
}

func runOp(input []byte, gas uint64) ([]byte, uint64, error) {
	return KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, input, gas, false)
}

// TestWidth_EveryOperationRequiresItsExactBody drives each operation with a
// body one byte short and one byte long. Both must be refused.
func TestWidth_EveryOperationRequiresItsExactBody(t *testing.T) {
	for op, width := range opWidths {
		for _, n := range []int{0, 1, width - 1, width + 1, 2 * width} {
			input := append([]byte{op}, make([]byte, n)...)
			out, _, err := runOp(input, KZG4844Precompile.RequiredGas(input))
			require.Errorf(t, err, "op 0x%02x accepted a %d-byte body (wants %d)", op, n, width)
			require.Nil(t, out)
		}
	}
}

// TestWidth_BatchDeclaredCountMustMatchTheBody: the two-byte count is what the
// caller is charged for, so a body that does not carry exactly that many
// openings is refused rather than truncated or padded.
func TestWidth_BatchDeclaredCountMustMatchTheBody(t *testing.T) {
	set := CommitmentSize + 2*FieldElementSize + ProofSize

	batch := func(declared int, bodySets int) []byte {
		input := make([]byte, 3+bodySets*set)
		input[0] = OpBatchVerifyProofs
		binary.BigEndian.PutUint16(input[1:3], uint16(declared))
		return input
	}

	// Declared more than supplied, and fewer.
	for _, tc := range []struct{ declared, supplied int }{{1, 0}, {2, 1}, {1, 2}, {0, 1}} {
		input := batch(tc.declared, tc.supplied)
		out, _, err := runOp(input, KZG4844Precompile.RequiredGas(input))
		require.Errorf(t, err, "declared=%d supplied=%d was accepted", tc.declared, tc.supplied)
		require.Nil(t, out)
	}

	// A count with no openings at all is vacuously true, but only when the
	// body carries nothing: trailing bytes must not hide inside it.
	empty := batch(0, 0)
	out, _, err := runOp(empty, KZG4844Precompile.RequiredGas(empty))
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, out)

	short := []byte{OpBatchVerifyProofs, 0x00}
	out, _, err = runOp(short, KZG4844Precompile.RequiredGas(short))
	require.Error(t, err)
	require.Nil(t, out)
}

// TestGas_BatchIsPricedByTheDeclaredCount: the fee is taken before the body is
// read, so it has to come from the count in the header.
func TestGas_BatchIsPricedByTheDeclaredCount(t *testing.T) {
	header := func(n uint16) []byte {
		in := []byte{OpBatchVerifyProofs, 0, 0}
		binary.BigEndian.PutUint16(in[1:3], n)
		return in
	}

	prev := uint64(0)
	for _, n := range []uint16{0, 1, 2, 16, 1024} {
		got := KZG4844Precompile.RequiredGas(header(n))
		require.Equal(t, uint64(GasBatchVerifyBase)+uint64(n)*GasBatchVerifyPerAdd, got)
		if n > 0 {
			require.Greater(t, got, prev)
		}
		prev = got
	}

	// A header too short to carry a count still costs the base.
	require.Equal(t, uint64(GasBatchVerifyBase), KZG4844Precompile.RequiredGas([]byte{OpBatchVerifyProofs}))
	require.Equal(t, uint64(GasBatchVerifyBase), KZG4844Precompile.RequiredGas([]byte{OpBatchVerifyProofs, 0x00}))
}

// TestGas_NoSuccessfulCallIsFree: the unknown selectors do nothing, and the
// contract for them is an error -- never an empty success with the gas
// returned, which the caller could repeat without cost.
func TestGas_NoSuccessfulCallIsFree(t *testing.T) {
	const supplied = 10_000_000

	known := map[byte]bool{
		OpBlobToCommitment: true, OpComputeProof: true, OpVerifyProof: true,
		OpVerifyBlobProof: true, OpBatchVerifyProofs: true,
	}

	for op := range 256 {
		input := []byte{byte(op)}
		out, remaining, err := runOp(input, supplied)
		if !known[byte(op)] {
			require.Errorf(t, err, "selector 0x%02x is not an operation but succeeded", op)
			require.Nil(t, out)
			continue
		}
		if err == nil {
			require.Lessf(t, remaining, uint64(supplied), "selector 0x%02x succeeded for free", op)
		}
	}

	out, remaining, err := runOp(nil, supplied)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Nil(t, out)
	require.Equal(t, uint64(supplied), remaining)
}

// TestCheckOpening_RejectsNonCanonicalScalars: z and y are field elements, so
// a 32-byte value at or above the BLS12-381 scalar modulus is not one, however
// well-formed the points beside it are.
func TestCheckOpening_RejectsNonCanonicalScalars(t *testing.T) {
	// The compressed encoding of the G1 point at infinity: a valid point, so
	// the only thing left to reject is a scalar.
	var (
		commitment gokzg4844.KZGCommitment
		proof      gokzg4844.KZGProof
	)
	commitment[0], proof[0] = 0xc0, 0xc0

	var zero, modulus gokzg4844.Scalar
	copy(modulus[:], blsModulusBytes[:])

	require.NoError(t, checkOpening(commitment, zero, zero, proof))

	for name, bad := range map[string][2]gokzg4844.Scalar{
		"z_is_the_modulus": {modulus, zero},
		"y_is_the_modulus": {zero, modulus},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, checkOpening(commitment, bad[0], bad[1], proof), ErrInvalidInput)
		})
	}

	// And through the precompile.
	input := []byte{OpVerifyProof}
	input = append(input, commitment[:]...)
	input = append(input, modulus[:]...)
	input = append(input, bytes.Repeat([]byte{0}, FieldElementSize)...)
	input = append(input, proof[:]...)

	out, _, err := runOp(input, KZG4844Precompile.RequiredGas(input))
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Nil(t, out)
}
