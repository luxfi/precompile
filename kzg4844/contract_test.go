// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestKZG4844Precompile_Address(t *testing.T) {
	// KZG4844 in ZK Proofs range: 0x0900...0014
	expectedAddr := common.HexToAddress("0x000000000000000000000000000000000000B002")
	require.Equal(t, expectedAddr, ContractAddress)
	require.Equal(t, expectedAddr, KZG4844Precompile.Address())
}

func TestKZG4844_ContextInitialized(t *testing.T) {
	require.NotNil(t, kzgContext, "KZG context should be initialized")
}

func TestKZG4844_BlobToCommitment(t *testing.T) {
	// Create a valid blob (4096 field elements, each < field modulus)
	blob := createValidBlob(t)

	input := make([]byte, 1+BlobSize)
	input[0] = OpBlobToCommitment
	copy(input[1:], blob[:])

	gas := KZG4844Precompile.RequiredGas(input)
	require.Equal(t, uint64(GasBlobToCommitment), gas)

	commitment, remainingGas, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, CommitmentSize, len(commitment))
}

func TestKZG4844_ComputeProof(t *testing.T) {
	blob := createValidBlob(t)

	// Create evaluation point (z)
	z := make([]byte, FieldElementSize)
	z[31] = 0x42 // Simple non-zero point

	input := make([]byte, 1+BlobSize+FieldElementSize)
	input[0] = OpComputeProof
	copy(input[1:], blob[:])
	copy(input[1+BlobSize:], z)

	gas := KZG4844Precompile.RequiredGas(input)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, ProofSize+FieldElementSize, len(result)) // proof + y
}

func TestKZG4844_VerifyProof(t *testing.T) {
	blob := createValidBlob(t)

	// First compute commitment
	commitmentInput := make([]byte, 1+BlobSize)
	commitmentInput[0] = OpBlobToCommitment
	copy(commitmentInput[1:], blob[:])

	commitment, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		commitmentInput,
		GasBlobToCommitment,
		false,
	)
	require.NoError(t, err)

	// Compute proof
	z := make([]byte, FieldElementSize)
	z[31] = 0x42

	proofInput := make([]byte, 1+BlobSize+FieldElementSize)
	proofInput[0] = OpComputeProof
	copy(proofInput[1:], blob[:])
	copy(proofInput[1+BlobSize:], z)

	proofResult, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		proofInput,
		GasComputeProof,
		false,
	)
	require.NoError(t, err)

	proof := proofResult[:ProofSize]
	y := proofResult[ProofSize:]

	// Now verify
	verifyInput := make([]byte, 1+CommitmentSize+FieldElementSize+FieldElementSize+ProofSize)
	verifyInput[0] = OpVerifyProof
	offset := 1
	copy(verifyInput[offset:], commitment)
	offset += CommitmentSize
	copy(verifyInput[offset:], z)
	offset += FieldElementSize
	copy(verifyInput[offset:], y)
	offset += FieldElementSize
	copy(verifyInput[offset:], proof)

	gas := KZG4844Precompile.RequiredGas(verifyInput)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)

	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, result) // Valid
}

func TestKZG4844_VerifyProof_Invalid(t *testing.T) {
	blob := createValidBlob(t)

	// Compute commitment
	commitmentInput := make([]byte, 1+BlobSize)
	commitmentInput[0] = OpBlobToCommitment
	copy(commitmentInput[1:], blob[:])

	commitment, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		commitmentInput,
		GasBlobToCommitment,
		false,
	)
	require.NoError(t, err)

	// Compute proof
	z := make([]byte, FieldElementSize)
	z[31] = 0x42

	proofInput := make([]byte, 1+BlobSize+FieldElementSize)
	proofInput[0] = OpComputeProof
	copy(proofInput[1:], blob[:])
	copy(proofInput[1+BlobSize:], z)

	proofResult, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		proofInput,
		GasComputeProof,
		false,
	)
	require.NoError(t, err)

	proof := proofResult[:ProofSize]
	y := proofResult[ProofSize:]

	// Corrupt the proof
	proof[0] ^= 0xFF

	verifyInput := make([]byte, 1+CommitmentSize+FieldElementSize+FieldElementSize+ProofSize)
	verifyInput[0] = OpVerifyProof
	offset := 1
	copy(verifyInput[offset:], commitment)
	offset += CommitmentSize
	copy(verifyInput[offset:], z)
	offset += FieldElementSize
	copy(verifyInput[offset:], y)
	offset += FieldElementSize
	copy(verifyInput[offset:], proof)

	gas := KZG4844Precompile.RequiredGas(verifyInput)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)

	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, result) // Invalid
}

func TestKZG4844_VerifyBlobProof(t *testing.T) {
	blob := createValidBlob(t)

	// Compute commitment
	commitmentInput := make([]byte, 1+BlobSize)
	commitmentInput[0] = OpBlobToCommitment
	copy(commitmentInput[1:], blob[:])

	commitment, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		commitmentInput,
		GasBlobToCommitment,
		false,
	)
	require.NoError(t, err)

	// Compute blob proof using go-kzg-4844 directly
	var kzgBlob gokzg4844.Blob
	copy(kzgBlob[:], blob[:])

	var kzgCommitment gokzg4844.KZGCommitment
	copy(kzgCommitment[:], commitment)

	proof, err := kzgContext.ComputeBlobKZGProof(&kzgBlob, kzgCommitment, 0)
	require.NoError(t, err)

	// Verify blob proof
	verifyInput := make([]byte, 1+BlobSize+CommitmentSize+ProofSize)
	verifyInput[0] = OpVerifyBlobProof
	offset := 1
	copy(verifyInput[offset:], blob[:])
	offset += BlobSize
	copy(verifyInput[offset:], commitment)
	offset += CommitmentSize
	copy(verifyInput[offset:], proof[:])

	gas := KZG4844Precompile.RequiredGas(verifyInput)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)

	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, result) // Valid
}

func TestKZG4844_BatchVerifyProofs(t *testing.T) {
	numProofs := 2
	proofSets := make([][]byte, numProofs)

	for i := 0; i < numProofs; i++ {
		blob := createValidBlob(t)

		// Compute commitment
		commitmentInput := make([]byte, 1+BlobSize)
		commitmentInput[0] = OpBlobToCommitment
		copy(commitmentInput[1:], blob[:])

		commitment, _, err := KZG4844Precompile.Run(
			nil,
			common.Address{},
			ContractAddress,
			commitmentInput,
			GasBlobToCommitment,
			false,
		)
		require.NoError(t, err)

		// Compute proof
		z := make([]byte, FieldElementSize)
		z[31] = byte(i + 1)

		proofInput := make([]byte, 1+BlobSize+FieldElementSize)
		proofInput[0] = OpComputeProof
		copy(proofInput[1:], blob[:])
		copy(proofInput[1+BlobSize:], z)

		proofResult, _, err := KZG4844Precompile.Run(
			nil,
			common.Address{},
			ContractAddress,
			proofInput,
			GasComputeProof,
			false,
		)
		require.NoError(t, err)

		// Build proof set: commitment + z + y + proof
		proofSet := make([]byte, CommitmentSize+FieldElementSize+FieldElementSize+ProofSize)
		copy(proofSet, commitment)
		copy(proofSet[CommitmentSize:], z)
		copy(proofSet[CommitmentSize+FieldElementSize:], proofResult[ProofSize:]) // y
		copy(proofSet[CommitmentSize+2*FieldElementSize:], proofResult[:ProofSize])

		proofSets[i] = proofSet
	}

	// Build batch verify input
	input := make([]byte, 3)
	input[0] = OpBatchVerifyProofs
	binary.BigEndian.PutUint16(input[1:], uint16(numProofs))

	for _, proofSet := range proofSets {
		input = append(input, proofSet...)
	}

	gas := KZG4844Precompile.RequiredGas(input)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, result) // All valid
}

func TestKZG4844_BatchVerifyProofs_Empty(t *testing.T) {
	input := make([]byte, 3)
	input[0] = OpBatchVerifyProofs
	binary.BigEndian.PutUint16(input[1:], 0) // 0 proofs

	gas := KZG4844Precompile.RequiredGas(input)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, result) // Empty batch is valid
}

func TestKZG4844_ComputeChallenge(t *testing.T) {
	commitment := make([]byte, CommitmentSize)
	rand.Read(commitment)

	input := make([]byte, 1+CommitmentSize)
	input[0] = OpComputeChallenge
	copy(input[1:], commitment)

	gas := KZG4844Precompile.RequiredGas(input)

	result, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, FieldElementSize, len(result))
}

func TestKZG4844_InvalidOperation(t *testing.T) {
	input := []byte{0xFF} // Invalid op

	gas := KZG4844Precompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas)

	_, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		1000000,
		false,
	)
	require.Error(t, err)
}

func TestKZG4844_InputTooShort(t *testing.T) {
	input := []byte{OpBlobToCommitment} // Missing blob

	_, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		GasBlobToCommitment,
		false,
	)
	require.Error(t, err)
}

func TestKZG4844_OutOfGas(t *testing.T) {
	blob := createValidBlob(t)

	input := make([]byte, 1+BlobSize)
	input[0] = OpBlobToCommitment
	copy(input[1:], blob[:])

	_, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		100, // Insufficient gas
		false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

func TestKZG4844_EmptyInput(t *testing.T) {
	_, _, err := KZG4844Precompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		[]byte{},
		100000,
		false,
	)
	require.Error(t, err)
}

func TestKZG4844_RequiredGas(t *testing.T) {
	tests := []struct {
		name string
		op   byte
		gas  uint64
	}{
		{"BlobToCommitment", OpBlobToCommitment, GasBlobToCommitment},
		{"ComputeProof", OpComputeProof, GasComputeProof},
		{"VerifyProof", OpVerifyProof, GasVerifyProof},
		{"VerifyBlobProof", OpVerifyBlobProof, GasVerifyBlobProof},
		{"ComputeChallenge", OpComputeChallenge, GasComputeChallenge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte{tt.op}, make([]byte, 200)...)
			gas := KZG4844Precompile.RequiredGas(input)
			require.Equal(t, tt.gas, gas)
		})
	}
}

func TestKZG4844_BatchVerifyGas(t *testing.T) {
	tests := []struct {
		numProofs int
		expected  uint64
	}{
		{1, GasBatchVerifyBase + 1*GasBatchVerifyPerAdd},
		{2, GasBatchVerifyBase + 2*GasBatchVerifyPerAdd},
		{5, GasBatchVerifyBase + 5*GasBatchVerifyPerAdd},
	}

	for _, tt := range tests {
		input := make([]byte, 3)
		input[0] = OpBatchVerifyProofs
		binary.BigEndian.PutUint16(input[1:], uint16(tt.numProofs))

		gas := KZG4844Precompile.RequiredGas(input)
		require.Equal(t, tt.expected, gas)
	}
}

// Helper functions

func createValidBlob(t testing.TB) []byte {
	t.Helper()

	// Create blob with valid field elements (each < BLS12-381 modulus)
	blob := make([]byte, BlobSize)

	// Fill with small random values that are definitely in field
	for i := 0; i < BlobElements; i++ {
		offset := i * FieldElementSize
		// Leave first 16 bytes as zero, set small random value in lower bytes
		// This ensures we're well under the field modulus
		randBytes := make([]byte, 16)
		rand.Read(randBytes)
		copy(blob[offset+16:offset+32], randBytes)
	}

	return blob
}

// Benchmarks

func BenchmarkKZG4844_BlobToCommitment(b *testing.B) {
	blob := make([]byte, BlobSize)
	for i := 0; i < BlobElements; i++ {
		offset := i * FieldElementSize
		blob[offset+31] = byte(i % 256)
	}

	input := make([]byte, 1+BlobSize)
	input[0] = OpBlobToCommitment
	copy(input[1:], blob)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, input, GasBlobToCommitment, false)
	}
}

func BenchmarkKZG4844_ComputeProof(b *testing.B) {
	blob := make([]byte, BlobSize)
	for i := 0; i < BlobElements; i++ {
		offset := i * FieldElementSize
		blob[offset+31] = byte(i % 256)
	}

	z := make([]byte, FieldElementSize)
	z[31] = 0x42

	input := make([]byte, 1+BlobSize+FieldElementSize)
	input[0] = OpComputeProof
	copy(input[1:], blob)
	copy(input[1+BlobSize:], z)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, input, GasComputeProof, false)
	}
}

func BenchmarkKZG4844_VerifyProof(b *testing.B) {
	blob := make([]byte, BlobSize)
	for i := 0; i < BlobElements; i++ {
		offset := i * FieldElementSize
		blob[offset+31] = byte(i % 256)
	}

	// Compute commitment
	commitmentInput := make([]byte, 1+BlobSize)
	commitmentInput[0] = OpBlobToCommitment
	copy(commitmentInput[1:], blob)

	commitment, _, _ := KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, commitmentInput, GasBlobToCommitment, false)

	// Compute proof
	z := make([]byte, FieldElementSize)
	z[31] = 0x42

	proofInput := make([]byte, 1+BlobSize+FieldElementSize)
	proofInput[0] = OpComputeProof
	copy(proofInput[1:], blob)
	copy(proofInput[1+BlobSize:], z)

	proofResult, _, _ := KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, proofInput, GasComputeProof, false)

	proof := proofResult[:ProofSize]
	y := proofResult[ProofSize:]

	verifyInput := make([]byte, 1+CommitmentSize+FieldElementSize+FieldElementSize+ProofSize)
	verifyInput[0] = OpVerifyProof
	offset := 1
	copy(verifyInput[offset:], commitment)
	offset += CommitmentSize
	copy(verifyInput[offset:], z)
	offset += FieldElementSize
	copy(verifyInput[offset:], y)
	offset += FieldElementSize
	copy(verifyInput[offset:], proof)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = KZG4844Precompile.Run(nil, common.Address{}, ContractAddress, verifyInput, GasVerifyProof, false)
	}
}
