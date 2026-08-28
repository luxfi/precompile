// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package kzg4844 implements EIP-4844 KZG polynomial commitment precompile
// for the Lux EVM. Address: 0x0900...0014 (ZK Proofs range)
//
// Note: Ethereum standard KZG point evaluation is at 0x0a (EIP-4844).
// This extended precompile provides additional operations beyond the standard.
//
// Provides efficient blob verification using Kate-Zaverucha-Goldberg commitments
// with BLS12-381 curve. See LP-3665 for full specification.
package kzg4844

import (
	"encoding/binary"
	"errors"
	"fmt"

	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the address of the KZG4844 precompile (Lux KZG Extensions range 0xB002)
	// Note: Standard EIP-4844 point evaluation is at 0x0a
	ContractAddress = common.HexToAddress("0xB002")

	// Singleton instance
	KZG4844Precompile = &kzg4844Precompile{}

	_ contract.StatefulPrecompiledContract = &kzg4844Precompile{}

	// Trusted setup context (initialized once)
	kzgContext *gokzg4844.Context

	ErrInvalidInput       = contract.ErrInvalidInput
	ErrInvalidBlob        = errors.New("invalid blob data")
	ErrInvalidCommitment  = errors.New("invalid commitment")
	ErrInvalidProof       = errors.New("invalid proof")
	ErrVerificationFailed = errors.New("verification failed")
)

// Sizes per EIP-4844 spec
const (
	BlobSize         = 131072 // 4096 * 32 bytes
	CommitmentSize   = 48     // G1 point compressed
	ProofSize        = 48     // G1 point compressed
	FieldElementSize = 32     // BLS12-381 scalar field element
	BlobElements     = 4096   // Number of field elements per blob
)

// Operation selectors
const (
	OpBlobToCommitment  = 0x01
	OpComputeProof      = 0x02
	OpVerifyProof       = 0x03
	OpVerifyBlobProof   = 0x04
	OpBatchVerifyProofs = 0x10
)

// Gas costs aligned with EIP-4844
const (
	GasBlobToCommitment  = 50000
	GasComputeProof      = 50000
	GasVerifyProof       = 50000
	GasVerifyBlobProof   = 50000
	GasBatchVerifyBase   = 50000
	GasBatchVerifyPerAdd = 10000
)

// The trusted setup is the Ethereum KZG ceremony output embedded in
// go-kzg-4844. It either parses or it does not, identically on every node, so
// a failure here is a broken build rather than a runtime condition: a node
// that cannot build the setup cannot answer a single KZG call, and starting it
// only to fail every request hides that.
func init() {
	ctx, err := gokzg4844.NewContext4096Secure()
	if err != nil {
		panic("kzg4844: trusted setup failed to load: " + err.Error())
	}
	kzgContext = ctx
}

type kzg4844Precompile struct{}

// Address returns the address of the KZG4844 precompile
func (p *kzg4844Precompile) Address() common.Address {
	return ContractAddress
}

// RequiredGas calculates gas for KZG4844 operations
func (p *kzg4844Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}

	op := input[0]

	switch op {
	case OpBlobToCommitment:
		return GasBlobToCommitment

	case OpComputeProof:
		return GasComputeProof

	case OpVerifyProof:
		return GasVerifyProof

	case OpVerifyBlobProof:
		return GasVerifyBlobProof

	case OpBatchVerifyProofs:
		if len(input) < 3 {
			return GasBatchVerifyBase
		}
		numProofs := int(binary.BigEndian.Uint16(input[1:3]))
		return GasBatchVerifyBase + uint64(numProofs)*GasBatchVerifyPerAdd

	default:
		return 0
	}
}

// Run executes the KZG4844 precompile
func (p *kzg4844Precompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	if len(input) < 1 {
		return nil, remainingGas, ErrInvalidInput
	}

	op := input[0]

	var result []byte

	switch op {
	case OpBlobToCommitment:
		result, err = p.blobToCommitment(input[1:])
	case OpComputeProof:
		result, err = p.computeProof(input[1:])
	case OpVerifyProof:
		result, err = p.verifyProof(input[1:])
	case OpVerifyBlobProof:
		result, err = p.verifyBlobProof(input[1:])
	case OpBatchVerifyProofs:
		result, err = p.batchVerifyProofs(input[1:])
	default:
		err = fmt.Errorf("unsupported operation: 0x%02x", op)
	}

	if err != nil {
		return nil, remainingGas, err
	}

	return result, remainingGas, nil
}

// blobToCommitment computes the KZG commitment for a blob
func (p *kzg4844Precompile) blobToCommitment(input []byte) ([]byte, error) {
	if len(input) != BlobSize {
		return nil, ErrInvalidBlob
	}

	// CPU is the single source of truth: go-kzg-4844 against the canonical
	// EIP-4844 trusted setup. The accel commitment path passed an EMPTY SRS
	// tensor and let "the GPU backend use its own embedded trusted setup" --
	// a commitment under a DIFFERENT (and unverifiable) SRS is not just a
	// CPU/GPU consensus split, it breaks the KZG binding the chain relies on.
	// Re-introducing accel requires committing against the SAME trusted setup,
	// proven bit-identical to BlobToKZGCommitment.
	var blob gokzg4844.Blob
	copy(blob[:], input[:BlobSize])

	commitment, err := kzgContext.BlobToKZGCommitment(&blob, 0)
	if err != nil {
		return nil, fmt.Errorf("commitment failed: %w", err)
	}

	return commitment[:], nil
}

// computeProof computes a KZG proof for a blob at a given point
func (p *kzg4844Precompile) computeProof(input []byte) ([]byte, error) {
	if len(input) != BlobSize+FieldElementSize {
		return nil, ErrInvalidInput
	}

	var blob gokzg4844.Blob
	copy(blob[:], input[:BlobSize])

	// Parse evaluation point
	var z gokzg4844.Scalar
	copy(z[:], input[BlobSize:BlobSize+FieldElementSize])

	// Compute proof
	proof, y, err := kzgContext.ComputeKZGProof(&blob, z, 0)
	if err != nil {
		return nil, fmt.Errorf("proof computation failed: %w", err)
	}

	// Return proof || y
	result := make([]byte, ProofSize+FieldElementSize)
	copy(result, proof[:])
	copy(result[ProofSize:], y[:])

	return result, nil
}

// verifyProof verifies a KZG proof
func (p *kzg4844Precompile) verifyProof(input []byte) ([]byte, error) {
	// commitment (48) + z (32) + y (32) + proof (48)
	expectedLen := CommitmentSize + FieldElementSize + FieldElementSize + ProofSize
	if len(input) != expectedLen {
		return nil, ErrInvalidInput
	}

	var commitment gokzg4844.KZGCommitment
	copy(commitment[:], input[:CommitmentSize])

	var z, y gokzg4844.Scalar
	copy(z[:], input[CommitmentSize:CommitmentSize+FieldElementSize])
	copy(y[:], input[CommitmentSize+FieldElementSize:CommitmentSize+2*FieldElementSize])

	var proof gokzg4844.KZGProof
	copy(proof[:], input[CommitmentSize+2*FieldElementSize:expectedLen])

	if err := checkOpening(commitment, z, y, proof); err != nil {
		return nil, err
	}
	if err := kzgContext.VerifyKZGProof(commitment, z, y, proof); err != nil {
		return []byte{0x00}, nil
	}
	return []byte{0x01}, nil
}

// checkOpening reports whether each field of an opening is a canonical
// encoding: a point in the r-order subgroup, a scalar below the modulus.
//
// A malformed encoding and a proof that does not verify are different answers.
// Reporting both as a zero tells a caller their prover cheated when in fact
// their calldata was mangled, and hides the mistake behind the one value a
// verifier is expected to return.
func checkOpening(commitment gokzg4844.KZGCommitment, z, y gokzg4844.Scalar, proof gokzg4844.KZGProof) error {
	if _, err := gokzg4844.DeserializeKZGCommitment(commitment); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCommitment, err)
	}
	if _, err := gokzg4844.DeserializeKZGProof(proof); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	for _, scalar := range []gokzg4844.Scalar{z, y} {
		if _, err := gokzg4844.DeserializeScalar(scalar); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidInput, err)
		}
	}
	return nil
}

// verifyBlobProof verifies a blob KZG proof (EIP-4844 point_evaluation_precompile)
func (p *kzg4844Precompile) verifyBlobProof(input []byte) ([]byte, error) {
	// blob (131072) + commitment (48) + proof (48)
	expectedLen := BlobSize + CommitmentSize + ProofSize
	if len(input) != expectedLen {
		return nil, ErrInvalidInput
	}

	var blob gokzg4844.Blob
	copy(blob[:], input[:BlobSize])

	var commitment gokzg4844.KZGCommitment
	copy(commitment[:], input[BlobSize:BlobSize+CommitmentSize])

	var proof gokzg4844.KZGProof
	copy(proof[:], input[BlobSize+CommitmentSize:expectedLen])

	if _, err := gokzg4844.DeserializeBlob(&blob); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBlob, err)
	}
	if _, err := gokzg4844.DeserializeKZGCommitment(commitment); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCommitment, err)
	}
	if _, err := gokzg4844.DeserializeKZGProof(proof); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}
	if err := kzgContext.VerifyBlobKZGProof(&blob, commitment, proof); err != nil {
		return []byte{0x00}, nil
	}
	return []byte{0x01}, nil
}

// batchVerifyProofs verifies multiple KZG proofs efficiently
func (p *kzg4844Precompile) batchVerifyProofs(input []byte) ([]byte, error) {
	if len(input) < 2 {
		return nil, ErrInvalidInput
	}

	numProofs := int(binary.BigEndian.Uint16(input[:2]))

	// Each proof set: commitment (48) + z (32) + y (32) + proof (48) = 160 bytes
	proofSetSize := CommitmentSize + FieldElementSize + FieldElementSize + ProofSize
	if len(input) != 2+numProofs*proofSetSize {
		return nil, ErrInvalidInput
	}
	if numProofs == 0 {
		return []byte{0x01}, nil
	}

	offset := 2

	commitments := make([]gokzg4844.KZGCommitment, numProofs)
	zs := make([]gokzg4844.Scalar, numProofs)
	ys := make([]gokzg4844.Scalar, numProofs)
	proofs := make([]gokzg4844.KZGProof, numProofs)

	for i := range numProofs {
		copy(commitments[i][:], input[offset:offset+CommitmentSize])
		offset += CommitmentSize

		copy(zs[i][:], input[offset:offset+FieldElementSize])
		offset += FieldElementSize

		copy(ys[i][:], input[offset:offset+FieldElementSize])
		offset += FieldElementSize

		copy(proofs[i][:], input[offset:offset+ProofSize])
		offset += ProofSize
	}

	// Every opening is checked for a canonical encoding before any of them is
	// verified, so one malformed member cannot be read as a failed proof.
	for i := range numProofs {
		if err := checkOpening(commitments[i], zs[i], ys[i], proofs[i]); err != nil {
			return nil, err
		}
	}
	for i := range numProofs {
		if err := kzgContext.VerifyKZGProof(commitments[i], zs[i], ys[i], proofs[i]); err != nil {
			return []byte{0x00}, nil
		}
	}

	return []byte{0x01}, nil
}
