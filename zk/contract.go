// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// Note: ErrInvalidPublicInputs is defined in types.go
	ErrInvalidInput       = errors.New("invalid zk input")
	ErrInvalidOperation   = errors.New("invalid operation selector")
	ErrInvalidProofLength = errors.New("invalid proof length")
	ErrVerificationFailed = errors.New("proof verification failed")
	ErrUnknownProofSystem = errors.New("unknown proof system")
)

// Operation selectors (first byte of input)
const (
	OpVerifyGroth16    = 0x01 // Verify Groth16 proof
	OpVerifyPLONK      = 0x02 // Verify PLONK proof
	OpVerifyFflonk     = 0x03 // Verify fflonk proof
	OpVerifyHalo2      = 0x04 // Verify Halo2 proof
	OpVerifyKZG        = 0x10 // Verify KZG commitment
	OpVerifyIPA        = 0x12 // Verify IPA commitment
	OpVerifyRangeProof = 0x23 // Verify Bulletproof range proof
	OpVerifyNullifier  = 0x21 // Verify nullifier
	OpVerifyCommitment = 0x22 // Verify Pedersen commitment
	OpVerifyBatch      = 0x30 // Verify batch of proofs
)

// Gas costs
const (
	GasGroth16Base    = 150000 // Base cost for Groth16
	GasPLONKBase      = 200000 // Base cost for PLONK
	GasFflonkBase     = 180000 // Base cost for fflonk
	GasHalo2Base      = 250000 // Base cost for Halo2
	GasKZGBase        = 50000  // Base cost for KZG
	GasIPABase        = 75000  // Base cost for IPA
	GasRangeProofBase = 30000  // Base cost for range proof
	GasNullifierBase  = 10000  // Base cost for nullifier check
	GasCommitmentBase = 20000  // Base cost for commitment
	GasPerPublicInput = 1000   // Per public input element
	GasPerBatchProof  = 50000  // Per proof in batch
)

type zkVerifyPrecompile struct {
	verifier *ZKVerifier
}

// Address returns the precompile address
func (p *zkVerifyPrecompile) Address() common.Address {
	return ZKVerifyContractAddress
}

// RequiredGas calculates gas for ZK operations
func (p *zkVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}

	op := input[0]

	switch op {
	case OpVerifyGroth16:
		publicInputs := countPublicInputs(input)
		return GasGroth16Base + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyPLONK:
		publicInputs := countPublicInputs(input)
		return GasPLONKBase + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyFflonk:
		publicInputs := countPublicInputs(input)
		return GasFflonkBase + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyHalo2:
		publicInputs := countPublicInputs(input)
		return GasHalo2Base + uint64(publicInputs)*GasPerPublicInput

	case OpVerifyKZG:
		return GasKZGBase

	case OpVerifyIPA:
		return GasIPABase

	case OpVerifyRangeProof:
		return GasRangeProofBase

	case OpVerifyNullifier:
		return GasNullifierBase

	case OpVerifyCommitment:
		return GasCommitmentBase

	case OpVerifyBatch:
		if len(input) < 5 {
			return 0
		}
		numProofs := binary.BigEndian.Uint32(input[1:5])
		return uint64(numProofs) * GasPerBatchProof

	default:
		return 0
	}
}

// countPublicInputs extracts number of public inputs from encoded data
func countPublicInputs(input []byte) int {
	if len(input) < 5 {
		return 0
	}
	// Format: [1 byte op][4 bytes num_public_inputs][...]
	return int(binary.BigEndian.Uint32(input[1:5]))
}

// Run executes the ZK verify precompile
func (p *zkVerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	// Calculate required gas
	requiredGas := p.RequiredGas(input)
	if suppliedGas < requiredGas {
		return nil, 0, contract.ErrOutOfGas
	}
	remainingGas = suppliedGas - requiredGas

	if len(input) < 1 {
		return nil, remainingGas, ErrInvalidInput
	}

	op := input[0]
	data := input[1:]

	switch op {
	case OpVerifyGroth16:
		valid, err := p.verifyGroth16(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyPLONK:
		valid, err := p.verifyPLONK(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyFflonk:
		valid, err := p.verifyFflonk(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyHalo2:
		valid, err := p.verifyHalo2(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyKZG:
		valid, err := p.verifyKZG(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyIPA:
		valid, err := p.verifyIPA(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyRangeProof:
		valid, err := p.verifyRangeProof(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyNullifier:
		valid, err := p.verifyNullifier(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyCommitment:
		valid, err := p.verifyCommitment(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	case OpVerifyBatch:
		valid, err := p.verifyBatch(data)
		if err != nil {
			return nil, remainingGas, err
		}
		return encodeBool(valid), remainingGas, nil

	default:
		return nil, remainingGas, ErrInvalidOperation
	}
}

// encodeBool encodes a boolean as 32-byte EVM word
func encodeBool(b bool) []byte {
	result := make([]byte, 32)
	if b {
		result[31] = 1
	}
	return result
}

// verifyGroth16 verifies a Groth16 proof
func (p *zkVerifyPrecompile) verifyGroth16(data []byte) (bool, error) {
	if len(data) < 4 {
		return false, ErrInvalidInput
	}

	// Parse public inputs count
	numInputs := binary.BigEndian.Uint32(data[:4])
	expectedLen := 4 + int(numInputs)*32 + 256 // inputs + proof (a,b,c points)

	if len(data) < expectedLen {
		return false, ErrInvalidProofLength
	}

	// For now, return true for valid format (actual verification via Metal/CGO)
	// TODO: Call into luxcpp/crypto for actual verification
	return true, nil
}

// verifyPLONK verifies a PLONK proof
func (p *zkVerifyPrecompile) verifyPLONK(data []byte) (bool, error) {
	if len(data) < 4 {
		return false, ErrInvalidInput
	}

	// TODO: Implement PLONK verification
	return true, nil
}

// verifyFflonk verifies an fflonk proof
func (p *zkVerifyPrecompile) verifyFflonk(data []byte) (bool, error) {
	if len(data) < 4 {
		return false, ErrInvalidInput
	}

	// TODO: Implement fflonk verification
	return true, nil
}

// verifyHalo2 verifies a Halo2 proof
func (p *zkVerifyPrecompile) verifyHalo2(data []byte) (bool, error) {
	if len(data) < 4 {
		return false, ErrInvalidInput
	}

	// TODO: Implement Halo2 verification
	return true, nil
}

// verifyKZG verifies a KZG commitment
func (p *zkVerifyPrecompile) verifyKZG(data []byte) (bool, error) {
	if len(data) < 96 { // commitment + proof + point
		return false, ErrInvalidInput
	}

	// TODO: Implement KZG verification via EIP-4844 precompile
	return true, nil
}

// verifyIPA verifies an Inner Product Argument
func (p *zkVerifyPrecompile) verifyIPA(data []byte) (bool, error) {
	if len(data) < 64 {
		return false, ErrInvalidInput
	}

	// TODO: Implement IPA verification
	return true, nil
}

// verifyRangeProof verifies a Bulletproof range proof
func (p *zkVerifyPrecompile) verifyRangeProof(data []byte) (bool, error) {
	if len(data) < 64 {
		return false, ErrInvalidInput
	}

	// TODO: Implement Bulletproof verification
	return true, nil
}

// verifyNullifier checks if a nullifier has been used
func (p *zkVerifyPrecompile) verifyNullifier(data []byte) (bool, error) {
	if len(data) < 32 {
		return false, ErrInvalidInput
	}

	// Check nullifier hasn't been spent
	// TODO: Query nullifier set from state
	return true, nil
}

// verifyCommitment verifies a Pedersen commitment
func (p *zkVerifyPrecompile) verifyCommitment(data []byte) (bool, error) {
	if len(data) < 96 { // commitment + value + blinding
		return false, ErrInvalidInput
	}

	// TODO: Implement Pedersen commitment verification
	return true, nil
}

// verifyBatch verifies a batch of proofs
func (p *zkVerifyPrecompile) verifyBatch(data []byte) (bool, error) {
	if len(data) < 4 {
		return false, ErrInvalidInput
	}

	numProofs := binary.BigEndian.Uint32(data[:4])
	if numProofs == 0 {
		return false, ErrInvalidInput
	}

	// TODO: Implement batch verification
	return true, nil
}
