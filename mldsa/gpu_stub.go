//go:build !gpu

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractMLDSABatchVerifyAddress is the address of the ML-DSA batch verify precompile
	ContractMLDSABatchVerifyAddress = common.HexToAddress("0x0200000000000000000000000000000000000016")

	// Singleton instance for batch verification
	MLDSABatchVerifyPrecompile = &mldsaBatchVerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &mldsaBatchVerifyPrecompile{}
)

// Batch verification gas costs
const (
	MLDSABatchVerifyBaseGas     uint64 = 50_000 // Fixed overhead
	MLDSABatchVerifyPerSigGas44 uint64 = 50_000 // Per-sig cost for ML-DSA-44
	MLDSABatchVerifyPerSigGas65 uint64 = 65_000 // Per-sig cost for ML-DSA-65
	MLDSABatchVerifyPerSigGas87 uint64 = 85_000 // Per-sig cost for ML-DSA-87
	MLDSABatchVerifyPerByteGas  uint64 = 5      // Per message byte
)

type mldsaBatchVerifyPrecompile struct{}

// Address returns the address of the batch verify precompile
func (p *mldsaBatchVerifyPrecompile) Address() common.Address {
	return ContractMLDSABatchVerifyAddress
}

// RequiredGas calculates gas for batch verification
func (p *mldsaBatchVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 3 {
		return MLDSABatchVerifyBaseGas
	}

	mode := input[0]
	count := uint64(input[1])<<8 | uint64(input[2])
	if count == 0 {
		return MLDSABatchVerifyBaseGas
	}

	var perSigGas uint64
	switch mode {
	case ModeMLDSA44:
		perSigGas = MLDSABatchVerifyPerSigGas44
	case ModeMLDSA65:
		perSigGas = MLDSABatchVerifyPerSigGas65
	case ModeMLDSA87:
		perSigGas = MLDSABatchVerifyPerSigGas87
	default:
		perSigGas = MLDSABatchVerifyPerSigGas65
	}

	return MLDSABatchVerifyBaseGas + count*perSigGas
}

// Run implements batch ML-DSA signature verification (CPU-only stub)
func (p *mldsaBatchVerifyPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, errors.New("out of gas")
	}

	if len(input) < 3 {
		return nil, suppliedGas - gasCost, ErrInvalidInputLength
	}

	mode := input[0]
	count := int(input[1])<<8 | int(input[2])
	if count == 0 {
		return nil, suppliedGas - gasCost, errors.New("empty batch")
	}

	// Get mode parameters
	pubKeySize, sigSize, _, mldsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	// Parse all signatures
	pks := make([]*mldsa.PublicKey, count)
	sigs := make([][]byte, count)
	msgs := make([][]byte, count)

	offset := 3
	for i := 0; i < count; i++ {
		if len(input) < offset+pubKeySize+sigSize+4 {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at signature %d",
				ErrInvalidInputLength, i)
		}

		pubKeyBytes := input[offset : offset+pubKeySize]
		pk, err := mldsa.PublicKeyFromBytes(pubKeyBytes, mldsaMode)
		if err != nil {
			return nil, suppliedGas - gasCost, fmt.Errorf("invalid public key %d: %w", i, err)
		}
		pks[i] = pk
		offset += pubKeySize

		sigs[i] = input[offset : offset+sigSize]
		offset += sigSize

		msgLen := int(input[offset])<<24 | int(input[offset+1])<<16 |
			int(input[offset+2])<<8 | int(input[offset+3])
		offset += 4

		if len(input) < offset+msgLen {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: message %d truncated",
				ErrInvalidInputLength, i)
		}
		msgs[i] = input[offset : offset+msgLen]
		offset += msgLen
	}

	// CPU-only verification
	results := make([]bool, len(pks))
	for i := range pks {
		if pks[i] != nil {
			results[i] = pks[i].Verify(msgs[i], sigs[i], nil)
		}
	}

	// Encode results: 32 bytes per result
	output := make([]byte, count*32)
	for i, valid := range results {
		if valid {
			output[i*32+31] = 1
		}
	}

	return output, suppliedGas - gasCost, nil
}

// GPUAvailable returns false in stub build
func GPUAvailable() bool {
	return false
}

// GPUThreshold returns default threshold
func GPUThreshold() int {
	return 4
}
