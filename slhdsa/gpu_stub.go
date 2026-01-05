//go:build !gpu

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractSLHDSABatchVerifyAddress is the address of the SLH-DSA batch verify precompile
	ContractSLHDSABatchVerifyAddress = common.HexToAddress("0x0600000000000000000000000000000000000011")

	// Singleton instance for batch verification
	SLHDSABatchVerifyPrecompile = &slhdsaBatchVerifyPrecompile{}

	_ contract.StatefulPrecompiledContract = &slhdsaBatchVerifyPrecompile{}
)

// Batch verification gas costs
const (
	SLHDSABatchVerifyBaseGas       uint64 = 40_000  // Fixed overhead
	SLHDSABatchVerifyPerSigGas128s uint64 = 35_000  // Per-sig cost
	SLHDSABatchVerifyPerSigGas128f uint64 = 50_000
	SLHDSABatchVerifyPerSigGas192s uint64 = 70_000
	SLHDSABatchVerifyPerSigGas192f uint64 = 100_000
	SLHDSABatchVerifyPerSigGas256s uint64 = 120_000
	SLHDSABatchVerifyPerSigGas256f uint64 = 175_000
	SLHDSABatchVerifyPerByteGas    uint64 = 5
)

type slhdsaBatchVerifyPrecompile struct{}

// Address returns the address of the batch verify precompile
func (p *slhdsaBatchVerifyPrecompile) Address() common.Address {
	return ContractSLHDSABatchVerifyAddress
}

// RequiredGas calculates gas for batch verification
func (p *slhdsaBatchVerifyPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 3 {
		return SLHDSABatchVerifyBaseGas
	}

	mode := input[0]
	count := uint64(binary.BigEndian.Uint16(input[1:3]))
	if count == 0 {
		return SLHDSABatchVerifyBaseGas
	}

	var perSigGas uint64
	switch mode {
	case ModeSHA2_128s, ModeSHAKE_128s:
		perSigGas = SLHDSABatchVerifyPerSigGas128s
	case ModeSHA2_128f, ModeSHAKE_128f:
		perSigGas = SLHDSABatchVerifyPerSigGas128f
	case ModeSHA2_192s, ModeSHAKE_192s:
		perSigGas = SLHDSABatchVerifyPerSigGas192s
	case ModeSHA2_192f, ModeSHAKE_192f:
		perSigGas = SLHDSABatchVerifyPerSigGas192f
	case ModeSHA2_256s, ModeSHAKE_256s:
		perSigGas = SLHDSABatchVerifyPerSigGas256s
	case ModeSHA2_256f, ModeSHAKE_256f:
		perSigGas = SLHDSABatchVerifyPerSigGas256f
	default:
		perSigGas = SLHDSABatchVerifyPerSigGas128s
	}

	return SLHDSABatchVerifyBaseGas + count*perSigGas
}

// Run implements batch SLH-DSA signature verification (CPU-only stub)
func (p *slhdsaBatchVerifyPrecompile) Run(
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
	count := int(binary.BigEndian.Uint16(input[1:3]))
	if count == 0 {
		return nil, suppliedGas - gasCost, errors.New("empty batch")
	}

	// Get mode parameters
	_, _, _, slhdsaMode, err := getModeParams(mode)
	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	// Parse all signatures
	pks := make([]*slhdsa.PublicKey, count)
	sigs := make([][]byte, count)
	msgs := make([][]byte, count)

	offset := 3
	for i := 0; i < count; i++ {
		if len(input) < offset+2 {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at pubkey length %d", ErrInvalidInputLength, i)
		}
		pubKeyLen := int(binary.BigEndian.Uint16(input[offset : offset+2]))
		offset += 2

		if len(input) < offset+pubKeyLen {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at pubkey %d", ErrInvalidInputLength, i)
		}
		pk, err := slhdsa.PublicKeyFromBytes(input[offset:offset+pubKeyLen], slhdsaMode)
		if err != nil {
			return nil, suppliedGas - gasCost, fmt.Errorf("invalid public key %d: %w", i, err)
		}
		pks[i] = pk
		offset += pubKeyLen

		if len(input) < offset+2 {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at sig length %d", ErrInvalidInputLength, i)
		}
		sigLen := int(binary.BigEndian.Uint16(input[offset : offset+2]))
		offset += 2

		if len(input) < offset+sigLen {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at sig %d", ErrInvalidInputLength, i)
		}
		sigs[i] = input[offset : offset+sigLen]
		offset += sigLen

		if len(input) < offset+2 {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at msg length %d", ErrInvalidInputLength, i)
		}
		msgLen := int(binary.BigEndian.Uint16(input[offset : offset+2]))
		offset += 2

		if len(input) < offset+msgLen {
			return nil, suppliedGas - gasCost, fmt.Errorf("%w: truncated at msg %d", ErrInvalidInputLength, i)
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
