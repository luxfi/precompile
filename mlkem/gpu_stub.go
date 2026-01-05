//go:build !gpu

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractMLKEMBatchAddress is the address of the ML-KEM batch precompile
	ContractMLKEMBatchAddress = common.HexToAddress("0x0200000000000000000000000000000000000017")

	// Singleton instance for batch operations
	MLKEMBatchPrecompile = &mlkemBatchPrecompile{}

	_ contract.StatefulPrecompiledContract = &mlkemBatchPrecompile{}
)

// Batch operation selectors
const (
	OpBatchEncapsulate = 0x11 // Batch encapsulation
	OpBatchDecapsulate = 0x12 // Batch decapsulation
)

// Batch gas costs
const (
	MLKEMBatchBaseGas            uint64 = 30_000  // Fixed overhead
	MLKEMBatchEncapsPerOpGas512  uint64 = 35_000  // Per-op cost for ML-KEM-512
	MLKEMBatchEncapsPerOpGas768  uint64 = 50_000  // Per-op cost for ML-KEM-768
	MLKEMBatchEncapsPerOpGas1024 uint64 = 70_000  // Per-op cost for ML-KEM-1024
	MLKEMBatchDecapsPerOpGas512  uint64 = 40_000
	MLKEMBatchDecapsPerOpGas768  uint64 = 60_000
	MLKEMBatchDecapsPerOpGas1024 uint64 = 80_000
)

type mlkemBatchPrecompile struct{}

// Address returns the address of the batch precompile
func (p *mlkemBatchPrecompile) Address() common.Address {
	return ContractMLKEMBatchAddress
}

// RequiredGas calculates gas for batch operations
func (p *mlkemBatchPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return MLKEMBatchBaseGas
	}

	op := input[0]
	mode := input[1]
	count := uint64(input[2])<<8 | uint64(input[3])
	if count == 0 {
		return MLKEMBatchBaseGas
	}

	var perOpGas uint64
	switch op {
	case OpBatchEncapsulate:
		switch mode {
		case ModeMLKEM512:
			perOpGas = MLKEMBatchEncapsPerOpGas512
		case ModeMLKEM768:
			perOpGas = MLKEMBatchEncapsPerOpGas768
		case ModeMLKEM1024:
			perOpGas = MLKEMBatchEncapsPerOpGas1024
		default:
			perOpGas = MLKEMBatchEncapsPerOpGas768
		}
	case OpBatchDecapsulate:
		switch mode {
		case ModeMLKEM512:
			perOpGas = MLKEMBatchDecapsPerOpGas512
		case ModeMLKEM768:
			perOpGas = MLKEMBatchDecapsPerOpGas768
		case ModeMLKEM1024:
			perOpGas = MLKEMBatchDecapsPerOpGas1024
		default:
			perOpGas = MLKEMBatchDecapsPerOpGas768
		}
	default:
		return MLKEMBatchBaseGas
	}

	return MLKEMBatchBaseGas + count*perOpGas
}

// Run implements batch ML-KEM operations (CPU-only stub)
func (p *mlkemBatchPrecompile) Run(
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

	if len(input) < 4 {
		return nil, suppliedGas - gasCost, ErrInvalidInputLength
	}

	op := input[0]
	mode := input[1]
	count := int(input[2])<<8 | int(input[3])
	if count == 0 {
		return nil, suppliedGas - gasCost, errors.New("empty batch")
	}

	// Get mode parameters
	pubKeySize, privKeySize, ctSize, sharedSize, _, _, mlkemMode, err := getModeParams(mode)
	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	switch op {
	case OpBatchEncapsulate:
		return p.batchEncapsulate(input[4:], count, pubKeySize, ctSize, sharedSize, mlkemMode, suppliedGas-gasCost)
	case OpBatchDecapsulate:
		return p.batchDecapsulate(input[4:], count, privKeySize, ctSize, mlkemMode, suppliedGas-gasCost)
	default:
		return nil, suppliedGas - gasCost, fmt.Errorf("%w: 0x%02x", ErrUnsupportedOperation, op)
	}
}

func (p *mlkemBatchPrecompile) batchEncapsulate(
	input []byte,
	count int,
	pubKeySize, ctSize, sharedSize int,
	mode mlkem.Mode,
	remainingGas uint64,
) ([]byte, uint64, error) {
	expectedInput := count * pubKeySize
	if len(input) < expectedInput {
		return nil, remainingGas, fmt.Errorf("%w: expected %d bytes for %d public keys",
			ErrInvalidInputLength, expectedInput, count)
	}

	pks := make([]*mlkem.PublicKey, count)
	for i := 0; i < count; i++ {
		pkBytes := input[i*pubKeySize : (i+1)*pubKeySize]
		pk, err := mlkem.PublicKeyFromBytes(pkBytes, mode)
		if err != nil {
			return nil, remainingGas, fmt.Errorf("invalid public key %d: %w", i, err)
		}
		pks[i] = pk
	}

	// CPU-only encapsulation
	cts := make([][]byte, count)
	sss := make([][]byte, count)
	for i, pk := range pks {
		ct, ss, err := pk.Encapsulate()
		if err != nil {
			continue
		}
		cts[i] = ct
		sss[i] = ss
	}

	output := make([]byte, count*(ctSize+sharedSize))
	for i := 0; i < count; i++ {
		if cts[i] != nil {
			copy(output[i*(ctSize+sharedSize):], cts[i])
		}
		if sss[i] != nil {
			copy(output[i*(ctSize+sharedSize)+ctSize:], sss[i])
		}
	}

	return output, remainingGas, nil
}

func (p *mlkemBatchPrecompile) batchDecapsulate(
	input []byte,
	count int,
	privKeySize, ctSize int,
	mode mlkem.Mode,
	remainingGas uint64,
) ([]byte, uint64, error) {
	expectedInput := privKeySize + count*ctSize
	if len(input) < expectedInput {
		return nil, remainingGas, fmt.Errorf("%w: expected %d bytes",
			ErrInvalidInputLength, expectedInput)
	}

	sk, err := mlkem.PrivateKeyFromBytes(input[:privKeySize], mode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("invalid private key: %w", err)
	}

	// CPU-only decapsulation
	output := make([]byte, count*32)
	for i := 0; i < count; i++ {
		start := privKeySize + i*ctSize
		ct := input[start : start+ctSize]
		ss, err := sk.Decapsulate(ct)
		if err != nil {
			continue
		}
		copy(output[i*32:], ss)
	}

	return output, remainingGas, nil
}

// GPUAvailable returns false in stub build
func GPUAvailable() bool {
	return false
}

// GPUThreshold returns default threshold
func GPUThreshold() int {
	return 4
}
