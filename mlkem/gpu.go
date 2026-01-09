//go:build cgo

// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mlkem"
	mlkemgpu "github.com/luxfi/crypto/pq/mlkem/gpu"
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
	MLKEMBatchBaseGas            uint64 = 30_000 // Fixed overhead
	MLKEMBatchEncapsPerOpGas512  uint64 = 35_000 // Per-op GPU cost for ML-KEM-512
	MLKEMBatchEncapsPerOpGas768  uint64 = 50_000 // Per-op GPU cost for ML-KEM-768
	MLKEMBatchEncapsPerOpGas1024 uint64 = 70_000 // Per-op GPU cost for ML-KEM-1024
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
// Input format:
//
//	[0]     = operation (0x11 = batch encaps, 0x12 = batch decaps)
//	[1]     = mode byte (0x00 = 512, 0x01 = 768, 0x02 = 1024)
//	[2:4]   = count (uint16 big-endian)
//	[4:...] = operation-specific data
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

	gas := MLKEMBatchBaseGas + count*perOpGas

	// GPU discount for large batches
	if mlkemgpu.Available() && count >= uint64(mlkemgpu.Threshold()) {
		gas = gas * 70 / 100
	}

	return gas
}

// Run implements batch ML-KEM operations
// Input format depends on operation:
//
// Batch Encapsulate (0x11):
//
//	[0]     = 0x11
//	[1]     = mode
//	[2:4]   = count
//	[4:...] = count * pubKey (mode-dependent size)
//
// Output: for each: ciphertext || sharedSecret (32 bytes)
//
// Batch Decapsulate (0x12):
//
//	[0]     = 0x12
//	[1]     = mode
//	[2:4]   = count
//	[4:4+privKeySize] = private key
//	[4+privKeySize:...] = count * ciphertext
//
// Output: count * sharedSecret (32 bytes each)
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

	// Parse public keys
	pks := make([]*mlkem.PublicKey, count)
	for i := 0; i < count; i++ {
		pkBytes := input[i*pubKeySize : (i+1)*pubKeySize]
		pk, err := mlkem.PublicKeyFromBytes(pkBytes, mode)
		if err != nil {
			return nil, remainingGas, fmt.Errorf("invalid public key %d: %w", i, err)
		}
		pks[i] = pk
	}

	// Encapsulate using GPU if available
	var cts [][]byte
	var sss [][]byte
	var err error

	if mlkemgpu.Available() && count >= mlkemgpu.Threshold() {
		cts, sss, err = mlkemgpu.BatchEncaps(pks, nil)
		if err != nil {
			// Fall back to CPU
			cts, sss = encapsulateCPU(pks)
		}
	} else {
		cts, sss = encapsulateCPU(pks)
	}

	// Build output: ct || ss for each
	output := make([]byte, count*(ctSize+sharedSize))
	for i := 0; i < count; i++ {
		copy(output[i*(ctSize+sharedSize):], cts[i])
		copy(output[i*(ctSize+sharedSize)+ctSize:], sss[i])
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

	// Parse private key
	sk, err := mlkem.PrivateKeyFromBytes(input[:privKeySize], mode)
	if err != nil {
		return nil, remainingGas, fmt.Errorf("invalid private key: %w", err)
	}

	// Parse ciphertexts
	cts := make([][]byte, count)
	for i := 0; i < count; i++ {
		start := privKeySize + i*ctSize
		cts[i] = input[start : start+ctSize]
	}

	// Decapsulate using GPU if available
	var sss [][]byte

	if mlkemgpu.Available() && count >= mlkemgpu.Threshold() {
		sss, err = mlkemgpu.BatchDecaps(sk, cts)
		if err != nil {
			// Fall back to CPU
			sss = decapsulateCPU(sk, cts)
		}
	} else {
		sss = decapsulateCPU(sk, cts)
	}

	// Build output: ss for each
	output := make([]byte, count*32)
	for i := 0; i < count; i++ {
		copy(output[i*32:], sss[i])
	}

	return output, remainingGas, nil
}

func encapsulateCPU(pks []*mlkem.PublicKey) ([][]byte, [][]byte) {
	cts := make([][]byte, len(pks))
	sss := make([][]byte, len(pks))
	for i, pk := range pks {
		ct, ss, err := pk.Encapsulate()
		if err != nil {
			continue
		}
		cts[i] = ct
		sss[i] = ss
	}
	return cts, sss
}

func decapsulateCPU(sk *mlkem.PrivateKey, cts [][]byte) [][]byte {
	sss := make([][]byte, len(cts))
	for i, ct := range cts {
		ss, err := sk.Decapsulate(ct)
		if err != nil {
			sss[i] = make([]byte, 32) // Zero on error
			continue
		}
		sss[i] = ss
	}
	return sss
}

// GPUAvailable returns true if GPU acceleration is available
func GPUAvailable() bool {
	return mlkemgpu.Available()
}

// GPUThreshold returns the minimum batch size for GPU acceleration
func GPUThreshold() int {
	return mlkemgpu.Threshold()
}
