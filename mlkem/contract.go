// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mlkem implements the ML-KEM (FIPS 203) key encapsulation precompile.
// Address: 0x0200000000000000000000000000000000000007
//
// Operations:
//   - 0x01: Encapsulate -- generate shared secret + ciphertext from public key
//
// Decapsulate is intentionally excluded: it requires the private key in
// calldata, which is public on-chain. Decapsulation MUST be performed off-chain.
//
// See LP-4318 for full specification.
package mlkem

import (
	"errors"
	"fmt"

	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/mlkem"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the address of the ML-KEM precompile
	ContractAddress = common.HexToAddress("0x0200000000000000000000000000000000000007")

	// Singleton instance
	MLKEMPrecompile = &mlkemPrecompile{}

	_ contract.StatefulPrecompiledContract = &mlkemPrecompile{}

	ErrInvalidInputLength   = errors.New("invalid input length")
	ErrInvalidMode          = errors.New("invalid ML-KEM mode")
	ErrUnsupportedMode      = errors.New("unsupported ML-KEM mode")
	ErrUnsupportedOperation = errors.New("unsupported operation")
	ErrEncapsulationFailed  = errors.New("encapsulation failed")
)

// Operation selectors -- encapsulate only, decapsulate is excluded for key safety
const (
	OpEncapsulate = 0x01
)

// ML-KEM modes (FIPS 203)
const (
	ModeMLKEM512  uint8 = 0x00 // ML-KEM-512 (128-bit security, NIST Level 1)
	ModeMLKEM768  uint8 = 0x01 // ML-KEM-768 (192-bit security, NIST Level 3)
	ModeMLKEM1024 uint8 = 0x02 // ML-KEM-1024 (256-bit security, NIST Level 5)
)

// Size constants for ML-KEM-512 (NIST Level 1)
const (
	MLKEM512PublicKeySize  = 800
	MLKEM512CiphertextSize = 768
	MLKEM512SharedKeySize  = 32
)

// Size constants for ML-KEM-768 (NIST Level 3)
const (
	MLKEM768PublicKeySize  = 1184
	MLKEM768CiphertextSize = 1088
	MLKEM768SharedKeySize  = 32
)

// Size constants for ML-KEM-1024 (NIST Level 5)
const (
	MLKEM1024PublicKeySize  = 1568
	MLKEM1024CiphertextSize = 1568
	MLKEM1024SharedKeySize  = 32
)

// Gas costs - based on computational complexity
const (
	MLKEM512EncapsulateGas  uint64 = 50_000
	MLKEM768EncapsulateGas  uint64 = 75_000
	MLKEM1024EncapsulateGas uint64 = 100_000
)

type mlkemPrecompile struct{}

// Address returns the address of the ML-KEM precompile
func (p *mlkemPrecompile) Address() common.Address {
	return ContractAddress
}

// getModeParams returns the parameters for a given ML-KEM mode
func getModeParams(mode uint8) (pubKeySize, ctSize, sharedSize int, encapsGas uint64, mlkemMode mlkem.Mode, err error) {
	switch mode {
	case ModeMLKEM512:
		return MLKEM512PublicKeySize, MLKEM512CiphertextSize, MLKEM512SharedKeySize,
			MLKEM512EncapsulateGas, mlkem.MLKEM512, nil
	case ModeMLKEM768:
		return MLKEM768PublicKeySize, MLKEM768CiphertextSize, MLKEM768SharedKeySize,
			MLKEM768EncapsulateGas, mlkem.MLKEM768, nil
	case ModeMLKEM1024:
		return MLKEM1024PublicKeySize, MLKEM1024CiphertextSize, MLKEM1024SharedKeySize,
			MLKEM1024EncapsulateGas, mlkem.MLKEM1024, nil
	default:
		return 0, 0, 0, 0, 0, ErrUnsupportedMode
	}
}

// RequiredGas calculates the gas required for ML-KEM operations
func (p *mlkemPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 2 {
		return MLKEM768EncapsulateGas
	}

	op := input[0]
	mode := input[1]

	if op != OpEncapsulate {
		return MLKEM768EncapsulateGas
	}

	_, _, _, encapsGas, _, err := getModeParams(mode)
	if err != nil {
		return MLKEM768EncapsulateGas
	}

	return encapsGas
}

// Run implements the ML-KEM precompile
// Input format:
//
//	[0]     = operation byte (0x01 = encapsulate)
//	[1]     = mode byte (0x00 = 512, 0x01 = 768, 0x02 = 1024)
//	[2:...] = public key
//
// Encapsulate output:
//
//	[0:ctSize]       = ciphertext
//	[ctSize:ctSize+32] = shared secret (32 bytes)
func (p *mlkemPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, contract.ErrOutOfGas
	}

	if len(input) < 2 {
		return nil, suppliedGas - gasCost, ErrInvalidInputLength
	}

	op := input[0]
	mode := input[1]

	var result []byte
	var err error

	switch op {
	case OpEncapsulate:
		result, err = p.encapsulate(mode, input[2:])
	default:
		err = fmt.Errorf("%w: 0x%02x", ErrUnsupportedOperation, op)
	}

	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	return result, suppliedGas - gasCost, nil
}

// encapsulate generates a shared secret and ciphertext from a public key
func (p *mlkemPrecompile) encapsulate(mode uint8, input []byte) ([]byte, error) {
	pubKeySize, ctSize, sharedSize, _, mlkemMode, err := getModeParams(mode)
	if err != nil {
		return nil, err
	}

	if len(input) != pubKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes for public key, got %d",
			ErrInvalidInputLength, pubKeySize, len(input))
	}

	// Try GPU-accelerated encapsulation first
	if ct, ss, gpuUsed := encapsulateGPU(input, ctSize, sharedSize); gpuUsed {
		result := make([]byte, ctSize+sharedSize)
		copy(result[:ctSize], ct)
		copy(result[ctSize:], ss)
		return result, nil
	}

	// CPU fallback
	pk, err := mlkem.PublicKeyFromBytes(input, mlkemMode)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	ciphertext, sharedSecret, err := pk.Encapsulate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncapsulationFailed, err)
	}

	result := make([]byte, ctSize+sharedSize)
	copy(result[:ctSize], ciphertext)
	copy(result[ctSize:], sharedSecret)

	return result, nil
}

// encapsulateGPU attempts GPU-accelerated ML-KEM encapsulation.
func encapsulateGPU(publicKey []byte, ctSize, ssSize int) (ct []byte, ss []byte, gpuUsed bool) {
	if !accel.Available() {
		return nil, nil, false
	}

	sess, err := accel.NewSession()
	if err != nil {
		return nil, nil, false
	}
	defer sess.Close()

	lattice := sess.Lattice()

	pkTensor, err := accel.NewTensorWithData[byte](sess, []int{len(publicKey)}, publicKey)
	if err != nil {
		return nil, nil, false
	}
	defer pkTensor.Close()

	ctTensor, err := accel.NewTensor[byte](sess, []int{ctSize})
	if err != nil {
		return nil, nil, false
	}
	defer ctTensor.Close()

	ssTensor, err := accel.NewTensor[byte](sess, []int{ssSize})
	if err != nil {
		return nil, nil, false
	}
	defer ssTensor.Close()

	if err := lattice.KyberEncaps(pkTensor.Untyped(), ctTensor.Untyped(), ssTensor.Untyped()); err != nil {
		return nil, nil, false
	}

	ctResult, err := ctTensor.ToSlice()
	if err != nil {
		return nil, nil, false
	}

	ssResult, err := ssTensor.ToSlice()
	if err != nil {
		return nil, nil, false
	}

	return ctResult, ssResult, true
}
