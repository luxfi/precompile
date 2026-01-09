// Copyright (C) 2019-2024, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"errors"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// Ciphertext type constants - must match github.com/luxfi/fhe FheUintType
const (
	TypeEbool    uint8 = 0 // FheBool - 1 bit
	TypeEuint4   uint8 = 1 // FheUint4 - 4 bits
	TypeEuint8   uint8 = 2 // FheUint8 - 8 bits
	TypeEuint16  uint8 = 3 // FheUint16 - 16 bits
	TypeEuint32  uint8 = 4 // FheUint32 - 32 bits
	TypeEuint64  uint8 = 5 // FheUint64 - 64 bits
	TypeEuint128 uint8 = 6 // FheUint128 - 128 bits
	TypeEuint160 uint8 = 7 // FheUint160 - 160 bits (Ethereum addresses)
	TypeEuint256 uint8 = 8 // FheUint256 - 256 bits
	TypeEaddress uint8 = 7 // Alias for TypeEuint160
)

// Gas costs for FHE operations
const (
	GasEncrypt        uint64 = 50000
	GasDecryptRequest uint64 = 10000
	GasAdd            uint64 = 65000
	GasSub            uint64 = 65000
	GasMul            uint64 = 150000
	GasDiv            uint64 = 500000
	GasRem            uint64 = 500000
	GasAnd            uint64 = 50000
	GasOr             uint64 = 50000
	GasXor            uint64 = 50000
	GasNot            uint64 = 30000
	GasShl            uint64 = 70000
	GasShr            uint64 = 70000
	GasRotl           uint64 = 70000
	GasRotr           uint64 = 70000
	GasEq             uint64 = 60000
	GasNe             uint64 = 60000
	GasGt             uint64 = 60000
	GasGe             uint64 = 60000
	GasLt             uint64 = 60000
	GasLe             uint64 = 60000
	GasMin            uint64 = 120000
	GasMax            uint64 = 120000
	GasSelect         uint64 = 100000
	GasNeg            uint64 = 50000
	GasRand           uint64 = 100000
	GasCast           uint64 = 30000
	GasRequire        uint64 = 80000
)

var (
	ErrInvalidInput      = errors.New("invalid input")
	ErrTypeMismatch      = errors.New("ciphertext type mismatch")
	ErrOperationFailed   = errors.New("FHE operation failed")
	ErrNotImplemented    = errors.New("operation not implemented")
	ErrInsufficientGas   = errors.New("insufficient gas for FHE operation")
	ErrInvalidCiphertext = errors.New("invalid ciphertext handle")
)

// FHEContract implements the main FHE precompile
type FHEContract struct{}

// Run executes the FHE precompile
func (c *FHEContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < 4 {
		return nil, suppliedGas, ErrInvalidInput
	}

	// Extract function selector (first 4 bytes)
	selector := input[:4]
	data := input[4:]

	// Route to appropriate handler based on selector
	switch string(selector) {
	// Arithmetic operations
	case "\x23\xb8\x72\xdd": // add(bytes32,bytes32)
		return c.handleAdd(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x51\xca\xb0\x91": // sub(bytes32,bytes32)
		return c.handleSub(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xc8\xa4\xac\x9c": // mul(bytes32,bytes32)
		return c.handleMul(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x0f\x5e\x1b\x2a": // div(bytes32,bytes32)
		return c.handleDiv(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x1e\x19\x1a\x96": // rem(bytes32,bytes32)
		return c.handleRem(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xe4\x7e\xf3\xfc": // neg(bytes32)
		return c.handleNeg(accessibleState, caller, data, suppliedGas, readOnly)

	// Scalar arithmetic
	case "\xf5\xa7\x96\xfb": // scalarAdd(bytes32,uint256)
		return c.handleScalarAdd(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xb6\x3a\x9e\x11": // scalarSub(bytes32,uint256)
		return c.handleScalarSub(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x3c\x96\x47\x95": // scalarMul(bytes32,uint256)
		return c.handleScalarMul(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x7b\x8f\x4a\x2d": // scalarDiv(bytes32,uint256)
		return c.handleScalarDiv(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x52\x91\xa3\x21": // scalarRem(bytes32,uint256)
		return c.handleScalarRem(accessibleState, caller, data, suppliedGas, readOnly)

	// Comparison operations
	case "\xa9\x05\x9c\xbb": // lt(bytes32,bytes32)
		return c.handleLt(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x26\xa3\x31\x9e": // le(bytes32,bytes32)
		return c.handleLe(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x4b\x64\xe4\x92": // gt(bytes32,bytes32)
		return c.handleGt(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x53\x1c\x19\xea": // ge(bytes32,bytes32)
		return c.handleGe(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x1c\xf4\x86\x63": // eq(bytes32,bytes32)
		return c.handleEq(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x14\x6e\x3a\x7e": // ne(bytes32,bytes32)
		return c.handleNe(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x7a\x8f\x63\xb8": // min(bytes32,bytes32)
		return c.handleMin(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x6e\x32\x91\x28": // max(bytes32,bytes32)
		return c.handleMax(accessibleState, caller, data, suppliedGas, readOnly)

	// Bitwise operations
	case "\xcd\x30\x32\x00": // and(bytes32,bytes32)
		return c.handleAnd(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x5a\x6b\x26\xba": // or(bytes32,bytes32)
		return c.handleOr(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xf6\x74\x70\x22": // xor(bytes32,bytes32)
		return c.handleXor(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x6b\x3a\x00\x11": // not(bytes32)
		return c.handleNot(accessibleState, caller, data, suppliedGas, readOnly)

	// Shift operations
	case "\x3e\x8c\x6c\x10": // shl(bytes32,uint8)
		return c.handleShl(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x5f\x46\xe5\x15": // shr(bytes32,uint8)
		return c.handleShr(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x89\xa1\x9e\x6b": // rotl(bytes32,uint8)
		return c.handleRotl(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xd7\x25\x1c\xb9": // rotr(bytes32,uint8)
		return c.handleRotr(accessibleState, caller, data, suppliedGas, readOnly)

	// Selection and casting
	case "\x2e\x17\xde\x78": // select(bytes32,bytes32,bytes32)
		return c.handleSelect(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xae\xd2\x44\x6b": // cast(bytes32,uint8)
		return c.handleCast(accessibleState, caller, data, suppliedGas, readOnly)

	// Encryption operations
	case "\xa5\x17\x5c\x89": // asEuint64(uint64)
		return c.handleAsEuint64(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xd4\x3f\x02\x80": // asEaddress(address)
		return c.handleAsEaddress(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x8c\x3f\x5a\x42": // asEbool(bool)
		return c.handleAsEbool(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x2d\xfa\x48\x63": // asEuint4(uint8)
		return c.handleAsEuint4(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x64\xc1\x51\x81": // asEuint8(uint8)
		return c.handleAsEuint8(accessibleState, caller, data, suppliedGas, readOnly)
	case "\xf8\x91\x08\x50": // asEuint16(uint16)
		return c.handleAsEuint16(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x6c\xa9\xea\xe9": // asEuint32(uint32)
		return c.handleAsEuint32(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x7d\x6d\x81\x95": // asEuint128(uint256)
		return c.handleAsEuint128(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x9e\x5b\x2e\xf3": // asEuint256(uint256)
		return c.handleAsEuint256(accessibleState, caller, data, suppliedGas, readOnly)

	// Utility operations
	case "\x71\x5a\xd3\x11": // rand(uint8)
		return c.handleRand(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x12\x3d\x4c\x87": // decrypt(bytes32)
		return c.handleDecrypt(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x45\xa9\x32\x18": // verify(bytes,uint8)
		return c.handleVerify(accessibleState, caller, data, suppliedGas, readOnly)
	case "\x56\x7a\x11\x98": // sealOutput(bytes32,bytes)
		return c.handleSealOutput(accessibleState, caller, data, suppliedGas, readOnly)

	default:
		return nil, suppliedGas, ErrNotImplemented
	}
}

// Gas returns the gas required for the FHE operation
func (c *FHEContract) Gas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	selector := string(input[:4])
	switch selector {
	case "\x23\xb8\x72\xdd": // add
		return GasAdd
	case "\x51\xca\xb0\x91": // sub
		return GasSub
	case "\xc8\xa4\xac\x9c": // mul
		return GasMul
	case "\xa9\x05\x9c\xbb", "\x4b\x64\xe4\x92": // lt, gt
		return GasLt
	case "\x1c\xf4\x86\x63": // eq
		return GasEq
	case "\x2e\x17\xde\x78": // select
		return GasSelect
	case "\xa5\x17\x5c\x89", "\xd4\x3f\x02\x80": // asEuint64, asEaddress
		return GasEncrypt
	case "\x6e\x32\x91\x28", "\x7a\x8f\x63\xb8": // max, min
		return GasMax
	case "\xcd\x30\x32\x00", "\x5a\x6b\x26\xba": // and, or
		return GasAnd
	case "\x6b\x3a\x00\x11": // not
		return GasNot
	case "\xe4\x7e\xf3\xfc": // neg
		return GasNeg
	case "\x71\x5a\xd3\x11": // rand
		return GasRand
	default:
		return 100000 // Default high gas for unknown operations
	}
}

// Handler implementations

func (c *FHEContract) handleAdd(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasAdd {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	// Delegate to Z-Chain FHE coprocessor
	result := performFHEOperation("add", handle1, handle2, caller)

	return result.Bytes(), gas - GasAdd, nil
}

func (c *FHEContract) handleSub(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasSub {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("sub", handle1, handle2, caller)

	return result.Bytes(), gas - GasSub, nil
}

func (c *FHEContract) handleMul(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasMul {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("mul", handle1, handle2, caller)

	return result.Bytes(), gas - GasMul, nil
}

func (c *FHEContract) handleLt(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasLt {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("lt", handle1, handle2, caller)

	return result.Bytes(), gas - GasLt, nil
}

func (c *FHEContract) handleGt(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasGt {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("gt", handle1, handle2, caller)

	return result.Bytes(), gas - GasGt, nil
}

func (c *FHEContract) handleEq(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEq {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("eq", handle1, handle2, caller)

	return result.Bytes(), gas - GasEq, nil
}

func (c *FHEContract) handleSelect(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 96 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasSelect {
		return nil, gas, ErrInsufficientGas
	}

	condition := common.BytesToHash(data[:32])
	ifTrue := common.BytesToHash(data[32:64])
	ifFalse := common.BytesToHash(data[64:96])

	result := performFHESelect(condition, ifTrue, ifFalse, caller)

	return result.Bytes(), gas - GasSelect, nil
}

func (c *FHEContract) handleAsEuint64(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptValue(value.Uint64(), TypeEuint64, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEaddress(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	addr := common.BytesToAddress(data[12:32])

	result := encryptAddress(addr, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleMax(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasMax {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("max", handle1, handle2, caller)

	return result.Bytes(), gas - GasMax, nil
}

func (c *FHEContract) handleMin(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasMin {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("min", handle1, handle2, caller)

	return result.Bytes(), gas - GasMin, nil
}

func (c *FHEContract) handleAnd(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasAnd {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("and", handle1, handle2, caller)

	return result.Bytes(), gas - GasAnd, nil
}

func (c *FHEContract) handleOr(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasOr {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("or", handle1, handle2, caller)

	return result.Bytes(), gas - GasOr, nil
}

func (c *FHEContract) handleNot(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasNot {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])

	result := performFHEUnaryOperation("not", handle, caller)

	return result.Bytes(), gas - GasNot, nil
}

func (c *FHEContract) handleNeg(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasNeg {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])

	result := performFHEUnaryOperation("neg", handle, caller)

	return result.Bytes(), gas - GasNeg, nil
}

func (c *FHEContract) handleRand(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 1 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasRand {
		return nil, gas, ErrInsufficientGas
	}

	ctType := data[0]

	result := generateEncryptedRandom(ctType, caller)

	return result.Bytes(), gas - GasRand, nil
}

// === Additional Arithmetic Handlers ===

func (c *FHEContract) handleDiv(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasDiv {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("div", handle1, handle2, caller)

	return result.Bytes(), gas - GasDiv, nil
}

func (c *FHEContract) handleRem(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasRem {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("rem", handle1, handle2, caller)

	return result.Bytes(), gas - GasRem, nil
}

// === Scalar Arithmetic Handlers ===

func (c *FHEContract) handleScalarAdd(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasAdd {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	scalar := new(big.Int).SetBytes(data[32:64])

	result := performFHEScalarOperation("scalarAdd", handle, scalar, caller)

	return result.Bytes(), gas - GasAdd, nil
}

func (c *FHEContract) handleScalarSub(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasSub {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	scalar := new(big.Int).SetBytes(data[32:64])

	result := performFHEScalarOperation("scalarSub", handle, scalar, caller)

	return result.Bytes(), gas - GasSub, nil
}

func (c *FHEContract) handleScalarMul(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasMul {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	scalar := new(big.Int).SetBytes(data[32:64])

	result := performFHEScalarOperation("scalarMul", handle, scalar, caller)

	return result.Bytes(), gas - GasMul, nil
}

func (c *FHEContract) handleScalarDiv(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasDiv {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	scalar := new(big.Int).SetBytes(data[32:64])

	result := performFHEScalarOperation("scalarDiv", handle, scalar, caller)

	return result.Bytes(), gas - GasDiv, nil
}

func (c *FHEContract) handleScalarRem(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasRem {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	scalar := new(big.Int).SetBytes(data[32:64])

	result := performFHEScalarOperation("scalarRem", handle, scalar, caller)

	return result.Bytes(), gas - GasRem, nil
}

// === Additional Comparison Handlers ===

func (c *FHEContract) handleLe(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasLe {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("le", handle1, handle2, caller)

	return result.Bytes(), gas - GasLe, nil
}

func (c *FHEContract) handleGe(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasGe {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("ge", handle1, handle2, caller)

	return result.Bytes(), gas - GasGe, nil
}

func (c *FHEContract) handleNe(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasNe {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("ne", handle1, handle2, caller)

	return result.Bytes(), gas - GasNe, nil
}

// === Additional Bitwise Handlers ===

func (c *FHEContract) handleXor(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasXor {
		return nil, gas, ErrInsufficientGas
	}

	handle1 := common.BytesToHash(data[:32])
	handle2 := common.BytesToHash(data[32:64])

	result := performFHEOperation("xor", handle1, handle2, caller)

	return result.Bytes(), gas - GasXor, nil
}

// === Shift Operation Handlers ===

func (c *FHEContract) handleShl(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 33 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasShl {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	shift := int(data[32])

	result := performFHEShiftOperation("shl", handle, shift, caller)

	return result.Bytes(), gas - GasShl, nil
}

func (c *FHEContract) handleShr(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 33 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasShr {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	shift := int(data[32])

	result := performFHEShiftOperation("shr", handle, shift, caller)

	return result.Bytes(), gas - GasShr, nil
}

func (c *FHEContract) handleRotl(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 33 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasRotl {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	shift := int(data[32])

	result := performFHEShiftOperation("rotl", handle, shift, caller)

	return result.Bytes(), gas - GasRotl, nil
}

func (c *FHEContract) handleRotr(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 33 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasRotr {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	shift := int(data[32])

	result := performFHEShiftOperation("rotr", handle, shift, caller)

	return result.Bytes(), gas - GasRotr, nil
}

// === Type Conversion and Encryption Handlers ===

func (c *FHEContract) handleCast(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 33 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasCast {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	toType := data[32]

	result := performFHECast(handle, toType, caller)

	return result.Bytes(), gas - GasCast, nil
}

func (c *FHEContract) handleAsEbool(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])
	var boolVal uint64
	if value.Sign() != 0 {
		boolVal = 1
	}

	result := encryptValue(boolVal, TypeEbool, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEuint4(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptValue(value.Uint64()&0xF, TypeEuint4, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEuint8(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptValue(value.Uint64()&0xFF, TypeEuint8, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEuint16(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptValue(value.Uint64()&0xFFFF, TypeEuint16, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEuint32(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptValue(value.Uint64()&0xFFFFFFFF, TypeEuint32, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEuint128(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptBigIntValue(value, TypeEuint128, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleAsEuint256(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	value := new(big.Int).SetBytes(data[:32])

	result := encryptBigIntValue(value, TypeEuint256, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

// === Utility Handlers ===

func (c *FHEContract) handleDecrypt(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasDecryptRequest {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])

	result := performFHEDecrypt(handle, caller)

	return result.Bytes(), gas - GasDecryptRequest, nil
}

func (c *FHEContract) handleVerify(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 33 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	ctType := data[0]
	inputHandle := data[1:]

	result := performFHEVerify(inputHandle, ctType, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

func (c *FHEContract) handleSealOutput(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	publicKey := data[32:]

	result := performFHESealOutput(handle, publicKey, caller)

	return result, gas - GasEncrypt, nil
}

// ciphertextStore holds encrypted values indexed by hash
var ciphertextStore = make(map[common.Hash][]byte)
var ciphertextTypes = make(map[common.Hash]uint8)

// storeCiphertext saves ciphertext and returns its hash
func storeCiphertext(ct []byte, ctType uint8) common.Hash {
	hash := common.BytesToHash(ct)
	ciphertextStore[hash] = ct
	ciphertextTypes[hash] = ctType
	return hash
}

// getCiphertext retrieves ciphertext by hash
func getCiphertext(hash common.Hash) ([]byte, uint8, bool) {
	ct, ok := ciphertextStore[hash]
	if !ok {
		return nil, 0, false
	}
	return ct, ciphertextTypes[hash], true
}

// performFHEOperation executes FHE binary operations using real TFHE library
func performFHEOperation(op string, handle1, handle2 common.Hash, caller common.Address) common.Hash {
	lhs, lhsType, ok := getCiphertext(handle1)
	if !ok {
		return common.Hash{}
	}
	rhs, _, ok := getCiphertext(handle2)
	if !ok {
		return common.Hash{}
	}

	var result []byte
	switch op {
	case "add":
		result = tfheAdd(lhs, rhs, lhsType)
	case "sub":
		result = tfheSub(lhs, rhs, lhsType)
	case "mul":
		result = tfheMul(lhs, rhs, lhsType)
	case "lt":
		result = tfheLt(lhs, rhs, lhsType)
	case "gt":
		result = tfheGt(lhs, rhs, lhsType)
	case "eq":
		result = tfheEq(lhs, rhs, lhsType)
	case "ne":
		result = tfheNe(lhs, rhs, lhsType)
	case "le":
		result = tfheLe(lhs, rhs, lhsType)
	case "ge":
		result = tfheGe(lhs, rhs, lhsType)
	case "and":
		result = tfheAnd(lhs, rhs, lhsType)
	case "or":
		result = tfheOr(lhs, rhs, lhsType)
	case "xor":
		result = tfheXor(lhs, rhs, lhsType)
	case "min":
		result = tfheMin(lhs, rhs, lhsType)
	case "max":
		result = tfheMax(lhs, rhs, lhsType)
	default:
		return common.Hash{}
	}

	if result == nil {
		return common.Hash{}
	}

	// Comparison ops return TypeEbool
	resultType := lhsType
	if op == "lt" || op == "gt" || op == "eq" || op == "ne" || op == "le" || op == "ge" {
		resultType = TypeEbool
	}

	return storeCiphertext(result, resultType)
}

// performFHESelect executes conditional selection using real TFHE library
func performFHESelect(condition, ifTrue, ifFalse common.Hash, caller common.Address) common.Hash {
	ctControl, _, ok := getCiphertext(condition)
	if !ok {
		return common.Hash{}
	}
	ctTrue, trueType, ok := getCiphertext(ifTrue)
	if !ok {
		return common.Hash{}
	}
	ctFalse, _, ok := getCiphertext(ifFalse)
	if !ok {
		return common.Hash{}
	}

	result := tfheSelect(ctControl, ctTrue, ctFalse, trueType)
	if result == nil {
		return common.Hash{}
	}

	return storeCiphertext(result, trueType)
}

// performFHEUnaryOperation executes FHE unary operations using real TFHE library
func performFHEUnaryOperation(op string, handle common.Hash, caller common.Address) common.Hash {
	ct, ctType, ok := getCiphertext(handle)
	if !ok {
		return common.Hash{}
	}

	var result []byte
	switch op {
	case "not":
		result = tfheNot(ct, ctType)
	case "neg":
		result = tfheNeg(ct, ctType)
	default:
		return common.Hash{}
	}

	if result == nil {
		return common.Hash{}
	}

	return storeCiphertext(result, ctType)
}

// encryptValue encrypts a plaintext value using real TFHE library
func encryptValue(value uint64, ctType uint8, caller common.Address) common.Hash {
	ct := tfheTrivialEncrypt(new(big.Int).SetUint64(value), ctType)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertext(ct, ctType)
}

// encryptAddress encrypts an address using real TFHE library
func encryptAddress(addr common.Address, caller common.Address) common.Hash {
	// Address is 160 bits
	value := new(big.Int).SetBytes(addr.Bytes())
	ct := tfheTrivialEncrypt(value, TypeEaddress)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertext(ct, TypeEaddress)
}

// generateEncryptedRandom generates random encrypted value using real TFHE library
func generateEncryptedRandom(ctType uint8, caller common.Address) common.Hash {
	// Use caller address as part of seed for determinism
	seed := new(big.Int).SetBytes(caller.Bytes()).Uint64()
	ct := tfheRandom(ctType, seed)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertext(ct, ctType)
}

// performFHEScalarOperation executes FHE scalar operations using real TFHE library
func performFHEScalarOperation(op string, handle common.Hash, scalar *big.Int, caller common.Address) common.Hash {
	ct, ctType, ok := getCiphertext(handle)
	if !ok {
		return common.Hash{}
	}

	var result []byte
	switch op {
	case "scalarAdd":
		result = tfheScalarAdd(ct, scalar.Uint64(), ctType)
	case "scalarSub":
		result = tfheScalarSub(ct, scalar.Uint64(), ctType)
	case "scalarMul":
		result = tfheScalarMul(ct, scalar.Uint64(), ctType)
	case "scalarDiv":
		result = tfheScalarDiv(ct, scalar.Uint64(), ctType)
	case "scalarRem":
		result = tfheScalarRem(ct, scalar.Uint64(), ctType)
	default:
		return common.Hash{}
	}

	if result == nil {
		return common.Hash{}
	}

	return storeCiphertext(result, ctType)
}

// performFHEShiftOperation executes FHE shift operations using real TFHE library
func performFHEShiftOperation(op string, handle common.Hash, shift int, caller common.Address) common.Hash {
	ct, ctType, ok := getCiphertext(handle)
	if !ok {
		return common.Hash{}
	}

	var result []byte
	switch op {
	case "shl":
		result = tfheShl(ct, shift, ctType)
	case "shr":
		result = tfheShr(ct, shift, ctType)
	case "rotl":
		result = tfheRotl(ct, shift, ctType)
	case "rotr":
		result = tfheRotr(ct, shift, ctType)
	default:
		return common.Hash{}
	}

	if result == nil {
		return common.Hash{}
	}

	return storeCiphertext(result, ctType)
}

// performFHECast executes type casting using real TFHE library
func performFHECast(handle common.Hash, toType uint8, caller common.Address) common.Hash {
	ct, fromType, ok := getCiphertext(handle)
	if !ok {
		return common.Hash{}
	}

	result := tfheCast(ct, fromType, toType)
	if result == nil {
		return common.Hash{}
	}

	return storeCiphertext(result, toType)
}

// encryptBigIntValue encrypts a big.Int value for types > 64 bits
func encryptBigIntValue(value *big.Int, ctType uint8, caller common.Address) common.Hash {
	ct := tfheTrivialEncrypt(value, ctType)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertext(ct, ctType)
}

// performFHEDecrypt decrypts a ciphertext (returns as big.Int bytes)
func performFHEDecrypt(handle common.Hash, caller common.Address) *big.Int {
	ct, ctType, ok := getCiphertext(handle)
	if !ok {
		return big.NewInt(0)
	}

	return tfheDecrypt(ct, ctType)
}

// performFHEVerify verifies and stores an input ciphertext
func performFHEVerify(inputHandle []byte, ctType uint8, caller common.Address) common.Hash {
	if !tfheVerify(inputHandle, ctType) {
		return common.Hash{}
	}
	return storeCiphertext(inputHandle, ctType)
}

// performFHESealOutput seals output for a specific public key
func performFHESealOutput(handle common.Hash, publicKey []byte, caller common.Address) []byte {
	ct, ctType, ok := getCiphertext(handle)
	if !ok {
		return nil
	}
	return tfheSealOutput(ct, publicKey, ctType)
}
