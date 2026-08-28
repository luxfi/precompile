// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto"
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

// Block-gas-budget calibration constants. The single source of truth for
// the gas-cost re-derivation rests on three numbers measured on commodity
// validator hardware (Apple M1 Max, the high end of the ARM commodity
// range; AMD64 commodity validators are within 2x):
//
//	BlockComputeBudgetMs    — wall-clock the chain will tolerate spending
//	                          inside FHE precompile handlers per block,
//	                          out of the 2 s block target. Half a block.
//	GasPerMsAt12MGasLimit   — at gasLimit=12_000_000 (real C-Chain mainnet,
//	                          see ~/work/lux/genesis/configs/mainnet/cchain.json),
//	                          this is how many gas units one ms of FHE
//	                          wall-clock maps to. Derived: 12_000_000 / 1000 = 12_000.
//	                          Any per-op gas cost is wall-clock-ms × this.
//	MinSafeGasMulRatio      — the activation gate refuses if
//	                          gasLimit / GasMul < this. With both numerator
//	                          and denominator measured, this enforces that
//	                          at most one Mul fits per block; the Mul wall-
//	                          clock alone already overruns the per-block
//	                          budget by 78×, so we set the ratio at 1 —
//	                          i.e. the gasLimit must be at least one full
//	                          Mul's worth of gas. Anything less and a single
//	                          tx with a single Mul instantly halts the chain
//	                          because the validator cannot finish its work
//	                          before the next block target.
//
// To re-derive on a new arch, run:
//
//	go test -run NONE -bench BenchmarkFHE -benchtime=1x ./precompile/fhe/...
//
// and update the wall-clock constants below.
const (
	// BlockComputeBudgetMs is the per-block wall-clock budget allotted
	// to FHE precompile handlers. Half of the 2 s block target.
	BlockComputeBudgetMs uint64 = 1_000

	// MainnetCChainGasLimit is the real Lux primary-network C-Chain
	// genesis gasLimit. See ~/work/lux/genesis/configs/mainnet/cchain.json
	// line 16 (feeConfig.gasLimit).
	MainnetCChainGasLimit uint64 = 12_000_000

	// PostFeeManagerGasLimit is the post-feeConfigManagerConfig gasLimit
	// (raised admin-side). See ~/work/lux/genesis/configs/mainnet/upgrade.json
	// line 9.
	PostFeeManagerGasLimit uint64 = 20_000_000

	// ReferenceGasLimit30M is the historic 30M reference used in
	// pre-2026 adversarial tests. Kept as a comparator for back-tests.
	ReferenceGasLimit30M uint64 = 30_000_000

	// MinSafeGasMulRatio is the minimum gasLimit/GasMul ratio the FHE
	// module.Configure activation gate will accept. Set to 1 because
	// even a single Mul takes 240 s wall-clock on commodity ARM —
	// allowing more than one Mul per block guarantees a chain halt.
	MinSafeGasMulRatio uint64 = 1
)

// Measured wall-clock per op (ms) on Apple M1 Max — high-end ARM commodity
// validator hardware. Re-measured 2026-06-01 via BenchmarkFHE* in bench_test.go.
//
// AMD64 commodity validators (Ryzen 7950X, EPYC 9654) measure within 2x of
// these numbers; the gas constants are sized off the slower ARM measurement
// to keep the chain safe on the worst-case validator. Re-measure on each
// arch and bump per-arch if the worst-case moves.
const (
	WallClockMsAddUint8 uint64 = 25_000  // measured 24.58 s (TFHE PN11QP54, FheUint8)
	WallClockMsMulUint8 uint64 = 240_000 // measured 239.99 s (TFHE PN11QP54, FheUint8)
)

// Gas costs for FHE operations.
//
// All costs are derived as wall-clock-ms × (MainnetCChainGasLimit /
// BlockComputeBudgetMs) = wall-clock-ms × 12_000. This sizes every op
// so that block-gas-limit / per-op-gas ≤ block-budget-ms / per-op-ms,
// i.e. the chain cannot include more ops in a block than will fit in
// the wall-clock budget.
//
// The resulting numbers vastly exceed the 12M block gas limit, which
// means in practice the FHE precompile is DISABLED on mainnet C-Chain
// at current TFHE perf. The activation gate in module.Configure
// enforces this explicitly by refusing fheConfig under a too-small
// gasLimit. See FHE_PRECOMPILE_DOS_AUDIT.md (file removed from tree
// per project rules — see precompile_dos_audit.go for the in-tree
// audit table).
//
// To unblock activation, two things must happen in tandem:
//  1. Wall-clock per op must drop by ≥ 78× (e.g. via the lux-private/
//     gpu-kernels TFHE-PBS fast path landing in the FHE evaluator;
//     see memory/vulkan_tfhe_pbs_fast_path.md — 20.4x is reported,
//     so 78x is several optimization passes away).
//  2. Chain gasLimit must be raised via feeConfigManagerConfig admin
//     so that gasLimit / GasMul ≥ MinSafeGasMulRatio.
const (
	// Bootstrap-dominated arithmetic ops.
	GasAdd uint64 = WallClockMsAddUint8 * 12_000              // 180_000_000
	GasSub uint64 = GasAdd                                    // same algorithm
	GasMul uint64 = WallClockMsMulUint8 * 12_000              // 936_000_000
	GasDiv uint64 = (WallClockMsMulUint8 * 12_000) * 70 / 100 // 655_200_000 — binary long div ~0.7x mul
	GasRem uint64 = GasDiv                                    // same algorithm
	GasNeg uint64 = GasAdd                                    // single subtraction from zero

	// Comparison ops (O(n) bootstraps; measured ratio ≈ Add).
	GasEq uint64 = GasAdd
	GasNe uint64 = GasAdd
	GasGt uint64 = GasAdd
	GasGe uint64 = GasAdd
	GasLt uint64 = GasAdd
	GasLe uint64 = GasAdd

	// Min/Max = compare + select.
	GasMin uint64 = GasAdd * 2
	GasMax uint64 = GasAdd * 2

	// Select = mux on encrypted bit; cheaper than full compare.
	GasSelect uint64 = GasAdd

	// Bitwise (per-bit bootstrap; cheaper than arithmetic but still bootstrap-bound).
	// Sized off Add scaled down ~6× — bench needed before lowering further.
	GasAnd uint64 = GasAdd / 6 // 30_000_000
	GasOr  uint64 = GasAnd
	GasXor uint64 = GasAnd
	GasNot uint64 = GasAnd / 2 // single complement, ~half the work

	// Shifts: O(n) muxes by shift amount.
	GasShl  uint64 = GasAdd
	GasShr  uint64 = GasAdd
	GasRotl uint64 = GasAdd
	GasRotr uint64 = GasAdd

	// Trivial encrypt / decrypt-request are cheap state operations,
	// not bootstraps. Kept at modest floor.
	GasEncrypt        uint64 = 50_000
	GasDecryptRequest uint64 = 10_000

	// Rand and Require involve a bootstrap operation.
	GasRand    uint64 = GasAdd
	GasRequire uint64 = GasAdd

	// Cast is bit-shuffling on existing ciphertext (no bootstrap).
	GasCast uint64 = 30_000
)

var (
	ErrInvalidInput    = contract.ErrInvalidInput
	ErrTypeMismatch    = errors.New("ciphertext type mismatch")
	ErrOperationFailed = errors.New("FHE operation failed")
	ErrNotImplemented  = errors.New("operation not implemented")
	// ErrInsufficientGas wraps contract.ErrOutOfGas so that callers using
	// errors.Is(err, contract.ErrOutOfGas) on any FHE gas failure get the
	// expected match — consistent with every other precompile in the tree.
	ErrInsufficientGas   = fmt.Errorf("insufficient gas for FHE operation: %w", contract.ErrOutOfGas)
	ErrInvalidCiphertext = errors.New("invalid ciphertext handle")

	// ErrACLUnauthorized is returned when a caller requests an operation on a
	// ciphertext handle it is not authorized for (it is not the owner). The
	// caller is rejected outright — it is never handed any plaintext-shaped
	// output.
	ErrACLUnauthorized = errors.New("FHE ACL: caller not authorized for ciphertext handle")

	// ErrThresholdDecryptionRequired is the fail-closed result of decrypt and
	// sealOutput. The precompile holds NO secret key — plaintext can be
	// recovered ONLY through the F-Chain (ThresholdVM) threshold-decryption
	// ceremony, where no single party can decrypt. That async Warp round-trip
	// (requestDecryption → threshold combine → fulfill) is not yet wired into
	// this precompile, so these ops fail closed rather than ever returning
	// plaintext from a local key. See LP-134.
	ErrThresholdDecryptionRequired = errors.New("FHE decrypt requires F-Chain threshold ceremony (no local secret key)")
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

	// Universal gas-exhaustion floor: even before we route to a handler
	// (which knows the precise per-op cost), a caller that supplied zero
	// gas cannot afford any FHE operation. Surface it as the canonical
	// contract.ErrOutOfGas via the ErrInsufficientGas wrapper so callers
	// using errors.Is(err, contract.ErrOutOfGas) catch the rejection at
	// the same chokepoint as per-handler exhaustion.
	if suppliedGas == 0 {
		return nil, 0, ErrInsufficientGas
	}

	// Every FHE op reads or writes ciphertext storage via the StateDB. The
	// precompile is meaningless without one — bail out cleanly rather than
	// nil-deref inside performFHEOperation when a test harness or external
	// caller invokes Run with a nil accessibleState.
	if accessibleState == nil || accessibleState.GetStateDB() == nil {
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
	result := performFHEOperation(state.GetStateDB(), "add", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "sub", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "mul", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "lt", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "gt", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "eq", handle1, handle2, caller)

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

	result := performFHESelect(state.GetStateDB(), condition, ifTrue, ifFalse, caller)

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

	result := encryptValue(state.GetStateDB(), value.Uint64(), TypeEuint64, caller)

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

	result := encryptAddress(state.GetStateDB(), addr, caller)

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

	result := performFHEOperation(state.GetStateDB(), "max", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "min", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "and", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "or", handle1, handle2, caller)

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

	result := performFHEUnaryOperation(state.GetStateDB(), "not", handle, caller)

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

	result := performFHEUnaryOperation(state.GetStateDB(), "neg", handle, caller)

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

	result := generateEncryptedRandom(state.GetStateDB(), ctType, caller)

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

	result := performFHEOperation(state.GetStateDB(), "div", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "rem", handle1, handle2, caller)

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

	result := performFHEScalarOperation(state.GetStateDB(), "scalarAdd", handle, scalar, caller)

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

	result := performFHEScalarOperation(state.GetStateDB(), "scalarSub", handle, scalar, caller)

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

	result := performFHEScalarOperation(state.GetStateDB(), "scalarMul", handle, scalar, caller)

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

	result := performFHEScalarOperation(state.GetStateDB(), "scalarDiv", handle, scalar, caller)

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

	result := performFHEScalarOperation(state.GetStateDB(), "scalarRem", handle, scalar, caller)

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

	result := performFHEOperation(state.GetStateDB(), "le", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "ge", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "ne", handle1, handle2, caller)

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

	result := performFHEOperation(state.GetStateDB(), "xor", handle1, handle2, caller)

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

	result := performFHEShiftOperation(state.GetStateDB(), "shl", handle, shift, caller)

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

	result := performFHEShiftOperation(state.GetStateDB(), "shr", handle, shift, caller)

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

	result := performFHEShiftOperation(state.GetStateDB(), "rotl", handle, shift, caller)

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

	result := performFHEShiftOperation(state.GetStateDB(), "rotr", handle, shift, caller)

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

	result := performFHECast(state.GetStateDB(), handle, toType, caller)

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

	result := encryptValue(state.GetStateDB(), boolVal, TypeEbool, caller)

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

	result := encryptValue(state.GetStateDB(), value.Uint64()&0xF, TypeEuint4, caller)

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

	result := encryptValue(state.GetStateDB(), value.Uint64()&0xFF, TypeEuint8, caller)

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

	result := encryptValue(state.GetStateDB(), value.Uint64()&0xFFFF, TypeEuint16, caller)

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

	result := encryptValue(state.GetStateDB(), value.Uint64()&0xFFFFFFFF, TypeEuint32, caller)

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

	result := encryptBigIntValue(state.GetStateDB(), value, TypeEuint128, caller)

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

	result := encryptBigIntValue(state.GetStateDB(), value, TypeEuint256, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

// === Utility Handlers ===

// handleDecrypt is the EVM gateway to F-Chain threshold decryption. It is NOT
// a local decrypt: the precompile holds no secret key. A decrypt is a gated
// REQUEST:
//
//  1. ACL gate — the caller must be authorized for the handle (owner). An
//     unauthorized caller is rejected with ErrACLUnauthorized; it never
//     receives plaintext-shaped output.
//  2. Threshold ceremony — plaintext is revealed only via the F-Chain
//     threshold-decryption protocol (requestDecryption → combine → fulfill),
//     where no single party can decrypt. That async Warp round-trip is not yet
//     wired into this precompile, so the request FAILS CLOSED here.
//
// Under no circumstances does this return plaintext recovered from a local key.
func (c *FHEContract) handleDecrypt(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasDecryptRequest {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	gasLeft := gas - GasDecryptRequest

	if !isAuthorized(state.GetStateDB(), handle, caller) {
		return nil, gasLeft, ErrACLUnauthorized
	}

	// Authorized — but decryption is a threshold ceremony on the F-Chain, not a
	// local operation. Fail closed until that integration lands. NEVER return
	// plaintext from a local key.
	return nil, gasLeft, ErrThresholdDecryptionRequired
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

	result := performFHEVerify(state.GetStateDB(), inputHandle, ctType, caller)

	return result.Bytes(), gas - GasEncrypt, nil
}

// handleSealOutput re-encrypts (seals) a ciphertext to a caller-provided public
// key so the caller can decrypt it off-chain. That re-encryption requires the
// network secret key (which the precompile does NOT hold) or a threshold
// re-encryption ceremony on the F-Chain (not yet wired). It is therefore
// ACL-gated and fails closed — it must NEVER hand the raw network-key
// ciphertext to the caller, which (combined with any key leak) would expose the
// plaintext. Same confidentiality posture as decrypt.
func (c *FHEContract) handleSealOutput(state contract.AccessibleState, caller common.Address, data []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	if gas < GasEncrypt {
		return nil, gas, ErrInsufficientGas
	}

	handle := common.BytesToHash(data[:32])
	gasLeft := gas - GasEncrypt

	if !isAuthorized(state.GetStateDB(), handle, caller) {
		return nil, gasLeft, ErrACLUnauthorized
	}

	// Authorized — but sealing to the caller's key is a threshold
	// re-encryption performed via the F-Chain, not locally. Fail closed.
	return nil, gasLeft, ErrThresholdDecryptionRequired
}

// Ciphertext storage layout in StateDB:
//
// For a ciphertext with handle H (= keccak256(ct_bytes)):
//   slot H          -> type (uint8) in low byte, length (uint32) in bytes 1-4
//   slot keccak(H, i) -> 32-byte chunk i of the ciphertext data
//
// This persists ciphertexts to the blockchain state trie, ensuring they survive
// across blocks and are identical on all validators.

// keccak256Hash computes Keccak256 and returns as common.Hash.
func keccak256Hash(data ...[]byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(data...))
}

// storeCiphertext persists a ciphertext to the EVM state trie and returns its handle.
func storeCiphertext(stateDB contract.StateDB, ct []byte, ctType uint8) common.Hash {
	handle := keccak256Hash(ct)

	// Pack type (1 byte) + length (4 bytes) into a single slot.
	var meta common.Hash
	meta[0] = ctType
	meta[1] = byte(len(ct) >> 24)
	meta[2] = byte(len(ct) >> 16)
	meta[3] = byte(len(ct) >> 8)
	meta[4] = byte(len(ct))
	stateDB.SetState(ContractAddress, handle, meta)

	// Store ciphertext bytes in 32-byte chunks.
	for i := 0; i < len(ct); i += 32 {
		slotIndex := common.BigToHash(big.NewInt(int64(i / 32)))
		slot := keccak256Hash(handle.Bytes(), slotIndex.Bytes())

		var chunk common.Hash
		end := i + 32
		if end > len(ct) {
			end = len(ct)
		}
		copy(chunk[:], ct[i:end])
		stateDB.SetState(ContractAddress, slot, chunk)
	}

	return handle
}

// getCiphertext reads a ciphertext from the EVM state trie.
func getCiphertext(stateDB contract.StateDB, handle common.Hash) ([]byte, uint8, bool) {
	meta := stateDB.GetState(ContractAddress, handle)

	// Zero meta means no ciphertext stored at this handle.
	if meta == (common.Hash{}) {
		return nil, 0, false
	}

	ctType := meta[0]
	ctLen := int(meta[1])<<24 | int(meta[2])<<16 | int(meta[3])<<8 | int(meta[4])

	if ctLen == 0 {
		return nil, 0, false
	}

	ct := make([]byte, ctLen)
	for i := 0; i < ctLen; i += 32 {
		slotIndex := common.BigToHash(big.NewInt(int64(i / 32)))
		slot := keccak256Hash(handle.Bytes(), slotIndex.Bytes())
		chunk := stateDB.GetState(ContractAddress, slot)

		end := i + 32
		if end > ctLen {
			end = ctLen
		}
		copy(ct[i:end], chunk[:end-i])
	}

	return ct, ctType, true
}

// performFHEOperation executes FHE binary operations on the chain's TFHE
// library. This is the single, deterministic source of truth for homomorphic
// evaluation across the validator set.
func performFHEOperation(stateDB contract.StateDB, op string, handle1, handle2 common.Hash, caller common.Address) common.Hash {
	lhs, lhsType, ok := getCiphertext(stateDB, handle1)
	if !ok {
		return common.Hash{}
	}
	rhs, _, ok := getCiphertext(stateDB, handle2)
	if !ok {
		return common.Hash{}
	}

	// CPU is the single source of truth: the chain's TFHE library. The removed
	// accel path computed BFV arithmetic (a DIFFERENT FHE scheme with an
	// incompatible ciphertext format -- its own comment admitted the format
	// conversion was "not yet implemented" and it used a nil relin key for
	// multiply). A BFV result stored as a TFHE ciphertext is meaningless under
	// the chain key AND differs from CPU validators -- a consensus split and a
	// state-corruption bug. Homomorphic evaluation must be bit-exact and
	// scheme-consistent across all validators.
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

	return storeCiphertextOwned(stateDB, result, resultType, caller)
}

// performFHESelect executes conditional selection using real TFHE library
func performFHESelect(stateDB contract.StateDB, condition, ifTrue, ifFalse common.Hash, caller common.Address) common.Hash {
	ctControl, _, ok := getCiphertext(stateDB, condition)
	if !ok {
		return common.Hash{}
	}
	ctTrue, trueType, ok := getCiphertext(stateDB, ifTrue)
	if !ok {
		return common.Hash{}
	}
	ctFalse, _, ok := getCiphertext(stateDB, ifFalse)
	if !ok {
		return common.Hash{}
	}

	result := tfheSelect(ctControl, ctTrue, ctFalse, trueType)
	if result == nil {
		return common.Hash{}
	}

	return storeCiphertextOwned(stateDB, result, trueType, caller)
}

// performFHEUnaryOperation executes FHE unary operations using real TFHE library
func performFHEUnaryOperation(stateDB contract.StateDB, op string, handle common.Hash, caller common.Address) common.Hash {
	ct, ctType, ok := getCiphertext(stateDB, handle)
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

	return storeCiphertextOwned(stateDB, result, ctType, caller)
}

// encryptValue encrypts a plaintext value using real TFHE library
func encryptValue(stateDB contract.StateDB, value uint64, ctType uint8, caller common.Address) common.Hash {
	ct := tfheTrivialEncrypt(new(big.Int).SetUint64(value), ctType)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertextOwned(stateDB, ct, ctType, caller)
}

// encryptAddress encrypts an address using real TFHE library
func encryptAddress(stateDB contract.StateDB, addr common.Address, caller common.Address) common.Hash {
	// Address is 160 bits
	value := new(big.Int).SetBytes(addr.Bytes())
	ct := tfheTrivialEncrypt(value, TypeEaddress)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertextOwned(stateDB, ct, TypeEaddress, caller)
}

// generateEncryptedRandom generates random encrypted value using real TFHE library
func generateEncryptedRandom(stateDB contract.StateDB, ctType uint8, caller common.Address) common.Hash {
	// Use caller address as part of seed for determinism
	seed := new(big.Int).SetBytes(caller.Bytes()).Uint64()
	ct := tfheRandom(ctType, seed)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertextOwned(stateDB, ct, ctType, caller)
}

// performFHEScalarOperation executes FHE scalar operations using real TFHE library
func performFHEScalarOperation(stateDB contract.StateDB, op string, handle common.Hash, scalar *big.Int, caller common.Address) common.Hash {
	ct, ctType, ok := getCiphertext(stateDB, handle)
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

	return storeCiphertextOwned(stateDB, result, ctType, caller)
}

// performFHEShiftOperation executes FHE shift operations using real TFHE library
func performFHEShiftOperation(stateDB contract.StateDB, op string, handle common.Hash, shift int, caller common.Address) common.Hash {
	ct, ctType, ok := getCiphertext(stateDB, handle)
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

	return storeCiphertextOwned(stateDB, result, ctType, caller)
}

// performFHECast executes type casting using real TFHE library
func performFHECast(stateDB contract.StateDB, handle common.Hash, toType uint8, caller common.Address) common.Hash {
	ct, fromType, ok := getCiphertext(stateDB, handle)
	if !ok {
		return common.Hash{}
	}

	result := tfheCast(ct, fromType, toType)
	if result == nil {
		return common.Hash{}
	}

	return storeCiphertextOwned(stateDB, result, toType, caller)
}

// encryptBigIntValue encrypts a big.Int value for types > 64 bits
func encryptBigIntValue(stateDB contract.StateDB, value *big.Int, ctType uint8, caller common.Address) common.Hash {
	ct := tfheTrivialEncrypt(value, ctType)
	if ct == nil {
		return common.Hash{}
	}
	return storeCiphertextOwned(stateDB, ct, ctType, caller)
}

// performFHEVerify verifies and stores an input ciphertext, recording the
// submitting caller as its owner.
func performFHEVerify(stateDB contract.StateDB, inputHandle []byte, ctType uint8, caller common.Address) common.Hash {
	if !tfheVerify(inputHandle, ctType) {
		return common.Hash{}
	}
	return storeCiphertextOwned(stateDB, inputHandle, ctType, caller)
}

// === Access Control List (ACL) ===
//
// Decryption and sealing are gated by ownership. Every ciphertext created
// through this precompile records its creator as owner; only the owner may
// request decryption/seal of that handle. There is no separate ACL precompile
// in this tree, so ownership is tracked here, co-located with the ciphertext
// storage it governs. Decrypt/seal additionally fail closed (threshold ceremony
// required), so this gate is defense-in-depth that also pre-positions the
// authorization check for when F-Chain threshold wiring lands.

// aclOwnerPrefix namespaces owner slots so they never collide with ciphertext
// data/meta slots in the precompile's state trie.
var aclOwnerPrefix = []byte("fhe/acl/owner/v1")

// ownerSlot is the deterministic state slot holding the owner of a handle.
func ownerSlot(handle common.Hash) common.Hash {
	return keccak256Hash(aclOwnerPrefix, handle.Bytes())
}

// setOwner records owner for handle on first creation. First-writer-wins: a
// content-addressed handle cannot have its ownership reassigned by a later
// creator producing identical ciphertext bytes.
func setOwner(stateDB contract.StateDB, handle common.Hash, owner common.Address) {
	slot := ownerSlot(handle)
	if stateDB.GetState(ContractAddress, slot) != (common.Hash{}) {
		return
	}
	stateDB.SetState(ContractAddress, slot, common.BytesToHash(owner.Bytes()))
}

// getOwner returns the recorded owner of handle, or the zero address if none.
func getOwner(stateDB contract.StateDB, handle common.Hash) common.Address {
	return common.BytesToAddress(stateDB.GetState(ContractAddress, ownerSlot(handle)).Bytes())
}

// isAuthorized reports whether caller may decrypt/seal handle. An unknown or
// unowned handle is never authorized (fail closed).
func isAuthorized(stateDB contract.StateDB, handle common.Hash, caller common.Address) bool {
	owner := getOwner(stateDB, handle)
	if owner == (common.Address{}) {
		return false
	}
	return owner == caller
}

// storeCiphertextOwned persists a ciphertext and records its creating caller as
// owner. Production ciphertext creation goes through this wrapper so every
// handle is ACL-owned at creation.
func storeCiphertextOwned(stateDB contract.StateDB, ct []byte, ctType uint8, owner common.Address) common.Hash {
	handle := storeCiphertext(stateDB, ct, ctType)
	if handle != (common.Hash{}) {
		setOwner(stateDB, handle, owner)
	}
	return handle
}
