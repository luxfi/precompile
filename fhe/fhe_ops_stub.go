// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !gpu

package fhe

import "math/big"

// Stub implementations for non-GPU builds
// These return nil/empty results - GPU required for actual FHE operations

func fheTypeToGPUBits(fheType uint8) int {
	return int(fheType) * 8
}

func tfheAdd(lhs, rhs []byte, fheType uint8) []byte {
	return nil // GPU required
}

func tfheSub(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheMul(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheDiv(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheRem(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheLt(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheLe(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheGt(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheGe(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheEq(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheNe(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheAnd(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheOr(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheXor(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheNot(ct []byte, fheType uint8) []byte {
	return nil
}

func tfheNeg(ct []byte, fheType uint8) []byte {
	return nil
}

func tfheSelect(control, ifTrue, ifFalse []byte, fheType uint8) []byte {
	return nil
}

func tfheCast(ct []byte, fromType, toType uint8) []byte {
	return nil
}

func tfheMin(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheMax(lhs, rhs []byte, fheType uint8) []byte {
	return nil
}

func tfheVerify(ct []byte, fheType uint8) bool {
	return false
}

func tfheDecrypt(ct []byte, fheType uint8) *big.Int {
	return nil
}

func tfheTrivialEncrypt(plaintext *big.Int, toType uint8) []byte {
	return nil
}

func tfheSealOutput(ct, pk []byte, fheType uint8) []byte {
	return nil
}

func tfheRandom(fheType uint8, seed uint64) []byte {
	return nil
}

func tfheGetNetworkPublicKey() []byte {
	return nil
}

func tfheShl(ct []byte, shift int, fheType uint8) []byte {
	return nil
}

func tfheShr(ct []byte, shift int, fheType uint8) []byte {
	return nil
}

func tfheRotl(ct []byte, shift int, fheType uint8) []byte {
	return nil
}

func tfheRotr(ct []byte, shift int, fheType uint8) []byte {
	return nil
}

func tfheScalarAdd(ct []byte, scalar uint64, fheType uint8) []byte {
	return nil
}

func tfheScalarSub(ct []byte, scalar uint64, fheType uint8) []byte {
	return nil
}

func tfheScalarMul(ct []byte, scalar uint64, fheType uint8) []byte {
	return nil
}

func tfheScalarDiv(ct []byte, scalar uint64, fheType uint8) []byte {
	return nil
}

func tfheScalarRem(ct []byte, scalar uint64, fheType uint8) []byte {
	return nil
}

func tfheMaxValue(fheType uint8) []byte {
	return nil
}
