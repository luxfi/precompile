// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package x25519 implements X25519 Diffie-Hellman key exchange precompile.
// Address: 0x0000000000000000000000000000000000009203 (Privacy range)
//
// Operations:
//   - 0x01: ScalarMult — 32-byte private scalar + 32-byte public point -> 32-byte shared secret
//   - 0x02: Basepoint  — 32-byte private scalar -> 32-byte public key (mult with basepoint)
//
// Used by: TLS 1.3, Signal Protocol, age encryption, WireGuard.
//
// WARNING: x25519 ScalarMult accepts a scalar in calldata. This scalar is PUBLIC
// on-chain. Do NOT use this precompile with long-term identity keys. Only use
// with ephemeral session keys or public scalars where public visibility is
// acceptable (e.g., verifiable randomness from a hash, commit-reveal DH where
// the scalar is derived from a public seed, or one-time key agreement where
// leaking the scalar after use is harmless).
//
// The aes, chacha20, and ecies precompiles were deleted for the same reason:
// symmetric keys and private keys in calldata are irrecoverably exposed. This
// precompile is retained because X25519 key exchange with ephemeral scalars is
// a valid on-chain pattern — the shared secret is not in calldata, only the
// (disposable) scalar is.
package x25519

import (
	"errors"

	"golang.org/x/crypto/curve25519"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000009203")

	X25519Precompile = &x25519Precompile{}

	_ contract.StatefulPrecompiledContract = &x25519Precompile{}

	ErrInvalidInput = errors.New("invalid x25519 input")
	ErrInvalidOp    = errors.New("invalid x25519 operation")
	ErrDHFailed     = errors.New("x25519 scalar multiplication failed")
)

const (
	OpScalarMult = 0x01
	OpBasepoint  = 0x02

	GasScalarMult = 3000
	GasBasepoint  = 3000
)

type x25519Precompile struct{}

func (p *x25519Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}
	switch input[0] {
	case OpScalarMult:
		return GasScalarMult
	case OpBasepoint:
		return GasBasepoint
	default:
		return 0
	}
}

func (p *x25519Precompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	gasCost := p.RequiredGas(input)
	gas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}
	if len(input) < 1 {
		return nil, gas, ErrInvalidInput
	}

	switch input[0] {
	case OpScalarMult:
		return p.scalarMult(input[1:], gas)
	case OpBasepoint:
		return p.basepoint(input[1:], gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

func (p *x25519Precompile) scalarMult(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 64 {
		return nil, gas, ErrInvalidInput
	}
	scalar := data[:32]
	point := data[32:64]

	shared, err := curve25519.X25519(scalar, point)
	if err != nil {
		return nil, gas, ErrDHFailed
	}
	return shared, gas, nil
}

func (p *x25519Precompile) basepoint(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < 32 {
		return nil, gas, ErrInvalidInput
	}
	scalar := data[:32]

	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, gas, ErrDHFailed
	}
	return pub, gas, nil
}
