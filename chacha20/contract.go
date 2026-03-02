// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package chacha20 implements ChaCha20-Poly1305 AEAD precompile.
// Address: 0x0000000000000000000000000000000000009211 (Crypto Ops range)
//
// Operations:
//   - 0x01: Encrypt — key(32) + nonce(12) + aad_len(2) + aad + plaintext -> ciphertext + tag(16)
//   - 0x02: Decrypt — key(32) + nonce(12) + aad_len(2) + aad + ciphertext+tag -> plaintext
//
// Used by: age encryption, WireGuard, TLS fallback.
package chacha20

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000009211")

	ChaCha20Precompile = &chacha20Precompile{}

	_ contract.StatefulPrecompiledContract = &chacha20Precompile{}

	ErrInvalidInput = errors.New("invalid chacha20 input")
	ErrInvalidOp    = errors.New("invalid chacha20 operation")
	ErrDecryptFail  = errors.New("chacha20-poly1305 decryption failed: authentication tag mismatch")
)

const (
	OpEncrypt = 0x01
	OpDecrypt = 0x02

	KeyLen   = 32
	NonceLen = 12
	TagLen   = 16

	GasEncryptBase = 2500
	GasDecryptBase = 2500
	GasPerByte     = 4
)

type chacha20Precompile struct{}

func (p *chacha20Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1+KeyLen+NonceLen+2 {
		return 0
	}
	dataLen := len(input) - 1 - KeyLen - NonceLen - 2
	switch input[0] {
	case OpEncrypt:
		return GasEncryptBase + uint64(dataLen)*GasPerByte
	case OpDecrypt:
		return GasDecryptBase + uint64(dataLen)*GasPerByte
	default:
		return 0
	}
}

func (p *chacha20Precompile) Run(
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
	case OpEncrypt:
		return p.encrypt(input[1:], gas)
	case OpDecrypt:
		return p.decrypt(input[1:], gas)
	default:
		return nil, gas, ErrInvalidOp
	}
}

func (p *chacha20Precompile) encrypt(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < KeyLen+NonceLen+2 {
		return nil, gas, ErrInvalidInput
	}
	key := data[:KeyLen]
	nonce := data[KeyLen : KeyLen+NonceLen]
	aadLen := int(data[KeyLen+NonceLen])<<8 | int(data[KeyLen+NonceLen+1])
	offset := KeyLen + NonceLen + 2

	if len(data) < offset+aadLen {
		return nil, gas, ErrInvalidInput
	}
	aad := data[offset : offset+aadLen]
	plaintext := data[offset+aadLen:]

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, gas, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, gas, nil
}

func (p *chacha20Precompile) decrypt(data []byte, gas uint64) ([]byte, uint64, error) {
	if len(data) < KeyLen+NonceLen+2 {
		return nil, gas, ErrInvalidInput
	}
	key := data[:KeyLen]
	nonce := data[KeyLen : KeyLen+NonceLen]
	aadLen := int(data[KeyLen+NonceLen])<<8 | int(data[KeyLen+NonceLen+1])
	offset := KeyLen + NonceLen + 2

	if len(data) < offset+aadLen+TagLen {
		return nil, gas, ErrInvalidInput
	}
	aad := data[offset : offset+aadLen]
	ciphertext := data[offset+aadLen:]

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, gas, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, gas, ErrDecryptFail
	}
	return plaintext, gas, nil
}
