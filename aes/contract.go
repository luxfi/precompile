// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aes implements AES-256-GCM authenticated encryption precompile.
// Address: 0x0000000000000000000000000000000000009210 (Crypto Ops range)
//
// Operations:
//   - 0x01: Encrypt — key(32) + nonce(12) + aad_len(2) + aad + plaintext -> ciphertext + tag(16)
//   - 0x02: Decrypt — key(32) + nonce(12) + aad_len(2) + aad + ciphertext+tag -> plaintext
//
// Used by: encrypted storage, on-chain data rooms, FHE key wrapping.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	ContractAddress = common.HexToAddress("0x0000000000000000000000000000000000009210")

	AESPrecompile = &aesPrecompile{}

	_ contract.StatefulPrecompiledContract = &aesPrecompile{}

	ErrInvalidInput = errors.New("invalid AES input")
	ErrInvalidOp    = errors.New("invalid AES operation")
	ErrDecryptFail  = errors.New("AES-GCM decryption failed: authentication tag mismatch")
)

const (
	OpEncrypt = 0x01
	OpDecrypt = 0x02

	KeyLen   = 32
	NonceLen = 12
	TagLen   = 16

	GasEncryptBase = 3000
	GasDecryptBase = 3000
	GasPerByte     = 5
)

type aesPrecompile struct{}

func (p *aesPrecompile) RequiredGas(input []byte) uint64 {
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

func (p *aesPrecompile) Run(
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

func (p *aesPrecompile) encrypt(data []byte, gas uint64) ([]byte, uint64, error) {
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

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, gas, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, gas, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, gas, nil
}

func (p *aesPrecompile) decrypt(data []byte, gas uint64) ([]byte, uint64, error) {
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

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, gas, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, gas, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, gas, ErrDecryptFail
	}
	return plaintext, gas, nil
}
