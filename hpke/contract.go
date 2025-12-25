// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hpke implements RFC 9180 HPKE (Hybrid Public Key Encryption) precompile
// for the Lux EVM. Address: 0x031A
//
// See LP-3662 for full specification.
package hpke

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompiles/contract"
)

var (
	// ContractAddress is the address of the HPKE precompile
	ContractAddress = common.HexToAddress("0x000000000000000000000000000000000000031A")

	// Singleton instance
	HPKEPrecompile = &hpkePrecompile{}

	_ contract.StatefulPrecompiledContract = &hpkePrecompile{}

	ErrInvalidInput       = errors.New("invalid HPKE input")
	ErrInvalidCipherSuite = errors.New("invalid cipher suite")
	ErrDecryptionFailed   = errors.New("decryption failed")
	ErrInvalidContext     = errors.New("invalid context handle")
)

// Operation selectors
const (
	OpSetupBaseS     = 0x01
	OpSetupBaseR     = 0x02
	OpSetupPSKS      = 0x03
	OpSetupPSKR      = 0x04
	OpSetupAuthS     = 0x05
	OpSetupAuthR     = 0x06
	OpSetupAuthPSKS  = 0x07
	OpSetupAuthPSKR  = 0x08
	OpSeal           = 0x10
	OpOpen           = 0x11
	OpExport         = 0x12
	OpSingleShotSeal = 0x20
	OpSingleShotOpen = 0x21
)

// KEM IDs
const (
	KEMP256   = 0x0010
	KEMP384   = 0x0011
	KEMP521   = 0x0012
	KEMX25519 = 0x0020
)

// Gas costs
const (
	GasKEMEncapsP256   = 6000
	GasKEMEncapsP384   = 9000
	GasKEMEncapsP521   = 15000
	GasKEMEncapsX25519 = 3000
	GasKDFExtract      = 200
	GasAEADBase        = 400
	GasAEADPer64Bytes  = 8
	GasSetupBase       = 500
)

type hpkePrecompile struct{}

// Address returns the address of the HPKE precompile
func (p *hpkePrecompile) Address() common.Address {
	return ContractAddress
}

func kemGas(kemID uint16) uint64 {
	switch kemID {
	case KEMP256:
		return GasKEMEncapsP256
	case KEMP384:
		return GasKEMEncapsP384
	case KEMP521:
		return GasKEMEncapsP521
	case KEMX25519:
		return GasKEMEncapsX25519
	default:
		return GasKEMEncapsX25519
	}
}

// RequiredGas calculates gas for HPKE operations
func (p *hpkePrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 1 {
		return 0
	}

	op := input[0]

	switch op {
	case OpSetupBaseS, OpSetupBaseR:
		if len(input) < 7 {
			return GasKEMEncapsX25519 + GasKDFExtract + GasSetupBase
		}
		kemID := uint16(input[1])<<8 | uint16(input[2])
		return kemGas(kemID) + GasKDFExtract + GasSetupBase

	case OpSetupAuthS, OpSetupAuthR:
		if len(input) < 7 {
			return 2*GasKEMEncapsX25519 + GasKDFExtract + 1000
		}
		kemID := uint16(input[1])<<8 | uint16(input[2])
		return 2*kemGas(kemID) + GasKDFExtract + 1000

	case OpSetupPSKS, OpSetupPSKR:
		if len(input) < 7 {
			return GasKEMEncapsX25519 + GasKDFExtract + 1000
		}
		kemID := uint16(input[1])<<8 | uint16(input[2])
		return kemGas(kemID) + GasKDFExtract + 1000

	case OpSeal, OpOpen:
		if len(input) < 35 {
			return GasAEADBase
		}
		dataLen := len(input) - 35
		return GasAEADBase + uint64(dataLen/64)*GasAEADPer64Bytes

	case OpSingleShotSeal, OpSingleShotOpen:
		if len(input) < 7 {
			return GasKEMEncapsX25519 + GasKDFExtract + GasAEADBase
		}
		kemID := uint16(input[1])<<8 | uint16(input[2])
		dataLen := len(input) - 100
		if dataLen < 0 {
			dataLen = 0
		}
		return kemGas(kemID) + GasKDFExtract + GasAEADBase + uint64(dataLen/64)*GasAEADPer64Bytes

	case OpExport:
		return 500

	default:
		return 0
	}
}

// Run executes the HPKE precompile
func (p *hpkePrecompile) Run(
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

	if len(input) < 1 {
		return nil, suppliedGas - gasCost, ErrInvalidInput
	}

	op := input[0]

	var result []byte
	var err error

	switch op {
	case OpSingleShotSeal:
		result, err = p.singleShotSeal(input[1:])
	case OpSingleShotOpen:
		result, err = p.singleShotOpen(input[1:])
	default:
		err = fmt.Errorf("unsupported operation: 0x%02x", op)
	}

	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	return result, suppliedGas - gasCost, nil
}

func (p *hpkePrecompile) parseSuite(input []byte) (hpke.Suite, error) {
	if len(input) < 6 {
		return hpke.Suite{}, ErrInvalidInput
	}

	kemID := uint16(input[0])<<8 | uint16(input[1])
	kdfID := uint16(input[2])<<8 | uint16(input[3])
	aeadID := uint16(input[4])<<8 | uint16(input[5])

	var kem hpke.KEM
	switch kemID {
	case KEMP256:
		kem = hpke.KEM_P256_HKDF_SHA256
	case KEMP384:
		kem = hpke.KEM_P384_HKDF_SHA384
	case KEMP521:
		kem = hpke.KEM_P521_HKDF_SHA512
	case KEMX25519:
		kem = hpke.KEM_X25519_HKDF_SHA256
	default:
		return hpke.Suite{}, ErrInvalidCipherSuite
	}

	var kdf hpke.KDF
	switch kdfID {
	case 0x0001:
		kdf = hpke.KDF_HKDF_SHA256
	case 0x0002:
		kdf = hpke.KDF_HKDF_SHA384
	case 0x0003:
		kdf = hpke.KDF_HKDF_SHA512
	default:
		return hpke.Suite{}, ErrInvalidCipherSuite
	}

	var aead hpke.AEAD
	switch aeadID {
	case 0x0001:
		aead = hpke.AEAD_AES128GCM
	case 0x0002:
		aead = hpke.AEAD_AES256GCM
	case 0x0003:
		aead = hpke.AEAD_ChaCha20Poly1305
	default:
		return hpke.Suite{}, ErrInvalidCipherSuite
	}

	return hpke.NewSuite(kem, kdf, aead), nil
}

func (p *hpkePrecompile) singleShotSeal(input []byte) ([]byte, error) {
	suite, err := p.parseSuite(input)
	if err != nil {
		return nil, err
	}

	offset := 6

	// Parse recipient public key length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	pkLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	if len(input) < offset+pkLen {
		return nil, ErrInvalidInput
	}
	recipientPk := input[offset : offset+pkLen]
	offset += pkLen

	// Parse info length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	infoLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	var info []byte
	if infoLen > 0 {
		if len(input) < offset+infoLen {
			return nil, ErrInvalidInput
		}
		info = input[offset : offset+infoLen]
		offset += infoLen
	}

	// Parse AAD length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	aadLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	var aad []byte
	if aadLen > 0 {
		if len(input) < offset+aadLen {
			return nil, ErrInvalidInput
		}
		aad = input[offset : offset+aadLen]
		offset += aadLen
	}

	// Plaintext is the rest
	plaintext := input[offset:]

	// Parse public key
	pk, err := suite.KEM.Scheme().UnmarshalBinaryPublicKey(recipientPk)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// Create sender and seal
	sender, err := suite.NewSender(pk, info)
	if err != nil {
		return nil, err
	}

	enc, sealer, err := sender.Setup(nil)
	if err != nil {
		return nil, err
	}

	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Return enc || ciphertext
	result := make([]byte, len(enc)+len(ciphertext))
	copy(result, enc)
	copy(result[len(enc):], ciphertext)

	return result, nil
}

func (p *hpkePrecompile) singleShotOpen(input []byte) ([]byte, error) {
	suite, err := p.parseSuite(input)
	if err != nil {
		return nil, err
	}

	offset := 6

	// Parse encapsulated key length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	encLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	if len(input) < offset+encLen {
		return nil, ErrInvalidInput
	}
	enc := input[offset : offset+encLen]
	offset += encLen

	// Parse recipient secret key length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	skLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	if len(input) < offset+skLen {
		return nil, ErrInvalidInput
	}
	recipientSk := input[offset : offset+skLen]
	offset += skLen

	// Parse info length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	infoLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	var info []byte
	if infoLen > 0 {
		if len(input) < offset+infoLen {
			return nil, ErrInvalidInput
		}
		info = input[offset : offset+infoLen]
		offset += infoLen
	}

	// Parse AAD length
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	aadLen := int(input[offset])<<8 | int(input[offset+1])
	offset += 2

	var aad []byte
	if aadLen > 0 {
		if len(input) < offset+aadLen {
			return nil, ErrInvalidInput
		}
		aad = input[offset : offset+aadLen]
		offset += aadLen
	}

	// Ciphertext is the rest
	ciphertext := input[offset:]

	// Parse secret key
	sk, err := suite.KEM.Scheme().UnmarshalBinaryPrivateKey(recipientSk)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Create receiver and open
	receiver, err := suite.NewReceiver(sk, info)
	if err != nil {
		return nil, err
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, err
	}

	plaintext, err := opener.Open(ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
