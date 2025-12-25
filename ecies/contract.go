// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ecies implements ECIES (Elliptic Curve Integrated Encryption Scheme)
// precompile for the Lux EVM. Address: 0x031B
//
// Compatible with go-ethereum's ECIES implementation used in devp2p.
// See LP-3663 for full specification.
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompiles/contract"
)

var (
	// ContractAddress is the address of the ECIES precompile
	ContractAddress = common.HexToAddress("0x000000000000000000000000000000000000031B")

	// Singleton instance
	ECIESPrecompile = &eciesPrecompile{}

	_ contract.StatefulPrecompiledContract = &eciesPrecompile{}

	ErrInvalidInput      = errors.New("invalid ECIES input")
	ErrInvalidCurve      = errors.New("invalid curve identifier")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrDecryptionFailed  = errors.New("decryption failed: MAC verification failed")
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")
)

// Operation selectors
const (
	OpEncrypt          = 0x01
	OpDecrypt          = 0x02
	OpEncryptWithParams = 0x03
	OpDecryptWithParams = 0x04
	OpECDH             = 0x10
	OpDeriveKey        = 0x11
)

// Curve IDs
const (
	CurveSecp256k1 = 0x01
	CurveP256      = 0x02
	CurveP384      = 0x03
)

// Gas costs
const (
	GasEncryptSecp256k1Base = 6000
	GasEncryptP256Base      = 5000
	GasEncryptP384Base      = 8000
	GasDecryptSecp256k1Base = 6500
	GasDecryptP256Base      = 5500
	GasDecryptP384Base      = 8500
	GasECDHSecp256k1        = 3000
	GasECDHP256             = 2500
	GasECDHP384             = 4000
	GasPerByte              = 10
)

type eciesPrecompile struct{}

// Address returns the address of the ECIES precompile
func (p *eciesPrecompile) Address() common.Address {
	return ContractAddress
}

// RequiredGas calculates gas for ECIES operations
func (p *eciesPrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 2 {
		return 0
	}

	op := input[0]
	curveID := input[1]

	var baseGas uint64

	switch op {
	case OpEncrypt, OpEncryptWithParams:
		switch curveID {
		case CurveSecp256k1:
			baseGas = GasEncryptSecp256k1Base
		case CurveP256:
			baseGas = GasEncryptP256Base
		case CurveP384:
			baseGas = GasEncryptP384Base
		default:
			return 0
		}
		dataLen := len(input) - 70
		if dataLen < 0 {
			dataLen = 0
		}
		return baseGas + uint64(dataLen)*GasPerByte

	case OpDecrypt, OpDecryptWithParams:
		switch curveID {
		case CurveSecp256k1:
			baseGas = GasDecryptSecp256k1Base
		case CurveP256:
			baseGas = GasDecryptP256Base
		case CurveP384:
			baseGas = GasDecryptP384Base
		default:
			return 0
		}
		dataLen := len(input) - 40
		if dataLen < 0 {
			dataLen = 0
		}
		return baseGas + uint64(dataLen)*GasPerByte

	case OpECDH:
		switch curveID {
		case CurveSecp256k1:
			return GasECDHSecp256k1
		case CurveP256:
			return GasECDHP256
		case CurveP384:
			return GasECDHP384
		default:
			return 0
		}

	default:
		return 0
	}
}

// Run executes the ECIES precompile
func (p *eciesPrecompile) Run(
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

	if len(input) < 2 {
		return nil, suppliedGas - gasCost, ErrInvalidInput
	}

	op := input[0]
	curveID := input[1]

	var result []byte
	var err error

	switch op {
	case OpEncrypt:
		result, err = p.encrypt(curveID, input[2:])
	case OpDecrypt:
		result, err = p.decrypt(curveID, input[2:])
	case OpECDH:
		result, err = p.ecdh(curveID, input[2:])
	default:
		err = fmt.Errorf("unsupported operation: 0x%02x", op)
	}

	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	return result, suppliedGas - gasCost, nil
}

func (p *eciesPrecompile) getCurve(id byte) (elliptic.Curve, error) {
	switch id {
	case CurveSecp256k1:
		return secp256k1.S256(), nil
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	default:
		return nil, ErrInvalidCurve
	}
}

func (p *eciesPrecompile) encrypt(curveID byte, input []byte) ([]byte, error) {
	curve, err := p.getCurve(curveID)
	if err != nil {
		return nil, err
	}

	// Parse recipient public key (uncompressed, 65 bytes)
	if len(input) < 65 {
		return nil, ErrInvalidInput
	}

	recipientPk := input[:65]

	// Parse s1 length and s1
	offset := 65
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	s1Len := int(binary.BigEndian.Uint16(input[offset:]))
	offset += 2

	var s1 []byte
	if s1Len > 0 {
		if len(input) < offset+s1Len {
			return nil, ErrInvalidInput
		}
		s1 = input[offset : offset+s1Len]
		offset += s1Len
	}

	// Plaintext is the rest
	plaintext := input[offset:]

	// Parse public key
	x, y := elliptic.Unmarshal(curve, recipientPk)
	if x == nil {
		return nil, ErrInvalidPublicKey
	}

	// Generate ephemeral key pair
	ephPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	// ECDH: compute shared secret
	sx, _ := curve.ScalarMult(x, y, ephPriv.D.Bytes())
	sharedSecret := sx.Bytes()

	// Ensure shared secret is correct length
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(sharedSecret) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	// Key derivation using Concat KDF (NIST SP 800-56A)
	keyLen := 32 // AES-256
	macKeyLen := 32
	derivedKey := concatKDF(sha256.New(), sharedSecret, s1, keyLen+macKeyLen)

	encKey := derivedKey[:keyLen]
	macKey := derivedKey[keyLen:]

	// Encrypt with AES-CTR
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(iv)+len(plaintext))
	copy(ciphertext, iv)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Compute MAC
	mac := hmac.New(sha256.New, macKey)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	// Serialize ephemeral public key
	ephPub := elliptic.Marshal(curve, ephPriv.PublicKey.X, ephPriv.PublicKey.Y)

	// Output: ephemeral_pk || ciphertext || mac
	result := make([]byte, len(ephPub)+len(ciphertext)+len(tag))
	copy(result, ephPub)
	copy(result[len(ephPub):], ciphertext)
	copy(result[len(ephPub)+len(ciphertext):], tag)

	return result, nil
}

func (p *eciesPrecompile) decrypt(curveID byte, input []byte) ([]byte, error) {
	curve, err := p.getCurve(curveID)
	if err != nil {
		return nil, err
	}

	// Parse recipient private key (32 bytes)
	if len(input) < 32 {
		return nil, ErrInvalidInput
	}
	recipientSk := input[:32]

	// Parse s1 length and s1
	offset := 32
	if len(input) < offset+2 {
		return nil, ErrInvalidInput
	}
	s1Len := int(binary.BigEndian.Uint16(input[offset:]))
	offset += 2

	var s1 []byte
	if s1Len > 0 {
		if len(input) < offset+s1Len {
			return nil, ErrInvalidInput
		}
		s1 = input[offset : offset+s1Len]
		offset += s1Len
	}

	// Ciphertext is the rest: ephemeral_pk || encrypted || mac
	ciphertext := input[offset:]

	// Determine public key size (65 for uncompressed)
	pubKeySize := 65
	macSize := 32

	if len(ciphertext) < pubKeySize+aes.BlockSize+macSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract components
	ephPub := ciphertext[:pubKeySize]
	encryptedWithIV := ciphertext[pubKeySize : len(ciphertext)-macSize]
	expectedMac := ciphertext[len(ciphertext)-macSize:]

	// Parse ephemeral public key
	ephX, ephY := elliptic.Unmarshal(curve, ephPub)
	if ephX == nil {
		return nil, ErrInvalidPublicKey
	}

	// ECDH: compute shared secret
	sx, _ := curve.ScalarMult(ephX, ephY, recipientSk)
	sharedSecret := sx.Bytes()

	// Ensure shared secret is correct length
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(sharedSecret) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	// Key derivation
	keyLen := 32
	macKeyLen := 32
	derivedKey := concatKDF(sha256.New(), sharedSecret, s1, keyLen+macKeyLen)

	encKey := derivedKey[:keyLen]
	macKey := derivedKey[keyLen:]

	// Verify MAC
	mac := hmac.New(sha256.New, macKey)
	mac.Write(encryptedWithIV)
	computedMac := mac.Sum(nil)

	if subtle.ConstantTimeCompare(expectedMac, computedMac) != 1 {
		return nil, ErrDecryptionFailed
	}

	// Decrypt with AES-CTR
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	iv := encryptedWithIV[:aes.BlockSize]
	encrypted := encryptedWithIV[aes.BlockSize:]

	plaintext := make([]byte, len(encrypted))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, encrypted)

	return plaintext, nil
}

func (p *eciesPrecompile) ecdh(curveID byte, input []byte) ([]byte, error) {
	curve, err := p.getCurve(curveID)
	if err != nil {
		return nil, err
	}

	// Parse private key (32 bytes)
	if len(input) < 32 {
		return nil, ErrInvalidInput
	}
	privateKey := input[:32]

	// Parse public key (rest)
	publicKey := input[32:]

	// Unmarshal public key
	x, y := elliptic.Unmarshal(curve, publicKey)
	if x == nil {
		return nil, ErrInvalidPublicKey
	}

	// Compute shared secret
	sx, _ := curve.ScalarMult(x, y, privateKey)

	// Return x-coordinate as shared secret
	byteLen := (curve.Params().BitSize + 7) / 8
	sharedSecret := make([]byte, byteLen)
	sxBytes := sx.Bytes()
	copy(sharedSecret[byteLen-len(sxBytes):], sxBytes)

	return sharedSecret, nil
}

// NIST SP 800-56A Concatenation Key Derivation Function
func concatKDF(h func() hash.Hash, z, otherInfo []byte, keyLen int) []byte {
	hashSize := h().Size()
	reps := (keyLen + hashSize - 1) / hashSize

	derivedKey := make([]byte, 0, reps*hashSize)

	for counter := uint32(1); counter <= uint32(reps); counter++ {
		hasher := h()
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		hasher.Write(counterBytes)
		hasher.Write(z)
		hasher.Write(otherInfo)
		derivedKey = hasher.Sum(derivedKey)
	}

	return derivedKey[:keyLen]
}
