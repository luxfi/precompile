// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ring implements LSAG (Linkable Spontaneous Anonymous Group) ring signatures
// precompile for the Lux EVM. Address: 0x9202 (Lux Crypto Privacy range)
//
// Ring signatures enable Q-Chain privacy transactions where the sender's identity
// is hidden among a set of possible signers.
// See LP-3664 for full specification.
package ring

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

var (
	// ContractAddress is the address of the Ring Signature precompile (Lux Crypto Privacy range 0x9202)
	ContractAddress = common.HexToAddress("0x9202")

	// Singleton instance
	RingSignaturePrecompile = &ringSignaturePrecompile{}

	_ contract.StatefulPrecompiledContract = &ringSignaturePrecompile{}

	ErrInvalidInput     = errors.New("invalid ring signature input")
	ErrInvalidScheme    = errors.New("invalid signature scheme")
	ErrInvalidRingSize  = errors.New("ring size must be >= 2")
	ErrInvalidSignerIdx = errors.New("signer index out of bounds")
	ErrInvalidSignature = errors.New("invalid ring signature")
	ErrInvalidPublicKey = errors.New("invalid public key in ring")
)

// Operation selectors
const (
	OpSign            = 0x01
	OpVerify          = 0x02
	OpVerifyKeyImage  = 0x03
	OpComputeKeyImage = 0x04
	OpBatchVerify     = 0x10
)

// Scheme IDs
const (
	SchemeLSAGSecp256k1 = 0x01
	SchemeLSAGEd25519   = 0x02
	SchemeDualRing      = 0x03
	SchemeLatticeLSAG   = 0x10
)

// Sizes
const (
	CompressedPubKeySize = 33
	PrivateKeySize       = 32
	ScalarSize           = 32
)

// Gas costs
const (
	GasSignBase        = 5000
	GasSignPerMember   = 3000
	GasVerifyBase      = 4000
	GasVerifyPerMember = 2500
	GasComputeKeyImage = 3000
	GasBatchVerifyBase = 3000
	GasBatchDiscount   = 80 // 80% of individual cost
	GasPerByte         = 5
)

type ringSignaturePrecompile struct{}

// Address returns the address of the Ring Signature precompile
func (p *ringSignaturePrecompile) Address() common.Address {
	return ContractAddress
}

// RequiredGas calculates gas for ring signature operations
func (p *ringSignaturePrecompile) RequiredGas(input []byte) uint64 {
	if len(input) < 3 {
		return 0
	}

	op := input[0]
	scheme := input[1]

	var baseGas, perMemberGas uint64

	switch scheme {
	case SchemeLSAGSecp256k1:
		baseGas = GasSignBase
		perMemberGas = GasSignPerMember
	case SchemeLSAGEd25519:
		baseGas = GasSignBase - 1000
		perMemberGas = GasSignPerMember - 1000
	case SchemeLatticeLSAG:
		baseGas = 50000
		perMemberGas = 10000
	default:
		return 0
	}

	switch op {
	case OpSign:
		ringSize := int(input[2])
		msgLen := len(input) - 3 - ringSize*CompressedPubKeySize - PrivateKeySize - 1
		if msgLen < 0 {
			msgLen = 0
		}
		return baseGas + uint64(ringSize)*perMemberGas + uint64(msgLen)*GasPerByte

	case OpVerify:
		ringSize := int(input[2])
		return (baseGas - 1000) + uint64(ringSize)*(perMemberGas-500)

	case OpComputeKeyImage:
		return GasComputeKeyImage

	case OpBatchVerify:
		if len(input) < 4 {
			return 0
		}
		numSigs := int(input[2])<<8 | int(input[3])
		return GasBatchVerifyBase + uint64(numSigs)*5000*GasBatchDiscount/100

	default:
		return 0
	}
}

// Run executes the Ring Signature precompile
func (p *ringSignaturePrecompile) Run(
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

	if len(input) < 3 {
		return nil, suppliedGas - gasCost, ErrInvalidInput
	}

	op := input[0]
	scheme := input[1]

	var result []byte
	var err error

	switch op {
	case OpSign:
		result, err = p.sign(scheme, input[2:])
	case OpVerify:
		result, err = p.verify(scheme, input[2:])
	case OpComputeKeyImage:
		result, err = p.computeKeyImage(scheme, input[2:])
	default:
		err = fmt.Errorf("unsupported operation: 0x%02x", op)
	}

	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	return result, suppliedGas - gasCost, nil
}

// LSAGSignature represents an LSAG ring signature
type LSAGSignature struct {
	KeyImage []byte     // 33 bytes
	C        []*big.Int // n challenges
	S        []*big.Int // n responses
}

// sign creates an LSAG ring signature
func (p *ringSignaturePrecompile) sign(scheme byte, input []byte) ([]byte, error) {
	if scheme != SchemeLSAGSecp256k1 {
		return nil, ErrInvalidScheme
	}

	if len(input) < 1 {
		return nil, ErrInvalidInput
	}

	ringSize := int(input[0])
	if ringSize < 2 {
		return nil, ErrInvalidRingSize
	}

	offset := 1

	// Parse ring public keys (33 bytes each, compressed)
	ring := make([][]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		if len(input) < offset+CompressedPubKeySize {
			return nil, ErrInvalidInput
		}
		ring[i] = make([]byte, CompressedPubKeySize)
		copy(ring[i], input[offset:offset+CompressedPubKeySize])
		offset += CompressedPubKeySize
	}

	// Parse signer's private key (32 bytes)
	if len(input) < offset+PrivateKeySize {
		return nil, ErrInvalidInput
	}
	signerSk := input[offset : offset+PrivateKeySize]
	offset += PrivateKeySize

	// Parse signer index (1 byte)
	if len(input) < offset+1 {
		return nil, ErrInvalidInput
	}
	signerIdx := int(input[offset])
	offset++

	if signerIdx >= ringSize {
		return nil, ErrInvalidSignerIdx
	}

	// Message is the rest
	message := input[offset:]

	// Create LSAG signature
	sig, err := lsagSign(ring, signerSk, signerIdx, message)
	if err != nil {
		return nil, err
	}

	return sig.Serialize(), nil
}

// verify verifies an LSAG ring signature
func (p *ringSignaturePrecompile) verify(scheme byte, input []byte) ([]byte, error) {
	if scheme != SchemeLSAGSecp256k1 {
		return nil, ErrInvalidScheme
	}

	if len(input) < 1 {
		return nil, ErrInvalidInput
	}

	ringSize := int(input[0])
	if ringSize < 2 {
		return nil, ErrInvalidRingSize
	}

	offset := 1

	// Parse ring
	ring := make([][]byte, ringSize)
	for i := 0; i < ringSize; i++ {
		if len(input) < offset+CompressedPubKeySize {
			return nil, ErrInvalidInput
		}
		ring[i] = make([]byte, CompressedPubKeySize)
		copy(ring[i], input[offset:offset+CompressedPubKeySize])
		offset += CompressedPubKeySize
	}

	// Signature: keyImage (33) + c[n] (32 each) + s[n] (32 each)
	sigLen := CompressedPubKeySize + ringSize*ScalarSize + ringSize*ScalarSize
	if len(input) < offset+sigLen {
		return nil, ErrInvalidInput
	}
	signature := input[offset : offset+sigLen]
	offset += sigLen

	message := input[offset:]

	// Parse and verify signature
	sig, err := parseLSAGSignature(signature, ringSize)
	if err != nil {
		return []byte{0x00}, nil
	}

	valid := lsagVerify(ring, sig, message)
	if valid {
		return []byte{0x01}, nil
	}
	return []byte{0x00}, nil
}

// computeKeyImage computes the key image for a private key
func (p *ringSignaturePrecompile) computeKeyImage(scheme byte, input []byte) ([]byte, error) {
	if scheme != SchemeLSAGSecp256k1 {
		return nil, ErrInvalidScheme
	}

	if len(input) < PrivateKeySize {
		return nil, ErrInvalidInput
	}

	privateKey := input[:PrivateKeySize]
	return computeKeyImageSecp256k1(privateKey)
}

// lsagSign creates an LSAG signature
func lsagSign(ring [][]byte, signerSk []byte, signerIdx int, message []byte) (*LSAGSignature, error) {
	n := len(ring)
	curve := secp256k1.S256()

	// Parse signer's private key
	x := new(big.Int).SetBytes(signerSk)

	// Get signer's public key
	pubX, pubY := curve.ScalarBaseMult(x.Bytes())
	signerPk := secp256k1.CompressPubkey(pubX, pubY)

	// Compute key image: I = x * H(P)
	hp := hashToPoint(signerPk)
	imgX, imgY := curve.ScalarMult(hp.X, hp.Y, x.Bytes())
	keyImage := secp256k1.CompressPubkey(imgX, imgY)

	// Initialize arrays
	c := make([]*big.Int, n)
	s := make([]*big.Int, n)

	// Generate random alpha
	alpha, _ := rand.Int(rand.Reader, curve.Params().N)

	// L = alpha * G
	Lx, Ly := curve.ScalarBaseMult(alpha.Bytes())

	// R = alpha * H(P)
	Rx, Ry := curve.ScalarMult(hp.X, hp.Y, alpha.Bytes())

	// c[signerIdx+1] = H(m, L, R)
	nextIdx := (signerIdx + 1) % n
	c[nextIdx] = hashRing(message, Lx, Ly, Rx, Ry)

	// Generate random s[i] for i != signerIdx and compute c[i]
	for i := 1; i < n; i++ {
		idx := (signerIdx + i) % n

		// Generate random s[idx]
		s[idx], _ = rand.Int(rand.Reader, curve.Params().N)

		// Parse P[idx]
		pkX, pkY := secp256k1.DecompressPubkey(ring[idx])
		if pkX == nil {
			return nil, ErrInvalidPublicKey
		}

		// L = s[idx] * G + c[idx] * P[idx]
		sGx, sGy := curve.ScalarBaseMult(s[idx].Bytes())
		cPx, cPy := curve.ScalarMult(pkX, pkY, c[idx].Bytes())
		Lx, Ly = curve.Add(sGx, sGy, cPx, cPy)

		// R = s[idx] * H(P[idx]) + c[idx] * I
		hpIdx := hashToPoint(ring[idx])
		sHx, sHy := curve.ScalarMult(hpIdx.X, hpIdx.Y, s[idx].Bytes())
		cIx, cIy := curve.ScalarMult(imgX, imgY, c[idx].Bytes())
		Rx, Ry = curve.Add(sHx, sHy, cIx, cIy)

		// c[(idx+1) % n] = H(m, L, R)
		nextIdx := (idx + 1) % n
		if nextIdx != signerIdx {
			c[nextIdx] = hashRing(message, Lx, Ly, Rx, Ry)
		}
	}

	// Close the ring: compute c[signerIdx] if not set
	if c[signerIdx] == nil {
		c[signerIdx] = hashRing(message, Lx, Ly, Rx, Ry)
	}

	// s[signerIdx] = alpha - c[signerIdx] * x mod n
	s[signerIdx] = new(big.Int).Mul(c[signerIdx], x)
	s[signerIdx].Mod(s[signerIdx], curve.Params().N)
	s[signerIdx].Sub(alpha, s[signerIdx])
	s[signerIdx].Mod(s[signerIdx], curve.Params().N)

	return &LSAGSignature{
		KeyImage: keyImage,
		C:        c,
		S:        s,
	}, nil
}

// lsagVerify verifies an LSAG signature
func lsagVerify(ring [][]byte, sig *LSAGSignature, message []byte) bool {
	n := len(ring)
	curve := secp256k1.S256()

	// Parse key image
	imgX, imgY := secp256k1.DecompressPubkey(sig.KeyImage)
	if imgX == nil {
		return false
	}

	// Verify ring
	cPrev := sig.C[0]
	for i := 0; i < n; i++ {
		// Parse P[i]
		pkX, pkY := secp256k1.DecompressPubkey(ring[i])
		if pkX == nil {
			return false
		}

		// L = s[i] * G + c[i] * P[i]
		sGx, sGy := curve.ScalarBaseMult(sig.S[i].Bytes())
		cPx, cPy := curve.ScalarMult(pkX, pkY, cPrev.Bytes())
		Lx, Ly := curve.Add(sGx, sGy, cPx, cPy)

		// R = s[i] * H(P[i]) + c[i] * I
		hp := hashToPoint(ring[i])
		sHx, sHy := curve.ScalarMult(hp.X, hp.Y, sig.S[i].Bytes())
		cIx, cIy := curve.ScalarMult(imgX, imgY, cPrev.Bytes())
		Rx, Ry := curve.Add(sHx, sHy, cIx, cIy)

		// c[i+1] = H(m, L, R)
		cNext := hashRing(message, Lx, Ly, Rx, Ry)

		if i == n-1 {
			// Check c[0] == computed c[n]
			return cNext.Cmp(sig.C[0]) == 0
		}
		cPrev = cNext
	}

	return false
}

// Point represents a curve point
type Point struct {
	X, Y *big.Int
}

func hashToPoint(pk []byte) *Point {
	// Hash public key and convert to curve point
	h := sha256.Sum256(pk)
	x, y := secp256k1.S256().ScalarBaseMult(h[:])
	return &Point{X: x, Y: y}
}

func hashRing(msg []byte, Lx, Ly, Rx, Ry *big.Int) *big.Int {
	h := sha256.New()
	h.Write(msg)
	h.Write(padTo32(Lx.Bytes()))
	h.Write(padTo32(Ly.Bytes()))
	h.Write(padTo32(Rx.Bytes()))
	h.Write(padTo32(Ry.Bytes()))
	return new(big.Int).SetBytes(h.Sum(nil))
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func computeKeyImageSecp256k1(privateKey []byte) ([]byte, error) {
	curve := secp256k1.S256()
	x := new(big.Int).SetBytes(privateKey)

	// Get public key
	pubX, pubY := curve.ScalarBaseMult(x.Bytes())
	pk := secp256k1.CompressPubkey(pubX, pubY)

	// Key image = x * H(P)
	hp := hashToPoint(pk)
	imgX, imgY := curve.ScalarMult(hp.X, hp.Y, x.Bytes())

	return secp256k1.CompressPubkey(imgX, imgY), nil
}

func (sig *LSAGSignature) Serialize() []byte {
	n := len(sig.C)
	// keyImage (33) + c[n] (32 each) + s[n] (32 each)
	result := make([]byte, CompressedPubKeySize+n*ScalarSize*2)
	copy(result, sig.KeyImage)

	offset := CompressedPubKeySize
	for i := 0; i < n; i++ {
		copy(result[offset:], padTo32(sig.C[i].Bytes()))
		offset += ScalarSize
	}
	for i := 0; i < n; i++ {
		copy(result[offset:], padTo32(sig.S[i].Bytes()))
		offset += ScalarSize
	}

	return result
}

func parseLSAGSignature(data []byte, ringSize int) (*LSAGSignature, error) {
	expectedLen := CompressedPubKeySize + ringSize*ScalarSize*2
	if len(data) < expectedLen {
		return nil, ErrInvalidSignature
	}

	sig := &LSAGSignature{
		KeyImage: make([]byte, CompressedPubKeySize),
		C:        make([]*big.Int, ringSize),
		S:        make([]*big.Int, ringSize),
	}

	copy(sig.KeyImage, data[:CompressedPubKeySize])

	offset := CompressedPubKeySize
	for i := 0; i < ringSize; i++ {
		sig.C[i] = new(big.Int).SetBytes(data[offset : offset+ScalarSize])
		offset += ScalarSize
	}
	for i := 0; i < ringSize; i++ {
		sig.S[i] = new(big.Int).SetBytes(data[offset : offset+ScalarSize])
		offset += ScalarSize
	}

	return sig, nil
}
