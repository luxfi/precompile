// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ring implements LSAG (Linkable Spontaneous Anonymous Group) ring signature
// verification precompile for the Lux EVM. Address: 0x9202 (Lux Crypto Privacy range)
//
// Ring signatures enable privacy transactions where the sender's identity
// is hidden among a set of possible signers.
//
// Operations:
//   - 0x02: Verify -- verify an LSAG ring signature
//
// Sign and ComputeKeyImage are intentionally excluded: both require the
// signer's private key in calldata, which is public on-chain. Signing
// MUST be performed off-chain.
//
// GPU: LSAG verify loop is sequential (each step feeds the next c[i+1]).
// Individual EC scalar mults within each step could be parallelized on GPU
// via secp256k1_recover.metal's ec_mul_affine, but the sequential dependency
// limits speedup. Batch ring verify across a block (multiple ring sig txs)
// is the effective GPU path via parallel.BlockExecutor.
// See LP-3664 for full specification.
package ring

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	gnarksecp "github.com/consensys/gnark-crypto/ecc/secp256k1"
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

	ErrInvalidInput     = contract.ErrInvalidInput
	ErrInvalidScheme    = errors.New("invalid signature scheme")
	ErrInvalidRingSize  = errors.New("ring size must be >= 2")
	ErrInvalidSignature = errors.New("invalid ring signature")
	ErrInvalidPublicKey = errors.New("invalid public key in ring")
)

// Operation selectors -- verify only, sign is excluded for key safety
const (
	OpVerify = 0x02
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
	ScalarSize           = 32
)

// Gas costs
const (
	GasVerifyBase      = 4000
	GasVerifyPerMember = 2500
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

	if op != OpVerify {
		return 0
	}

	var baseGas, perMemberGas uint64

	switch scheme {
	case SchemeLSAGSecp256k1:
		baseGas = GasVerifyBase
		perMemberGas = GasVerifyPerMember
	case SchemeLSAGEd25519:
		baseGas = GasVerifyBase - 1000
		perMemberGas = GasVerifyPerMember - 500
	case SchemeLatticeLSAG:
		baseGas = 50000
		perMemberGas = 10000
	default:
		return 0
	}

	ringSize := int(input[2])
	return baseGas + uint64(ringSize)*perMemberGas
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
	remainingGas, err := contract.DeductGas(suppliedGas, gasCost)
	if err != nil {
		return nil, 0, err
	}

	if len(input) < 3 {
		return nil, remainingGas, ErrInvalidInput
	}

	op := input[0]
	scheme := input[1]

	// Classical LSAG schemes (secp256k1, Ed25519, DualRing) are gated by
	// the chain's strict-PQ profile. The lattice scheme (SchemeLatticeLSAG)
	// remains open on every chain.
	switch scheme {
	case SchemeLSAGSecp256k1, SchemeLSAGEd25519, SchemeDualRing:
		if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
			return nil, remainingGas, err
		}
	}

	var result []byte

	switch op {
	case OpVerify:
		result, err = p.verify(scheme, input[2:])
	default:
		err = fmt.Errorf("unsupported operation: 0x%02x", op)
	}

	if err != nil {
		return nil, remainingGas, err
	}

	return result, remainingGas, nil
}

// LSAGSignature represents an LSAG ring signature
type LSAGSignature struct {
	KeyImage []byte     // 33 bytes
	C        []*big.Int // n challenges
	S        []*big.Int // n responses
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
	for i := range ringSize {
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

// lsagVerify verifies an LSAG signature.
//
// GPU fast path: when accel is available, batch SHA256 precomputes all
// hashToPoint values in a single GPU dispatch. The verify loop itself is
// sequential (c[i+1] depends on c[i]) so EC scalar mults remain on CPU.
// For block-level parallelism (many ring sig txs), use parallel.BlockExecutor.
func lsagVerify(ring [][]byte, sig *LSAGSignature, message []byte) bool {
	n := len(ring)
	curve := secp256k1.S256()

	// Parse key image
	imgX, imgY := secp256k1.DecompressPubkey(sig.KeyImage)
	if imgX == nil {
		return false
	}

	// Precompute all hash-to-point values.
	hps := batchHashToPoint(ring)
	if hps == nil {
		return false
	}

	// Verify ring -- sequential: c[i+1] = H(m, L_i, R_i)
	cPrev := sig.C[0]
	for i := range n {
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
		hp := hps[i]
		sHx, sHy := curve.ScalarMult(hp.X, hp.Y, sig.S[i].Bytes())
		cIx, cIy := curve.ScalarMult(imgX, imgY, cPrev.Bytes())
		Rx, Ry := curve.Add(sHx, sHy, cIx, cIy)

		// c[i+1] = H(m, L, R)
		cNext := hashRing(message, Lx, Ly, Rx, Ry)

		if i == n-1 {
			return cNext.Cmp(sig.C[0]) == 0
		}
		cPrev = cNext
	}

	return false
}

// batchHashToPoint precomputes hashToPoint for every ring member.
//
// Each call uses RFC 9380 hash-to-curve (SVDW map) which produces a point
// whose DLOG relative to G is unknown. The previous GPU batch SHA256 path
// was removed because it fed hashes into ScalarBaseMult (producing h*G
// with known DLOG, breaking LSAG anonymity -- see M-06).
func batchHashToPoint(ring [][]byte) []*Point {
	n := len(ring)
	points := make([]*Point, n)
	for i := range n {
		points[i] = hashToPoint(ring[i])
	}
	return points
}

// Point represents a curve point
type Point struct {
	X, Y *big.Int
}

// hashToPoint maps a public key to a curve point whose discrete log relative
// to the generator G is unknown. This is critical for LSAG security: if
// DLOG(H(P), G) were computable, an attacker could extract the signer's
// identity from the key image.
//
// Uses gnark-crypto's SVDW-based HashToG1 (RFC 9380 compliant). The domain
// separation tag "LUX-LSAG-H2C-SECP256K1" binds the output to this protocol.
func hashToPoint(pk []byte) *Point {
	dst := []byte("LUX-LSAG-H2C-SECP256K1")
	pt, err := gnarksecp.HashToG1(pk, dst)
	if err != nil {
		// HashToG1 only errors on empty DST (ours is constant and non-empty).
		// Defensive: fall back to EncodeToG1.
		pt, _ = gnarksecp.EncodeToG1(pk, dst)
	}
	x := new(big.Int)
	y := new(big.Int)
	pt.X.BigInt(x)
	pt.Y.BigInt(y)
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

func (sig *LSAGSignature) Serialize() []byte {
	n := len(sig.C)
	result := make([]byte, CompressedPubKeySize+n*ScalarSize*2)
	copy(result, sig.KeyImage)

	offset := CompressedPubKeySize
	for i := range n {
		copy(result[offset:], padTo32(sig.C[i].Bytes()))
		offset += ScalarSize
	}
	for i := range n {
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
	for i := range ringSize {
		sig.C[i] = new(big.Int).SetBytes(data[offset : offset+ScalarSize])
		offset += ScalarSize
	}
	for i := range ringSize {
		sig.S[i] = new(big.Int).SetBytes(data[offset : offset+ScalarSize])
		offset += ScalarSize
	}

	return sig, nil
}
