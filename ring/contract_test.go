// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"testing"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

func TestRingSignaturePrecompile_Address(t *testing.T) {
	expectedAddr := common.HexToAddress("0x0000000000000000000000000000000000009202")
	require.Equal(t, expectedAddr, ContractAddress)
	require.Equal(t, expectedAddr, RingSignaturePrecompile.Address())
}

// signOffChain creates an LSAG ring signature off-chain (not via precompile).
// This is the only safe way to sign -- private keys never touch calldata.
//
// rnd supplies alpha and the decoy responses. Production callers pass
// crypto/rand.Reader; tests that need a fixed corpus pass detBytes so the
// branches they reach are identical on every run.
func signOffChain(ring [][]byte, signerSk []byte, signerIdx int, message []byte, rnd io.Reader) (*LSAGSignature, error) {
	n := len(ring)
	curve := secp256k1.S256()

	x := new(big.Int).SetBytes(signerSk)
	pubX, pubY := curve.ScalarBaseMult(x.Bytes())
	signerPk := secp256k1.CompressPubkey(pubX, pubY)

	// Use the same hashToPoint as the precompile (gnark-crypto SVDW)
	hp := hashToPoint(signerPk)
	imgX, imgY := curve.ScalarMult(hp.X, hp.Y, x.Bytes())
	keyImage := secp256k1.CompressPubkey(imgX, imgY)

	c := make([]*big.Int, n)
	s := make([]*big.Int, n)

	alpha, _ := rand.Int(rnd, curve.Params().N)
	Lx, Ly := curve.ScalarBaseMult(alpha.Bytes())
	Rx, Ry := curve.ScalarMult(hp.X, hp.Y, alpha.Bytes())

	nextIdx := (signerIdx + 1) % n
	c[nextIdx] = hashRing(message, Lx, Ly, Rx, Ry)

	for i := 1; i < n; i++ {
		idx := (signerIdx + i) % n
		s[idx], _ = rand.Int(rnd, curve.Params().N)

		pkX, pkY := secp256k1.DecompressPubkey(ring[idx])
		if pkX == nil {
			return nil, ErrInvalidPublicKey
		}

		sGx, sGy := curve.ScalarBaseMult(s[idx].Bytes())
		cPx, cPy := curve.ScalarMult(pkX, pkY, c[idx].Bytes())
		Lx, Ly = curve.Add(sGx, sGy, cPx, cPy)

		hpIdx := hashToPoint(ring[idx])
		sHx, sHy := curve.ScalarMult(hpIdx.X, hpIdx.Y, s[idx].Bytes())
		cIx, cIy := curve.ScalarMult(imgX, imgY, c[idx].Bytes())
		Rx, Ry = curve.Add(sHx, sHy, cIx, cIy)

		next := (idx + 1) % n
		if next != signerIdx {
			c[next] = hashRing(message, Lx, Ly, Rx, Ry)
		}
	}

	if c[signerIdx] == nil {
		c[signerIdx] = hashRing(message, Lx, Ly, Rx, Ry)
	}

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

func TestRing_Verify_Size2(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := range 2 {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message := []byte("Ring signature test message")
	signerIdx := 0

	signerSk := privKeys[signerIdx].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	sig, err := signOffChain(ring, signerSk, signerIdx, message, rand.Reader)
	require.NoError(t, err)

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), message)
	gas := RingSignaturePrecompile.RequiredGas(verifyInput)

	result, remainingGas, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, uint64(0), remainingGas)
	require.Equal(t, []byte{0x01}, result)
}

func TestRing_Verify_Size5(t *testing.T) {
	curve := secp256k1.S256()

	ringSize := 5
	ring := make([][]byte, ringSize)
	privKeys := make([]*ecdsa.PrivateKey, ringSize)

	for i := range ringSize {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message := []byte("Ring signature with 5 members")
	signerIdx := 3

	signerSk := privKeys[signerIdx].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	sig, err := signOffChain(ring, signerSk, signerIdx, message, rand.Reader)
	require.NoError(t, err)

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), message)
	gas := RingSignaturePrecompile.RequiredGas(verifyInput)

	result, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, result)
}

func TestRing_Verify_InvalidSignature(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := range 2 {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	sig, err := signOffChain(ring, signerSk, 0, []byte("Test message"), rand.Reader)
	require.NoError(t, err)

	signature := sig.Serialize()
	signature[10] ^= 0xFF

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, signature, []byte("Test message"))
	gas := RingSignaturePrecompile.RequiredGas(verifyInput)

	result, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, result)
}

func TestRing_Verify_WrongMessage(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	privKeys := make([]*ecdsa.PrivateKey, 2)

	for i := range 2 {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	sig, err := signOffChain(ring, signerSk, 0, []byte("Original message"), rand.Reader)
	require.NoError(t, err)

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), []byte("Different message"))
	gas := RingSignaturePrecompile.RequiredGas(verifyInput)

	result, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		verifyInput,
		gas,
		false,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, result)
}

func TestRing_SignRejected(t *testing.T) {
	input := []byte{0x01, SchemeLSAGSecp256k1, 2}
	gas := RingSignaturePrecompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas)

	_, _, err := RingSignaturePrecompile.Run(
		nil, common.Address{}, ContractAddress,
		append(input, make([]byte, 200)...),
		1000000, false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported operation")
}

func TestRing_InvalidScheme(t *testing.T) {
	input := []byte{OpVerify, 0xFF, 2}
	gas := RingSignaturePrecompile.RequiredGas(input)
	require.Equal(t, uint64(0), gas)
}

func TestRing_OutOfGas(t *testing.T) {
	input := []byte{OpVerify, SchemeLSAGSecp256k1, 2}

	_, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		append(input, make([]byte, 200)...),
		100,
		false,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of gas")
}

func TestRing_InputTooShort(t *testing.T) {
	input := []byte{OpVerify, SchemeLSAGSecp256k1}

	_, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		100000,
		false,
	)
	require.Error(t, err)
}

func TestRing_RequiredGas(t *testing.T) {
	tests := []struct {
		name     string
		ringSize int
		minGas   uint64
	}{
		{"Verify size 2", 2, GasVerifyBase + 2*GasVerifyPerMember},
		{"Verify size 5", 5, GasVerifyBase + 5*GasVerifyPerMember},
		{"Verify size 10", 10, GasVerifyBase + 10*GasVerifyPerMember},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte{OpVerify, SchemeLSAGSecp256k1, byte(tt.ringSize)}
			gas := RingSignaturePrecompile.RequiredGas(input)
			require.Equal(t, tt.minGas, gas)
		})
	}
}

// Helper functions

func buildVerifyInput(scheme byte, ring [][]byte, signature, message []byte) []byte {
	input := make([]byte, 0)
	input = append(input, OpVerify, scheme)
	input = append(input, byte(len(ring)))

	for _, pk := range ring {
		input = append(input, pk...)
	}

	input = append(input, signature...)
	input = append(input, message...)

	return input
}

// Regression: M-06 -- hashToPoint must NOT be h*G (DLOG known).
func TestRing_HashToPoint_NotScalarBaseMult(t *testing.T) {
	curve := secp256k1.S256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	pk := secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)

	pt := hashToPoint(pk)
	require.NotNil(t, pt)
	require.NotNil(t, pt.X)
	require.NotNil(t, pt.Y)

	// Verify on secp256k1: y^2 = x^3 + 7 mod p
	p := curve.Params().P
	y2 := new(big.Int).Mul(pt.Y, pt.Y)
	y2.Mod(y2, p)
	x3 := new(big.Int).Mul(pt.X, pt.X)
	x3.Mul(x3, pt.X)
	x3.Add(x3, big.NewInt(7))
	x3.Mod(x3, p)
	require.Equal(t, 0, y2.Cmp(x3), "hashToPoint result must be on secp256k1")

	// The old broken code did SHA256(pk) -> ScalarBaseMult (known DLOG).
	brokenHash := sha256.Sum256(pk)
	oldX, oldY := curve.ScalarBaseMult(brokenHash[:])
	require.False(t, pt.X.Cmp(oldX) == 0 && pt.Y.Cmp(oldY) == 0,
		"hashToPoint must NOT equal SHA256(pk)*G -- that has known DLOG")
}

func TestRing_HashToPoint_Deterministic(t *testing.T) {
	pk := []byte{0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55,
		0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D,
		0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98}
	pt1 := hashToPoint(pk)
	pt2 := hashToPoint(pk)
	require.Equal(t, 0, pt1.X.Cmp(pt2.X))
	require.Equal(t, 0, pt1.Y.Cmp(pt2.Y))
}

// Benchmarks

func BenchmarkRing_Verify_Size3(b *testing.B) {
	curve := secp256k1.S256()
	ringSize := 3

	ring := make([][]byte, ringSize)
	privKeys := make([]*ecdsa.PrivateKey, ringSize)

	for i := range ringSize {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	signerSk := privKeys[0].D.Bytes()
	if len(signerSk) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(signerSk):], signerSk)
		signerSk = padded
	}

	message := []byte("benchmark")
	sig, _ := signOffChain(ring, signerSk, 0, message, rand.Reader)

	verifyInput := buildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), message)
	gas := RingSignaturePrecompile.RequiredGas(verifyInput)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, verifyInput, gas, false)
	}
}
