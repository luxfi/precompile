// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	gnarksecp "github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// C-04: Ring Sign op (0x01) must not be accepted.
//
// Vulnerability: OpSign required a private key directly in calldata,
// which is public on-chain. The precompile now only supports OpVerify.
func TestC04_RingSignRejected(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 2)
	var signerSk []byte
	for i := range 2 {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
		if i == 0 {
			signerSk = padTo32(priv.D.Bytes())
		}
	}

	message := []byte("test message")
	input := secBuildSignInput(SchemeLSAGSecp256k1, ring, signerSk, 0, message)

	ret, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		10_000_000,
		false,
	)
	require.Error(t, err, "Ring Sign (0x01) must be rejected -- accepts private key in calldata")
	require.Nil(t, ret, "Sign must not return any data")
}

// C-04: Ring ComputeKeyImage (0x04) must not be accepted.
func TestC04_RingComputeKeyImageRejected(t *testing.T) {
	privKey := make([]byte, 32)
	_, _ = rand.Read(privKey)

	input := []byte{0x04, SchemeLSAGSecp256k1} // 0x04 = old OpComputeKeyImage
	input = append(input, privKey...)

	ret, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		10_000_000,
		false,
	)
	require.Error(t, err, "ComputeKeyImage (0x04) must be rejected -- accepts private key in calldata")
	require.Nil(t, ret, "ComputeKeyImage must not return data")
}

// C-04: Ring Verify must still work.
func TestC04_RingVerifyStillWorks(t *testing.T) {
	curve := secp256k1.S256()

	ring := make([][]byte, 3)
	privKeys := make([]*ecdsa.PrivateKey, 3)
	for i := range 3 {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		privKeys[i] = priv
		ring[i] = secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)
	}

	message := []byte("verify should still work")
	signerSk := padTo32(privKeys[0].D.Bytes())

	// Create signature off-chain (this is the correct flow)
	sig, err := signOffChain(ring, signerSk, 0, message)
	require.NoError(t, err)

	// Build verify input
	input := secBuildVerifyInput(SchemeLSAGSecp256k1, ring, sig.Serialize(), message)

	ret, _, err := RingSignaturePrecompile.Run(
		nil,
		common.Address{},
		ContractAddress,
		input,
		10_000_000,
		false,
	)
	require.NoError(t, err, "Verify must succeed")
	require.Equal(t, []byte{0x01}, ret, "Valid signature must return 0x01")
}

// M-06: hashToPoint DLOG must be unknown.
//
// Vulnerability: If hashToPoint(pk) = SHA256(pk) * G, then the discrete log
// of H(pk) w.r.t. G is known (it's SHA256(pk)). This breaks LSAG anonymity
// because the key image I = x * H(P) becomes I = x * h * G where h is known,
// allowing extraction of x (the signer's private key) from I.
//
// Fix: Use RFC 9380 hash-to-curve (SVDW map via gnark-crypto's HashToG1)
// which produces a point with unknown DLOG relative to G.
func TestM06_RingHashToPointDLOGUnknown(t *testing.T) {
	curve := secp256k1.S256()

	for i := range 10 {
		// Generate a random public key
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		pk := secp256k1.CompressPubkey(priv.PublicKey.X, priv.PublicKey.Y)

		P := hashToPoint(pk)
		require.NotNil(t, P, "hashToPoint must not return nil")
		require.NotNil(t, P.X, "hashToPoint X must not be nil")
		require.NotNil(t, P.Y, "hashToPoint Y must not be nil")

		// The BAD implementation: P = SHA256(pk) * G
		// If this were the case, DLOG(P, G) = SHA256(pk) -- trivially known.
		h := sha256.Sum256(pk)
		k := new(big.Int).SetBytes(h[:])
		k.Mod(k, curve.Params().N) // reduce mod group order
		badX, badY := curve.ScalarBaseMult(k.Bytes())

		isBadImpl := P.X.Cmp(badX) == 0 && P.Y.Cmp(badY) == 0
		require.False(t, isBadImpl,
			"hashToPoint MUST NOT be SHA256(pk)*G -- DLOG would be known, breaking LSAG anonymity (iteration %d)", i)
	}
}

// M-06: hashToPoint must use RFC 9380 SVDW (gnark-crypto HashToG1).
//
// Verify that hashToPoint produces points deterministically and that they
// are valid curve points on secp256k1 (not infinity, on curve).
func TestM06_RingHashToPointIsValidCurvePoint(t *testing.T) {
	curve := secp256k1.S256()

	for i := range 20 {
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)

		P := hashToPoint(seed)
		require.NotNil(t, P)
		require.NotNil(t, P.X)
		require.NotNil(t, P.Y)

		// Verify the point is on secp256k1
		require.True(t, curve.IsOnCurve(P.X, P.Y),
			"hashToPoint must return a valid secp256k1 point (iteration %d)", i)
	}
}

// M-06: hashToPoint must be deterministic (consensus requirement).
func TestM06_RingHashToPointDeterministic(t *testing.T) {
	pk := []byte{0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d,
		0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
		0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c,
		0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5}

	p1 := hashToPoint(pk)
	p2 := hashToPoint(pk)

	require.Equal(t, p1.X.Cmp(p2.X), 0, "hashToPoint must be deterministic (X)")
	require.Equal(t, p1.Y.Cmp(p2.Y), 0, "hashToPoint must be deterministic (Y)")
}

// M-06: hashToPoint must use gnark-crypto's SVDW HashToG1 with proper DST.
//
// Verify the output matches the expected gnark-crypto result directly.
func TestM06_RingHashToPointMatchesSVDW(t *testing.T) {
	pk := []byte("test-public-key-for-svdw-check")
	dst := []byte("LUX-LSAG-H2C-SECP256K1")

	// Compute expected result directly via gnark-crypto
	expected, err := gnarksecp.HashToG1(pk, dst)
	require.NoError(t, err, "gnark-crypto HashToG1 must succeed")

	expectedX := new(big.Int)
	expectedY := new(big.Int)
	expected.X.BigInt(expectedX)
	expected.Y.BigInt(expectedY)

	actual := hashToPoint(pk)
	require.NotNil(t, actual)
	require.Equal(t, 0, actual.X.Cmp(expectedX), "hashToPoint must match gnark HashToG1 X")
	require.Equal(t, 0, actual.Y.Cmp(expectedY), "hashToPoint must match gnark HashToG1 Y")
}

// Helpers (prefixed sec* to avoid redeclaration with contract_test.go)

func secBuildSignInput(scheme byte, ring [][]byte, signerSk []byte, signerIdx byte, message []byte) []byte {
	input := []byte{0x01, scheme, byte(len(ring))} // 0x01 = old OpSign
	for _, pk := range ring {
		input = append(input, pk...)
	}
	input = append(input, signerSk...)
	input = append(input, signerIdx)
	input = append(input, message...)
	return input
}

func secBuildVerifyInput(scheme byte, ring [][]byte, signature []byte, message []byte) []byte {
	input := []byte{OpVerify, scheme, byte(len(ring))}
	for _, pk := range ring {
		input = append(input, pk...)
	}
	input = append(input, signature...)
	input = append(input, message...)
	return input
}
