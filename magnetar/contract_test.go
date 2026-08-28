// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
	mpc "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
	"github.com/stretchr/testify/require"
)

// TestMagnetarPrecompile_RoundTrip_VerifyAcceptsValid is the manifesto
// test: a single-party FIPS 205 signature on the Magnetar precompile
// context verifies through the Magnetar precompile, because the
// verification operation IS FIPS 205 SLH-DSA.Verify. The Magnetar MPC
// ceremony off-chain produces byte-equal output.
//
// The frozen vector in kat_test.go pins one key forever; this pins that a
// freshly generated key works too, and that the same key's signature over a
// different context does not.
func TestMagnetarPrecompile_RoundTrip_VerifyAcceptsValid(t *testing.T) {
	// Use SHA2_128s for the round-trip — smallest parameter set.
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	require.NoError(t, err)

	message := []byte("magnetar threshold sign roundtrip via precompile")
	signature, err := priv.SignCtx(rand.Reader, message, precompileCtx)
	require.NoError(t, err)

	out, err := call(t, buildInput(ModeSHA2_128s, priv.PublicKey.Bytes(), message, signature))
	require.NoError(t, err)
	require.Equal(t, word(1), out, "valid signature should verify")

	elsewhere, err := priv.SignCtx(rand.Reader, message, []byte("lux-evm-precompile-slhdsa-v1"))
	require.NoError(t, err)
	out, err = call(t, buildInput(ModeSHA2_128s, priv.PublicKey.Bytes(), message, elsewhere))
	require.NoError(t, err)
	require.Equal(t, word(0), out, "a signature minted for another slot must not verify here")
}

// TestPrecompile_MagnetarMPCSignature_VerifiesUnderFIPS205 is the
// integration test the v0.5 audit asked for: a signature produced
// via magnetar's actual MPC code path (the v0.5 per-validator
// standalone primary primitive — PerValidatorKeypair + Sign with
// precompileCtx) is wrapped in the magnetar MAGS wire codec, the
// FIPS 205 payload is extracted, and the precompile verifier is
// called over that payload. PASS = the actual MPC output verifies
// under stock FIPS 205 SLH-DSA verify, end-to-end.
//
// This complements TestMagnetarPrecompile_RoundTrip_VerifyAcceptsValid
// (which uses slhdsa.GenerateKey + priv.SignCtx directly, never
// exercising magnetar's code path). The audit required an
// integration test that hits magnetar's actual signing primitive —
// this is it. Both modes verify because magnetar's v0.5 primary
// path IS single-party FIPS 205 SignDeterministic byte-for-byte
// (see magnetar/ref/go/pkg/magnetar/sign.go::Sign,
// TestMagnetar_Wire_FIPS205Verifiable upstream).
//
// MPC entry point exercised:
//   - mpc.PerValidatorKeypair(params, rng) → (sk, pk) at
//     magnetar/ref/go/pkg/magnetar/standalone.go:197
//   - mpc.Sign(params, sk, msg, precompileCtx, false, nil) at
//     magnetar/ref/go/pkg/magnetar/sign.go:42
//   - mpc.Signature.MarshalBinary() at
//     magnetar/ref/go/pkg/magnetar/wire.go (MAGS frame)
//   - extractMagnetarPayload() strips the 11-byte MAGS header
//   - precompile verifier consumes the raw FIPS 205 bytes
func TestPrecompile_MagnetarMPCSignature_VerifiesUnderFIPS205(t *testing.T) {
	// ModeM192s is magnetar's canonical / RECOMMENDED v0.5
	// parameter set (SHAKE-192s, NIST PQ category 3). The precompile
	// SHAKE-192s slot is ModeSHAKE_192s = 0x12; both surfaces
	// dispatch into the same circl/slhdsa.SHAKE_192s primitive.
	params := mpc.MustParamsFor(mpc.ModeM192s)

	// MPC ENTRY 1: PerValidatorKeypair — the v0.5 public-BFT
	// primary primitive. No DKG, no shared seed, no dealer. One
	// standalone FIPS 205 keypair per validator. This is the code
	// path magnetar names as the canonical MPC entry in
	// CHANGELOG.md [0.5.0] §"Per-validator standalone is the
	// primary public-BFT primitive".
	sk, pk, err := mpc.PerValidatorKeypair(params, rand.Reader)
	require.NoError(t, err, "PerValidatorKeypair")
	require.NotNil(t, sk)
	require.NotNil(t, pk)

	message := []byte("magnetar MPC signature verifies under FIPS 205")

	// MPC ENTRY 2: magnetar.Sign with the precompile context. The
	// public-BFT primary surface (ValidatorSign) deliberately omits
	// ctx; for the precompile slot binding we want the
	// "lux-evm-precompile-magnetar-v1" ctx to participate in the
	// FIPS 205 transcript. magnetar.Sign with randomized=false →
	// SignDeterministic byte-identical to single-party FIPS 205 on
	// (sk.Bytes, message, precompileCtx).
	sig, err := mpc.Sign(params, sk, message, precompileCtx, false, nil)
	require.NoError(t, err, "magnetar.Sign with precompileCtx")
	require.Equal(t, params.SignatureSize, len(sig.Bytes),
		"sig length must match FIPS 205 SignatureSize for SHAKE-192s")

	// WIRE: wrap in the MAGS frame to prove the codec is path-
	// preserving end-to-end.
	wireSig, err := sig.MarshalBinary()
	require.NoError(t, err, "sig.MarshalBinary")
	wirePk, err := mpc.MarshalGroupKey(pk)
	require.NoError(t, err, "MarshalGroupKey")

	// EXTRACT: strip the 11-byte MAGS / MAGG headers.
	rawSig := extractMagnetarPayload(t, wireSig, params.SignatureSize)
	rawPk := extractMagnetarPayload(t, wirePk, params.PublicKeySize)

	// Byte-identity sanity: the MAGS payload IS the raw FIPS 205
	// bytes verbatim.
	require.Equal(t, sig.Bytes, rawSig,
		"MAGS payload must byte-equal magnetar.Signature.Bytes (no envelope)")
	require.Equal(t, pk.Bytes, rawPk,
		"MAGG payload must byte-equal magnetar.PublicKey.Bytes (no envelope)")

	// CALL THE PRECOMPILE: feed raw FIPS 205 bytes through the
	// precompile's [mode][pkLen][pk][msgLen][msg][sig] wire format.
	// The precompile internally dispatches to luxfi/crypto/slhdsa
	// which is the SAME circl/slhdsa.SHAKE_192s primitive that
	// magnetar called at Sign time. If the MPC code path produced a
	// signature byte-identical to FIPS 205 — which TestMagnetar_Wire_
	// FIPS205Verifiable upstream pins — the precompile verifier
	// MUST accept.
	input := buildInput(ModeSHAKE_192s, rawPk, message, rawSig)
	gas := MagnetarVerifyPrecompile.RequiredGas(input)
	result, _, err := MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress,
		input, gas, true,
	)
	require.NoError(t, err, "precompile.Run on MPC-signed input")
	require.Equal(t, byte(1), result[31],
		"precompile rejected a magnetar-MPC-produced signature — "+
			"either the v0.5 MPC code path is NOT byte-identical to "+
			"FIPS 205 SignDeterministic, the precompile ctx is not "+
			"reaching the verifier, or the wire codec is corrupting "+
			"the payload")

	// Tamper resistance: flip a byte in the raw FIPS 205 sig — the
	// precompile MUST reject (returns 0). Same precompile call
	// shape; this guards against a degenerate "always returns 1"
	// regression in the precompile while we change the test.
	tampered := append([]byte(nil), rawSig...)
	tampered[len(tampered)/2] ^= 0x01
	tInput := buildInput(ModeSHAKE_192s, rawPk, message, tampered)
	tResult, _, err := MagnetarVerifyPrecompile.Run(
		nil, common.Address{}, ContractMagnetarVerifyAddress,
		tInput, gas, true,
	)
	require.NoError(t, err)
	require.Equal(t, byte(0), tResult[31],
		"precompile accepted a tampered FIPS 205 signature")
}

// extractMagnetarPayload strips the 11-byte MAGS / MAGG header
// from a magnetar wire frame and returns the raw FIPS 205 payload.
// Verifies the declared payload length matches the expected size
// for the parameter set. Mirrors the audit's "any external party
// with a FIPS 205 verifier should be able to peel this" property.
func extractMagnetarPayload(t *testing.T, wire []byte, expectedLen int) []byte {
	t.Helper()
	const headerSize = 4 + 2 + 1 + 4 // magic + version + mode + len
	require.GreaterOrEqual(t, len(wire), headerSize,
		"wire frame too short for header")
	declared := binary.BigEndian.Uint32(wire[7:11])
	require.Equal(t, expectedLen, int(declared),
		"declared payload length must match FIPS 205 size for mode")
	require.Equal(t, headerSize+expectedLen, len(wire),
		"total wire length must equal header + declared payload")
	return wire[headerSize:]
}

// buildInput serialises [mode][pubKeyLen][pubKey][msgLen][msg][sig]
// in the wire format the precompile expects.
func buildInput(mode uint8, pubKey, message, signature []byte) []byte {
	out := make([]byte, 0, 1+2+len(pubKey)+2+len(message)+len(signature))
	out = append(out, mode)

	var plen [2]byte
	binary.BigEndian.PutUint16(plen[:], uint16(len(pubKey)))
	out = append(out, plen[:]...)
	out = append(out, pubKey...)

	var mlen [2]byte
	binary.BigEndian.PutUint16(mlen[:], uint16(len(message)))
	out = append(out, mlen[:]...)
	out = append(out, message...)

	out = append(out, signature...)
	return out
}
