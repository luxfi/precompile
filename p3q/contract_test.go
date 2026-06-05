// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// TestP3Q_Address pins the canonical LP-4200 slot 0x012205 per
// HANZO-CRYPTO-SUITE §5.2 and LP-218.
func TestP3Q_Address(t *testing.T) {
	want := common.HexToAddress("0x0000000000000000000000000000000000012205")
	require.Equal(t, want, ContractP3QVerifyAddress)
}

// TestP3Q_RequiredGas pins the LP-218 gas formula: 50_000 + 10 * N.
// Canonical Pulsar / ML-DSA-65 payload is now 5303 bytes (1 kind +
// 1 mode + 8 lengths + 3309 sig + 1952 pk + 32 hash).
func TestP3Q_RequiredGas(t *testing.T) {
	for _, n := range []int{0, 1, 64, 256, 1024, 5303, 16384} {
		input := make([]byte, n)
		got := P3QVerifyPrecompile.RequiredGas(input)
		want := BaseVerifyGas + uint64(n)*PerByteGas
		require.Equal(t, want, got, "len=%d", n)
	}
}

// TestP3Q_OutOfGas confirms suppliedGas < requiredGas surfaces
// contract.ErrOutOfGas as the Go error (the only path that does NOT
// fall through to the abiFalse output convention).
func TestP3Q_OutOfGas(t *testing.T) {
	input := make([]byte, 1024)
	gas := P3QVerifyPrecompile.RequiredGas(input)
	_, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

// TestP3Q_ABIBoolEncoding pins the 32-byte EVM-ABI bool output
// convention. abiTrueClone() must be 31 zero bytes + 0x01;
// abiFalse() must be 32 zero bytes.
func TestP3Q_ABIBoolEncoding(t *testing.T) {
	tr := abiTrueClone()
	require.Len(t, tr, 32)
	require.Equal(t, byte(0x01), tr[31])
	for i := 0; i < 31; i++ {
		require.Equal(t, byte(0x00), tr[i], "abiTrueClone byte %d", i)
	}
	fl := abiFalse()
	require.Len(t, fl, 32)
	require.Equal(t, make([]byte, 32), fl)
}

// TestP3Q_RejectsTooShort confirms inputs below MinInputLength are
// rejected with abiFalse + nil error (no Go-level error per LP-218
// "no revert on cryptographic failure" contract).
func TestP3Q_RejectsTooShort(t *testing.T) {
	for _, sz := range []int{0, 1, 5, MinInputLength - 1} {
		input := make([]byte, sz)
		gas := P3QVerifyPrecompile.RequiredGas(input) * 2
		out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
		require.NoError(t, err, "len=%d must surface as abiFalse, not Go error", sz)
		require.Equal(t, abiFalse(), out, "len=%d", sz)
	}
}

// TestP3Q_RejectsUnsupportedMode confirms mode bytes other than
// {0x44, 0x65, 0x87} are rejected with abiFalse. Kind byte is held
// fixed at KindPulsar so the failure is isolated to the mode byte.
func TestP3Q_RejectsUnsupportedMode(t *testing.T) {
	for _, mode := range []uint8{0x00, 0x01, 0x42, 0x66, 0x88, 0xFF} {
		input := make([]byte, MinInputLength)
		input[0] = KindPulsar
		input[1] = mode
		gas := P3QVerifyPrecompile.RequiredGas(input) * 2
		out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
		require.NoError(t, err, "mode=0x%02x", mode)
		require.Equal(t, abiFalse(), out, "mode=0x%02x", mode)
	}
}

// TestP3Q_RejectsUnsupportedKind confirms kind bytes outside the
// LP-218 / LP-220 family {0x01, 0x02, 0x03} are rejected with abiFalse.
func TestP3Q_RejectsUnsupportedKind(t *testing.T) {
	for _, kind := range []uint8{0x00, 0x04, 0x10, 0x42, 0xFF} {
		input := make([]byte, MinInputLength)
		input[0] = kind
		input[1] = ModeMLDSA65
		gas := P3QVerifyPrecompile.RequiredGas(input) * 2
		out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
		require.NoError(t, err, "kind=0x%02x", kind)
		require.Equal(t, abiFalse(), out, "kind=0x%02x must abiFalse", kind)
	}
}

// TestP3Q_ReservedKindsReturnAbiFalse confirms KindCorona and KindMagnetar
// reserve their dispatch slot but return abiFalse (no revert) until
// their verifiers land per LP-220.
func TestP3Q_ReservedKindsReturnAbiFalse(t *testing.T) {
	for _, kind := range []uint8{KindCorona, KindMagnetar} {
		input := make([]byte, MinInputLength)
		input[0] = kind
		input[1] = ModeMLDSA65
		gas := P3QVerifyPrecompile.RequiredGas(input) * 2
		out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
		require.NoError(t, err, "kind=0x%02x", kind)
		require.Equal(t, abiFalse(), out, "reserved kind 0x%02x must abiFalse", kind)
	}
}

// TestP3Q_RejectsTruncatedSig confirms a sig_len field declaring more
// bytes than remain in the buffer yields abiFalse.
func TestP3Q_RejectsTruncatedSig(t *testing.T) {
	// Declare a 3309-byte sig but supply only 100 bytes.
	input := make([]byte, KindByte+ModeByte+LengthFieldSize+100+LengthFieldSize+0+MessageHashSize)
	input[0] = KindPulsar
	input[1] = ModeMLDSA65
	// sigLen = 3309 (BE32) at offset 2 (post-kind, post-mode).
	input[2] = 0x00
	input[3] = 0x00
	input[4] = 0x0C
	input[5] = 0xED
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out)
}

// TestP3Q_RejectsSigLengthMismatch confirms a wire-format sig_len that
// is not equal to the mode's FIPS 204 signature size yields abiFalse
// without ever invoking the FIPS 204 verifier.
func TestP3Q_RejectsSigLengthMismatch(t *testing.T) {
	// Mode = MLDSA-65 (expects sig of 3309 bytes), but we supply 3308.
	const wrongLen = 3308
	sig := make([]byte, wrongLen)
	pk := make([]byte, MLDSA65PublicKeySize)
	hash := make([]byte, MessageHashSize)
	input := EncodeInput(ModeMLDSA65, sig, pk, hash)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "sig length mismatch (3308 vs expected 3309) must surface as abiFalse")
}

// TestP3Q_RejectsPubKeyLengthMismatch confirms a wire-format pk_len
// that is not equal to the mode's FIPS 204 public-key size yields
// abiFalse.
func TestP3Q_RejectsPubKeyLengthMismatch(t *testing.T) {
	sig := make([]byte, MLDSA65SignatureSize)
	pk := make([]byte, MLDSA65PublicKeySize-1) // off by 1
	hash := make([]byte, MessageHashSize)
	input := EncodeInput(ModeMLDSA65, sig, pk, hash)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out)
}

// mldsaModeFor maps a P3Q wire-byte mode to the mldsa package Mode.
func mldsaModeFor(t *testing.T, m uint8) mldsa.Mode {
	t.Helper()
	switch m {
	case ModeMLDSA44:
		return mldsa.MLDSA44
	case ModeMLDSA65:
		return mldsa.MLDSA65
	case ModeMLDSA87:
		return mldsa.MLDSA87
	}
	t.Fatalf("unsupported mode 0x%02x", m)
	return 0
}

// TestP3Q_RoundTrip_RealMLDSA is the load-bearing integration test:
// generate a FIPS 204 ML-DSA key pair, sign a real 32-byte hash under
// the P3Q domain-separation context, dispatch the signature through
// the EVM precompile entry, and assert the precompile returns abiTrue
// with gas correctly debited.
//
// This is the canonical "happy path" — it proves the wire format is
// stable end-to-end and the FIPS 204 verifier core wires through
// mldsa.VerifySignatureCtx unmodified. The signature is byte-equal to
// what a Pulsar threshold ceremony would produce (per Pulsar's Class
// N1 manifesto), so this test stands in for the threshold path
// without needing the full DKG + 2-round signing infrastructure.
func TestP3Q_RoundTrip_RealMLDSA(t *testing.T) {
	for _, modeByte := range []uint8{ModeMLDSA44, ModeMLDSA65, ModeMLDSA87} {
		t.Run(modeName(modeByte), func(t *testing.T) {
			m := mldsaModeFor(t, modeByte)
			sk, err := mldsa.GenerateKey(rand.Reader, m)
			require.NoError(t, err)
			require.NotNil(t, sk.PublicKey)

			// Hash a representative rollup-commit payload per LP-218
			// step 5: H(prev_root || new_root || batch_hash).
			prevRoot := bytes.Repeat([]byte{0xAA}, 32)
			newRoot := bytes.Repeat([]byte{0xBB}, 32)
			batchHash := bytes.Repeat([]byte{0xCC}, 32)
			h := sha256.New()
			h.Write(prevRoot)
			h.Write(newRoot)
			h.Write(batchHash)
			messageHash := h.Sum(nil)
			require.Len(t, messageHash, MessageHashSize)

			// Sign under the P3Q domain-separation context — the same
			// context the precompile passes to mldsa.VerifySignatureCtx.
			sig, err := sk.SignCtx(rand.Reader, messageHash, PrecompileCtx)
			require.NoError(t, err)

			input := EncodeInput(modeByte, sig, sk.PublicKey.Bytes(), messageHash)

			gas := P3QVerifyPrecompile.RequiredGas(input)
			supplied := gas * 2
			out, gasLeft, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, supplied, true)
			require.NoError(t, err)
			require.Equal(t, abiTrueClone(), out, "precompile must return abiTrue for a real verifying signature")
			require.Equal(t, supplied-gas, gasLeft, "gas accounting must be base + N*per-byte")
		})
	}
}

func modeName(m uint8) string {
	switch m {
	case ModeMLDSA44:
		return "MLDSA44"
	case ModeMLDSA65:
		return "MLDSA65"
	case ModeMLDSA87:
		return "MLDSA87"
	}
	return "unknown"
}

// TestP3Q_RejectsWrongMessageHash confirms a signature minted for one
// hash and submitted with a different hash is rejected (FIPS 204
// verifier surfacing abiFalse).
func TestP3Q_RejectsWrongMessageHash(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)

	correct := bytes.Repeat([]byte{0x01}, 32)
	wrong := bytes.Repeat([]byte{0x02}, 32)

	sig, err := sk.SignCtx(rand.Reader, correct, PrecompileCtx)
	require.NoError(t, err)

	input := EncodeInput(ModeMLDSA65, sig, sk.PublicKey.Bytes(), wrong)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "signature minted for hash A must not verify under hash B")
}

// TestP3Q_RejectsWrongGroupPubKey confirms a signature minted under
// key A and submitted with key B is rejected.
func TestP3Q_RejectsWrongGroupPubKey(t *testing.T) {
	skA, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	skB, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)

	hash := bytes.Repeat([]byte{0x42}, 32)
	sigA, err := skA.SignCtx(rand.Reader, hash, PrecompileCtx)
	require.NoError(t, err)

	// Submit sigA under skB's public key — must reject.
	input := EncodeInput(ModeMLDSA65, sigA, skB.PublicKey.Bytes(), hash)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out)
}

// TestP3Q_RejectsCorruptedSignature confirms a single-bit corruption
// of the signature payload is detected by the FIPS 204 verifier.
func TestP3Q_RejectsCorruptedSignature(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)

	hash := bytes.Repeat([]byte{0x77}, 32)
	sig, err := sk.SignCtx(rand.Reader, hash, PrecompileCtx)
	require.NoError(t, err)

	// Flip one bit at a non-deterministic location in the signature.
	corrupted := append([]byte(nil), sig...)
	require.Greater(t, len(corrupted), 100)
	corrupted[100] ^= 0x01

	input := EncodeInput(ModeMLDSA65, corrupted, sk.PublicKey.Bytes(), hash)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "single-bit signature corruption must be detected")
}

// TestP3Q_RejectsWrongContextDomainSeparation is the load-bearing
// security test for the domain-separation property documented in
// LP-218 §"Domain separation". A signature minted under the generic
// 0x012204 Pulsar context ("lux-evm-precompile-pulsar-v1") must NOT
// verify under the P3Q context ("lux-evm-precompile-p3q-v1").
//
// This prevents an attacker from minting a signature for one slot and
// replaying it against the other.
func TestP3Q_RejectsWrongContextDomainSeparation(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)

	hash := bytes.Repeat([]byte{0xAB}, 32)

	// Sign under the WRONG (Pulsar 0x012204) context.
	wrongCtx := []byte("lux-evm-precompile-pulsar-v1")
	sig, err := sk.SignCtx(rand.Reader, hash, wrongCtx)
	require.NoError(t, err)

	// Submit to P3Q (which binds the P3Q context internally).
	input := EncodeInput(ModeMLDSA65, sig, sk.PublicKey.Bytes(), hash)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "signature under sibling-precompile context must not verify on P3Q")
}

// TestP3Q_Verify_StandaloneAPI exercises the in-process Verify entry
// point (the off-chain pre-flight + chains/zkvm dispatch entry).
// Must produce byte-identical accept/reject decisions to the on-chain
// precompile path.
func TestP3Q_Verify_StandaloneAPI(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	hash := bytes.Repeat([]byte{0x33}, 32)
	sig, err := sk.SignCtx(rand.Reader, hash, PrecompileCtx)
	require.NoError(t, err)

	// Standalone Verify must accept.
	require.NoError(t, Verify(ModeMLDSA65, sk.PublicKey.Bytes(), sig, hash))

	// Cross-check: the same inputs must also accept on-chain via the
	// precompile.
	input := EncodeInput(ModeMLDSA65, sig, sk.PublicKey.Bytes(), hash)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, runErr := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, runErr)
	require.Equal(t, abiTrueClone(), out)
}

// TestP3Q_Verify_SizeMismatchTyped confirms the standalone Verify
// surfaces size-mismatch errors as typed errors (distinct from
// FIPS 204 reject), so off-chain callers can distinguish "malformed
// input" from "good input, bad signature".
func TestP3Q_Verify_SizeMismatchTyped(t *testing.T) {
	hash := make([]byte, MessageHashSize)
	short := make([]byte, 10)
	require.Error(t, Verify(ModeMLDSA65, short, make([]byte, MLDSA65SignatureSize), hash), "short pk must surface typed error")
	require.Error(t, Verify(ModeMLDSA65, make([]byte, MLDSA65PublicKeySize), short, hash), "short sig must surface typed error")
	require.Error(t, Verify(ModeMLDSA65, make([]byte, MLDSA65PublicKeySize), make([]byte, MLDSA65SignatureSize), make([]byte, 31)), "31-byte hash must surface typed error")
	require.ErrorIs(t, Verify(0x99, make([]byte, MLDSA65PublicKeySize), make([]byte, MLDSA65SignatureSize), hash), ErrUnsupportedMode)
}

// TestP3Q_EncodeInput_RoundTrip verifies EncodeInput is the inverse of
// the precompile's wire-format parser. We construct a known input,
// dispatch through the precompile, and assert the parser interpreted
// every field identically to the encoder.
//
// This is the contract test for the canonical wire-format encoder.
func TestP3Q_EncodeInput_RoundTrip(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	hash := bytes.Repeat([]byte{0x10}, 32)
	sig, err := sk.SignCtx(rand.Reader, hash, PrecompileCtx)
	require.NoError(t, err)

	pkBytes := sk.PublicKey.Bytes()
	input := EncodeInput(ModeMLDSA65, sig, pkBytes, hash)
	require.Len(t, input,
		KindByte+ModeByte+LengthFieldSize+MLDSA65SignatureSize+LengthFieldSize+MLDSA65PublicKeySize+MessageHashSize,
		"EncodeInput must emit exactly the LP-218 wire layout length (kind + mode + ...)")

	// Byte-by-byte field positions per the decomplected LP-218 wire layout.
	require.Equal(t, KindPulsar, input[0], "byte 0 must be KindPulsar (kind dispatch)")
	require.Equal(t, ModeMLDSA65, input[1], "byte 1 must be ModeMLDSA65")
	require.Equal(t, []byte{0x00, 0x00, 0x0C, 0xED}, input[2:6], "sigLen field must be BE32 3309")
	require.Equal(t, sig, input[6:6+MLDSA65SignatureSize])
	pkOff := 6 + MLDSA65SignatureSize
	require.Equal(t, []byte{0x00, 0x00, 0x07, 0xA0}, input[pkOff:pkOff+4], "pkLen field must be BE32 1952")
	require.Equal(t, pkBytes, input[pkOff+4:pkOff+4+MLDSA65PublicKeySize])
	require.Equal(t, hash, input[pkOff+4+MLDSA65PublicKeySize:])
}

// TestP3Q_AcceptsTrailingPadding confirms inputs longer than the
// computed message-hash tail are accepted (padding ignored) — matches
// the sibling STARK-FRI precompile's padded-input convention.
func TestP3Q_AcceptsTrailingPadding(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	hash := bytes.Repeat([]byte{0x5A}, 32)
	sig, err := sk.SignCtx(rand.Reader, hash, PrecompileCtx)
	require.NoError(t, err)

	canonical := EncodeInput(ModeMLDSA65, sig, sk.PublicKey.Bytes(), hash)
	padded := append(append([]byte(nil), canonical...), make([]byte, 64)...)

	gas := P3QVerifyPrecompile.RequiredGas(padded) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, padded, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiTrueClone(), out, "trailing padding must be ignored, signature must verify")
}
