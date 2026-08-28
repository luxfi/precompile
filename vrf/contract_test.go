// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vrf

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"

	edwards "filippo.io/edwards25519"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

const testGas = 10_000_000

// ─── Gas ──────────────────────────────────────────────────────────────────────

// TestGas_VerifyGrowsWithInput is the regression test for a flat verify fee.
// ECVRF_encode_to_curve hashes the whole alpha_string, once per counter, so a
// fee that ignores the length lets a caller buy unbounded hashing at a fixed
// price.
func TestGas_VerifyGrowsWithInput(t *testing.T) {
	alphaLens := []int{0, 32, 64, 1024, 65535}

	prev := uint64(0)
	for _, n := range alphaLens {
		input := buildVerifyInput(make([]byte, PublicKeySize), make([]byte, n), make([]byte, ProofSize))
		got := VRFPrecompile.RequiredGas(input)

		want := GasVerify + words(len(input)-1)*GasVerifyPerWord
		require.Equalf(t, want, got, "alpha_len=%d", n)
		require.Greaterf(t, got, prev, "fee must rise with alpha_len (%d)", n)
		prev = got
	}

	// The largest alpha the two-byte length prefix can describe must cost
	// materially more than the size-independent part alone.
	maxInput := buildVerifyInput(make([]byte, PublicKeySize), make([]byte, 65535), make([]byte, ProofSize))
	require.Greater(t, VRFPrecompile.RequiredGas(maxInput), 3*uint64(GasVerify))
}

// TestGas_FlatVerifyFeeNoLongerBuysMaxAlpha states the same property through
// Run: the old flat fee is not enough to verify a maximum-length alpha_string.
func TestGas_FlatVerifyFeeNoLongerBuysMaxAlpha(t *testing.T) {
	input := buildVerifyInput(make([]byte, PublicKeySize), make([]byte, 65535), make([]byte, ProofSize))

	_, remaining, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, GasVerify, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	// It is affordable at the advertised price and not one gas below it.
	need := VRFPrecompile.RequiredGas(input)
	_, _, err = VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, need-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	_, remaining, err = VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, need, true)
	require.NoError(t, err)
	require.Zero(t, remaining)
}

// TestGas_NoCallIsEverFree is the regression test for a successful zero-gas
// call. Every selector, including the 254 that do nothing, must either charge
// gas or fail; a nil error with the full gas returned is a free call.
func TestGas_NoCallIsEverFree(t *testing.T) {
	for op := range 256 {
		input := []byte{byte(op)}
		charged := VRFPrecompile.RequiredGas(input)
		require.Positivef(t, charged, "selector 0x%02x is free", op)

		if op != OpVerify && op != OpProofToHash {
			require.GreaterOrEqualf(t, charged, uint64(MinCallGas),
				"selector 0x%02x does no work and is priced below the floor", op)
		}

		_, remaining, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		if err != nil {
			continue
		}
		require.Lessf(t, remaining, uint64(testGas), "selector 0x%02x succeeded without charging gas", op)
	}
}

func TestGas_UnknownSelectorIsAnError(t *testing.T) {
	for _, op := range []byte{0x00, 0x03, 0x10, 0xFF} {
		out, remaining, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, []byte{op}, testGas, true)
		require.ErrorIsf(t, err, contract.ErrInvalidOp, "selector 0x%02x", op)
		require.Nil(t, out)
		require.Equal(t, uint64(testGas-MinCallGas), remaining)
	}
}

func TestGas_EmptyInputIsAnError(t *testing.T) {
	require.Equal(t, uint64(MinCallGas), VRFPrecompile.RequiredGas(nil))

	out, remaining, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, nil, testGas, true)
	require.ErrorIs(t, err, contract.ErrInvalidInput)
	require.Nil(t, out)
	require.Equal(t, uint64(testGas-MinCallGas), remaining)
}

// TestGas_RunChargesTheAdvertisedPrice ties Run's accounting to RequiredGas
// for every operation, so the two can never drift apart.
func TestGas_RunChargesTheAdvertisedPrice(t *testing.T) {
	v := rfc9381TAI[1]
	inputs := map[string][]byte{
		"verify":        buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mustHex(v.pi)),
		"proof_to_hash": append([]byte{OpProofToHash}, mustHex(v.pi)...),
		"unknown":       {0xFF},
		"empty":         {},
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			want := VRFPrecompile.RequiredGas(input)
			_, remaining, _ := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			require.Equal(t, uint64(testGas)-want, remaining)
		})
	}
}

func TestGas_ProofToHashIsFixedPrice(t *testing.T) {
	for _, n := range []int{0, ProofSize, 4096} {
		input := append([]byte{OpProofToHash}, make([]byte, n)...)
		require.Equal(t, uint64(GasProofToHash), VRFPrecompile.RequiredGas(input))
	}
}

func TestGas_Words(t *testing.T) {
	require.Equal(t, uint64(0), words(0))
	require.Equal(t, uint64(1), words(1))
	require.Equal(t, uint64(1), words(32))
	require.Equal(t, uint64(2), words(33))
}

// ─── Key validation (RFC 9381 Section 5.4.5) ─────────────────────────────────

// smallOrderKeys are the encodings of the Ed25519 points killed by the
// cofactor: the identity, the point of order 2, the two of order 4 and the
// four of order 8. Each is checked to be exactly that below rather than
// trusted, so a wrong constant fails loudly instead of weakening the test.
var smallOrderKeys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
}

func TestValidateKey_RejectsExactlyTheSmallOrderPoints(t *testing.T) {
	for _, h := range smallOrderKeys {
		P, err := new(edwards.Point).SetBytes(mustHex(h))
		require.NoErrorf(t, err, "%s is not a point encoding", h)
		require.Equalf(t, 1, new(edwards.Point).MultByCofactor(P).Equal(edwards.NewIdentityPoint()),
			"%s is not killed by the cofactor", h)
		require.Falsef(t, validateKey(P), "%s must fail ECVRF_validate_key", h)
	}

	// A real public key survives.
	for _, v := range rfc9381TAI {
		Y, err := new(edwards.Point).SetBytes(mustHex(v.pk))
		require.NoError(t, err)
		require.True(t, validateKey(Y))
	}
}

// TestVerify_RejectsSmallOrderKey drives the same keys through the precompile.
func TestVerify_RejectsSmallOrderKey(t *testing.T) {
	v := rfc9381TAI[0]
	for _, h := range smallOrderKeys {
		input := buildVerifyInput(mustHex(h), mustHex(v.alpha), mustHex(v.pi))
		out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.NoError(t, err)
		require.Nilf(t, out, "small-order key %s was accepted", h)
	}
}

// TestVerify_IdentityKeyForgeryIsRefused builds the proof that an unvalidated
// key buys and requires the precompile to refuse it.
//
// With Y and Gamma both the identity, U = s*B and V = s*H no longer depend on
// c, so the challenge can simply be computed and written into the proof: the
// c == c' comparison passes for any alpha_string with no secret key at all,
// and beta_string is Hash(suite || 0x03 || point_to_string(identity) || 0x00),
// the same constant every time. ECVRF_validate_key is the only step that
// stands between a caller and a VRF output they picked in advance.
func TestVerify_IdentityKeyForgeryIsRefused(t *testing.T) {
	identity := edwards.NewIdentityPoint()
	pk := identity.Bytes()
	s := edwards.NewScalar()
	_, err := s.SetCanonicalBytes(append([]byte{1}, make([]byte, 31)...))
	require.NoError(t, err)

	forge := func(alpha []byte) []byte {
		H := encodeToCurve(pk, alpha)
		require.NotNil(t, H)
		U := new(edwards.Point).ScalarBaseMult(s) // s*B - c*identity
		V := new(edwards.Point).ScalarMult(s, H)  // s*H - c*identity
		c := challengeGeneration(identity, H, identity, U, V)

		pi := make([]byte, ProofSize)
		copy(pi[:32], identity.Bytes())
		cBytes := c.Bytes()
		copy(pi[32:48], cBytes[:16])
		copy(pi[48:80], s.Bytes())
		return pi
	}

	// The forgery is arithmetically sound: every step of ECVRF_verify after
	// key validation accepts it.
	alphaA, alphaB := []byte("lottery round 1"), []byte("lottery round 2")
	piA, piB := forge(alphaA), forge(alphaB)

	for _, tc := range []struct {
		alpha []byte
		pi    []byte
	}{{alphaA, piA}, {alphaB, piB}} {
		Gamma, c, sc, ok := decodeProof(tc.pi)
		require.True(t, ok)
		Y, err := new(edwards.Point).SetBytes(pk)
		require.NoError(t, err)
		H := encodeToCurve(pk, tc.alpha)
		cNeg := new(edwards.Scalar).Negate(c)
		U := new(edwards.Point).VarTimeDoubleScalarBaseMult(cNeg, Y, sc)
		V := new(edwards.Point).Subtract(new(edwards.Point).ScalarMult(sc, H), new(edwards.Point).ScalarMult(c, Gamma))
		require.Equal(t, 1, c.Equal(challengeGeneration(Y, H, Gamma, U, V)),
			"forgery does not satisfy c == c'; the test no longer models the attack")
	}

	// The output it would have produced is one constant, known before either
	// alpha_string was chosen.
	predicted := proofToHash(identity)
	require.Equal(t, predicted, proofToHash(identity))

	// And the precompile refuses both.
	for _, tc := range []struct {
		alpha []byte
		pi    []byte
	}{{alphaA, piA}, {alphaB, piB}} {
		input := buildVerifyInput(pk, tc.alpha, tc.pi)
		out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.NoError(t, err)
		require.Nil(t, out, "identity public key produced a valid VRF output")
		require.NotEqual(t, predicted, out)
	}
}

// ─── Encoding refusals ────────────────────────────────────────────────────────

func TestVerify_RejectsShortInput(t *testing.T) {
	minLen := PublicKeySize + AlphaLenSize + ProofSize
	for n := 0; n < minLen; n += 7 {
		input := append([]byte{OpVerify}, make([]byte, n)...)
		out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.NoError(t, err)
		require.Nilf(t, out, "accepted a %d-byte verify body", n)
	}
}

// TestVerify_RejectsAlphaLenOverrun covers a declared alpha_len that runs past
// the end of the supplied buffer.
func TestVerify_RejectsAlphaLenOverrun(t *testing.T) {
	v := rfc9381TAI[2]
	base := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mustHex(v.pi))

	for _, declared := range []uint16{3, 100, 0xFFFF} {
		input := bytes.Clone(base)
		binary.BigEndian.PutUint16(input[1+PublicKeySize:], declared)
		out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.NoError(t, err)
		require.Nilf(t, out, "accepted alpha_len=%d over a %d-byte body", declared, len(base)-1)
	}
}

// TestVerify_RejectsTrailingBytes: a declared alpha_len shorter than the body,
// or bytes appended after the proof, would give one query two encodings.
func TestVerify_RejectsTrailingBytes(t *testing.T) {
	v := rfc9381TAI[2]
	base := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mustHex(v.pi))

	// Sanity: the exact encoding is accepted.
	out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, base, testGas, true)
	require.NoError(t, err)
	require.NotNil(t, out)

	appended := append(bytes.Clone(base), 0x00)
	out, _, err = VRFPrecompile.Run(nil, ContractAddress, ContractAddress, appended, testGas, true)
	require.NoError(t, err)
	require.Nil(t, out, "accepted a trailing byte")

	// alpha_len one short: the last alpha byte would be read as proof.
	short := bytes.Clone(base)
	binary.BigEndian.PutUint16(short[1+PublicKeySize:], 1)
	out, _, err = VRFPrecompile.Run(nil, ContractAddress, ContractAddress, short, testGas, true)
	require.NoError(t, err)
	require.Nil(t, out, "accepted a short alpha_len over a longer body")
}

// notOnCurve is a y with no matching x: (y^2-1)/(dy^2+1) is not a square.
const notOnCurve = "0200000000000000000000000000000000000000000000000000000000000000"

// nonCanonicalPoints are octet strings that edwards25519.Point.SetBytes accepts
// but RFC 8032 string_to_point does not: an unreduced y, and a set sign bit
// where x is zero. Each aliases a point that already has its own encoding, so
// accepting them would give one Gamma two pi_strings and one key two addresses.
var nonCanonicalPoints = map[string]string{
	"y_equal_to_p":       "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"y_above_p":          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"identity_sign_set":  "0100000000000000000000000000000000000000000000000000000000000080",
	"order_two_sign_set": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestDecodePoint_RejectsNonCanonicalEncodings(t *testing.T) {
	for name, h := range nonCanonicalPoints {
		t.Run(name, func(t *testing.T) {
			raw := mustHex(h)

			// The leniency being closed here is real: the library accepts it.
			P, err := new(edwards.Point).SetBytes(raw)
			require.NoError(t, err, "test constant is not accepted even leniently")
			require.NotEqual(t, h, hex.EncodeToString(P.Bytes()), "test constant is canonical after all")

			_, err = decodePoint(raw)
			require.ErrorIs(t, err, errNonCanonicalPoint)

			// The canonical encoding of the same point is accepted.
			canonical, err := decodePoint(P.Bytes())
			require.NoError(t, err)
			require.Equal(t, 1, canonical.Equal(P))
		})
	}

	_, err := decodePoint(mustHex(notOnCurve))
	require.Error(t, err)
	require.NotErrorIs(t, err, errNonCanonicalPoint)

	_, err = decodePoint(make([]byte, 31))
	require.Error(t, err)
}

func TestVerify_RejectsUndecodableGamma(t *testing.T) {
	v := rfc9381TAI[0]
	pi := mustHex(v.pi)

	mutants := map[string]string{"not_on_curve": notOnCurve}
	for name, h := range nonCanonicalPoints {
		mutants[name] = h
	}

	for name, h := range mutants {
		t.Run(name, func(t *testing.T) {
			mutant := bytes.Clone(pi)
			copy(mutant[:32], mustHex(h))

			_, _, _, ok := decodeProof(mutant)
			require.False(t, ok)

			input := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mutant)
			out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			require.NoError(t, err)
			require.Nil(t, out)

			p2h, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, append([]byte{OpProofToHash}, mutant...), testGas, true)
			require.NoError(t, err)
			require.Nil(t, p2h)
		})
	}
}

// TestVerify_RejectsNonCanonicalS pins the s < q check in ECVRF_decode_proof.
// Without it a proof has a second encoding, s + q, which verifies identically.
func TestVerify_RejectsNonCanonicalS(t *testing.T) {
	v := rfc9381TAI[0]
	pi := bytes.Clone(mustHex(v.pi))
	for i := 48; i < 80; i++ {
		pi[i] = 0xFF
	}

	_, _, _, ok := decodeProof(pi)
	require.False(t, ok, "s >= q must not decode")

	input := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), pi)
	out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestVerify_RejectsUndecodablePublicKey(t *testing.T) {
	v := rfc9381TAI[0]

	keys := map[string]string{"not_on_curve": notOnCurve}
	for name, h := range nonCanonicalPoints {
		keys[name] = h
	}

	for name, h := range keys {
		t.Run(name, func(t *testing.T) {
			input := buildVerifyInput(mustHex(h), mustHex(v.alpha), mustHex(v.pi))
			out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			require.NoError(t, err)
			require.Nil(t, out)
		})
	}
}

func TestProofToHash_RequiresExactProofLength(t *testing.T) {
	pi := mustHex(rfc9381TAI[0].pi)
	for _, n := range []int{0, 1, ProofSize - 1, ProofSize + 1, 2 * ProofSize} {
		body := make([]byte, n)
		copy(body, pi)
		out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, append([]byte{OpProofToHash}, body...), testGas, true)
		require.NoError(t, err)
		require.Nilf(t, out, "accepted a %d-byte proof", n)
	}
}

func TestProofToHash_RejectsUndecodableGamma(t *testing.T) {
	pi := bytes.Clone(mustHex(rfc9381TAI[0].pi))
	copy(pi[:32], mustHex("0200000000000000000000000000000000000000000000000000000000000000"))

	out, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, append([]byte{OpProofToHash}, pi...), testGas, true)
	require.NoError(t, err)
	require.Nil(t, out)
}

// ─── Round trip ───────────────────────────────────────────────────────────────

// TestProveAndVerify covers alpha_string lengths the published vectors do not
// reach. The published vectors are what pin the construction; this pins that
// nothing breaks as alpha grows.
func TestProveAndVerify(t *testing.T) {
	sk := mustHex(rfc9381TAI[1].sk)
	_, Y := expandSecretKey(sk)

	for _, alpha := range [][]byte{
		[]byte("ECVRF-EDWARDS25519-SHA512-TAI"),
		make([]byte, 256),
		bytes.Repeat([]byte{0xA5}, 4096),
	} {
		pi := testProve(sk, Y, alpha)
		require.Len(t, pi, ProofSize)

		input := buildVerifyInput(Y.Bytes(), alpha, pi)
		beta, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.NoError(t, err)
		require.Len(t, beta, BetaSize)

		// proof_to_hash agrees with verify, and both are deterministic.
		p2h, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, append([]byte{OpProofToHash}, pi...), testGas, true)
		require.NoError(t, err)
		require.Equal(t, beta, p2h)

		again, _, _ := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.Equal(t, beta, again)
	}
}

// TestUniqueness: distinct keys over one alpha_string give distinct outputs.
func TestUniqueness(t *testing.T) {
	alpha := []byte("uniqueness")
	seen := map[string]bool{}

	for _, v := range rfc9381TAI {
		sk := mustHex(v.sk)
		_, Y := expandSecretKey(sk)
		pi := testProve(sk, Y, alpha)

		input := buildVerifyInput(Y.Bytes(), alpha, pi)
		beta, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
		require.NoError(t, err)
		require.NotNil(t, beta)
		require.False(t, seen[hex.EncodeToString(beta)], "two keys produced one beta")
		seen[hex.EncodeToString(beta)] = true
	}
}

// inPrimeOrderSubgroup reports whether q*P is the identity. Scalars reduce mod
// q, so q itself is not representable; (q-1)*P + P is.
func inPrimeOrderSubgroup(P *edwards.Point) bool {
	one, err := new(edwards.Scalar).SetCanonicalBytes(append([]byte{1}, make([]byte, 31)...))
	if err != nil {
		panic(err)
	}
	qMinus1 := new(edwards.Scalar).Negate(one)
	qP := new(edwards.Point).Add(new(edwards.Point).ScalarMult(qMinus1, P), P)
	return qP.Equal(edwards.NewIdentityPoint()) == 1
}

// TestEncodeToCurve_IsInThePrimeOrderSubgroup: encode_to_curve multiplies by
// the cofactor and rejects the identity, so H always lies in the group the
// proof is checked in.
func TestEncodeToCurve_IsInThePrimeOrderSubgroup(t *testing.T) {
	identity := edwards.NewIdentityPoint()

	// The predicate has teeth: a torsion point fails it.
	for _, h := range smallOrderKeys[1:] {
		P, err := new(edwards.Point).SetBytes(mustHex(h))
		require.NoError(t, err)
		require.Falsef(t, inPrimeOrderSubgroup(P), "%s should not be in the prime-order subgroup", h)
	}

	for i := range 64 {
		H := encodeToCurve([]byte{byte(i)}, []byte("subgroup"))
		require.NotNil(t, H)
		require.Equal(t, 0, H.Equal(identity), "encode_to_curve returned the identity")
		require.True(t, inPrimeOrderSubgroup(H))
	}
}

// TestInterpretHashAsPoint_AdvancesTheCounterOnATorsionPoint pins the identity
// rejection inside encode_to_curve. If a counter's octets decode to a point the
// cofactor kills, H would be the identity and V = s*H would carry no binding to
// alpha_string at all, so the counter has to advance instead.
func TestInterpretHashAsPoint_AdvancesTheCounterOnATorsionPoint(t *testing.T) {
	hash := make([]byte, 64)

	for _, h := range smallOrderKeys {
		copy(hash, mustHex(h))
		require.Nilf(t, interpretHashAsPoint(hash), "torsion point %s was used as H", h)
	}

	copy(hash, mustHex(notOnCurve))
	require.Nil(t, interpretHashAsPoint(hash))

	copy(hash, mustHex(nonCanonicalPoints["y_above_p"]))
	require.Nil(t, interpretHashAsPoint(hash))

	// A hash that does decode gives a point in the prime-order subgroup.
	H := encodeToCurve(mustHex(rfc9381TAI[0].pk), nil)
	require.NotNil(t, H)
	require.True(t, inPrimeOrderSubgroup(H))
}

// TestDecodeProof_RequiresExactLength: ECVRF_decode_proof splits pi_string at
// fixed offsets, so a short or long buffer is refused rather than padded.
func TestDecodeProof_RequiresExactLength(t *testing.T) {
	pi := mustHex(rfc9381TAI[0].pi)
	for _, n := range []int{0, ProofSize - 1, ProofSize + 1} {
		buf := make([]byte, n)
		copy(buf, pi)
		_, _, _, ok := decodeProof(buf)
		require.Falsef(t, ok, "decoded a %d-byte pi_string", n)
	}

	_, _, _, ok := decodeProof(pi)
	require.True(t, ok)
}

// TestChallengeGeneration_AcceptsEveryTruncation: the challenge is 16 bytes
// widened to a 32-byte scalar, which is below the group order for every
// possible value, so the encoding check it goes through cannot reject one.
func TestChallengeGeneration_AcceptsEveryTruncation(t *testing.T) {
	var maxTruncation [32]byte
	for i := range 16 {
		maxTruncation[i] = 0xFF
	}
	c, err := new(edwards.Scalar).SetCanonicalBytes(maxTruncation[:])
	require.NoError(t, err)
	require.NotNil(t, c)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func buildVerifyInput(pk, alpha, proof []byte) []byte {
	var alphaLen [AlphaLenSize]byte
	binary.BigEndian.PutUint16(alphaLen[:], uint16(len(alpha)))

	input := []byte{OpVerify}
	input = append(input, pk...)
	input = append(input, alphaLen[:]...)
	input = append(input, alpha...)
	input = append(input, proof...)
	return input
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ─── Test-only prover (RFC 9381 Section 5.1) ─────────────────────────────────

// expandSecretKey derives (x, Y) from an Ed25519 seed exactly as RFC 9381
// Section 5.5 specifies for this suite.
func expandSecretKey(sk []byte) (*edwards.Scalar, *edwards.Point) {
	h := sha512.Sum512(sk)
	x, err := new(edwards.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		panic(err)
	}
	return x, new(edwards.Point).ScalarBaseMult(x)
}

// testProve implements ECVRF_prove (RFC 9381 Section 5.1) with the nonce
// generation of Section 5.4.2.2. TestRFC9381_Prove requires it to reproduce
// the published pi_string, so it is an implementation of the RFC rather than a
// mirror of the verifier.
func testProve(sk []byte, Y *edwards.Point, alpha []byte) []byte {
	expanded := sha512.Sum512(sk)

	x, err := new(edwards.Scalar).SetBytesWithClamping(expanded[:32])
	if err != nil {
		panic(err)
	}

	H := encodeToCurve(Y.Bytes(), alpha)
	if H == nil {
		panic("encode_to_curve found no point")
	}

	Gamma := new(edwards.Point).ScalarMult(x, H)

	// k_string = Hash(truncated_hashed_sk_string || point_to_string(H))
	nonce := sha512.New()
	nonce.Write(expanded[32:64])
	nonce.Write(H.Bytes())
	k, err := edwards.NewScalar().SetUniformBytes(nonce.Sum(nil))
	if err != nil {
		panic(err)
	}

	U := new(edwards.Point).ScalarBaseMult(k)
	V := new(edwards.Point).ScalarMult(k, H)
	c := challengeGeneration(Y, H, Gamma, U, V)

	s := new(edwards.Scalar).Add(k, new(edwards.Scalar).Multiply(c, x))

	pi := make([]byte, ProofSize)
	copy(pi[:32], Gamma.Bytes())
	cBytes := c.Bytes()
	copy(pi[32:48], cBytes[:16])
	copy(pi[48:80], s.Bytes())
	return pi
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkVerify(b *testing.B) {
	v := rfc9381TAI[1]
	input := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mustHex(v.pi))

	b.ResetTimer()
	for b.Loop() {
		VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true) //nolint:errcheck
	}
}

func BenchmarkProofToHash(b *testing.B) {
	input := append([]byte{OpProofToHash}, mustHex(rfc9381TAI[1].pi)...)

	b.ResetTimer()
	for b.Loop() {
		VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true) //nolint:errcheck
	}
}
