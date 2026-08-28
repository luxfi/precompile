// keygen_sign_verify_test drives the threshold-signature precompiles through
// the precompile dispatch path with real signatures.
//
// What these tests used to do, and why none of them could pass:
//
//   - CGGMP21 is threshold ECDSA on secp256k1, and the test generated a P-256
//     key. The precompile rejected it, correctly, with "invalid secp256k1
//     public key".
//   - FROST here is secp256k1 with BIP-340-style x-only keys (see
//     verifySchnorrSignature, which calls curve.Secp256k1{}.LiftX), and the
//     test built an edwards25519 key. Wrong curve entirely; the comment
//     claiming "FROST produces Ed25519-compatible keys" does not hold for this
//     implementation.
//   - Both FROST and Ed25519 seeded a scalar with 32 bytes straight from
//     rand.Read and passed them to SetCanonicalBytes. An ed25519 scalar must be
//     below the group order L, which is just under 2^252, so uniform 256-bit
//     bytes are canonical only about one time in sixteen. The tests failed on
//     their own key generation, before reaching a precompile, roughly 94% of
//     runs.
//   - The "Ed25519" test then hand-rolled a SHA-256 Schnorr scheme with the
//     verification equation s = k - e*x. RFC 8032 uses SHA-512 and s = r + e*a.
//     Even with a valid scalar it could never have verified against the
//     precompile, which calls ed25519.Verify.
//
// None of this was visible because e2e/go.mod required a published
// github.com/luxfi/precompile instead of the module in this repo.
//
// Keys are drawn from a seeded source so a failure reproduces.
//
// Precompiles exercised: CGGMP21, FROST, Ed25519.
package scenarios

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	mathrand "math/rand/v2"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/precompile/cggmp21"
	"github.com/luxfi/precompile/e2e/harness"
	precompileed25519 "github.com/luxfi/precompile/ed25519"
	"github.com/luxfi/precompile/frost"
	"github.com/stretchr/testify/require"
)

// seeded is a reproducible byte source for key generation. Tests must not turn
// on the operating system's entropy: a signature scheme that fails one run in
// sixteen is indistinguishable from flaky infrastructure.
type seeded struct{ rng *mathrand.Rand }

func newSeeded(seed uint64) *seeded {
	return &seeded{rng: mathrand.New(mathrand.NewPCG(seed, seed^0x5deece66d))}
}

func (s *seeded) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(s.rng.Uint32())
	}
	return len(p), nil
}

// verified reports whether a precompile call accepted the signature. A refusal
// may surface either as an error or as a non-true return word, and a rejecting
// precompile may return no bytes at all — so this never indexes blindly.
func verified(out []byte, err error) bool {
	return err == nil && len(out) == 32 && out[31] == 1
}

// ─── CGGMP21 (threshold ECDSA, secp256k1) ─────────────────────────────────────

// encodeCGGMP21 lays out the precompile's calldata:
//
//	threshold(4) || totalSigners(4) || pubkey(65) || msgHash(32) || sig(65)
func encodeCGGMP21(threshold, total uint32, pubKey, msgHash, sig []byte) []byte {
	input := make([]byte, 0, cggmp21.MinInputSize)
	input = append(input, harness.Uint32BE(threshold)...)
	input = append(input, harness.Uint32BE(total)...)
	input = append(input, pubKey...)
	input = append(input, msgHash...)
	input = append(input, sig...)
	return input
}

// cggmp21Material produces a secp256k1 key and a signature over msg, in the
// encodings the precompile expects: an uncompressed 65-byte public key and a
// 65-byte [R || S || V] signature. An aggregated CGGMP21 threshold signature is
// an ordinary ECDSA signature, so this is what the ceremony emits.
func cggmp21Material(t *testing.T, msg []byte, seed uint64) (pubKey, msgHash, sig []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(crypto.S256(), newSeeded(seed))
	require.NoError(t, err, "secp256k1 keygen")

	h := sha256.Sum256(msg)
	sig, err = crypto.Sign(h[:], priv)
	require.NoError(t, err, "sign")

	return crypto.FromECDSAPub(&priv.PublicKey), h[:], sig
}

func TestKeygenSignVerify_CGGMP21(t *testing.T) {
	pubKey, msgHash, sig := cggmp21Material(t, []byte("Lux e2e: full CGGMP21 lifecycle test"), 1)
	require.Len(t, pubKey, 65)
	require.Len(t, sig, 65)

	out, gasUsed, err := harness.Call(
		cggmp21.CGGMP21VerifyPrecompile,
		cggmp21.ContractCGGMP21VerifyAddress,
		encodeCGGMP21(2, 3, pubKey, msgHash, sig),
		true,
	)
	require.NoError(t, err, "CGGMP21 verify call error")
	require.Len(t, out, 32, "output should be 32 bytes")
	require.Equal(t, byte(1), out[31], "a valid signature must verify")
	harness.GasReport(t, "CGGMP21 verify", gasUsed)
}

// The signature must bind the message. Verifying a signature against a hash it
// was not made over is the whole property; if this passes, the precompile is
// decorative.
func TestKeygenSignVerify_CGGMP21RejectsWrongMessage(t *testing.T) {
	pubKey, _, sig := cggmp21Material(t, []byte("the message that was signed"), 2)
	other := sha256.Sum256([]byte("a message that was not signed"))

	out, _, err := harness.Call(
		cggmp21.CGGMP21VerifyPrecompile,
		cggmp21.ContractCGGMP21VerifyAddress,
		encodeCGGMP21(2, 3, pubKey, other[:], sig),
		true,
	)
	require.False(t, verified(out, err), "a signature verified against the wrong message")
}

// Every single-bit corruption of the signature must be rejected.
func TestKeygenSignVerify_CGGMP21RejectsCorruptedSignature(t *testing.T) {
	pubKey, msgHash, sig := cggmp21Material(t, []byte("Lux e2e: corruption corpus"), 3)

	for _, bit := range []int{0, 7, 8, 255, 256, 263, 511} {
		corrupt := make([]byte, len(sig))
		copy(corrupt, sig)
		corrupt[bit/8] ^= 1 << (bit % 8)

		out, _, err := harness.Call(
			cggmp21.CGGMP21VerifyPrecompile,
			cggmp21.ContractCGGMP21VerifyAddress,
			encodeCGGMP21(2, 3, pubKey, msgHash, corrupt),
			true,
		)
		require.False(t, verified(out, err), "signature with bit %d flipped verified", bit)
	}
}

// Input shorter than the fixed layout is refused rather than read past.
func TestKeygenSignVerify_CGGMP21RefusesShortInput(t *testing.T) {
	pubKey, msgHash, sig := cggmp21Material(t, []byte("short input"), 4)
	full := encodeCGGMP21(2, 3, pubKey, msgHash, sig)

	for _, n := range []int{0, 1, 8, 73, 105, len(full) - 1} {
		_, _, err := harness.Call(
			cggmp21.CGGMP21VerifyPrecompile,
			cggmp21.ContractCGGMP21VerifyAddress,
			full[:n],
			true,
		)
		require.Error(t, err, "a %d-byte input was accepted", n)
	}
}

// An all-zero public key is not a point on secp256k1 and must be refused.
func TestKeygenSignVerify_CGGMP21RefusesZeroKey(t *testing.T) {
	_, msgHash, sig := cggmp21Material(t, []byte("zero key"), 5)

	out, _, err := harness.Call(
		cggmp21.CGGMP21VerifyPrecompile,
		cggmp21.ContractCGGMP21VerifyAddress,
		encodeCGGMP21(2, 3, make([]byte, 65), msgHash, sig),
		true,
	)
	require.False(t, verified(out, err), "the all-zero public key verified a signature")
}

// ─── FROST (Schnorr, secp256k1 x-only) ────────────────────────────────────────

// The positive case — a genuine aggregated FROST signature verifying — is owned
// by frost/real_sig_test.go, which can reach the threshold library's signing
// internals and the precompile's domain-separated challenge construction.
// Rebuilding that here would put the challenge construction in two places, and
// a second copy of a wire format is exactly what let the StableSwap scenarios
// drift out of sync unnoticed. What e2e adds instead is the dispatch path: that
// the precompile is reachable at its address and refuses what it should.
func TestKeygenSignVerify_FROSTRefusesMalformed(t *testing.T) {
	// A well-formed frame carrying a signature that is not one.
	input := make([]byte, 0, frost.MinInputSize)
	input = append(input, harness.Uint32BE(2)...) // threshold
	input = append(input, harness.Uint32BE(3)...) // total signers
	input = append(input, make([]byte, 32)...)    // public key (all zero)
	msgHash := sha256.Sum256([]byte("Lux e2e: FROST dispatch"))
	input = append(input, msgHash[:]...)
	input = append(input, make([]byte, 64)...) // signature (all zero)

	out, gasUsed, err := harness.Call(
		frost.FROSTVerifyPrecompile,
		frost.ContractFROSTVerifyAddress,
		input,
		true,
	)
	require.False(t, verified(out, err),
		"an all-zero key and signature verified")
	harness.GasReport(t, "FROST verify (refusal)", gasUsed)

	// And truncations of the same frame.
	for _, n := range []int{0, 8, 40, 72, len(input) - 1} {
		_, _, err := harness.Call(
			frost.FROSTVerifyPrecompile,
			frost.ContractFROSTVerifyAddress,
			input[:n],
			true,
		)
		require.Error(t, err, "a %d-byte input was accepted", n)
	}
}

// ─── Ed25519 (RFC 8032) ───────────────────────────────────────────────────────

// encodeEd25519 lays out the precompile's calldata:
//
//	message(32) || signature(64) || publicKey(32)
func encodeEd25519(msgHash, sig, pubKey []byte) []byte {
	input := make([]byte, 0, precompileed25519.InputLength)
	input = append(input, msgHash...)
	input = append(input, sig...)
	input = append(input, pubKey...)
	return input
}

func ed25519Material(t *testing.T, msg []byte, seed uint64) (pubKey, msgHash, sig []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(newSeeded(seed))
	require.NoError(t, err, "ed25519 keygen")

	h := sha256.Sum256(msg)
	// The precompile verifies over the 32-byte word it is handed, so that word
	// is what gets signed.
	return pub, h[:], ed25519.Sign(priv, h[:])
}

func TestKeygenSignVerify_Ed25519Direct(t *testing.T) {
	pubKey, msgHash, sig := ed25519Material(t, []byte("Lux e2e: Ed25519 direct verify"), 6)

	out, gasUsed, err := harness.Call(
		precompileed25519.Ed25519VerifyPrecompile,
		precompileed25519.ContractAddress,
		encodeEd25519(msgHash, sig, pubKey),
		true,
	)
	require.NoError(t, err, "Ed25519 verify call error")
	require.Len(t, out, 32, "output should be 32 bytes")
	require.Equal(t, byte(1), out[31], "a valid RFC 8032 signature must verify")
	harness.GasReport(t, "Ed25519 verify", gasUsed)
}

func TestKeygenSignVerify_Ed25519RejectsWrongMessage(t *testing.T) {
	pubKey, _, sig := ed25519Material(t, []byte("the signed message"), 7)
	other := sha256.Sum256([]byte("a different message"))

	out, _, err := harness.Call(
		precompileed25519.Ed25519VerifyPrecompile,
		precompileed25519.ContractAddress,
		encodeEd25519(other[:], sig, pubKey),
		true,
	)
	require.False(t, verified(out, err), "a signature verified against the wrong message")
}

func TestKeygenSignVerify_Ed25519RejectsCorruption(t *testing.T) {
	pubKey, msgHash, sig := ed25519Material(t, []byte("Lux e2e: ed25519 corruption"), 8)

	// Corrupt the signature, then the key. Both must be refused.
	for _, bit := range []int{0, 255, 256, 511} {
		corrupt := make([]byte, len(sig))
		copy(corrupt, sig)
		corrupt[bit/8] ^= 1 << (bit % 8)

		out, _, err := harness.Call(
			precompileed25519.Ed25519VerifyPrecompile,
			precompileed25519.ContractAddress,
			encodeEd25519(msgHash, corrupt, pubKey),
			true,
		)
		require.False(t, verified(out, err), "signature with bit %d flipped verified", bit)
	}

	badKey := make([]byte, len(pubKey))
	copy(badKey, pubKey)
	badKey[0] ^= 1
	out, _, err := harness.Call(
		precompileed25519.Ed25519VerifyPrecompile,
		precompileed25519.ContractAddress,
		encodeEd25519(msgHash, sig, badKey),
		true,
	)
	require.False(t, verified(out, err), "a corrupted public key verified")
}

// The precompile takes a fixed 128-byte frame and must refuse anything else, in
// both directions.
//
// Note the refusal SHAPE differs across this repo's verifiers: ed25519 reports
// failure by returning empty output with a nil error (documented at the top of
// its Run), while cggmp21 and frost return an error. Both are safe — neither
// can be mistaken for the success word — but a caller cannot distinguish
// "malformed frame" from "signature did not verify" here, which for a verifier
// is the conservative choice. Assert the property that matters in both shapes:
// the call did not verify.
func TestKeygenSignVerify_Ed25519RefusesWrongLength(t *testing.T) {
	pubKey, msgHash, sig := ed25519Material(t, []byte("length discipline"), 9)
	full := encodeEd25519(msgHash, sig, pubKey)
	require.Len(t, full, precompileed25519.InputLength)

	for _, in := range [][]byte{
		nil,
		full[:precompileed25519.InputLength-1],
		append(append([]byte{}, full...), 0x00),
	} {
		out, gasUsed, err := harness.Call(
			precompileed25519.Ed25519VerifyPrecompile,
			precompileed25519.ContractAddress,
			in,
			true,
		)
		require.False(t, verified(out, err), "a %d-byte input verified", len(in))
		// And it was still charged: a malformed frame must not be free to repeat.
		require.NotZero(t, gasUsed,
			"a %d-byte input was refused without charging gas", len(in))
	}
}
