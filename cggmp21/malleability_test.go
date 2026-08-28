// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/stretchr/testify/require"
)

// secp256k1 group order n and field prime p.
var (
	groupOrder, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	fieldPrime, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
)

// pad32 left-pads a big-endian integer to 32 bytes.
func pad32(x *big.Int) []byte {
	out := make([]byte, 32)
	b := x.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// negateY returns -P for an uncompressed 0x04||x||y encoding: a genuine
// secp256k1 point, distinct from P, which therefore reaches the verification
// equation instead of the encoding check.
func negateY(t *testing.T, pk []byte) []byte {
	t.Helper()
	require.Len(t, pk, 65)
	y := new(big.Int).SetBytes(pk[33:65])
	out := append([]byte(nil), pk...)
	copy(out[33:65], pad32(new(big.Int).Sub(fieldPrime, y)))
	return out
}

// withS returns the KAT signature with s replaced.
func withS(t *testing.T, s *big.Int, v byte) []byte {
	t.Helper()
	sig := mustHex(t, katSIGHex)
	copy(sig[32:64], pad32(s))
	sig[64] = v
	return sig
}

// TestCGGMP21_HighSRefused is the ECDSA malleability check.
//
// ECDSA is malleable by construction: for a valid (r, s) the pair (r, n-s)
// satisfies the same equation over the same message and key. If both were
// accepted, one signature would have two accepted 65-byte encodings, and any
// on-chain replay protection keyed on the signature bytes would be defeated by
// resubmitting the negated form.
//
// Measured verdict: the low-S rule is enforced, in crypto.VerifySignature
// itself (libsecp256k1 refuses an s above n/2), before the recover-and-compare
// is reached. This test pins BOTH halves -- the primitive's refusal and the
// precompile's -- so that swapping the crypto dependency for one without the
// rule cannot silently open the hole.
func TestCGGMP21_HighSRefused(t *testing.T) {
	pk, mh, sig := katVector(t)

	s := new(big.Int).SetBytes(sig[32:64])
	require.Negative(t, s.Cmp(new(big.Int).Rsh(groupOrder, 1)), "the KAT must be the low-S form")
	negS := new(big.Int).Sub(groupOrder, s)
	require.Positive(t, negS.Cmp(new(big.Int).Rsh(groupOrder, 1)), "n-s must be the high-S form")

	// Evidence: the primitive itself refuses the high-S pair.
	require.True(t, crypto.VerifySignature(pk, mh, sig[:64]), "low-S must satisfy the primitive")
	high := withS(t, negS, sig[64])
	require.False(t, crypto.VerifySignature(pk, mh, high[:64]),
		"high-S must be refused by crypto.VerifySignature (EIP-2 low-S rule)")

	// The precompile inherits the refusal, under every recovery byte -- the
	// recovery byte flips when s is negated, so both candidates are covered.
	for _, v := range []byte{0, 1, 27, 28} {
		accepted, err := verdict(t, pk, mh, withS(t, negS, v))
		require.NoError(t, err)
		require.False(t, accepted, "high-S with v=%d must be refused", v)
	}
}

// TestCGGMP21_DegenerateScalars: r or s outside [1, n) has no meaning. Zero
// and values at or above the group order must all be refused, otherwise the
// signature encoding admits values the equation cannot represent.
func TestCGGMP21_DegenerateScalars(t *testing.T) {
	pk, mh, sig := katVector(t)
	zero, one := new(big.Int), big.NewInt(1)

	for _, tc := range []struct {
		name string
		put  func([]byte)
	}{
		{"r == 0", func(b []byte) { copy(b[0:32], pad32(zero)) }},
		{"s == 0", func(b []byte) { copy(b[32:64], pad32(zero)) }},
		{"r == n", func(b []byte) { copy(b[0:32], pad32(groupOrder)) }},
		{"s == n", func(b []byte) { copy(b[32:64], pad32(groupOrder)) }},
		{"r == n+1", func(b []byte) { copy(b[0:32], pad32(new(big.Int).Add(groupOrder, one))) }},
		{"s == n+1", func(b []byte) { copy(b[32:64], pad32(new(big.Int).Add(groupOrder, one))) }},
		{"r,s all-ff", func(b []byte) { copy(b[0:64], mustHex(t, allOnesHex+allOnesHex)) }},
		{"r,s zero", func(b []byte) { copy(b[0:64], make([]byte, 64)) }},
	} {
		bad := append([]byte(nil), sig...)
		tc.put(bad)
		accepted, err := verdict(t, pk, mh, bad)
		require.NoError(t, err, "%s must be a verdict, not a revert", tc.name)
		require.False(t, accepted, "%s must be refused", tc.name)
	}
}

// TestCGGMP21_RecoveryByteSweep pins the verdict for every shape of the
// recovery byte. The current rule, read off the code: v is normalised by
// subtracting 27 when v >= 27, then handed to ecrecover, which refuses
// anything at or above 4. So exactly two byte values are accepted for a given
// signature -- the true recovery id and that id plus 27.
//
// That is an ENCODING malleability: two distinct 170-byte calldatas produce
// the same accepted verdict for one signature. It is pinned rather than fixed
// because narrowing it to v in {0, 1} changes the accept set of a deployed
// precompile, which is a consensus change and belongs in an upgrade, not in a
// test pass. This test is what makes such a change deliberate: it fails the
// moment the accept set moves.
func TestCGGMP21_RecoveryByteSweep(t *testing.T) {
	pk, mh, sig := katVector(t)
	trueV := sig[64]
	require.Less(t, trueV, byte(2), "the KAT recovery id must be 0 or 1")

	accept := map[byte]bool{trueV: true, trueV + 27: true}
	for _, v := range []byte{0, 1, 2, 3, 4, 5, 26, 27, 28, 29, 30, 31, 100, 254, 255} {
		bad := append([]byte(nil), sig...)
		bad[64] = v
		accepted, err := verdict(t, pk, mh, bad)
		require.NoError(t, err, "v=%d must be a verdict, not a revert", v)
		require.Equal(t, accept[v], accepted, "v=%d verdict moved", v)
	}
}

// TestCGGMP21_TwoEncodingsPerSignature states the malleability finding as an
// assertion in its own right: one signature, two accepted calldatas that
// differ only in the recovery byte. Anything on chain that keys replay
// protection on the signature bytes is defeated by resubmitting the other
// encoding. Narrowing the accept set to v in {0, 1} closes it.
func TestCGGMP21_TwoEncodingsPerSignature(t *testing.T) {
	pk, mh, sig := katVector(t)

	alias := append([]byte(nil), sig...)
	alias[64] = sig[64] + 27
	require.NotEqual(t, sig, alias, "the two encodings must differ on the wire")

	a, err := verdict(t, pk, mh, sig)
	require.NoError(t, err)
	b, err := verdict(t, pk, mh, alias)
	require.NoError(t, err)
	require.True(t, a && b,
		"v and v+27 are both accepted today; changing that is a consensus change")
}

// lambda is a nontrivial cube root of 1 modulo the group order -- the
// secp256k1 GLV scalar. Its defining property here is geometric:
// lambda*(x, y) = (beta*x, y), so lambda*P shares P's y-coordinate and has a
// different x. That is what makes it the counterexample to comparing only y.
const lambdaHex = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72"

func pubOf(d *big.Int) *ecdsa.PublicKey {
	x, y := crypto.S256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}
}

// evenNonce returns the smallest k > 1 whose R = k*G has an even y and an x
// below the group order -- i.e. a nonce whose recovery id is 0.
func evenNonce(t *testing.T) *big.Int {
	t.Helper()
	for k := int64(2); k < 64; k++ {
		x, y := crypto.S256().ScalarBaseMult(big.NewInt(k).Bytes())
		if y.Bit(0) == 0 && x.Cmp(groupOrder) < 0 {
			return big.NewInt(k)
		}
	}
	t.Fatal("no small nonce with recovery id 0")
	return nil
}

// craft assembles (public key, message hash, r||s||0) for chosen k, s and
// message scalar z, such that the recovery id 0 recovery IS the public key --
// so crypto.VerifySignature accepts it. No private key is signed with: the
// discrete log is derived from the recovery equation, d = (s*k - z)/r.
func craft(t *testing.T, k, s, z *big.Int) (pk, mh, sig []byte, d *big.Int) {
	t.Helper()
	rx, ry := crypto.S256().ScalarBaseMult(k.Bytes())
	require.Zero(t, ry.Bit(0), "k must give an even-y R")
	require.Negative(t, rx.Cmp(groupOrder), "r must not exceed the group order")

	num := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(s, k), z), groupOrder)
	d = new(big.Int).Mod(new(big.Int).Mul(num, new(big.Int).ModInverse(rx, groupOrder)), groupOrder)

	pk = crypto.FromECDSAPub(pubOf(d))
	mh = pad32(z)
	sig = append(append(pad32(rx), pad32(s)...), 0)
	return pk, mh, sig, d
}

// TestCGGMP21_BothCoordinatesAreCompared.
//
// On secp256k1 a single coordinate does not identify a point. Two points
// share an x (P and -P) and three share a y (P, lambda*P, lambda^2*P, the GLV
// endomorphism images). So the recovered-key check must compare BOTH
// coordinates; comparing either alone admits a key that is not the one the
// caller supplied.
//
// Both halves are demonstrated with a constructed signature rather than an
// argument. In each case r||s satisfies the equation under the supplied key,
// so crypto.VerifySignature says yes and only the recovered-key comparison
// stands between the caller and an accepted verdict:
//
//   - message scalar z = 0 makes the two recovery candidates exact negatives,
//     Q1 = -Q0. Presenting recovery id 1 recovers -P: same x, different y. A
//     check that compared only x would accept it.
//   - choosing z = -s*k*(1+lambda)/(1-lambda) makes Q1 = lambda*Q0. Presenting
//     recovery id 1 recovers lambda*P: different x, same y. A check that
//     compared only y would accept it.
func TestCGGMP21_BothCoordinatesAreCompared(t *testing.T) {
	k := evenNonce(t)

	t.Run("shared x, different y", func(t *testing.T) {
		pk, mh, sig, d := craft(t, k, big.NewInt(3), new(big.Int))
		require.True(t, crypto.VerifySignature(pk, mh, sig[:64]),
			"r||s must satisfy the equation under the supplied key")

		accepted, err := verdict(t, pk, mh, sig)
		require.NoError(t, err)
		require.True(t, accepted, "recovery id 0 is the supplied key")

		flipped := append([]byte(nil), sig...)
		flipped[64] = 1
		rec, err := recoverPublicKey(mh, flipped)
		require.NoError(t, err)
		P := pubOf(d)
		require.Equal(t, 0, rec.X.Cmp(P.X), "construction: the negated recovery must share x")
		require.NotEqual(t, 0, rec.Y.Cmp(P.Y), "construction: the negated recovery must differ in y")

		accepted, err = verdict(t, pk, mh, flipped)
		require.NoError(t, err)
		require.False(t, accepted, "-P shares x with P and must still be refused")
	})

	t.Run("shared y, different x", func(t *testing.T) {
		lam, ok := new(big.Int).SetString(lambdaHex, 16)
		require.True(t, ok)
		require.Equal(t, 0, new(big.Int).Exp(lam, big.NewInt(3), groupOrder).Cmp(big.NewInt(1)),
			"lambda must be a cube root of 1")

		s := big.NewInt(5)
		num := new(big.Int).Mul(new(big.Int).Mul(s, k), new(big.Int).Add(big.NewInt(1), lam))
		den := new(big.Int).Sub(big.NewInt(1), lam)
		z := new(big.Int).Mod(
			new(big.Int).Neg(new(big.Int).Mul(num, new(big.Int).ModInverse(den, groupOrder))),
			groupOrder)

		pk, mh, sig, d := craft(t, k, s, z)
		require.True(t, crypto.VerifySignature(pk, mh, sig[:64]),
			"r||s must satisfy the equation under the supplied key")

		accepted, err := verdict(t, pk, mh, sig)
		require.NoError(t, err)
		require.True(t, accepted, "recovery id 0 is the supplied key")

		flipped := append([]byte(nil), sig...)
		flipped[64] = 1
		rec, err := recoverPublicKey(mh, flipped)
		require.NoError(t, err)
		P := pubOf(d)
		require.Equal(t, 0, rec.X.Cmp(pubOf(new(big.Int).Mod(new(big.Int).Mul(lam, d), groupOrder)).X),
			"construction: the second recovery must be lambda*P")
		require.NotEqual(t, 0, rec.X.Cmp(P.X), "construction: lambda*P must differ in x")
		require.Equal(t, 0, rec.Y.Cmp(P.Y), "construction: lambda*P must share y")

		accepted, err = verdict(t, pk, mh, flipped)
		require.NoError(t, err)
		require.False(t, accepted, "lambda*P shares y with P and must still be refused")
	})
}

// TestCGGMP21_RecoveredKeyIsCompared: crypto.VerifySignature reads only r||s,
// so without the recover-and-compare the recovery byte would be unbound and
// the precompile would accept a signature under a recovery id that recovers a
// different key. Asserting the wrong-id refusal is what keeps that comparison
// in the code.
func TestCGGMP21_RecoveredKeyIsCompared(t *testing.T) {
	pk, mh, sig := katVector(t)
	wrongID := append([]byte(nil), sig...)
	wrongID[64] = sig[64] ^ 1

	// The primitive alone still says yes -- it never sees the recovery byte.
	require.True(t, crypto.VerifySignature(pk, mh, wrongID[:64]),
		"r||s alone is unaffected by the recovery byte")

	// The precompile says no, because it recovers under that byte and compares.
	accepted, err := verdict(t, pk, mh, wrongID)
	require.NoError(t, err)
	require.False(t, accepted, "the recovered key must be compared against the supplied key")

	// And the recovery is not vacuous: under the correct id it returns the key.
	rec, err := recoverPublicKey(mh, sig)
	require.NoError(t, err)
	require.Equal(t, pk, crypto.FromECDSAPub(rec), "the correct id must recover the supplied key")

	rec, err = recoverPublicKey(mh, wrongID)
	if err == nil {
		require.NotEqual(t, pk, crypto.FromECDSAPub(rec), "the wrong id must not recover the supplied key")
	}
}
