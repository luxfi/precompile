// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func katInt(tb testing.TB, s string) *big.Int {
	tb.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	require.True(tb, ok, "bad hex literal %q", s)
	return v
}

func word(tb testing.TB, v *big.Int) []byte {
	tb.Helper()
	require.LessOrEqual(tb, v.BitLen(), 256, "value does not fit in a 32-byte word")
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

// calldata lays out the RIP-7212 input: hash(32) || r(32) || s(32) || x(32) || y(32).
func calldata(tb testing.TB, hash []byte, r, s, x, y *big.Int) []byte {
	tb.Helper()
	out := make([]byte, 0, InputLength)
	out = append(out, hash...)
	out = append(out, word(tb, r)...)
	out = append(out, word(tb, s)...)
	out = append(out, word(tb, x)...)
	return append(out, word(tb, y)...)
}

// rfc6979 holds the P-256 / SHA-256 deterministic-ECDSA vectors from RFC 6979
// appendix A.2.5. They were re-checked against an independent implementation of
// the verification equation, and the public key was re-derived from the private
// scalar, before being written here.
var rfc6979 = struct {
	d, x, y string
	cases   []struct{ msg, r, s string }
}{
	d: "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
	x: "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
	y: "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
	cases: []struct{ msg, r, s string }{
		{
			msg: "sample",
			r:   "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			s:   "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
		},
		{
			msg: "test",
			r:   "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			s:   "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
		},
	},
}

// TestKAT_RFC6979 pins the verifier against published vectors, and binds the
// public key to the published private scalar so key handling is covered too.
func TestKAT_RFC6979(t *testing.T) {
	curve := elliptic.P256()
	x, y := katInt(t, rfc6979.x), katInt(t, rfc6979.y)

	dx, dy := curve.ScalarBaseMult(word(t, katInt(t, rfc6979.d)))
	require.Zero(t, dx.Cmp(x), "published private scalar must produce the published X")
	require.Zero(t, dy.Cmp(y), "published private scalar must produce the published Y")

	c := &Contract{}
	for _, tc := range rfc6979.cases {
		t.Run(tc.msg, func(t *testing.T) {
			h := sha256.Sum256([]byte(tc.msg))
			r, s := katInt(t, tc.r), katInt(t, tc.s)

			out, err := c.Run(calldata(t, h[:], r, s, x, y))
			require.NoError(t, err)
			require.Equal(t, successResult, out, "published vector must verify")
			require.True(t, Verify(h[:], r, s, x, y))
		})
	}
}

// TestKAT_RFC6979_MutationsRejected flips one bit in each field of each
// published vector. Without this a verifier that answers true unconditionally
// still passes TestKAT_RFC6979.
func TestKAT_RFC6979_MutationsRejected(t *testing.T) {
	x, y := katInt(t, rfc6979.x), katInt(t, rfc6979.y)
	c := &Contract{}

	for _, tc := range rfc6979.cases {
		h := sha256.Sum256([]byte(tc.msg))
		full := calldata(t, h[:], katInt(t, tc.r), katInt(t, tc.s), x, y)

		for at := range full {
			bad := append([]byte{}, full...)
			bad[at] ^= 0x01
			out, err := c.Run(bad)
			require.NoError(t, err)
			require.Nil(t, out, "%s: mutating byte %d must not verify", tc.msg, at)
		}
	}
}

// verifyIndependently is a textbook ECDSA check over math/big, deliberately not
// sharing a line of code with crypto/ecdsa's nistec path. It exists so the
// property tests below compare two implementations rather than one against
// itself.
func verifyIndependently(hash []byte, r, s, px, py *big.Int) bool {
	c := elliptic.P256().Params()
	if r.Sign() <= 0 || r.Cmp(c.N) >= 0 || s.Sign() <= 0 || s.Cmp(c.N) >= 0 {
		return false
	}
	if !c.IsOnCurve(px, py) {
		return false
	}
	// e is the leftmost min(bitlen(N), 8*len(hash)) bits of the hash.
	e := new(big.Int).SetBytes(hash)
	if excess := 8*len(hash) - c.N.BitLen(); excess > 0 {
		e.Rsh(e, uint(excess))
	}
	w := new(big.Int).ModInverse(s, c.N)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mod(new(big.Int).Mul(e, w), c.N)
	u2 := new(big.Int).Mod(new(big.Int).Mul(r, w), c.N)

	ax, ay := c.ScalarBaseMult(u1.Bytes())
	bx, by := c.ScalarMult(px, py, u2.Bytes())
	qx, qy := c.Add(ax, ay, bx, by)
	if qx.Sign() == 0 && qy.Sign() == 0 {
		return false
	}
	return new(big.Int).Mod(qx, c.N).Cmp(r) == 0
}

// TestAgreesWithIndependentVerifier runs fresh keys and signatures, plus
// deliberately broken ones, through both implementations and requires the same
// verdict every time. Fixed vectors cannot catch an error that only shows on
// inputs nobody published.
func TestAgreesWithIndependentVerifier(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N
	c := &Contract{}

	for i := range 24 {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		h := sha256.Sum256([]byte{byte(i)})
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		require.NoError(t, err)

		for _, tc := range []struct {
			name string
			r, s *big.Int
			x, y *big.Int
			hash []byte
		}{
			{"genuine", r, s, priv.X, priv.Y, h[:]},
			{"malleated s", r, new(big.Int).Sub(n, s), priv.X, priv.Y, h[:]},
			{"swapped r,s", s, r, priv.X, priv.Y, h[:]},
			{"other hash", r, s, priv.X, priv.Y, sha256.New().Sum(nil)},
			{"y negated", r, s, priv.X, new(big.Int).Sub(curve.Params().P, priv.Y), h[:]},
			{"r incremented", new(big.Int).Add(r, big.NewInt(1)), s, priv.X, priv.Y, h[:]},
		} {
			want := verifyIndependently(tc.hash, tc.r, tc.s, tc.x, tc.y)
			out, err := c.Run(calldata(t, tc.hash, tc.r, tc.s, tc.x, tc.y))
			require.NoError(t, err)
			require.Equal(t, want, out != nil,
				"iteration %d %q: precompile and independent verifier disagree", i, tc.name)
			require.Equal(t, want, Verify(tc.hash, tc.r, tc.s, tc.x, tc.y))
		}
	}
}

// TestMalleability_HighSIsAcceptedBySpec records a real property of this
// precompile: RIP-7212 requires only 1 <= s <= n-1, so both s and n-s verify.
// Every P-256 signature therefore has two accepted encodings. That is correct
// here -- unlike secp256k1's ecrecover, no low-s rule exists for P-256, and
// enforcing one would reject signatures WebAuthn authenticators legitimately
// produce. Callers that need a unique signature identity must canonicalise
// themselves. This test fails the day someone adds a low-s check, which would
// be a consensus change.
func TestMalleability_HighSIsAcceptedBySpec(t *testing.T) {
	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)
	c := &Contract{}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	h := sha256.Sum256([]byte("malleability"))

	var lowS, highS *big.Int
	var r *big.Int
	for range 64 {
		sr, ss, err := ecdsa.Sign(rand.Reader, priv, h[:])
		require.NoError(t, err)
		r = sr
		if ss.Cmp(halfN) > 0 {
			highS, lowS = ss, new(big.Int).Sub(n, ss)
		} else {
			lowS, highS = ss, new(big.Int).Sub(n, ss)
		}
		break
	}
	require.NotNil(t, r)
	require.LessOrEqual(t, lowS.Cmp(halfN), 0)
	require.Positive(t, highS.Cmp(halfN))

	for name, s := range map[string]*big.Int{"low-s": lowS, "high-s": highS} {
		out, err := c.Run(calldata(t, h[:], r, s, priv.X, priv.Y))
		require.NoError(t, err)
		require.Equal(t, successResult, out, "%s must verify: RIP-7212 has no low-s rule", name)
	}
}

// TestRefusals_PointAndScalarRanges is the input-validation surface. Every one
// of these is a well-formed 160-byte call that must not verify.
func TestRefusals_PointAndScalarRanges(t *testing.T) {
	curve := elliptic.P256()
	params := curve.Params()
	n, p := params.N, params.P

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	h := sha256.Sum256([]byte("refusals"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	require.NoError(t, err)
	c := &Contract{}

	// Sanity: the unmutated call really does verify, so a rejection below is
	// attributable to the mutation and not to a broken fixture.
	out, err := c.Run(calldata(t, h[:], r, s, priv.X, priv.Y))
	require.NoError(t, err)
	require.Equal(t, successResult, out)

	offCurveY := new(big.Int).Add(priv.Y, big.NewInt(1))
	require.False(t, curve.IsOnCurve(priv.X, offCurveY), "fixture must really be off-curve")

	for _, tc := range []struct {
		name       string
		r, s, x, y *big.Int
	}{
		// Invalid-curve attack: well-formed coordinates off the curve.
		{"point off curve", r, s, priv.X, offCurveY},
		{"point off curve (x+1)", r, s, new(big.Int).Add(priv.X, big.NewInt(1)), priv.Y},
		// Point at infinity, spelled (0, 0).
		{"point at infinity", r, s, big.NewInt(0), big.NewInt(0)},
		{"x zero", r, s, big.NewInt(0), priv.Y},
		{"y zero", r, s, priv.X, big.NewInt(0)},
		// Non-canonical field elements: x = p reduces to 0, which is not a
		// coordinate. It must be refused rather than reduced.
		{"x = p", r, s, p, priv.Y},
		{"y = p", r, s, priv.X, p},
		// Scalars outside [1, n-1].
		{"r = 0", big.NewInt(0), s, priv.X, priv.Y},
		{"s = 0", r, big.NewInt(0), priv.X, priv.Y},
		{"r = n", n, s, priv.X, priv.Y},
		{"s = n", r, n, priv.X, priv.Y},
		{"r = n+1", new(big.Int).Add(n, big.NewInt(1)), s, priv.X, priv.Y},
		{"s = n+1", r, new(big.Int).Add(n, big.NewInt(1)), priv.X, priv.Y},
		{"r = s = 0", big.NewInt(0), big.NewInt(0), priv.X, priv.Y},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := calldata(t, h[:], tc.r, tc.s, tc.x, tc.y)
			require.Len(t, in, InputLength, "refusal must come from validation, not length")
			out, err := c.Run(in)
			require.NoError(t, err, "a refusal is an empty return, not an error")
			require.Nil(t, out)
			require.False(t, Verify(h[:], tc.r, tc.s, tc.x, tc.y))
			require.False(t, verifyIndependently(h[:], tc.r, tc.s, tc.x, tc.y),
				"independent verifier must agree on the refusal")
		})
	}
}

// TestRefusals_Length covers empty, one short, one long and the all-zero call.
func TestRefusals_Length(t *testing.T) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	h := sha256.Sum256([]byte("length"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	require.NoError(t, err)
	full := calldata(t, h[:], r, s, priv.X, priv.Y)
	c := &Contract{}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
		{"one short", full[:InputLength-1]},
		{"one long", append(append([]byte{}, full...), 0)},
		{"double", append(append([]byte{}, full...), full...)},
		{"all zero", make([]byte, InputLength)},
		{"all ones", func() []byte {
			b := make([]byte, InputLength)
			for i := range b {
				b[i] = 0xFF
			}
			return b
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := c.Run(tc.in)
			require.NoError(t, err)
			require.Nil(t, out)
		})
	}

	out, err := c.Run(full)
	require.NoError(t, err)
	require.Equal(t, successResult, out, "the exact length still verifies")
}

// --- stateful wrapper ---------------------------------------------------

// TestStateful_DeductsGasThenDelegates covers the modules.Module entry point,
// which is what the EVM actually calls.
func TestStateful_DeductsGasThenDelegates(t *testing.T) {
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	h := sha256.Sum256([]byte("stateful"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	require.NoError(t, err)
	in := calldata(t, h[:], r, s, priv.X, priv.Y)

	// Production reaches the wrapper's gas price through an optional interface
	// (see bindings/cabi), not through StatefulPrecompiledContract, so assert it
	// exactly that way.
	estimator, ok := StatefulPrecompile.(interface{ RequiredGas([]byte) uint64 })
	require.True(t, ok, "the registered precompile must expose RequiredGas")
	require.Equal(t, uint64(GasP256Verify), estimator.RequiredGas(in))

	out, left, err := StatefulPrecompile.Run(nil, common.Address{}, Address, in, GasP256Verify+5, false)
	require.NoError(t, err)
	require.Equal(t, successResult, out)
	require.Equal(t, uint64(5), left, "exactly RequiredGas is deducted")

	// Exactly enough gas.
	_, left, err = StatefulPrecompile.Run(nil, common.Address{}, Address, in, GasP256Verify, true)
	require.NoError(t, err)
	require.Zero(t, left)

	// One short.
	out, left, err = StatefulPrecompile.Run(nil, common.Address{}, Address, in, GasP256Verify-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Nil(t, out)
	require.Zero(t, left)

	// Zero gas.
	_, _, err = StatefulPrecompile.Run(nil, common.Address{}, Address, in, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)

	// A failed verify still costs full price and still returns no error.
	bad := append([]byte{}, in...)
	bad[0] ^= 0xFF
	out, left, err = StatefulPrecompile.Run(nil, common.Address{}, Address, bad, GasP256Verify+2, true)
	require.NoError(t, err)
	require.Nil(t, out)
	require.Equal(t, uint64(2), left)
}

// TestRequiredGas_IsFlat: the input is a fixed 160 bytes, so a size-dependent
// price would be wrong. Longer input is refused, not metered.
func TestRequiredGas_IsFlat(t *testing.T) {
	c := &Contract{}
	for _, n := range []int{0, 1, 159, 160, 161, 1 << 16} {
		require.Equal(t, uint64(GasP256Verify), c.RequiredGas(make([]byte, n)), "len=%d", n)
		require.Equal(t, uint64(GasP256Verify), (&stateful{}).RequiredGas(make([]byte, n)))
	}
	require.Equal(t, uint64(GasP256Verify), c.RequiredGas(nil))
}

// --- module + config ----------------------------------------------------

func TestRegistryModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, RegistryModule.ConfigKey)
	require.Equal(t, Address, RegistryModule.Address)
	require.Same(t, StatefulPrecompile, RegistryModule.Contract)
	require.NotNil(t, RegistryModule.Configurator)

	// RIP-7212 fixes the address at 0x100; moving it forks the chain.
	require.Equal(t, common.HexToAddress(P256VerifyAddress), Address)
	want, err := hex.DecodeString("0000000000000000000000000000000000000100")
	require.NoError(t, err)
	require.Equal(t, want, Address.Bytes())
}

func TestConfigurator_Surface(t *testing.T) {
	c := &configurator{}
	require.IsType(t, &Config{}, c.MakeConfig())
	require.NoError(t, c.Configure(nil, nil, nil, nil))
}

func TestConfig_Surface(t *testing.T) {
	c := &Config{}
	require.Equal(t, ConfigKey, c.Key())
	require.Nil(t, c.Timestamp())
	require.False(t, c.IsDisabled())
	require.NoError(t, c.Verify(nil))

	ts := uint64(99)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(100)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil))

	d := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, d.IsDisabled())
}

// TestRegisterModuleIsIdempotentlyRefused exercises the condition init() panics
// on. The panic itself runs before any test binary can observe it.
func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(RegistryModule))
}
