// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	stded "crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
	luxed "github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func katHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}

// rfc8032 carries the Ed25519 vectors from RFC 8032 section 7.1. Each was
// re-derived from the seed and re-verified against an independent reference
// implementation of the verification equation before being written down here,
// so a uniformly wrong verifier cannot satisfy them.
var rfc8032 = []struct {
	name string
	seed string
	pub  string
	msg  string
	sig  string
}{
	{
		name: "RFC8032/TEST1/empty-message",
		seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		msg:  "",
		sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f" +
			"b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	},
	{
		name: "RFC8032/TEST2/one-byte",
		seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		msg:  "72",
		sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08" +
			"5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	},
	{
		name: "RFC8032/TEST3/two-byte",
		seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		pub:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		msg:  "af82",
		sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18" +
			"ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
	},
	{
		name: "RFC8032/TEST-SHA(abc)/64-byte",
		seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		pub:  "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		msg: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a21" +
			"92992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		sig: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909" +
			"351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
	},
}

// TestKAT_RFC8032 pins the verifier against published vectors. A round trip
// (sign then verify with the same code) passes even when the whole scheme is
// uniformly wrong; these do not.
func TestKAT_RFC8032(t *testing.T) {
	for _, v := range rfc8032 {
		t.Run(v.name, func(t *testing.T) {
			seed, pub := katHex(t, v.seed), katHex(t, v.pub)
			msg, sig := katHex(t, v.msg), katHex(t, v.sig)

			// The seed must produce the published public key: this binds key
			// derivation, not just the verification equation.
			priv := stded.NewKeyFromSeed(seed)
			require.Equal(t, pub, []byte(priv.Public().(stded.PublicKey)))
			require.Equal(t, sig, stded.Sign(priv, msg))

			require.True(t, VerifyRaw(msg, sig, pub), "published vector must verify")
			require.True(t, Verify(msg, sig, pub))
		})
	}
}

// TestKAT_RFC8032_BitFlipsRejected mutates one bit of every field of every
// published vector and requires rejection. Without this a verifier that always
// answers true still passes TestKAT_RFC8032.
func TestKAT_RFC8032_BitFlipsRejected(t *testing.T) {
	for _, v := range rfc8032 {
		pub, msg, sig := katHex(t, v.pub), katHex(t, v.msg), katHex(t, v.sig)

		for _, f := range []struct {
			field string
			at    int
			buf   []byte
		}{
			{"R", 0, sig}, {"R", 31, sig},
			{"S", 32, sig}, {"S", 63, sig},
			{"pubkey", 0, pub}, {"pubkey", 31, pub},
		} {
			t.Run(v.name+"/"+f.field+"/byte", func(t *testing.T) {
				m := append([]byte{}, f.buf...)
				m[f.at] ^= 0x01
				p, s := pub, sig
				if f.field == "pubkey" {
					p = m
				} else {
					s = m
				}
				require.False(t, VerifyRaw(msg, s, p), "mutated %s must not verify", f.field)
			})
		}
		if len(msg) > 0 {
			t.Run(v.name+"/message", func(t *testing.T) {
				m := append([]byte{}, msg...)
				m[0] ^= 0x01
				require.False(t, VerifyRaw(m, sig, pub))
			})
		}
	}
}

// order is the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
func order() *big.Int {
	l, ok := new(big.Int).SetString(
		"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("bad order literal")
	}
	return l
}

// TestKAT_MalleableScalarRejected is the malleability refusal that matters for
// a precompile: (R, S) and (R, S+L) satisfy the same verification equation over
// the group, so a verifier that reduces S instead of refusing it hands every
// caller a second valid encoding of one signature. RFC 8032 requires 0 <= S < L.
func TestKAT_MalleableScalarRejected(t *testing.T) {
	l := order()
	for _, v := range rfc8032 {
		pub, msg, sig := katHex(t, v.pub), katHex(t, v.msg), katHex(t, v.sig)
		require.True(t, VerifyRaw(msg, sig, pub), "precondition")

		// S is little-endian. S + k*L stays inside 64 bytes for k = 1, 2, 3.
		s := new(big.Int).SetBytes(reversed(sig[32:]))
		require.Negative(t, s.Cmp(l), "published S must already be reduced")

		for k := int64(1); k <= 3; k++ {
			t.Run(v.name+"/S+"+string(rune('0'+k))+"L", func(t *testing.T) {
				sk := new(big.Int).Add(s, new(big.Int).Mul(big.NewInt(k), l))
				if sk.BitLen() > 256 {
					t.Skipf("S+%dL does not fit in 32 bytes", k)
				}
				be := make([]byte, 32)
				sk.FillBytes(be)
				mal := append(append([]byte{}, sig[:32]...), reversed(be)...)
				require.Len(t, mal, 64)
				require.NotEqual(t, sig, mal, "mutation must change the encoding")
				require.False(t, VerifyRaw(msg, mal, pub),
					"non-canonical S (>= L) must be refused, not reduced")
			})
		}
	}
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// smallOrder lists the canonical encodings of the eight points of order
// dividing 8 on Edwards25519 -- the whole torsion subgroup.
var smallOrder = []string{
	"0100000000000000000000000000000000000000000000000000000000000000", // identity, order 1
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
}

// TestKAT_SmallOrderKeyForgesWithZeroSignature demonstrates the one accepting
// path a caller must defend against, and pins it so nobody has to rediscover
// it.
//
// The verifier is cofactorless, exactly like RFC 8032, ref10, libsodium and the
// Go standard library it delegates to: it checks [S]B == R + [k]A without ever
// asking whether A generates the prime-order group. For a torsion point A the
// discrete log is public (everyone "owns" the key), so the all-zero signature
// (R = the order-4 point, S = 0) satisfies the equation whenever
// k = SHA512(R || A || M) lands in the right residue class -- about one message
// in four. An attacker who picks the message hash simply grinds it.
//
// This is not a defect in the arithmetic; diverging from every other Ed25519
// stack would break the very external-chain signatures the precompile exists to
// check. It IS a caller obligation: a contract that treats "verify succeeded"
// as "a specific person signed" must bind the public key to a pre-registered
// account, or reject torsion keys itself. Losing this test means the accepting
// path moved, which is a consensus event either way.
func TestKAT_SmallOrderKeyForgesWithZeroSignature(t *testing.T) {
	for _, enc := range smallOrder {
		pub := katHex(t, enc)
		// Confirm the encoding really is a torsion point: 8*P is the identity.
		p, err := new(edwards25519.Point).SetBytes(pub)
		require.NoError(t, err, "vector must decode")
		require.Equal(t, byte(1),
			new(edwards25519.Point).MultByCofactor(p).Bytes()[0],
			"vector must be small order")

		// A signature made for a real key never transfers to a torsion key.
		for _, v := range rfc8032 {
			require.False(t, VerifyRaw(katHex(t, "af82"), katHex(t, v.sig), pub),
				"a genuine signature must not verify under key %s", enc)
		}
	}

	// The forgery itself: the order-4 key with the all-zero signature, over
	// message hashes an attacker enumerates. Roughly a quarter land.
	pub := katHex(t, "0000000000000000000000000000000000000000000000000000000000000000")
	zeroSig := make([]byte, SignatureSize)

	accepted := 0
	for i := range 64 {
		msg := make([]byte, MessageHashSize)
		msg[MessageHashSize-1] = byte(i)
		if VerifyRaw(msg, zeroSig, pub) {
			accepted++
		}
	}
	require.Positive(t, accepted,
		"cofactorless verification accepts the zero signature for a torsion key; "+
			"if this stopped being true the verifier changed semantics")
	require.Less(t, accepted, 64,
		"it must not accept every message -- that would be a broken equation, not cofactorlessness")

	// And through the precompile, so the finding is stated where it bites.
	msg := make([]byte, MessageHashSize)
	msg[MessageHashSize-1] = 3
	require.True(t, VerifyRaw(msg, zeroSig, pub), "witness message must be one of the accepting ones")
	out, _, err := runPrecompile(t, buildRun(msg, zeroSig, pub), GasEd25519Verify)
	require.NoError(t, err)
	require.Equal(t, successResult, out,
		"precompile inherits the standard-library verdict for torsion keys")
}

// TestKAT_SmallOrderRRejected substitutes a torsion point for R. The signature
// no longer satisfies the equation for the published message.
func TestKAT_SmallOrderRRejected(t *testing.T) {
	for _, v := range rfc8032 {
		pub, msg, sig := katHex(t, v.pub), katHex(t, v.msg), katHex(t, v.sig)
		for _, enc := range smallOrder {
			bad := append(append([]byte{}, katHex(t, enc)...), sig[32:]...)
			require.False(t, VerifyRaw(msg, bad, pub),
				"small-order R %s must not verify", enc)
		}
	}
}

// TestKAT_NonCanonicalPointEncodingAccepted records, deliberately, that the
// verifier follows ref10 and Go's standard library: a y-coordinate encoded as
// y+p decodes to y, so one point has several accepted encodings. It is not a
// forgery -- the signature still has to satisfy the equation -- but calldata is
// therefore NOT a unique identifier for a (key, signature) pair. Any caller
// keying a replay cache off raw calldata must canonicalise first. If this ever
// starts failing, the verifier has diverged from every other Ed25519 stack and
// that is a consensus event, not an improvement.
func TestKAT_NonCanonicalPointEncodingAccepted(t *testing.T) {
	// p = 2^255 - 19; encodings of y and y+p decode to the same field element.
	for _, enc := range []string{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p   -> 0
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p+1 -> 1 (identity)
	} {
		_, err := new(edwards25519.Point).SetBytes(katHex(t, enc))
		require.NoError(t, err, "non-canonical encoding %s is accepted by the decoder", enc)
	}

	// The identity has two accepted encodings; both are refused as public keys
	// because neither can carry a real signature.
	msg := katHex(t, "af82")
	for _, enc := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		require.False(t, VerifyRaw(msg, katHex(t, rfc8032[2].sig), katHex(t, enc)))
	}
}

// --- precompile surface -------------------------------------------------

// runPrecompile is the single call shape used below.
func runPrecompile(tb testing.TB, in []byte, gas uint64) ([]byte, uint64, error) {
	tb.Helper()
	return Ed25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress, in, gas, true)
}

// buildRun lays out the 128-byte calldata: msg(32) || sig(64) || pub(32).
func buildRun(msg, sig, pub []byte) []byte {
	in := make([]byte, 0, InputLength)
	in = append(in, msg...)
	in = append(in, sig...)
	return append(in, pub...)
}

// TestRun_AcceptsSignatureOverThirtyTwoByteMessage exercises the precompile's
// fixed layout. The key comes from an RFC 8032 seed, so the public key half of
// the calldata is still a published constant; only the message differs (the
// precompile carries exactly 32 message bytes, and no RFC vector is that long).
func TestRun_AcceptsSignatureOverThirtyTwoByteMessage(t *testing.T) {
	seed := katHex(t, rfc8032[0].seed)
	priv := stded.NewKeyFromSeed(seed)
	pub := []byte(priv.Public().(stded.PublicKey))
	require.Equal(t, katHex(t, rfc8032[0].pub), pub)

	msg := katHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.Len(t, msg, MessageHashSize)
	sig := stded.Sign(priv, msg)

	in := buildRun(msg, sig, pub)
	require.Len(t, in, InputLength)

	out, left, err := runPrecompile(t, in, GasEd25519Verify+7)
	require.NoError(t, err)
	require.Equal(t, successResult, out)
	require.Equal(t, uint64(7), left, "exactly RequiredGas is deducted")

	// Every single-byte mutation of every field must flip the verdict.
	for at := range in {
		bad := append([]byte{}, in...)
		bad[at] ^= 0x01
		out, _, err := runPrecompile(t, bad, GasEd25519Verify)
		require.NoError(t, err)
		require.Nil(t, out, "byte %d mutation must not verify", at)
	}
}

// TestRun_LengthRefusals covers one byte short, one byte long, empty and nil.
// Gas is still charged: length is not known until the call is made.
func TestRun_LengthRefusals(t *testing.T) {
	seed := katHex(t, rfc8032[1].seed)
	priv := stded.NewKeyFromSeed(seed)
	pub := []byte(priv.Public().(stded.PublicKey))
	msg := make([]byte, MessageHashSize)
	valid := buildRun(msg, stded.Sign(priv, msg), pub)
	require.Len(t, valid, InputLength)

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte short", valid[:InputLength-1]},
		{"one byte long", append(append([]byte{}, valid...), 0)},
		{"truncated to 64", valid[:64]},
		{"all zero", make([]byte, InputLength)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, left, err := runPrecompile(t, tc.in, GasEd25519Verify+11)
			require.NoError(t, err, "a wrong length is a failed verify, not a revert")
			require.Nil(t, out)
			require.Equal(t, uint64(11), left, "gas is charged regardless of length")
		})
	}

	// The valid input at the exact length still verifies -- proves the refusals
	// above come from the length check and not from a broken vector.
	out, _, err := runPrecompile(t, valid, GasEd25519Verify)
	require.NoError(t, err)
	require.Equal(t, successResult, out)
}

func TestRun_OutOfGasIsExact(t *testing.T) {
	in := make([]byte, InputLength)
	_, left, err := runPrecompile(t, in, GasEd25519Verify-1)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, left)

	_, left, err = runPrecompile(t, in, GasEd25519Verify)
	require.NoError(t, err)
	require.Zero(t, left)
}

// TestRequiredGas_IndependentOfInput: the work is fixed-size, so the price is
// flat. A size-dependent price here would be wrong, not just different.
func TestRequiredGas_IndependentOfInput(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 129, 1 << 16} {
		require.Equal(t, uint64(GasEd25519Verify),
			Ed25519VerifyPrecompile.RequiredGas(make([]byte, n)), "len=%d", n)
	}
	require.Equal(t, uint64(GasEd25519Verify), Ed25519VerifyPrecompile.RequiredGas(nil))
}

// TestVerifyHelpers_LengthGuards covers the exported convenience wrappers.
func TestVerifyHelpers_LengthGuards(t *testing.T) {
	v := rfc8032[2]
	pub, msg, sig := katHex(t, v.pub), katHex(t, v.msg), katHex(t, v.sig)

	require.True(t, Verify(msg, sig, pub))
	require.True(t, VerifyRaw(msg, sig, pub))

	for _, tc := range []struct {
		name     string
		sig, pub []byte
	}{
		{"short pubkey", sig, pub[:31]},
		{"long pubkey", sig, append(append([]byte{}, pub...), 0)},
		{"nil pubkey", sig, nil},
		{"short sig", sig[:63], pub},
		{"long sig", append(append([]byte{}, sig...), 0), pub},
		{"nil sig", nil, pub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, Verify(msg, tc.sig, tc.pub))
			require.False(t, VerifyRaw(msg, tc.sig, tc.pub))
		})
	}
}

// --- module + config ----------------------------------------------------

func TestRegistryModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, RegistryModule.ConfigKey)
	require.Equal(t, ContractAddress, RegistryModule.Address)
	require.Same(t, Ed25519VerifyPrecompile, RegistryModule.Contract)
	require.NotNil(t, RegistryModule.Configurator)

	// The address is the LP-3211 slot; a silent move is a chain fork.
	require.Equal(t,
		common.HexToAddress("0x3211000000000000000000000000000000000000"),
		ContractAddress)
}

func TestConfigurator_Surface(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.IsType(t, &Config{}, cfg)
	require.NoError(t, c.Configure(nil, nil, nil, nil))
}

func TestConfig_Surface(t *testing.T) {
	c := &Config{}
	require.Equal(t, ConfigKey, c.Key())
	require.Nil(t, c.Timestamp())
	require.False(t, c.IsDisabled())
	require.NoError(t, c.Verify(nil))

	ts := uint64(4242)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(4243)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil), "a nil config is not equal to a set one")

	d := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, d.IsDisabled())
	require.False(t, d.Equal(a))
}

// TestSizeConstantsMatchLibrary is the guard that replaced the unreachable
// length check deleted from Run: the slice bounds there are constants, so the
// only way the extraction can go wrong is if these constants drift apart.
func TestSizeConstantsMatchLibrary(t *testing.T) {
	require.Equal(t, luxed.PublicKeySize, PublicKeySize)
	require.Equal(t, luxed.SignatureSize, SignatureSize)
	require.Equal(t, MessageHashSize+SignatureSize+PublicKeySize, InputLength)
}

// TestRegisterModuleIsIdempotentlyRefused exercises the failure the init()
// panic exists for. The panic statement itself runs before any test can, so it
// is unreachable from a test binary by construction; this asserts the condition
// it fires on instead.
func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(RegistryModule),
		"registering the same address twice must be refused, which is what init() panics on")
}
