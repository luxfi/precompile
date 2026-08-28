// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package curve25519

import (
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func kat(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	require.Len(tb, b, 32)
	return b
}

func call(tb testing.TB, op byte, args ...[]byte) ([]byte, uint64, error) {
	tb.Helper()
	in := []byte{op}
	for _, a := range args {
		in = append(in, a...)
	}
	return Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, in, 1<<22, true)
}

// scalarLE encodes a small integer as a canonical 32-byte little-endian scalar.
func scalarLE(v uint64) []byte {
	s := make([]byte, 32)
	for i := 0; v > 0; i++ {
		s[i] = byte(v)
		v >>= 8
	}
	return s
}

// Reference encodings of k*B on Edwards25519, computed with an independent
// implementation of the twisted-Edwards addition law and checked against the
// RFC 8032 base point.
const (
	basepointEnc = "5866666666666666666666666666666666666666666666666666666666666666"
	identityEnc  = "0100000000000000000000000000000000000000000000000000000000000000"
	twoB         = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
	threeB       = "d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16712"
	sevenB       = "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"
	tenB         = "2c7be86ab07488ba43e8e03d85a67625cfbf98c8544de4c877241b7aaafc7fe3"
	thirteenB    = "801f40eaaee1ef8723279a28b2cf4037b889dad222604678748b53ed0db0db92"
	bigB         = "ef4f62f8479733ad879cfaced3c89a9c39dd4fc795ef2efa1c3eafe4d729a081" // 12345*B
	negB         = "58666666666666666666666666666666666666666666666666666666666666e6" // (L-1)*B
)

// TestKAT_BasepointMul pins scalar-base multiplication against reference
// encodings. Round-tripping the precompile against itself would pass even if
// every one of these were wrong.
func TestKAT_BasepointMul(t *testing.T) {
	for _, tc := range []struct {
		k    uint64
		want string
	}{
		{1, basepointEnc},
		{2, twoB},
		{3, threeB},
		{7, sevenB},
		{13, thirteenB},
		{12345, bigB},
	} {
		out, _, err := call(t, OpBasepointMul, scalarLE(tc.k))
		require.NoError(t, err)
		require.Equal(t, kat(t, tc.want), out, "%d*B", tc.k)
	}

	// k = 0 is the identity; k = L-1 is -B.
	out, _, err := call(t, OpBasepointMul, make([]byte, ScalarLen))
	require.NoError(t, err)
	require.Equal(t, kat(t, identityEnc), out, "0*B is the identity")

	lMinus1 := new(big.Int).Sub(groupOrder(), big.NewInt(1))
	out, _, err = call(t, OpBasepointMul, leBytes(lMinus1))
	require.NoError(t, err)
	require.Equal(t, kat(t, negB), out, "(L-1)*B is -B")
}

// TestKAT_BasepointMulMatchesRFC8032KeyDerivation crosses this precompile with
// a published Ed25519 vector: RFC 8032 test 1's public key IS [a]B for the
// clamped scalar derived from its seed. Reproducing it here proves the scalar
// multiplication agrees with an entirely separate standard.
func TestKAT_BasepointMulMatchesRFC8032KeyDerivation(t *testing.T) {
	seed := kat(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	h := sha512.Sum512(seed)

	// RFC 8032 clamping.
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	// The clamped scalar exceeds L, and decodeScalar rightly refuses
	// non-canonical scalars, so reduce first: [a]B == [a mod L]B.
	a := new(big.Int).SetBytes(reverse(h[:32]))
	a.Mod(a, groupOrder())

	out, _, err := call(t, OpBasepointMul, leBytes(a))
	require.NoError(t, err)
	require.Equal(t,
		kat(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"), out,
		"must reproduce the RFC 8032 TEST 1 public key")
}

// TestKAT_PointAdd pins addition and cross-checks it against multiplication.
func TestKAT_PointAdd(t *testing.T) {
	B := kat(t, basepointEnc)
	id := kat(t, identityEnc)

	out, _, err := call(t, OpPointAdd, B, B)
	require.NoError(t, err)
	require.Equal(t, kat(t, twoB), out, "B + B == 2B")

	out, _, err = call(t, OpPointAdd, kat(t, twoB), B)
	require.NoError(t, err)
	require.Equal(t, kat(t, threeB), out, "2B + B == 3B")

	// Identity is neutral, in both argument positions.
	for _, args := range [][2][]byte{{B, id}, {id, B}} {
		out, _, err := call(t, OpPointAdd, args[0], args[1])
		require.NoError(t, err)
		require.Equal(t, B, out)
	}

	// B + (-B) is the identity.
	out, _, err = call(t, OpPointAdd, B, kat(t, negB))
	require.NoError(t, err)
	require.Equal(t, id, out)

	// Addition is commutative and associative over the reference values.
	ab, _, err := call(t, OpPointAdd, kat(t, threeB), kat(t, sevenB))
	require.NoError(t, err)
	ba, _, err := call(t, OpPointAdd, kat(t, sevenB), kat(t, threeB))
	require.NoError(t, err)
	require.Equal(t, ab, ba)
	require.Equal(t, kat(t, tenB), ab, "3B + 7B == 10B")
}

// TestKAT_ScalarMulMatchesBasepointMul is the cross-implementation check
// between the variable-base ladder and the fixed-base table. Both must land on
// the same reference encodings.
func TestKAT_ScalarMulMatchesBasepointMul(t *testing.T) {
	B := kat(t, basepointEnc)
	for _, k := range []uint64{0, 1, 2, 3, 7, 13, 12345, 1 << 32} {
		viaBase, _, err := call(t, OpBasepointMul, scalarLE(k))
		require.NoError(t, err)
		viaMul, _, err := call(t, OpScalarMul, B, scalarLE(k))
		require.NoError(t, err)
		require.Equal(t, viaBase, viaMul, "k=%d: the two ladders must agree", k)
	}

	// Doubling by scalar equals doubling by addition, on a non-generator point.
	P := kat(t, sevenB)
	byMul, _, err := call(t, OpScalarMul, P, scalarLE(2))
	require.NoError(t, err)
	byAdd, _, err := call(t, OpPointAdd, P, P)
	require.NoError(t, err)
	require.Equal(t, byAdd, byMul)
}

// TestKAT_MSM pins the multiscalar path against the reference: 3*B + 5*(2B)
// is 13B, which is a published-by-construction value computed independently.
func TestKAT_MSM(t *testing.T) {
	B := kat(t, basepointEnc)
	out, _, err := call(t, OpMSM, B, scalarLE(3), kat(t, twoB), scalarLE(5))
	require.NoError(t, err)
	require.Equal(t, kat(t, thirteenB), out, "3*B + 5*(2B) == 13B")

	// A single pair degenerates to scalar multiplication.
	single, _, err := call(t, OpMSM, B, scalarLE(7))
	require.NoError(t, err)
	require.Equal(t, kat(t, sevenB), single)

	// An all-zero scalar set sums to the identity.
	zeros, _, err := call(t, OpMSM, B, make([]byte, 32), kat(t, twoB), make([]byte, 32))
	require.NoError(t, err)
	require.Equal(t, kat(t, identityEnc), zeros)

	// Order does not matter.
	swapped, _, err := call(t, OpMSM, kat(t, twoB), scalarLE(5), B, scalarLE(3))
	require.NoError(t, err)
	require.Equal(t, out, swapped)
}

// smallOrder is the full torsion subgroup of Edwards25519, canonical encodings.
var smallOrder = []string{
	identityEnc, // order 1
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
}

// TestSmallOrderPointsAreAccepted records, deliberately, that this precompile
// is raw group arithmetic and admits the torsion subgroup. Multiplying any of
// these by 8 lands on the identity, which is exactly the property a caller
// building ring signatures, key images or a VRF must check for itself before
// trusting a point it did not generate. If this ever starts refusing them, the
// arithmetic surface shrank and downstream protocols break.
func TestSmallOrderPointsAreAccepted(t *testing.T) {
	id := kat(t, identityEnc)
	for _, enc := range smallOrder {
		P := kat(t, enc)

		out, _, err := call(t, OpScalarMul, P, scalarLE(8))
		require.NoError(t, err, "torsion point %s is valid input", enc[:12])
		require.Equal(t, id, out, "8 * torsion point is the identity")

		// Adding it to the base point is accepted and moves the point: this is
		// how a cofactor-unaware caller loses uniqueness of the representative.
		shifted, _, err := call(t, OpPointAdd, kat(t, basepointEnc), P)
		require.NoError(t, err)
		if enc == identityEnc {
			require.Equal(t, kat(t, basepointEnc), shifted)
		} else {
			require.NotEqual(t, kat(t, basepointEnc), shifted,
				"a non-identity torsion point must change the encoding")
		}
	}
}

// TestNonCanonicalPointEncodingAccepted pins the decoder's documented
// behaviour: it follows ref10, so y and y+p decode to the same point and one
// point has several accepted encodings. The result is always re-encoded
// canonically, so no operation can be made to emit a non-canonical point --
// but calldata is not a unique name for an input.
func TestNonCanonicalPointEncodingAccepted(t *testing.T) {
	canonical := kat(t, identityEnc)
	// y = p+1 reduces to y = 1, which is the identity.
	noncanonical := kat(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	require.NotEqual(t, canonical, noncanonical)

	B := kat(t, basepointEnc)
	viaCanonical, _, err := call(t, OpPointAdd, B, canonical)
	require.NoError(t, err)
	viaOther, _, err := call(t, OpPointAdd, B, noncanonical)
	require.NoError(t, err, "the ref10 decoder accepts the non-canonical encoding")
	require.Equal(t, viaCanonical, viaOther, "both encodings name the same point")
	require.Equal(t, B, viaOther)
	require.Equal(t, canonical, edwards25519.NewIdentityPoint().Bytes(),
		"output is always the canonical encoding")
}

// TestRefusal_PointNotOnCurve is the invalid-curve refusal. Every one of these
// is a well-formed 32-byte word whose y-coordinate has no matching x on the
// curve, so decoding must fail rather than produce a point on some other curve.
func TestRefusal_PointNotOnCurve(t *testing.T) {
	B := kat(t, basepointEnc)

	var offCurve [][]byte
	for y := byte(2); len(offCurve) < 6 && y < 200; y++ {
		enc := make([]byte, 32)
		enc[0] = y
		if _, err := new(edwards25519.Point).SetBytes(enc); err != nil {
			offCurve = append(offCurve, enc)
		}
	}
	require.NotEmpty(t, offCurve, "must find genuinely off-curve encodings")

	for i, bad := range offCurve {
		for _, tc := range []struct {
			name string
			in   [][]byte
			op   byte
		}{
			{"pointAdd first", [][]byte{bad, B}, OpPointAdd},
			{"pointAdd second", [][]byte{B, bad}, OpPointAdd},
			{"scalarMul", [][]byte{bad, scalarLE(2)}, OpScalarMul},
			{"msm", [][]byte{bad, scalarLE(2)}, OpMSM},
			{"msm second pair", [][]byte{B, scalarLE(1), bad, scalarLE(2)}, OpMSM},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out, _, err := call(t, tc.op, tc.in...)
				require.ErrorIs(t, err, ErrInvalidPoint, "case %d", i)
				require.Nil(t, out)
			})
		}
	}
}

// TestRefusal_NonCanonicalScalar is the malleability refusal on the scalar
// side: L, L+1 and 2^255-1 all reduce into range, and accepting them would give
// every scalar multiple several encodings.
func TestRefusal_NonCanonicalScalar(t *testing.T) {
	B := kat(t, basepointEnc)
	l := groupOrder()

	for _, tc := range []struct {
		name string
		s    []byte
	}{
		{"s = L", leBytes(l)},
		{"s = L+1", leBytes(new(big.Int).Add(l, big.NewInt(1)))},
		{"s = 2L-1", leBytes(new(big.Int).Sub(new(big.Int).Lsh(l, 1), big.NewInt(1)))},
		{"s = all ones", func() []byte {
			b := make([]byte, 32)
			for i := range b {
				b[i] = 0xFF
			}
			return b
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Len(t, tc.s, ScalarLen)
			for op, args := range map[byte][][]byte{
				OpScalarMul:    {B, tc.s},
				OpBasepointMul: {tc.s},
				OpMSM:          {B, tc.s},
			} {
				out, _, err := call(t, op, args...)
				require.ErrorIs(t, err, ErrInvalidInput, "op %#x must refuse s >= L", op)
				require.Nil(t, out)
			}
		})
	}

	// L-1 is the largest accepted scalar; it must still work.
	out, _, err := call(t, OpBasepointMul, leBytes(new(big.Int).Sub(l, big.NewInt(1))))
	require.NoError(t, err)
	require.Equal(t, kat(t, negB), out)
}

// TestRefusal_Length walks every short, empty and misaligned shape.
func TestRefusal_Length(t *testing.T) {
	B := kat(t, basepointEnc)
	s := scalarLE(3)

	for _, tc := range []struct {
		name string
		in   []byte
		err  error
	}{
		{"nil", nil, ErrInvalidInput},
		{"empty", []byte{}, ErrInvalidInput},
		{"pointAdd op only", []byte{OpPointAdd}, ErrInvalidInput},
		{"pointAdd one point", append([]byte{OpPointAdd}, B...), ErrInvalidInput},
		{"pointAdd one byte short", append([]byte{OpPointAdd}, append(append([]byte{}, B...), B[:31]...)...), ErrInvalidInput},
		{"scalarMul op only", []byte{OpScalarMul}, ErrInvalidInput},
		{"scalarMul no scalar", append([]byte{OpScalarMul}, B...), ErrInvalidInput},
		{"scalarMul one byte short", append([]byte{OpScalarMul}, append(append([]byte{}, B...), s[:31]...)...), ErrInvalidInput},
		{"basepointMul op only", []byte{OpBasepointMul}, ErrInvalidInput},
		{"basepointMul one byte short", append([]byte{OpBasepointMul}, s[:31]...), ErrInvalidInput},
		{"msm op only", []byte{OpMSM}, ErrInvalidInput},
		{"msm half pair", append([]byte{OpMSM}, B...), ErrInvalidInput},
		{"msm one byte long", append([]byte{OpMSM}, append(append(append([]byte{}, B...), s...), 0)...), ErrInvalidInput},
		{"msm one byte short", append([]byte{OpMSM}, append(append([]byte{}, B...), s[:31]...)...), ErrInvalidInput},
		{"unknown op 0x00", []byte{0x00}, ErrInvalidOp},
		{"unknown op 0x05", []byte{0x05}, ErrInvalidOp},
		{"unknown op 0xff", append([]byte{0xFF}, B...), ErrInvalidOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, tc.in, 1<<22, true)
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, out)
		})
	}

	// Trailing data past a fixed-width operand is ignored, not refused.
	short, _, err := call(t, OpPointAdd, B, B)
	require.NoError(t, err)
	long, _, err := call(t, OpPointAdd, B, B, []byte{0xAA, 0xBB})
	require.NoError(t, err)
	require.Equal(t, short, long, "trailing bytes are ignored on the fixed-width ops")
}

// TestGas_Schedule covers every arm, and asserts that MSM is priced per pair --
// a flat price there would let one call buy an unbounded multiscalar.
func TestGas_Schedule(t *testing.T) {
	pair := CompressedLen + ScalarLen

	for _, tc := range []struct {
		name string
		in   []byte
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"pointAdd", []byte{OpPointAdd}, GasPointAdd},
		{"scalarMul", []byte{OpScalarMul}, GasScalarMul},
		{"basepointMul", []byte{OpBasepointMul}, GasBasepointMul},
		{"unknown 0x00", []byte{0x00}, 0},
		{"unknown 0x05", []byte{0x05}, 0},
		{"unknown 0xff", []byte{0xFF}, 0},
		{"msm no data", []byte{OpMSM}, 0},
		{"msm short of one pair", append([]byte{OpMSM}, make([]byte, pair-1)...), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, Curve25519Precompile.RequiredGas(tc.in))
		})
	}

	// Price rises by exactly one per-pair unit for each additional pair.
	prev := uint64(0)
	for n := 1; n <= 32; n++ {
		in := append([]byte{OpMSM}, make([]byte, n*pair)...)
		got := Curve25519Precompile.RequiredGas(in)
		require.Equal(t, uint64(GasMSMBase+n*GasMSMPerPair), got, "n=%d", n)
		if n > 1 {
			require.Equal(t, uint64(GasMSMPerPair), got-prev, "each pair costs the same")
		}
		prev = got
	}

	// A huge declared pair count neither overflows nor wraps: the count comes
	// from the actual byte length, so it cannot be inflated independently.
	huge := append([]byte{OpMSM}, make([]byte, 4096*pair)...)
	require.Equal(t, uint64(GasMSMBase+4096*GasMSMPerPair), Curve25519Precompile.RequiredGas(huge))
	require.Greater(t, Curve25519Precompile.RequiredGas(huge), uint64(GasMSMBase))

	// Every zero-priced input must refuse: nothing is bought for free.
	for _, in := range [][]byte{nil, {}, {0x00}, {0x05}, {0xFF}, {OpMSM}, append([]byte{OpMSM}, make([]byte, pair-1)...)} {
		require.Zero(t, Curve25519Precompile.RequiredGas(in))
		out, _, err := Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.Error(t, err, "a zero-gas input must not execute")
		require.Nil(t, out)
	}
}

func TestGas_Deduction(t *testing.T) {
	in := append([]byte{OpBasepointMul}, scalarLE(3)...)

	_, left, err := Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBasepointMul+9, true)
	require.NoError(t, err)
	require.Equal(t, uint64(9), left)

	_, left, err = Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBasepointMul, true)
	require.NoError(t, err)
	require.Zero(t, left)

	_, left, err = Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBasepointMul-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, left)

	// MSM must be unaffordable at the single-pair price when two pairs are sent.
	pair := CompressedLen + ScalarLen
	two := append([]byte{OpMSM}, make([]byte, 2*pair)...)
	_, _, err = Curve25519Precompile.Run(nil, common.Address{}, ContractAddress, two,
		GasMSMBase+GasMSMPerPair, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas, "two pairs must cost more than one")
}

// --- helpers ------------------------------------------------------------

func groupOrder() *big.Int {
	l, ok := new(big.Int).SetString(
		"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("bad order literal")
	}
	return l
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// leBytes encodes v as 32 little-endian bytes.
func leBytes(v *big.Int) []byte {
	be := make([]byte, 32)
	v.FillBytes(be)
	return reverse(be)
}

// --- module + config ----------------------------------------------------

func TestModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, Curve25519Precompile, Module.Contract)
	require.NotNil(t, Module.Configurator)
	require.Equal(t,
		common.HexToAddress("0x0000000000000000000000000000000000009204"),
		ContractAddress)
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

	ts := uint64(11)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(12)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil))
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module))
}
