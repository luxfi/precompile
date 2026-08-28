// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pedersen

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func hexBytes(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}

func scalar32(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

func fire(tb testing.TB, op byte, data ...[]byte) ([]byte, uint64, error) {
	tb.Helper()
	in := []byte{op}
	for _, d := range data {
		in = append(in, d...)
	}
	return PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, in, 1<<24, true)
}

// TestKAT_Generators pins the derived generators. They are the public
// parameters of every commitment this precompile has ever produced: changing
// one silently invalidates every stored commitment, so they belong in the test
// suite as constants rather than as whatever the derivation happens to emit.
func TestKAT_Generators(t *testing.T) {
	_, _, g1, _ := bn254.Generators()
	require.Equal(t, g1.Marshal(), genG.Marshal(), "G must be the standard BN254 G1 generator")
	require.Equal(t, hexBytes(t,
		"0000000000000000000000000000000000000000000000000000000000000001"+
			"0000000000000000000000000000000000000000000000000000000000000002"),
		genG.Marshal())

	require.Equal(t, hexBytes(t,
		"167ee3e50591aab77ddfeb4fc1df8720a14033eedbe0209e7fc1c70c67399a52"+
			"248e4bb6192c1b605f29c4974d64e10a87bcabaa5df6e629bbdbc2695cc87a95"),
		genH.Marshal(), "H is a fixed public parameter")

	require.Equal(t, hexBytes(t,
		"115cc397834e042c864f20e181a6f7706576fcd5dbdbd278de8811d454deeca2"+
			"2532e5ab8a42a4d941aa328297869daefc19f4101eac0223870080bde5df9baa"),
		genVi[0].Marshal())
	require.Equal(t, hexBytes(t,
		"2c68086f0f67176b240069897b5654c78f68157d2da4f478a5871ca248107f48"+
			"1b847c62886d1b9dc2ee6ef97e32622d5ab489f8f2650f7d5155e04e53560252"),
		genVi[31].Marshal())
}

// TestGeneratorsAreValidAndIndependent is the binding precondition. A generator
// off the curve, at infinity, or equal to another one destroys the binding
// property: a caller could open one commitment to two values.
func TestGeneratorsAreValidAndIndependent(t *testing.T) {
	all := append([]bn254.G1Affine{genG, genH}, genVi[:]...)
	require.Len(t, all, 34)

	for i, g := range all {
		require.True(t, g.IsOnCurve(), "generator %d must be on the curve", i)
		require.False(t, g.IsInfinity(), "generator %d must not be the identity", i)
		// BN254's G1 has cofactor one, so on-curve already implies prime order;
		// asserting it makes that dependency explicit rather than assumed.
		require.True(t, g.IsInSubGroup(), "generator %d must have prime order", i)
	}

	for i := range all {
		for j := i + 1; j < len(all); j++ {
			require.False(t, all[i].Equal(&all[j]),
				"generators %d and %d are equal: the commitment would not bind", i, j)
			neg := new(bn254.G1Affine).Neg(&all[j])
			require.False(t, all[i].Equal(neg),
				"generator %d is the negation of %d: their sum vanishes", i, j)
		}
	}
}

// TestHashToG1IsDeterministicAndOnCurve exercises the derivation itself,
// including the rejection loop: about half of all candidate x values have no
// square root, so most seeds take more than one try.
func TestHashToG1IsDeterministicAndOnCurve(t *testing.T) {
	seeds := []string{
		"Lux_Pedersen_H_Generator",
		"", "a", "\x00", "0123456789abcdef0123456789abcdef",
		"Lux_Pedersen_Gen_A", "Lux_Pedersen_Gen_Z",
	}
	seen := map[string]string{}
	for _, s := range seeds {
		got := hashToG1(s)
		again := hashToG1(s)
		require.True(t, got.IsOnCurve(), "seed %q must land on the curve", s)
		require.False(t, got.IsInfinity())
		require.Equal(t, got.Marshal(), again.Marshal(), "derivation must be deterministic")

		key := string(got.Marshal())
		prev, dup := seen[key]
		require.False(t, dup, "seeds %q and %q derive the same generator", prev, s)
		seen[key] = s
	}

	// Reproduce the loop here to pin how many candidates each live seed needs.
	// The panic at 256 tries is unreachable for these fixed seeds: the worst of
	// the 34 finds a point on its eighth candidate, and failing 256 in a row has
	// probability about 2^-256 for any seed at all.
	tries := func(seed string) int {
		b := []byte(seed)
		for c := 0; c < 256; c++ {
			h := sha256.Sum256(append(b, byte(c)))
			var x, x2, x3, rhs, y, three fp.Element
			x.SetBytes(h[:])
			x2.Square(&x)
			x3.Mul(&x2, &x)
			three.SetInt64(3)
			rhs.Add(&x3, &three)
			if y.Sqrt(&rhs) != nil {
				var pt bn254.G1Affine
				pt.X, pt.Y = x, y
				if pt.IsOnCurve() && !pt.IsInfinity() {
					return c
				}
			}
		}
		return -1
	}
	worst := 0
	for i := range 32 {
		n := tries("Lux_Pedersen_Gen_" + string(rune('A'+i)))
		require.GreaterOrEqual(t, n, 0, "generator %d must be derivable", i)
		if n > worst {
			worst = n
		}
	}
	require.GreaterOrEqual(t, tries("Lux_Pedersen_H_Generator"), 0)
	require.Less(t, worst, 32,
		"the live seeds all resolve far below the 256-try limit the panic guards")
}

// TestKAT_CommitIsTheHashOfTheGroupElement pins the commitment against the
// group arithmetic it claims to perform, computed here rather than taken from
// the precompile: C = sha256(marshal(v*G + r*H)).
func TestKAT_CommitIsTheHashOfTheGroupElement(t *testing.T) {
	for _, tc := range []struct{ v, r int64 }{
		{0, 0}, {1, 0}, {0, 1}, {1, 1}, {7, 9}, {12345, 67890},
	} {
		v, r := big.NewInt(tc.v), big.NewInt(tc.r)

		var vG, rH, c bn254.G1Affine
		vG.ScalarMultiplication(&genG, v)
		rH.ScalarMultiplication(&genH, r)
		c.Add(&vG, &rH)
		want := sha256.Sum256(c.Marshal())

		got, _, err := fire(t, OpCommit, scalar32(v), scalar32(r))
		require.NoError(t, err)
		require.Equal(t, want[:], got, "v=%d r=%d", tc.v, tc.r)

		// And Verify accepts exactly that opening.
		ok, _, err := fire(t, OpVerify, got, scalar32(v), scalar32(r))
		require.NoError(t, err)
		require.Equal(t, byte(1), ok[31])
	}
}

// TestCommitIsHomomorphicInTheGroup states what the scheme actually gives and
// what it does not. v*G + r*H is additively homomorphic, so committing to
// v1+v2 with blinding r1+r2 lands on the sum of the two group elements -- but
// Commit returns sha256 of that element, and Add operates on raw 64-byte
// points, so the two operations do NOT compose through this API. A caller who
// needs the homomorphism must keep the points, not the digests.
func TestCommitIsHomomorphicInTheGroup(t *testing.T) {
	v1, r1 := big.NewInt(11), big.NewInt(22)
	v2, r2 := big.NewInt(33), big.NewInt(44)

	point := func(v, r *big.Int) bn254.G1Affine {
		var vG, rH, c bn254.G1Affine
		vG.ScalarMultiplication(&genG, v)
		rH.ScalarMultiplication(&genH, r)
		c.Add(&vG, &rH)
		return c
	}
	c1, c2 := point(v1, r1), point(v2, r2)

	var sum bn254.G1Affine
	sum.Add(&c1, &c2)
	combined := point(new(big.Int).Add(v1, v2), new(big.Int).Add(r1, r2))
	require.Equal(t, combined.Marshal(), sum.Marshal(),
		"C(v1,r1) + C(v2,r2) == C(v1+v2, r1+r2)")

	// Add reproduces that sum on the wire.
	added, _, err := fire(t, OpAdd, c1.Marshal(), c2.Marshal())
	require.NoError(t, err)
	require.Equal(t, sum.Marshal(), added)

	// The digests do not add: Commit's output is a hash, by construction.
	d1, _, err := fire(t, OpCommit, scalar32(v1), scalar32(r1))
	require.NoError(t, err)
	require.Len(t, d1, 32)
	_, _, err = fire(t, OpAdd, d1, d1)
	require.ErrorIs(t, err, ErrInvalidInput,
		"a commitment digest is not a point and Add must refuse it")

	// Verify only accepts the exact opening: any other one fails.
	digest, _, err := fire(t, OpCommit, scalar32(v1), scalar32(r1))
	require.NoError(t, err)
	for _, bad := range [][2]*big.Int{
		{new(big.Int).Add(v1, big.NewInt(1)), r1},
		{v1, new(big.Int).Add(r1, big.NewInt(1))},
		{r1, v1},
		{big.NewInt(0), big.NewInt(0)},
	} {
		out, _, err := fire(t, OpVerify, digest, scalar32(bad[0]), scalar32(bad[1]))
		require.NoError(t, err)
		require.Equal(t, byte(0), out[31], "a wrong opening must not verify")
	}
}

// TestScalarsReduceModTheGroupOrder documents why reduction is correct here,
// unlike for a coordinate. G and H have order r, so (v+r)*G == v*G as group
// elements: the multiplier's domain IS the scalar field, and two words that
// differ by r name the same scalar. Nothing is lost by reducing.
func TestScalarsReduceModTheGroupOrder(t *testing.T) {
	r := fr.Modulus()
	require.Equal(t, r.String(), bn254.ID.ScalarField().String(),
		"the reduction modulus must be the G1 group order")

	base, _, err := fire(t, OpCommit, scalar32(big.NewInt(7)), scalar32(big.NewInt(9)))
	require.NoError(t, err)

	shifted, _, err := fire(t, OpCommit,
		scalar32(new(big.Int).Add(r, big.NewInt(7))), scalar32(big.NewInt(9)))
	require.NoError(t, err)
	require.Equal(t, base, shifted, "(7+r)*G == 7*G: same scalar, same commitment")

	// A different scalar still gives a different commitment.
	other, _, err := fire(t, OpCommit,
		scalar32(new(big.Int).Add(r, big.NewInt(8))), scalar32(big.NewInt(9)))
	require.NoError(t, err)
	require.NotEqual(t, base, other)
}

// TestKAT_VectorCommit pins the vector commitment against the same arithmetic
// computed here: C = sum(v_i * V_i) + r*H, hashed.
func TestKAT_VectorCommit(t *testing.T) {
	for _, n := range []int{0, 1, 2, 5, 31, 32} {
		vals := make([]*big.Int, n)
		payload := []byte{byte(n)}
		for i := range n {
			vals[i] = big.NewInt(int64(i*7 + 1))
			payload = append(payload, scalar32(vals[i])...)
		}
		blind := big.NewInt(int64(n) + 100)
		payload = append(payload, scalar32(blind)...)

		var sum bn254.G1Jac
		for i := range n {
			var viG bn254.G1Affine
			viG.ScalarMultiplication(&genVi[i], vals[i])
			var j bn254.G1Jac
			j.FromAffine(&viG)
			sum.AddAssign(&j)
		}
		var rH bn254.G1Affine
		rH.ScalarMultiplication(&genH, blind)
		var rHJac bn254.G1Jac
		rHJac.FromAffine(&rH)
		sum.AddAssign(&rHJac)
		var affine bn254.G1Affine
		affine.FromJacobian(&sum)
		want := sha256.Sum256(affine.Marshal())

		got, _, err := fire(t, OpVectorCommit, payload)
		require.NoError(t, err, "n=%d", n)
		require.Equal(t, want[:], got, "n=%d", n)
	}
}

// TestVectorCommitBindsPositionAndValue: swapping two values must change the
// commitment, which is only true if each slot uses its own generator.
func TestVectorCommitBindsPosition(t *testing.T) {
	build := func(vals ...int64) []byte {
		p := []byte{byte(len(vals))}
		for _, v := range vals {
			p = append(p, scalar32(big.NewInt(v))...)
		}
		return append(p, scalar32(big.NewInt(5))...)
	}
	a, _, err := fire(t, OpVectorCommit, build(1, 2, 3))
	require.NoError(t, err)
	b, _, err := fire(t, OpVectorCommit, build(3, 2, 1))
	require.NoError(t, err)
	require.NotEqual(t, a, b, "a permutation of the vector must change the commitment")

	c, _, err := fire(t, OpVectorCommit, build(1, 2))
	require.NoError(t, err)
	require.NotEqual(t, a, c, "the length must be bound too")
}

// TestRefusal_AddPointValidation is the invalid-curve refusal. gnark's decoder
// checks canonicality, curve membership and subgroup membership, and Add must
// surface every one of those as a refusal rather than compute on the result.
func TestRefusal_AddPointValidation(t *testing.T) {
	_, _, g1, _ := bn254.Generators()
	good := g1.Marshal()
	require.Len(t, good, 128/2)

	offCurve := append([]byte{}, good...)
	offCurve[63] ^= 0x01
	var probe bn254.G1Affine
	require.Error(t, probe.Unmarshal(offCurve), "fixture must really be invalid")

	xPlusP := make([]byte, 64)
	new(big.Int).Add(new(big.Int).SetBytes(good[:32]), fp.Modulus()).FillBytes(xPlusP[:32])
	copy(xPlusP[32:], good[32:])

	xEqualsP := make([]byte, 64)
	fp.Modulus().FillBytes(xEqualsP[:32])
	copy(xEqualsP[32:], good[32:])

	allOnes := make([]byte, 64)
	for i := range allOnes {
		allOnes[i] = 0xFF
	}

	for _, tc := range []struct {
		name string
		bad  []byte
	}{
		{"off curve", offCurve},
		{"x + p is not canonical", xPlusP},
		{"x = p is not canonical", xEqualsP},
		{"all ones", allOnes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, args := range [][2][]byte{{tc.bad, good}, {good, tc.bad}, {tc.bad, tc.bad}} {
				out, _, err := fire(t, OpAdd, args[0], args[1])
				require.ErrorIs(t, err, ErrInvalidInput)
				require.Nil(t, out)
			}
		})
	}

	// The point at infinity is a legal encoding and is the additive identity.
	inf := make([]byte, 64)
	out, _, err := fire(t, OpAdd, good, inf)
	require.NoError(t, err)
	require.Equal(t, good, out)
	out, _, err = fire(t, OpAdd, inf, inf)
	require.NoError(t, err)
	require.Equal(t, inf, out)

	// G + (-G) is infinity.
	neg := new(bn254.G1Affine).Neg(&g1)
	out, _, err = fire(t, OpAdd, good, neg.Marshal())
	require.NoError(t, err)
	require.Equal(t, inf, out)
}

// TestRefusal_Shape walks every truncation, oversize and selector refusal.
func TestRefusal_Shape(t *testing.T) {
	_, _, g1, _ := bn254.Generators()
	good := g1.Marshal()
	v := scalar32(big.NewInt(1))

	for _, tc := range []struct {
		name string
		in   []byte
		err  error
	}{
		{"nil", nil, ErrInvalidInput},
		{"empty", []byte{}, ErrInvalidInput},
		{"commit op only", []byte{OpCommit}, ErrInvalidInput},
		{"commit one scalar", append([]byte{OpCommit}, v...), ErrInvalidInput},
		{"commit one byte short", append([]byte{OpCommit}, make([]byte, 63)...), ErrInvalidInput},
		{"verify op only", []byte{OpVerify}, ErrInvalidInput},
		{"verify one byte short", append([]byte{OpVerify}, make([]byte, 95)...), ErrInvalidInput},
		{"add op only", []byte{OpAdd}, ErrInvalidInput},
		{"add one point", append([]byte{OpAdd}, good...), ErrInvalidInput},
		{"add one byte short", append([]byte{OpAdd}, make([]byte, 127)...), ErrInvalidInput},
		{"vector op only", []byte{OpVectorCommit}, ErrInvalidInput},
		{"vector n=1 no data", []byte{OpVectorCommit, 1}, ErrInvalidInput},
		{"vector n=1 short", append([]byte{OpVectorCommit, 1}, make([]byte, 63)...), ErrInvalidInput},
		{"vector n=0 no blinding", []byte{OpVectorCommit, 0}, ErrInvalidInput},
		{"vector n=33", append([]byte{OpVectorCommit, 33}, make([]byte, 33*32+32)...), ErrTooManyVals},
		{"vector n=255", append([]byte{OpVectorCommit, 255}, make([]byte, 255*32+32)...), ErrTooManyVals},
		{"unknown op 0x00", []byte{0x00}, ErrInvalidOp},
		{"unknown op 0x05", []byte{0x05}, ErrInvalidOp},
		{"unknown op 0xff", []byte{0xFF}, ErrInvalidOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, tc.in, 1<<24, true)
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, out)
		})
	}

	// The boundaries either side of each refusal must work.
	out, _, err := fire(t, OpVectorCommit, append([]byte{32}, make([]byte, 32*32+32)...))
	require.NoError(t, err, "32 values is the maximum width")
	require.Len(t, out, 32)

	out, _, err = fire(t, OpVectorCommit, append([]byte{0}, make([]byte, 32)...))
	require.NoError(t, err, "a zero-length vector is just the blinding term")
	require.Len(t, out, 32)

	// Trailing data past a fixed operand is ignored, not refused.
	short, _, err := fire(t, OpCommit, v, v)
	require.NoError(t, err)
	long, _, err := fire(t, OpCommit, v, v, []byte{0xAA})
	require.NoError(t, err)
	require.Equal(t, short, long)
}

// TestEqualIsLengthCheckedAndConstantTime covers the comparison used by Verify.
func TestEqualIsLengthChecked(t *testing.T) {
	require.True(t, equal(nil, nil))
	require.True(t, equal([]byte{}, []byte{}))
	require.True(t, equal([]byte{1, 2, 3}, []byte{1, 2, 3}))

	require.False(t, equal([]byte{1, 2, 3}, []byte{1, 2}), "length mismatch must not compare equal")
	require.False(t, equal([]byte{1, 2}, []byte{1, 2, 3}))
	require.False(t, equal(nil, []byte{0}))
	require.False(t, equal([]byte{0}, nil))
	require.False(t, equal([]byte{1, 2, 3}, []byte{1, 2, 4}), "a difference in the last byte counts")
	require.False(t, equal([]byte{1, 2, 3}, []byte{9, 2, 3}), "a difference in the first byte counts")

	// It accumulates rather than returning early, so every byte is read.
	a := make([]byte, 32)
	b := make([]byte, 32)
	b[0] = 1
	require.False(t, equal(a, b))
	b[0], b[31] = 0, 1
	require.False(t, equal(a, b))
}

// TestGas_Schedule covers every arm and proves nothing is bought for free.
func TestGas_Schedule(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"commit", []byte{OpCommit}, GasCommit},
		{"verify", []byte{OpVerify}, GasVerify},
		{"add", []byte{OpAdd}, GasAdd},
		{"vector op only", []byte{OpVectorCommit}, 0},
		{"vector n=0", []byte{OpVectorCommit, 0}, GasVectorBase},
		{"vector n=1", []byte{OpVectorCommit, 1}, GasVectorBase + GasVectorPerVal},
		{"vector n=32", []byte{OpVectorCommit, 32}, GasVectorBase + 32*GasVectorPerVal},
		{"vector n=255", []byte{OpVectorCommit, 255}, GasVectorBase + 255*GasVectorPerVal},
		{"unknown 0x00", []byte{0x00}, 0},
		{"unknown 0x05", []byte{0x05}, 0},
		{"unknown 0xff", []byte{0xFF}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PedersenPrecompile.RequiredGas(tc.in))
		})
	}

	// The vector price rises by one unit per declared value, and the declared
	// count is a single byte, so it can never overflow the accumulator.
	prev := uint64(GasVectorBase)
	for n := 1; n <= 255; n++ {
		got := PedersenPrecompile.RequiredGas([]byte{OpVectorCommit, byte(n)})
		require.Equal(t, uint64(GasVectorBase+n*GasVectorPerVal), got, "n=%d", n)
		require.Equal(t, uint64(GasVectorPerVal), got-prev)
		prev = got
	}
	require.Greater(t, PedersenPrecompile.RequiredGas([]byte{OpVectorCommit, 255}),
		uint64(GasVectorBase), "the maximum declared count must not wrap")

	// A count above the 32-value limit is charged and then refused: the caller
	// pays for the width it declared, so over-declaring buys nothing.
	_, _, err := PedersenPrecompile.Run(nil, common.Address{}, ContractAddress,
		append([]byte{OpVectorCommit, 255}, make([]byte, 255*32+32)...),
		uint64(GasVectorBase+255*GasVectorPerVal), true)
	require.ErrorIs(t, err, ErrTooManyVals)

	// The fixed-width arms do not move with input size.
	require.Equal(t, uint64(GasCommit),
		PedersenPrecompile.RequiredGas(append([]byte{OpCommit}, make([]byte, 1<<16)...)))

	// Every zero-priced input must refuse.
	for _, in := range [][]byte{nil, {}, {OpVectorCommit}, {0x00}, {0x05}, {0xFF}} {
		require.Zero(t, PedersenPrecompile.RequiredGas(in))
		out, _, err := PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.Error(t, err, "a zero-gas input must not execute")
		require.Nil(t, out)
	}
}

func TestGas_Deduction(t *testing.T) {
	v := scalar32(big.NewInt(3))
	in := append([]byte{OpCommit}, append(append([]byte{}, v...), v...)...)

	_, left, err := PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, in, GasCommit+23, true)
	require.NoError(t, err)
	require.Equal(t, uint64(23), left)

	_, left, err = PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, in, GasCommit, true)
	require.NoError(t, err)
	require.Zero(t, left)

	_, left, err = PedersenPrecompile.Run(nil, common.Address{}, ContractAddress, in, GasCommit-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, left)

	// Verify costs more than Commit because it commits and then compares.
	require.Greater(t, uint64(GasVerify), uint64(GasCommit))
}

// --- module + config ----------------------------------------------------

func TestModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, PedersenPrecompile, Module.Contract)
	require.NotNil(t, Module.Configurator)
	require.Equal(t,
		common.HexToAddress("0x0500000000000000000000000000000000000006"),
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

	ts := uint64(51)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(52)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil))
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module))
}
