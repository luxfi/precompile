// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pasta

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func dec(tb testing.TB, s string) *big.Int {
	tb.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	require.True(tb, ok, "bad decimal literal %q", s)
	return v
}

func word(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

func words(x, y *big.Int) []byte { return append(word(x), word(y)...) }

func exec(tb testing.TB, curveID, op byte, args ...[]byte) ([]byte, uint64, error) {
	tb.Helper()
	in := []byte{curveID, op}
	for _, a := range args {
		in = append(in, a...)
	}
	return PastaPrecompile.Run(nil, common.Address{}, ContractAddress, in, 1<<24, true)
}

// generator returns the Pasta generator (-1, 2), which satisfies
// y^2 = x^3 + 5 as 4 = -1 + 5 on both curves.
func generator(curveID byte) (*big.Int, *big.Int) {
	return new(big.Int).Sub(modulus(curveID), big.NewInt(1)), big.NewInt(2)
}

// groupOrder returns the order of the curve's group. Pallas and Vesta form a
// 2-cycle: each one's group order is the other's base field modulus.
func groupOrder(curveID byte) *big.Int { return modulus(curveID ^ 0x03) }

// multiples holds k*G for both curves, computed with an independent
// implementation of the short-Weierstrass chord-and-tangent law. Each was
// checked to satisfy y^2 = x^3 + 5 and to have the published group order before
// being written here.
var multiples = map[byte]map[int][2]string{
	CurvePallas: {
		2: {"12664759760331458874453076485325239921471337210849432813230171084403110838275",
			"19449452489080454700052938888178047022259553573804486106032048451047634501628"},
		3: {"4027241023027617754036171531542546502751647131375064771810253584944963179107",
			"21762326383673887073830845720227757791980770399450032709429395080608314263493"},
		7: {"11597971188910290580510217765257817734852330887059848818989398919746936474521",
			"16072930402498746743190202080148926785915484279186972392222802455510868042413"},
		13: {"18071519724993305994823418956020412618942156734267125192164762840965296331733",
			"19818191382159177435510133618996785660947641416707759797575257840979978328136"},
		12345: {"18979344285946257891976342328653028961358577761991777536576238509026147226792",
			"16682595558766154259970161743373292552444720227662848748247144435751974152804"},
	},
	CurveVesta: {
		2: {"12664759760331458874453076485325239921471337210849470728609887452422096289795",
			"19449452489080454700052938888178047022259553573804544333222327159076790730748"},
		3: {"25090067966472946007446590780583652548116456464496053869245354133418193309279",
			"14485812765332067710838382555935059365898177416503303828814702067459945738374"},
		7: {"25239266693512118316897230459878239393039601456471569695166164382595970610905",
			"11285412150649616874720335020355225107778890555574340278102540384742252572629"},
		13: {"10156475246948922191667186682453517613403044314391612076993990862302619077531",
			"18230172829350593030385658896184831891431135274899809641065219710746269229566"},
		12345: {"20982986658818477740166501316994920625962009651848408555069289392931482296445",
			"492782312291387666733785462487308572527117237245988757616569697279745631012"},
	},
}

func expected(tb testing.TB, curveID byte, k int) []byte {
	tb.Helper()
	v, ok := multiples[curveID][k]
	require.True(tb, ok, "no reference for %d", k)
	return words(dec(tb, v[0]), dec(tb, v[1]))
}

func bothCurves(t *testing.T, f func(t *testing.T, curveID byte)) {
	t.Helper()
	for name, id := range map[string]byte{"pallas": CurvePallas, "vesta": CurveVesta} {
		t.Run(name, func(t *testing.T) { f(t, id) })
	}
}

// TestKAT_GeneratorIsOnCurve pins the generator itself: (-1, 2) satisfies the
// curve equation, and its order is the published group order.
func TestKAT_GeneratorIsOnCurve(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		gx, gy := generator(id)
		p := modulus(id)

		lhs := new(big.Int).Mod(new(big.Int).Mul(gy, gy), p)
		rhs := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Exp(gx, big.NewInt(3), p), curveB), p)
		require.Zero(t, lhs.Cmp(rhs), "generator must satisfy y^2 = x^3 + 5")

		// n*G is the point at infinity, encoded as 64 zero bytes.
		out, _, err := exec(t, id, OpScalarMul, words(gx, gy), word(groupOrder(id)))
		require.NoError(t, err)
		require.Equal(t, make([]byte, PointLen), out, "n*G must be the point at infinity")

		// (n-1)*G is -G.
		out, _, err = exec(t, id, OpScalarMul, words(gx, gy),
			word(new(big.Int).Sub(groupOrder(id), big.NewInt(1))))
		require.NoError(t, err)
		require.Equal(t, words(gx, new(big.Int).Sub(p, gy)), out, "(n-1)*G must be -G")
	})
}

// TestKAT_ScalarMul pins k*G against independently computed reference points.
func TestKAT_ScalarMul(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		gx, gy := generator(id)
		G := words(gx, gy)
		for _, k := range []int{2, 3, 7, 13, 12345} {
			out, _, err := exec(t, id, OpScalarMul, G, word(big.NewInt(int64(k))))
			require.NoError(t, err)
			require.Equal(t, expected(t, id, k), out, "%d*G", k)
		}

		// 1*G is G, and 0*G is infinity.
		out, _, err := exec(t, id, OpScalarMul, G, word(big.NewInt(1)))
		require.NoError(t, err)
		require.Equal(t, G, out)

		out, _, err = exec(t, id, OpScalarMul, G, word(big.NewInt(0)))
		require.NoError(t, err)
		require.Equal(t, make([]byte, PointLen), out)
	})
}

// TestKAT_PointAdd pins the addition law against the same reference points, and
// ties it back to scalar multiplication.
func TestKAT_PointAdd(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		gx, gy := generator(id)
		G := words(gx, gy)
		inf := make([]byte, PointLen)

		out, _, err := exec(t, id, OpPointAdd, G, G)
		require.NoError(t, err)
		require.Equal(t, expected(t, id, 2), out, "G + G == 2G (the doubling branch)")

		out, _, err = exec(t, id, OpPointAdd, expected(t, id, 2), G)
		require.NoError(t, err)
		require.Equal(t, expected(t, id, 3), out, "2G + G == 3G (the chord branch)")

		// Commutative.
		ab, _, err := exec(t, id, OpPointAdd, expected(t, id, 3), expected(t, id, 7))
		require.NoError(t, err)
		ba, _, err := exec(t, id, OpPointAdd, expected(t, id, 7), expected(t, id, 3))
		require.NoError(t, err)
		require.Equal(t, ab, ba)

		// Infinity is neutral in both positions.
		for _, args := range [][2][]byte{{G, inf}, {inf, G}} {
			out, _, err := exec(t, id, OpPointAdd, args[0], args[1])
			require.NoError(t, err)
			require.Equal(t, G, out)
		}
		out, _, err = exec(t, id, OpPointAdd, inf, inf)
		require.NoError(t, err)
		require.Equal(t, inf, out)

		// G + (-G) is infinity: the vertical-line branch.
		negG := words(gx, new(big.Int).Sub(modulus(id), gy))
		out, _, err = exec(t, id, OpPointAdd, G, negG)
		require.NoError(t, err)
		require.Equal(t, inf, out)

		// Doubling a point whose y is zero would be a vertical tangent. No such
		// point exists on y^2 = x^3 + 5 over these fields (5 is not a cube), so
		// the branch is driven through infinity instead.
		out, _, err = exec(t, id, OpScalarMul, negG, word(groupOrder(id)))
		require.NoError(t, err)
		require.Equal(t, inf, out)
	})
}

// TestKAT_MSM pins the multiscalar sum: 3*G + 5*(2G) is 13G.
func TestKAT_MSM(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		gx, gy := generator(id)
		G := words(gx, gy)

		out, _, err := exec(t, id, OpMSM,
			G, word(big.NewInt(3)),
			expected(t, id, 2), word(big.NewInt(5)))
		require.NoError(t, err)
		require.Equal(t, expected(t, id, 13), out, "3G + 5(2G) == 13G")

		// Order of the pairs does not matter.
		swapped, _, err := exec(t, id, OpMSM,
			expected(t, id, 2), word(big.NewInt(5)),
			G, word(big.NewInt(3)))
		require.NoError(t, err)
		require.Equal(t, out, swapped)

		// One pair degenerates to scalar multiplication.
		single, _, err := exec(t, id, OpMSM, G, word(big.NewInt(7)))
		require.NoError(t, err)
		require.Equal(t, expected(t, id, 7), single)

		// All-zero scalars sum to infinity.
		zeros, _, err := exec(t, id, OpMSM,
			G, make([]byte, 32), expected(t, id, 2), make([]byte, 32))
		require.NoError(t, err)
		require.Equal(t, make([]byte, PointLen), zeros)
	})
}

// TestKAT_CurvesAreDistinct guards the curve selector. Pallas and Vesta differ
// only in their modulus, so a selector that was ignored -- or inverted -- would
// otherwise go unnoticed on the generator, which is (-1, 2) for both.
func TestKAT_CurvesAreDistinct(t *testing.T) {
	require.NotEqual(t, pallasP, vestaP)
	require.Equal(t, pallasP, modulus(CurvePallas))
	require.Equal(t, vestaP, modulus(CurveVesta))
	require.Equal(t, vestaP, groupOrder(CurvePallas), "Pallas's group order is Vesta's field")
	require.Equal(t, pallasP, groupOrder(CurveVesta), "Vesta's group order is Pallas's field")

	for _, k := range []int{2, 3, 7, 13, 12345} {
		require.NotEqual(t, expected(t, CurvePallas, k), expected(t, CurveVesta, k),
			"%d*G must differ between the curves", k)
	}

	// A Pallas point at high x is not a Vesta point and must be refused there.
	// pallasP < vestaP, so pallasP itself is a canonical Vesta coordinate that
	// is NOT canonical on Pallas.
	require.Negative(t, pallasP.Cmp(vestaP))
}

// TestNonCanonicalCoordinateRejected is the regression for the defect this file
// was written around.
//
// decodePoint used to accept any 32-byte word as a coordinate. Two encodings of
// one point (x and x+p) therefore reached addPoints, which compares raw
// integers: it missed the doubling case, took the chord branch, and there
// ModInverse of a multiple of p returns nil while leaving its receiver
// untouched. The discarded nil became a bogus slope and the precompile returned
// a point that is NOT ON THE CURVE -- (2, p-2) where 2G was expected.
func TestNonCanonicalCoordinateRejected(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		p := modulus(id)
		gx, gy := generator(id)
		G := words(gx, gy)

		ncX := new(big.Int).Add(gx, p)
		require.LessOrEqual(t, ncX.BitLen(), 256, "the second encoding must fit a word")
		ghost := words(ncX, gy)
		require.NotEqual(t, G, ghost)

		for _, tc := range []struct {
			name string
			args [][]byte
			op   byte
		}{
			// The exact shape that produced an off-curve answer.
			{"add ghost + real", [][]byte{ghost, G}, OpPointAdd},
			{"add real + ghost", [][]byte{G, ghost}, OpPointAdd},
			{"scalarMul ghost", [][]byte{ghost, word(big.NewInt(2))}, OpScalarMul},
			{"msm ghost", [][]byte{ghost, word(big.NewInt(2))}, OpMSM},
			// y is a field element too.
			{"y + p", [][]byte{words(gx, new(big.Int).Add(gy, p)), G}, OpPointAdd},
			// x = p reduces to 0, y = p reduces to 0: the infinity spelling.
			{"x = p", [][]byte{words(p, gy), G}, OpPointAdd},
			{"y = p", [][]byte{words(gx, p), G}, OpPointAdd},
			{"both = p", [][]byte{words(p, p), G}, OpPointAdd},
			{"x = 2^256-1", [][]byte{
				words(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), gy), G},
				OpPointAdd},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out, _, err := exec(t, id, tc.op, tc.args...)
				require.ErrorIs(t, err, ErrInvalidInput,
					"a coordinate at or above p must be refused, not reduced")
				require.Nil(t, out)
			})
		}

		// The canonical pair still works, so the refusals are attributable to
		// canonicality rather than to a broken fixture.
		out, _, err := exec(t, id, OpPointAdd, G, G)
		require.NoError(t, err)
		require.Equal(t, expected(t, id, 2), out)
	})
}

// TestEveryOutputIsOnCurve is the invariant the off-curve defect violated. It
// sweeps the operations over reference and derived points and re-checks the
// curve equation on every answer, independently of how it was produced.
func TestEveryOutputIsOnCurve(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		p := modulus(id)
		gx, gy := generator(id)
		G := words(gx, gy)

		onCurve := func(out []byte) {
			t.Helper()
			require.Len(t, out, PointLen)
			x := new(big.Int).SetBytes(out[:32])
			y := new(big.Int).SetBytes(out[32:])
			require.Negative(t, x.Cmp(p), "output x must be canonical")
			require.Negative(t, y.Cmp(p), "output y must be canonical")
			if x.Sign() == 0 && y.Sign() == 0 {
				return // point at infinity
			}
			lhs := new(big.Int).Mod(new(big.Int).Mul(y, y), p)
			rhs := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), p), curveB), p)
			require.Zero(t, lhs.Cmp(rhs), "output (%s, %s) is not on the curve", x, y)
		}

		acc := G
		for k := 1; k <= 24; k++ {
			out, _, err := exec(t, id, OpScalarMul, G, word(big.NewInt(int64(k))))
			require.NoError(t, err)
			onCurve(out)

			sum, _, err := exec(t, id, OpPointAdd, acc, G)
			require.NoError(t, err)
			onCurve(sum)
			acc = sum

			msm, _, err := exec(t, id, OpMSM, G, word(big.NewInt(int64(k))), acc, word(big.NewInt(3)))
			require.NoError(t, err)
			onCurve(msm)
		}
	})
}

// TestRefusal_PointNotOnCurve is the invalid-curve refusal: canonical
// coordinates that do not satisfy the curve equation.
func TestRefusal_PointNotOnCurve(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		gx, gy := generator(id)
		G := words(gx, gy)
		bad := words(gx, new(big.Int).Add(gy, big.NewInt(1)))

		for _, tc := range []struct {
			name string
			args [][]byte
			op   byte
		}{
			{"add first", [][]byte{bad, G}, OpPointAdd},
			{"add second", [][]byte{G, bad}, OpPointAdd},
			{"scalarMul", [][]byte{bad, word(big.NewInt(3))}, OpScalarMul},
			{"msm", [][]byte{bad, word(big.NewInt(3))}, OpMSM},
			{"msm second pair", [][]byte{G, word(big.NewInt(1)), bad, word(big.NewInt(3))}, OpMSM},
			{"x only", [][]byte{words(gx, big.NewInt(0)), G}, OpPointAdd},
			{"y only", [][]byte{words(big.NewInt(0), gy), G}, OpPointAdd},
		} {
			t.Run(tc.name, func(t *testing.T) {
				out, _, err := exec(t, id, tc.op, tc.args...)
				require.ErrorIs(t, err, ErrNotOnCurve)
				require.Nil(t, out)
			})
		}
	})
}

// TestRefusal_CurveSelector: only 0x01 and 0x02 name a curve.
func TestRefusal_CurveSelector(t *testing.T) {
	gx, gy := generator(CurvePallas)
	G := words(gx, gy)
	for _, id := range []byte{0x00, 0x03, 0x04, 0x7F, 0x80, 0xFF} {
		out, _, err := exec(t, id, OpPointAdd, G, G)
		require.ErrorIs(t, err, ErrInvalidCurve, "selector %#x", id)
		require.Nil(t, out)
	}
}

// TestRefusal_Length walks every truncation and the unknown-opcode arm.
func TestRefusal_Length(t *testing.T) {
	gx, gy := generator(CurvePallas)
	G := words(gx, gy)
	s := word(big.NewInt(3))

	for _, tc := range []struct {
		name string
		in   []byte
		err  error
	}{
		{"nil", nil, ErrInvalidInput},
		{"empty", []byte{}, ErrInvalidInput},
		{"curve byte only", []byte{CurvePallas}, ErrInvalidInput},
		{"header only", []byte{CurvePallas, OpPointAdd}, ErrInvalidInput},
		{"add one point", append([]byte{CurvePallas, OpPointAdd}, G...), ErrInvalidInput},
		{"add one byte short", append([]byte{CurvePallas, OpPointAdd}, append(append([]byte{}, G...), G[:PointLen-1]...)...), ErrInvalidInput},
		{"scalarMul no scalar", append([]byte{CurvePallas, OpScalarMul}, G...), ErrInvalidInput},
		{"scalarMul one byte short", append([]byte{CurvePallas, OpScalarMul}, append(append([]byte{}, G...), s[:31]...)...), ErrInvalidInput},
		{"msm empty", []byte{CurvePallas, OpMSM}, ErrInvalidInput},
		{"msm half pair", append([]byte{CurvePallas, OpMSM}, G...), ErrInvalidInput},
		{"msm one byte long", append([]byte{CurvePallas, OpMSM}, append(append(append([]byte{}, G...), s...), 0)...), ErrInvalidInput},
		{"msm one byte short", append([]byte{CurvePallas, OpMSM}, append(append([]byte{}, G...), s[:31]...)...), ErrInvalidInput},
		{"unknown op 0x00", []byte{CurvePallas, 0x00}, ErrInvalidOp},
		{"unknown op 0x04", []byte{CurvePallas, 0x04}, ErrInvalidOp},
		{"unknown op 0xff", append([]byte{CurvePallas, 0xFF}, G...), ErrInvalidOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := PastaPrecompile.Run(nil, common.Address{}, ContractAddress, tc.in, 1<<24, true)
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, out)
		})
	}

	// Trailing data past a fixed-width operand is ignored, not refused.
	short, _, err := exec(t, CurvePallas, OpPointAdd, G, G)
	require.NoError(t, err)
	long, _, err := exec(t, CurvePallas, OpPointAdd, G, G, []byte{0xAA})
	require.NoError(t, err)
	require.Equal(t, short, long)
}

// TestGas_Schedule covers every arm, and proves MSM is priced per pair.
func TestGas_Schedule(t *testing.T) {
	pair := PointLen + 32

	for _, tc := range []struct {
		name string
		in   []byte
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"curve byte only", []byte{CurvePallas}, 0},
		{"pointAdd", []byte{CurvePallas, OpPointAdd}, GasPointAdd},
		{"scalarMul", []byte{CurveVesta, OpScalarMul}, GasScalarMul},
		{"unknown op 0x00", []byte{CurvePallas, 0x00}, 0},
		{"unknown op 0x04", []byte{CurvePallas, 0x04}, 0},
		{"unknown op 0xff", []byte{CurvePallas, 0xFF}, 0},
		{"msm no data", []byte{CurvePallas, OpMSM}, 0},
		{"msm short of a pair", append([]byte{CurvePallas, OpMSM}, make([]byte, pair-1)...), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PastaPrecompile.RequiredGas(tc.in))
		})
	}

	// The price is set by the operation byte, not the curve byte.
	require.Equal(t,
		PastaPrecompile.RequiredGas([]byte{CurvePallas, OpScalarMul}),
		PastaPrecompile.RequiredGas([]byte{CurveVesta, OpScalarMul}))
	require.Equal(t, uint64(GasPointAdd),
		PastaPrecompile.RequiredGas([]byte{0xFF, OpPointAdd}),
		"an invalid curve still costs its operation: the work is decided later")

	// Each additional pair costs exactly one per-pair unit.
	prev := uint64(0)
	for n := 1; n <= 32; n++ {
		in := append([]byte{CurvePallas, OpMSM}, make([]byte, n*pair)...)
		got := PastaPrecompile.RequiredGas(in)
		require.Equal(t, uint64(GasMSMBase+n*GasMSMPerPt), got, "n=%d", n)
		if n > 1 {
			require.Equal(t, uint64(GasMSMPerPt), got-prev)
		}
		prev = got
	}

	// A large pair count neither wraps nor overflows: the count is derived from
	// the actual byte length, so it cannot be declared independently of the work.
	huge := append([]byte{CurvePallas, OpMSM}, make([]byte, 4096*pair)...)
	require.Equal(t, uint64(GasMSMBase+4096*GasMSMPerPt), PastaPrecompile.RequiredGas(huge))
	require.Greater(t, PastaPrecompile.RequiredGas(huge), uint64(GasMSMBase))

	// Every zero-priced input must refuse.
	for _, in := range [][]byte{
		nil, {}, {CurvePallas}, {CurvePallas, 0x00}, {CurvePallas, 0x04}, {CurvePallas, 0xFF},
		{CurvePallas, OpMSM}, append([]byte{CurvePallas, OpMSM}, make([]byte, pair-1)...),
	} {
		require.Zero(t, PastaPrecompile.RequiredGas(in))
		out, _, err := PastaPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.Error(t, err, "a zero-gas input must not execute")
		require.Nil(t, out)
	}
}

func TestGas_Deduction(t *testing.T) {
	gx, gy := generator(CurvePallas)
	G := words(gx, gy)
	in := append([]byte{CurvePallas, OpPointAdd}, append(append([]byte{}, G...), G...)...)

	_, left, err := PastaPrecompile.Run(nil, common.Address{}, ContractAddress, in, GasPointAdd+31, true)
	require.NoError(t, err)
	require.Equal(t, uint64(31), left)

	_, left, err = PastaPrecompile.Run(nil, common.Address{}, ContractAddress, in, GasPointAdd, true)
	require.NoError(t, err)
	require.Zero(t, left)

	_, left, err = PastaPrecompile.Run(nil, common.Address{}, ContractAddress, in, GasPointAdd-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, left)

	// Two MSM pairs must be unaffordable at the one-pair price.
	pair := PointLen + 32
	two := append([]byte{CurvePallas, OpMSM}, make([]byte, 2*pair)...)
	_, _, err = PastaPrecompile.Run(nil, common.Address{}, ContractAddress, two,
		GasMSMBase+GasMSMPerPt, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

// --- module + config ----------------------------------------------------

func TestModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, PastaPrecompile, Module.Contract)
	require.NotNil(t, Module.Configurator)
	require.Equal(t,
		common.HexToAddress("0x0500000000000000000000000000000000000008"),
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

	ts := uint64(31)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(32)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil))
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module))
}

// TestHelperGuards exercises the two defensive branches in the arithmetic
// helpers directly. Both are unreachable through Run today -- every caller
// slices exactly PointLen bytes before calling decodePoint, and the Pasta
// groups have prime order so no point of order two (y = 0) exists, and the
// ladder never hands doublePoint the identity. They stay because deleting them
// turns a future mis-slice into a panic and a nil dereference rather than an
// error, and they are asserted here so they cannot rot unnoticed.
func TestHelperGuards(t *testing.T) {
	bothCurves(t, func(t *testing.T, id byte) {
		// decodePoint refuses a short slice instead of panicking on it.
		for _, n := range []int{0, 1, 31, 32, 63} {
			_, err := decodePoint(id, make([]byte, n))
			require.ErrorIs(t, err, ErrInvalidInput, "len=%d", n)
		}

		// doublePoint of the identity is the identity.
		require.True(t, doublePoint(id, point{inf: true}).inf)

		// A point with y = 0 has order two. No such point is on this curve, so
		// the guard is what stops the tangent slope from dividing by zero.
		require.True(t, doublePoint(id, point{x: big.NewInt(1), y: big.NewInt(0)}).inf)

		// The prime group order is why no such point exists: it is odd, so the
		// group has no element of order two.
		require.Equal(t, uint(1), groupOrder(id).Bit(0), "group order must be odd")
	})
}
