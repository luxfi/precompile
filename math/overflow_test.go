// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package math

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

var (
	ovMaxU256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	ovQ128    = new(big.Int).Lsh(big.NewInt(1), 128)
)

// call builds `[op][32-byte words...]` and runs it with a generous gas budget, so
// every failure below is a semantic refusal rather than an incidental out-of-gas.
func call(op byte, words ...*big.Int) ([]byte, uint64, error) {
	in := []byte{op}
	for _, w := range words {
		in = append(in, padTo32(w.Bytes())...)
	}
	return Precompile.Run(nil, common.Address{}, ContractAddress, in, 1_000_000, false)
}

func mustCall(t *testing.T, op byte, words ...*big.Int) *big.Int {
	t.Helper()
	out, _, err := call(op, words...)
	require.NoError(t, err)
	require.Len(t, out, 32, "every numeric result must be exactly one word")
	return new(big.Int).SetBytes(out)
}

// ---------------------------------------------------------------------------
// REGRESSION: silent uint256 truncation.
// ---------------------------------------------------------------------------

// TestMulDivRefusesOverflowInsteadOfTruncating pins the fix for a silent
// wrong-answer defect. Results are returned through padTo32, which keeps only the
// LOW 32 bytes, so before the bound an out-of-range quotient was not an error — it
// was a different number that looked entirely real:
//
//	MulDiv(2^255, 4, 1) = 2^257  -> returned 0
//	MulDiv(max,  max, 1) ~ 2^512 -> returned 1
//
// This is the primitive fees and share ratios are computed with; a caller cannot
// distinguish a wrapped answer from a correct one, so the only safe outcome is a
// refusal (which the EVM surfaces as a revert, matching FullMath.sol's require).
func TestMulDivRefusesOverflowInsteadOfTruncating(t *testing.T) {
	for _, op := range []byte{OpMulDiv, OpMulDivRoundUp} {
		// The exact values that used to truncate to 0 and 1.
		_, _, err := call(op, new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(4), big.NewInt(1))
		require.ErrorIsf(t, err, ErrOverflow, "op %#x: 2^257 must be refused, not truncated to 0", op)

		_, _, err = call(op, ovMaxU256, ovMaxU256, big.NewInt(1))
		require.ErrorIsf(t, err, ErrOverflow, "op %#x: max*max must be refused, not truncated to 1", op)
	}

	// The boundary is exact: a result of exactly maxU256 is legal, one more is not.
	require.Equal(t, 0, mustCall(t, OpMulDiv, ovMaxU256, big.NewInt(1), big.NewInt(1)).Cmp(ovMaxU256),
		"a result of exactly maxU256 must be returned, not refused")
	_, _, err := call(OpMulDiv, ovMaxU256, big.NewInt(2), big.NewInt(1))
	require.ErrorIs(t, err, ErrOverflow, "one step past maxU256 must be refused")

	// Rounding UP must never produce a value BELOW rounding down. A wrap is exactly
	// what that would look like, so this is the shape-level check that catches a
	// truncation the exact-value assertions might miss.
	for _, args := range [][3]*big.Int{
		{ovMaxU256, ovMaxU256, ovMaxU256},
		{ovMaxU256, big.NewInt(1), big.NewInt(3)},
		{new(big.Int).Lsh(big.NewInt(1), 200), new(big.Int).Lsh(big.NewInt(1), 55), big.NewInt(7)},
	} {
		lo, _, errLo := call(OpMulDiv, args[0], args[1], args[2])
		hi, _, errHi := call(OpMulDivRoundUp, args[0], args[1], args[2])
		if errLo != nil || errHi != nil {
			require.Equal(t, errLo != nil, errHi != nil,
				"floor and ceiling must agree on whether the result fits")
			continue
		}
		require.GreaterOrEqual(t, new(big.Int).SetBytes(hi).Cmp(new(big.Int).SetBytes(lo)), 0,
			"ceiling below floor is a wrap")
	}
}

// TestExpRefusesOverflow: e^x leaves uint256 for any sizeable x, and the truncated
// remainder is a plausible number unrelated to e^x. Refuse instead.
func TestExpRefusesOverflow(t *testing.T) {
	// e^0 == 1.0 in Q128.128.
	require.Equal(t, 0, mustCall(t, OpExp, big.NewInt(0)).Cmp(ovQ128), "e^0 must be exactly 1.0")

	// e^1 is between 2.0 and 3.0 in Q128.128 — a real value, not a wrapped one.
	e1 := mustCall(t, OpExp, ovQ128)
	require.Positive(t, e1.Cmp(new(big.Int).Mul(big.NewInt(2), ovQ128)), "e^1 > 2")
	require.Negative(t, e1.Cmp(new(big.Int).Mul(big.NewInt(3), ovQ128)), "e^1 < 3")

	// Large exponents must be refused rather than silently wrapped.
	for _, shift := range []uint{140, 200, 255} {
		_, _, err := call(OpExp, new(big.Int).Lsh(big.NewInt(1), shift))
		require.ErrorIsf(t, err, ErrOverflow, "exp(2^%d) must be refused, not truncated", shift)
	}

	// e^x must be monotonically increasing wherever it returns a value at all — a
	// wrapped result would break monotonicity, which is how the defect shows up.
	prev := big.NewInt(0)
	for x := int64(0); x <= 40; x++ {
		out, _, err := call(OpExp, new(big.Int).Mul(big.NewInt(x), ovQ128))
		if err != nil {
			require.ErrorIs(t, err, ErrOverflow)
			break
		}
		got := new(big.Int).SetBytes(out)
		require.Positivef(t, got.Cmp(prev), "e^%d must exceed e^%d; a wrap would break monotonicity", x, x-1)
		prev = got
	}
	require.Positive(t, prev.Sign(), "the monotonic sweep must have produced values")
}

// TestNoResultIsEverTruncated is the standing property: whatever the precompile
// returns as a number, re-reading it must be the value it meant. A returned word is
// 32 bytes, so any op whose true result exceeds uint256 must have errored instead.
// Deterministic seed 606060 — fixed, so a regression reproduces identically.
func TestNoResultIsEverTruncated(t *testing.T) {
	const seed = 606060
	r := rand.New(rand.NewSource(seed))

	for range 20000 {
		a := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), uint(1+r.Intn(256))))
		b := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), uint(1+r.Intn(256))))
		d := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), uint(1+r.Intn(256)))))

		for _, roundUp := range []bool{false, true} {
			op := byte(OpMulDiv)
			if roundUp {
				op = OpMulDivRoundUp
			}
			// The exact answer, computed independently of the implementation.
			want := new(big.Int).Mul(a, b)
			if roundUp {
				want.Add(want, new(big.Int).Sub(d, big.NewInt(1)))
			}
			want.Div(want, d)

			out, _, err := call(op, a, b, d)
			if want.Cmp(ovMaxU256) > 0 {
				require.ErrorIsf(t, err, ErrOverflow,
					"seed=%d op=%#x result %v exceeds uint256 and must be refused", seed, op, want)
				continue
			}
			require.NoErrorf(t, err, "seed=%d op=%#x in-range result must succeed", seed, op)
			require.Equalf(t, 0, new(big.Int).SetBytes(out).Cmp(want),
				"seed=%d op=%#x returned a different value than the exact quotient", seed, op)
		}
	}
}

// ---------------------------------------------------------------------------
// ROUNDING DIRECTION.
// ---------------------------------------------------------------------------

// TestMulDivRoundingDirections pins floor vs ceiling exhaustively over every
// remainder class, plus the defining inequality on random inputs.
func TestMulDivRoundingDirections(t *testing.T) {
	for d := int64(1); d <= 17; d++ {
		for num := int64(0); num <= 150; num++ {
			down := mustCall(t, OpMulDiv, big.NewInt(num), big.NewInt(1), big.NewInt(d))
			require.Equalf(t, num/d, down.Int64(), "MulDiv(%d,1,%d) must floor", num, d)

			up := mustCall(t, OpMulDivRoundUp, big.NewInt(num), big.NewInt(1), big.NewInt(d))
			want := num / d
			if num%d != 0 {
				want++
			}
			require.Equalf(t, want, up.Int64(), "MulDivRoundUp(%d,1,%d) must ceil", num, d)
		}
	}

	// One wei of remainder rounds up to a whole unit; an exact division does not.
	require.Equal(t, int64(1), mustCall(t, OpMulDivRoundUp, big.NewInt(1), big.NewInt(1), big.NewInt(1e6)).Int64())
	require.Equal(t, int64(5), mustCall(t, OpMulDivRoundUp, big.NewInt(10), big.NewInt(1), big.NewInt(2)).Int64())
	require.Equal(t, int64(0), mustCall(t, OpMulDivRoundUp, big.NewInt(0), big.NewInt(999), big.NewInt(7)).Int64())

	// Ceiling is never below floor and never more than one above it.
	const seed = 707070
	r := rand.New(rand.NewSource(seed))
	for range 10000 {
		a := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100))
		b := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100))
		d := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 100)))
		lo := mustCall(t, OpMulDiv, a, b, d)
		hi := mustCall(t, OpMulDivRoundUp, a, b, d)
		delta := new(big.Int).Sub(hi, lo)
		require.Truef(t, delta.Sign() >= 0 && delta.Cmp(big.NewInt(1)) <= 0,
			"seed=%d ceil-floor must be 0 or 1, got %v", seed, delta)
	}
}

// ---------------------------------------------------------------------------
// THE REMAINING OPERATIONS.
// ---------------------------------------------------------------------------

// TestSqrt asserts the defining property rather than sample outputs: for every
// input, r*r <= x < (r+1)*(r+1).
func TestSqrtFloorProperty(t *testing.T) {
	for _, x := range []int64{0, 1, 2, 3, 4, 8, 9, 15, 16, 17, 99, 100, 101, 1 << 40} {
		r := mustCall(t, OpSqrt, big.NewInt(x))
		sq := new(big.Int).Mul(r, r)
		require.LessOrEqualf(t, sq.Cmp(big.NewInt(x)), 0, "sqrt(%d)^2 must not exceed %d", x, x)
		next := new(big.Int).Add(r, big.NewInt(1))
		require.Positivef(t, new(big.Int).Mul(next, next).Cmp(big.NewInt(x)), "sqrt(%d) must be maximal", x)
	}

	const seed = 818181
	rnd := rand.New(rand.NewSource(seed))
	for range 5000 {
		x := new(big.Int).Rand(rnd, ovMaxU256)
		r := mustCall(t, OpSqrt, x)
		require.LessOrEqualf(t, new(big.Int).Mul(r, r).Cmp(x), 0, "seed=%d floor property", seed)
		next := new(big.Int).Add(r, big.NewInt(1))
		require.Positivef(t, new(big.Int).Mul(next, next).Cmp(x), "seed=%d maximality", seed)
	}

	// sqrt of the largest input must not overflow the returned word.
	require.Equal(t, 128, mustCall(t, OpSqrt, ovMaxU256).BitLen(), "sqrt(maxU256) is a 128-bit value")
}

// TestLog2 asserts floor(log2(x)) by its defining property, including the
// documented x==0 case which returns 0 rather than erroring.
func TestLog2FloorProperty(t *testing.T) {
	require.Equal(t, int64(0), mustCall(t, OpLog2, big.NewInt(0)).Int64(), "log2(0) is defined as 0 here")
	require.Equal(t, int64(0), mustCall(t, OpLog2, big.NewInt(1)).Int64())

	for shift := uint(0); shift < 256; shift++ {
		x := new(big.Int).Lsh(big.NewInt(1), shift)
		require.Equalf(t, int64(shift), mustCall(t, OpLog2, x).Int64(), "log2(2^%d)", shift)
		// One below a power of two floors to shift-1.
		if shift > 0 {
			below := new(big.Int).Sub(x, big.NewInt(1))
			require.Equalf(t, int64(shift-1), mustCall(t, OpLog2, below).Int64(), "log2(2^%d - 1)", shift)
		}
	}
}

// TestPowIsModular2Pow256 pins that Pow deliberately wraps, matching the EVM's own
// EXP opcode. This is the ONE place truncation is correct — and it is correct
// because it mirrors an opcode, not because overflow was overlooked. The contrast
// with MulDiv above is the point.
func TestPowIsModular2Pow256(t *testing.T) {
	require.Equal(t, int64(1), mustCall(t, OpPow, big.NewInt(2), big.NewInt(0)).Int64(), "b^0 == 1")
	require.Equal(t, int64(0), mustCall(t, OpPow, big.NewInt(0), big.NewInt(5)).Int64(), "0^n == 0")
	require.Equal(t, int64(1), mustCall(t, OpPow, big.NewInt(1), ovMaxU256).Int64(), "1^n == 1")
	require.Equal(t, int64(1024), mustCall(t, OpPow, big.NewInt(2), big.NewInt(10)).Int64())

	// 2^256 wraps to 0, exactly as EXP does on the EVM.
	require.Equal(t, int64(0), mustCall(t, OpPow, big.NewInt(2), big.NewInt(256)).Int64(),
		"2^256 wraps to zero, matching EVM EXP semantics")

	// Agreement with an independently computed modular exponentiation.
	const seed = 929292
	r := rand.New(rand.NewSource(seed))
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	for range 2000 {
		base := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 64))
		exp := new(big.Int).Rand(r, big.NewInt(1000))
		want := new(big.Int).Exp(base, exp, mod)
		require.Equalf(t, 0, mustCall(t, OpPow, base, exp).Cmp(want), "seed=%d pow mismatch", seed)
	}
}

// ---------------------------------------------------------------------------
// REFUSAL SURFACE AND GAS.
// ---------------------------------------------------------------------------

// TestRefusesMalformedInput walks every refusal: empty input, unknown opcode,
// division by zero, and a truncated argument list on every operation. No prefix of
// any valid call may be read past its end.
func TestRefusesMalformedInput(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		_, _, err := Precompile.Run(nil, common.Address{}, ContractAddress, nil, 1_000_000, false)
		require.ErrorIs(t, err, ErrInvalidInput)
	})

	t.Run("unknown opcode", func(t *testing.T) {
		for _, op := range []byte{0x00, 0x07, 0x42, 0xff} {
			_, _, err := Precompile.Run(nil, common.Address{}, ContractAddress,
				[]byte{op}, 1_000_000, false)
			require.ErrorIsf(t, err, ErrUnknownOp, "op %#x", op)
		}
	})

	t.Run("division by zero", func(t *testing.T) {
		for _, op := range []byte{OpMulDiv, OpMulDivRoundUp} {
			_, _, err := call(op, big.NewInt(10), big.NewInt(10), big.NewInt(0))
			require.ErrorIsf(t, err, ErrDivByZero, "op %#x must refuse a zero denominator", op)
		}
	})

	t.Run("truncated arguments", func(t *testing.T) {
		full := map[byte][]byte{
			OpMulDiv:        {OpMulDiv},
			OpMulDivRoundUp: {OpMulDivRoundUp},
			OpSqrt:          {OpSqrt},
			OpLog2:          {OpLog2},
			OpExp:           {OpExp},
			OpPow:           {OpPow},
		}
		body := make([]byte, 96)
		for i := range body {
			body[i] = 0x11
		}
		for op, prefix := range full {
			in := append(append([]byte{}, prefix...), body...)
			for cut := 1; cut < len(in); cut++ {
				require.NotPanicsf(t, func() {
					_, _, _ = Precompile.Run(nil, common.Address{}, ContractAddress, in[:cut], 1_000_000, false)
				}, "op %#x truncated to %d bytes must not panic", op, cut)
			}
			// Specifically: one byte short of the required argument length is refused.
			need := map[byte]int{OpMulDiv: 96, OpMulDivRoundUp: 96, OpSqrt: 32, OpLog2: 32, OpExp: 32, OpPow: 64}[op]
			_, _, err := Precompile.Run(nil, common.Address{}, ContractAddress, in[:need], 1_000_000, false)
			require.ErrorIsf(t, err, ErrInvalidInput, "op %#x with %d argument bytes must be refused", op, need-1)
		}
	})
}

// TestGasScalesWithInputSize proves the fee is NOT flat: it is a base plus a
// per-word charge over the argument bytes, so a larger payload costs more. A flat
// fee over unbounded input would be a DoS.
func TestGasScalesWithInputSize(t *testing.T) {
	cost := func(dataLen int) uint64 {
		words := uint64(dataLen+31) / 32
		return GasBase + words*GasWord
	}

	// Exactly the computed charge succeeds; one gas less is refused with nothing left.
	in := append([]byte{OpMulDiv}, make([]byte, 96)...)
	in[96] = 1 // non-zero denominator
	_, remaining, err := Precompile.Run(nil, common.Address{}, ContractAddress, in, cost(96), false)
	require.NoError(t, err)
	require.Zero(t, remaining, "the whole charge must be consumed")

	_, remaining, err = Precompile.Run(nil, common.Address{}, ContractAddress, in, cost(96)-1, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	// A bigger payload costs strictly more, and the increase is per 32-byte word.
	require.Greater(t, cost(96), cost(32), "gas must grow with input size")
	require.Equal(t, cost(32)+2*GasWord, cost(96), "each additional word adds GasWord")

	// A caller cannot buy a large payload at a small payload's price.
	big1024 := append([]byte{OpMulDiv}, make([]byte, 1024)...)
	big1024[96] = 1
	_, _, err = Precompile.Run(nil, common.Address{}, ContractAddress, big1024, cost(96), false)
	require.ErrorIs(t, err, contract.ErrOutOfGas, "a 1KB payload must not run at a 96-byte price")
	_, _, err = Precompile.Run(nil, common.Address{}, ContractAddress, big1024, cost(1024), false)
	require.NoError(t, err, "the correctly-priced 1KB payload succeeds")
}

// TestWorkIsBoundedPerCall records the DoS assessment for this precompile: every
// operation does work bounded by a constant regardless of input VALUE, so the
// size-proportional fee above is the whole story. exp is capped at 30 Taylor terms
// and pow at 256 modular squarings by the uint256 exponent width.
func TestWorkIsBoundedPerCall(t *testing.T) {
	// The most expensive inputs each operation admits still return promptly and
	// within their charged gas — the test completing is the boundedness proof.
	worst := []struct {
		name string
		op   byte
		args []*big.Int
	}{
		{"pow max base, max exponent", OpPow, []*big.Int{ovMaxU256, ovMaxU256}},
		{"sqrt max", OpSqrt, []*big.Int{ovMaxU256}},
		{"log2 max", OpLog2, []*big.Int{ovMaxU256}},
		{"muldiv max over one", OpMulDiv, []*big.Int{ovMaxU256, big.NewInt(1), big.NewInt(1)}},
	}
	for _, w := range worst {
		require.NotPanicsf(t, func() {
			_, _, err := call(w.op, w.args...)
			require.NoErrorf(t, err, "%s must complete", w.name)
		}, "%s must not panic", w.name)
	}
	// exp at its largest admissible input is refused by the overflow bound rather
	// than running away.
	_, _, err := call(OpExp, ovMaxU256)
	require.ErrorIs(t, err, ErrOverflow)
}

// TestPureUnderReadOnly: every operation is a pure function of calldata, so a
// static call must be byte-identical to a mutating one.
func TestPureUnderReadOnly(t *testing.T) {
	inputs := [][]*big.Int{
		{big.NewInt(123456), big.NewInt(789), big.NewInt(31)},
	}
	for _, args := range inputs {
		for _, op := range []byte{OpMulDiv, OpMulDivRoundUp} {
			in := []byte{op}
			for _, w := range args {
				in = append(in, padTo32(w.Bytes())...)
			}
			rw, gasRW, errRW := Precompile.Run(nil, common.Address{}, ContractAddress, in, 1_000_000, false)
			ro, gasRO, errRO := Precompile.Run(nil, common.Address{}, ContractAddress, in, 1_000_000, true)
			require.Equal(t, errRW, errRO, "readOnly must not change the outcome")
			require.Equal(t, rw, ro, "readOnly must not change the result")
			require.Equal(t, gasRW, gasRO, "readOnly must not change the gas")
		}
	}
}

// TestPadTo32 covers the output encoder at its boundaries.
func TestPadTo32(t *testing.T) {
	require.Equal(t, make([]byte, 32), padTo32(nil))
	require.Equal(t, append(make([]byte, 31), 0x07), padTo32([]byte{0x07}))

	exact := make([]byte, 32)
	exact[0], exact[31] = 0xde, 0xad
	require.Equal(t, exact, padTo32(exact))

	// Oversized input keeps the LOW 32 bytes. Every caller that could produce one is
	// now range-checked first, so this branch is the encoder's contract, not a path
	// any operation reaches with a real value.
	over := make([]byte, 33)
	over[0], over[32] = 0xff, 0xbe
	got := padTo32(over)
	require.Len(t, got, 32)
	require.Equal(t, byte(0xbe), got[31])
}

// ---------------------------------------------------------------------------
// MODULE / CONFIG SURFACE.
// ---------------------------------------------------------------------------

func TestModuleRegistration(t *testing.T) {
	require.Equal(t, ContractAddress, Module.Address)
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, Precompile, Module.Contract)
	require.False(t, Module.AlwaysOn, "math must be opt-in per chain, not always active")
	require.Equal(t, "0x0400000000000000000000000000000000000050", ContractAddress.Hex())
}

// TestRegisterModuleRejectsDuplicate proves the error path in init() is real: the
// module is already registered, so a second attempt must be refused. init turns
// that error into a panic — a duplicate address must abort the node rather than
// silently shadow a live precompile.
func TestRegisterModuleRejectsDuplicate(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module))
}

func TestConfigLifecycle(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.IsType(t, &Config{}, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, c.Configure(nil, cfg, nil, nil))

	mc, ok := cfg.(*Config)
	require.True(t, ok)
	require.NoError(t, mc.Verify(nil))
	require.False(t, mc.IsDisabled())
	require.Nil(t, mc.Timestamp())

	ts := uint64(4242)
	on := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, ts, *on.Timestamp())
	off := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts, Disable: true}}
	require.True(t, off.IsDisabled())
}

// TestConfigEqual: Equal must distinguish a different timestamp, a different
// disable flag, and a foreign type. An Equal that agrees too readily lets an
// upgrade silently no-op.
func TestConfigEqual(t *testing.T) {
	ts1, ts2 := uint64(1), uint64(2)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}))
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}))
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1, Disable: true}}))
	require.False(t, a.Equal(nil))
}
