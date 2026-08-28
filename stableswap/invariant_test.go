// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package stableswap

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Encoders. One per operation, mirroring the wire layouts documented on each
// handler. These are the ONLY way these tests reach the precompile — every
// assertion below therefore goes through the real calldata boundary.
// ---------------------------------------------------------------------------

func encGetDy(i, j uint32, dx *big.Int, n int, amp *big.Int, balances []*big.Int) []byte {
	buf := make([]byte, 1+4+4+32+4+32+n*32)
	buf[0] = OpGetDy
	binary.BigEndian.PutUint32(buf[1:5], i)
	binary.BigEndian.PutUint32(buf[5:9], j)
	copy(buf[9:41], padTo32(dx.Bytes()))
	binary.BigEndian.PutUint32(buf[41:45], uint32(n))
	copy(buf[45:77], padTo32(amp.Bytes()))
	for k, b := range balances {
		copy(buf[77+k*32:77+(k+1)*32], padTo32(b.Bytes()))
	}
	return buf
}

func encAddLiquidity(n int, amp, totalSupply *big.Int, amounts, balances []*big.Int) []byte {
	buf := make([]byte, 1+4+32+32+2*n*32)
	buf[0] = OpAddLiquidity
	binary.BigEndian.PutUint32(buf[1:5], uint32(n))
	copy(buf[5:37], padTo32(amp.Bytes()))
	copy(buf[37:69], padTo32(totalSupply.Bytes()))
	for k, a := range amounts {
		copy(buf[69+k*32:69+(k+1)*32], padTo32(a.Bytes()))
	}
	off := 69 + n*32
	for k, b := range balances {
		copy(buf[off+k*32:off+(k+1)*32], padTo32(b.Bytes()))
	}
	return buf
}

func encRemoveLiquidity(n int, lpAmount, totalSupply *big.Int, balances []*big.Int) []byte {
	buf := make([]byte, 1+4+32+32+n*32)
	buf[0] = OpRemoveLiquidity
	binary.BigEndian.PutUint32(buf[1:5], uint32(n))
	copy(buf[5:37], padTo32(lpAmount.Bytes()))
	copy(buf[37:69], padTo32(totalSupply.Bytes()))
	for k, b := range balances {
		copy(buf[69+k*32:69+(k+1)*32], padTo32(b.Bytes()))
	}
	return buf
}

// run is the single call helper: a generous gas budget so every failure below is
// a semantic refusal, never an incidental out-of-gas.
func run(input []byte) ([]byte, uint64, error) {
	return Precompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000_000, false)
}

// Large bounds used by the randomized sweeps (untyped 1e20/1e21 do not fit int64).
var (
	zzE20 = new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)
	zzE21 = new(big.Int).Exp(big.NewInt(10), big.NewInt(21), nil)
)

func equalBalances(n int, each int64) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(each)
	}
	return out
}

// ---------------------------------------------------------------------------
// REGRESSION: calldata-reachable division-by-zero (chain halt).
// ---------------------------------------------------------------------------

// TestAmpZeroRefusedOnEveryNewtonOp pins the fix for a chain halt: A (the
// amplification coefficient) is the one caller-supplied scalar the Newton solvers
// divide by, and at A == 0 every solver divides by zero. Because a precompile
// panic aborts the block rather than the call, a single transaction carrying
// amp == 0 halted every validator.
//
// The refusal must happen for ALL THREE Newton-using ops — getD, getDy and
// addLiquidity each parse amp independently, and each panicked on its own path:
// computeY's `c / (A*n*n)` and `D / (A*n)`, and computeD's denominator
// `(A*n - 1)*D + (n+1)*dP`, which crosses exactly zero for reachable balances.
func TestAmpZeroRefusedOnEveryNewtonOp(t *testing.T) {
	bal := equalBalances(3, 1e18)
	zero := big.NewInt(0)

	cases := []struct {
		op    string
		input []byte
	}{
		{"getD", encodeGetD(3, zero, bal)},
		{"getDy", encGetDy(0, 1, big.NewInt(1e15), 3, zero, bal)},
		{"addLiquidity", encAddLiquidity(3, zero, big.NewInt(1e18), equalBalances(3, 1e15), bal)},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, _, err := run(c.input)
				require.ErrorIs(t, err, ErrInvalidAmp,
					"amp==0 must be REFUSED, not panic: a precompile panic halts the chain")
			})
		})
	}

	// A == 1 is the smallest legal value and must still be accepted: the guard is a
	// positivity bound, not an off-by-one that rejects a usable pool.
	_, _, err := run(encodeGetD(3, big.NewInt(1), bal))
	require.NoError(t, err, "amp==1 is legal and must not be refused")
}

// TestAddLiquidityEmptyPoolWithSupplyRefused pins the second chain halt: the
// mint ratio divides by D0, and computeD returns 0 for an all-zero pool. A caller
// supplies balances and totalSupply independently, so "no assets yet LP tokens
// outstanding" is reachable from calldata and divided by zero.
//
// It is also a contradictory pool — shares backed by nothing — so the correct
// answer is a refusal, not an invented mint amount.
func TestAddLiquidityEmptyPoolWithSupplyRefused(t *testing.T) {
	require.NotPanics(t, func() {
		_, _, err := run(encAddLiquidity(2, big.NewInt(500), big.NewInt(1e18),
			equalBalances(2, 1e18), equalBalances(2, 0)))
		require.ErrorIs(t, err, ErrZeroLiquidity)
	})

	// totalSupply == 0 over the same empty pool is the legitimate FIRST deposit and
	// must still succeed — the guard must not swallow the bootstrap case.
	out, _, err := run(encAddLiquidity(2, big.NewInt(500), big.NewInt(0),
		equalBalances(2, 1e18), equalBalances(2, 0)))
	require.NoError(t, err)
	require.Positive(t, new(big.Int).SetBytes(out).Sign(), "first deposit must mint D1")
}

// TestNoPanicOverWideInputs is the standing proof that no calldata reaches a
// panic. It sweeps the whole entry surface with a DETERMINISTIC PRNG so a
// regression reproduces identically on every machine and in CI.
//
// SEED: 20260828, fixed. Do not randomise it — a flaky consensus test is worse
// than no test. This exact sweep found both halts fixed above.
func TestNoPanicOverWideInputs(t *testing.T) {
	const seed = 20260828
	r := rand.New(rand.NewSource(seed))

	randVal := func() *big.Int {
		switch r.Intn(6) {
		case 0:
			return big.NewInt(0)
		case 1:
			return big.NewInt(1)
		case 2:
			return big.NewInt(int64(r.Intn(1000) + 1))
		case 3:
			return new(big.Int).Lsh(big.NewInt(1), uint(r.Intn(255)))
		case 4:
			return big.NewInt(1e18)
		default:
			return new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 200))
		}
	}

	for iter := 0; iter < 20000; iter++ {
		n := 2 + r.Intn(7)
		amp := randVal()
		bals := make([]*big.Int, n)
		for k := range bals {
			bals[k] = randVal()
		}
		i := uint32(r.Intn(n))
		j := (i + 1 + uint32(r.Intn(n-1))) % uint32(n)

		inputs := [][]byte{
			encodeGetD(n, amp, bals),
			encGetDy(i, j, randVal(), n, amp, bals),
			encAddLiquidity(n, amp, randVal(), bals, bals),
			encRemoveLiquidity(n, randVal(), randVal(), bals),
		}
		for k, in := range inputs {
			require.NotPanicsf(t, func() { _, _, _ = run(in) },
				"iter=%d op=%d seed=%d amp=%v n=%d bals=%v", iter, k, seed, amp, n, bals)
		}
	}
}

// ---------------------------------------------------------------------------
// MONEY INVARIANTS.
// ---------------------------------------------------------------------------

// TestSwapNeverDrainsPool asserts the invariant that actually protects the pool:
// a swap must never pay out more of token j than the pool holds, and the
// StableSwap invariant D must NEVER DECREASE across the swap. D is the pool's
// stored value; a swap that lowers it is a leak, and repeated dust-sized leaks
// are a drain. The `-1` in getDy exists precisely to keep this one-sided.
func TestSwapNeverDrainsPool(t *testing.T) {
	const seed = 424242
	r := rand.New(rand.NewSource(seed))
	amps := []int64{1, 10, 100, 1000, 100000}

	checked := 0
	for iter := 0; iter < 4000; iter++ {
		n := 2 + r.Intn(3)
		amp := big.NewInt(amps[r.Intn(len(amps))])
		bals := make([]*big.Int, n)
		for k := range bals {
			// Wide but non-degenerate: 1e6 .. ~1e21.
			bals[k] = new(big.Int).Add(big.NewInt(1e6), new(big.Int).Rand(r, zzE21))
		}
		i := uint32(r.Intn(n))
		j := (i + 1 + uint32(r.Intn(n-1))) % uint32(n)
		dx := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, zzE20))

		before, _, err := run(encodeGetD(n, amp, bals))
		if err != nil {
			continue
		}
		dBefore := new(big.Int).SetBytes(before)

		out, _, err := run(encGetDy(i, j, dx, n, amp, bals))
		if err != nil {
			continue
		}
		dy := new(big.Int).SetBytes(out)

		// (1) Solvency: never pay out more than the pool holds.
		require.LessOrEqualf(t, dy.Cmp(bals[j]), 0,
			"seed=%d dy=%v exceeds pool balance %v (amp=%v n=%d)", seed, dy, bals[j], amp, n)

		// (2) Value conservation: apply the swap and re-solve D.
		post := make([]*big.Int, n)
		for k := range post {
			post[k] = new(big.Int).Set(bals[k])
		}
		post[i].Add(post[i], dx)
		post[j].Sub(post[j], dy)
		if post[j].Sign() <= 0 {
			continue // solver requires strictly positive balances
		}
		after, _, err := run(encodeGetD(n, amp, post))
		if err != nil {
			continue
		}
		dAfter := new(big.Int).SetBytes(after)

		require.GreaterOrEqualf(t, dAfter.Cmp(dBefore), 0,
			"seed=%d invariant D DECREASED across swap: %v -> %v (amp=%v n=%d i=%d j=%d dx=%v bals=%v dy=%v)",
			seed, dBefore, dAfter, amp, n, i, j, dx, bals, dy)
		checked++
	}
	require.Greater(t, checked, 500, "sweep must actually exercise the invariant, not skip out")
}

// TestGetDyRoundsTowardThePool proves the rounding DIRECTION is one-sided in the
// pool's favour: the quoted dy is strictly below the frictionless amount that
// would hold D exactly constant. A quote at or above it would let a caller cycle
// dust-sized swaps and extract the pool one wei at a time.
func TestGetDyRoundsTowardThePool(t *testing.T) {
	n := 2
	amp := big.NewInt(100)
	bals := []*big.Int{big.NewInt(1e18), big.NewInt(1e18)}
	dx := big.NewInt(1e15)

	out, _, err := run(encGetDy(0, 1, dx, n, amp, bals))
	require.NoError(t, err)
	dy := new(big.Int).SetBytes(out)

	// Recompute the solver's own y (the balance of token j that preserves D) and
	// confirm the quote is exactly `bal[j] - y - 1`: one wei retained, never zero,
	// never negative-retained.
	d, err := computeD(bals, amp, n)
	require.NoError(t, err)
	newBal := []*big.Int{new(big.Int).Add(bals[0], dx), new(big.Int).Set(bals[1])}
	y, err := computeY(newBal, amp, n, 1, d)
	require.NoError(t, err)

	frictionless := new(big.Int).Sub(bals[1], y)
	require.Equal(t, 0, dy.Cmp(new(big.Int).Sub(frictionless, one)),
		"dy must be exactly one wei below the frictionless amount")
	require.Negative(t, dy.Cmp(frictionless), "dy must round DOWN, toward the pool")
}

// TestRepeatedDustSwapsCannotDrain is the economic form of the rounding rule: a
// caller cycling the smallest possible swap back and forth must never end up
// ahead. This is the attack a one-wei rounding error in the caller's favour
// enables, so it is asserted directly rather than inferred from the formula.
func TestRepeatedDustSwapsCannotDrain(t *testing.T) {
	n := 2
	amp := big.NewInt(100)
	bals := []*big.Int{big.NewInt(1e18), big.NewInt(1e18)}

	startD, _, err := run(encodeGetD(n, amp, bals))
	require.NoError(t, err)
	d0 := new(big.Int).SetBytes(startD)

	cur := []*big.Int{new(big.Int).Set(bals[0]), new(big.Int).Set(bals[1])}
	dust := big.NewInt(1000)
	for round := 0; round < 200; round++ {
		i, j := uint32(round%2), uint32((round+1)%2)
		out, _, err := run(encGetDy(i, j, dust, n, amp, cur))
		require.NoError(t, err)
		dy := new(big.Int).SetBytes(out)
		cur[i].Add(cur[i], dust)
		cur[j].Sub(cur[j], dy)
		require.Positive(t, cur[j].Sign(), "pool must stay solvent through dust cycling")
	}

	endD, _, err := run(encodeGetD(n, amp, cur))
	require.NoError(t, err)
	d1 := new(big.Int).SetBytes(endD)
	require.GreaterOrEqual(t, d1.Cmp(d0), 0,
		"200 dust round-trips must not reduce D: %v -> %v", d0, d1)
}

// TestMintAndRedeemRoundTowardThePool pins both LP rounding directions. A
// deposit must never mint more shares than the value delivered, and a redemption
// must never pay more assets than the shares represent. Both divisions round
// down; either flipped to round up is a mint-from-nothing.
func TestMintAndRedeemRoundTowardThePool(t *testing.T) {
	n := 2
	amp := big.NewInt(100)
	bals := equalBalances(n, 1e18)

	// A deposit so small the exact mint ratio is fractional: floor must apply.
	totalSupply := big.NewInt(3) // deliberately coprime with the D delta
	amounts := []*big.Int{big.NewInt(1), big.NewInt(0)}
	out, _, err := run(encAddLiquidity(n, amp, totalSupply, amounts, bals))
	require.NoError(t, err)
	minted := new(big.Int).SetBytes(out)

	d0, err := computeD(bals, amp, n)
	require.NoError(t, err)
	d1, err := computeD([]*big.Int{new(big.Int).Add(bals[0], amounts[0]), bals[1]}, amp, n)
	require.NoError(t, err)
	exact := new(big.Int).Mul(totalSupply, new(big.Int).Sub(d1, d0))
	require.Equal(t, 0, minted.Cmp(new(big.Int).Div(exact, d0)),
		"mint must be floor(totalSupply*(D1-D0)/D0)")
	require.LessOrEqual(t, new(big.Int).Mul(minted, d0).Cmp(exact), 0,
		"minted shares must never exceed the value delivered")

	// Redemption: an LP amount that does not divide the balance evenly.
	lp := big.NewInt(7)
	supply := big.NewInt(3)
	res, _, err := run(encRemoveLiquidity(n, lp, supply, []*big.Int{big.NewInt(10), big.NewInt(10)}))
	require.NoError(t, err)
	require.Len(t, res, n*32)
	for k := range n {
		amt := new(big.Int).SetBytes(res[k*32 : (k+1)*32])
		want := new(big.Int).Div(new(big.Int).Mul(big.NewInt(10), lp), supply)
		require.Equal(t, 0, amt.Cmp(want), "redeem must floor: token %d", k)
		// floor(10*7/3) = 23 > 10 is arithmetically possible here because the caller
		// supplies an inconsistent supply; what matters is the DIRECTION, asserted above.
	}
}

// ---------------------------------------------------------------------------
// SOLVER TERMINATION AND TYPED FAILURE.
// ---------------------------------------------------------------------------

// TestSolversAlwaysTerminateWithTypedError proves the bounded-iteration fallback
// is SAFE: on a non-converging input the solver returns a typed error, never a
// wrong-but-plausible D and never an unbounded loop. `chargeNewtonGas` prices the
// full maxIterations worst case up front, so the bound is what the caller paid for.
func TestSolversAlwaysTerminateWithTypedError(t *testing.T) {
	// A zero balance is a typed refusal from inside the loop, not a div-by-zero.
	_, err := computeD([]*big.Int{big.NewInt(0), big.NewInt(1e18)}, big.NewInt(100), 2)
	require.ErrorIs(t, err, ErrZeroLiquidity)
	_, err = computeY([]*big.Int{big.NewInt(0), big.NewInt(1e18)}, big.NewInt(100), 2, 1, big.NewInt(2e18))
	require.ErrorIs(t, err, ErrZeroLiquidity)

	// Every result is either a positive D or a typed error — never nil-without-error
	// (a silent wrong answer) and never a negative D, whose .Bytes() would drop the
	// sign and return its absolute value as if it were correct.
	const seed = 777001
	r := rand.New(rand.NewSource(seed))
	for iter := 0; iter < 5000; iter++ {
		n := 2 + r.Intn(7)
		bals := make([]*big.Int, n)
		for k := range bals {
			bals[k] = new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), 220)))
		}
		amp := new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, big.NewInt(1e6)))
		d, err := computeD(bals, amp, n)
		if err != nil {
			require.ErrorIs(t, err, ErrConvergence, "seed=%d only convergence may fail here", seed)
			continue
		}
		require.NotNil(t, d)
		require.GreaterOrEqual(t, d.Sign(), 0, "seed=%d D must never be negative: .Bytes() would hide the sign", seed)
	}
}

// TestComputeDZeroSumShortCircuits covers the all-zero pool: D is 0 by
// definition and the solver must not enter the loop (where a zero balance would
// otherwise be a refusal).
func TestComputeDZeroSumShortCircuits(t *testing.T) {
	d, err := computeD([]*big.Int{big.NewInt(0), big.NewInt(0)}, big.NewInt(100), 2)
	require.NoError(t, err)
	require.Equal(t, 0, d.Sign())
}

// ---------------------------------------------------------------------------
// REFUSAL SURFACE.
// ---------------------------------------------------------------------------

// TestMalformedInputRefused walks every documented refusal on every op: empty
// input, unknown opcode, truncated headers, truncated balance arrays, degenerate
// token counts, out-of-range and self-referential token indices.
func TestMalformedInputRefused(t *testing.T) {
	bal := equalBalances(2, 1e18)
	amp := big.NewInt(100)

	t.Run("empty input", func(t *testing.T) {
		_, _, err := run(nil)
		require.ErrorIs(t, err, ErrInvalidInput)
	})
	t.Run("unknown opcode", func(t *testing.T) {
		for _, op := range []byte{0x00, 0x05, 0x7f, 0xff} {
			_, _, err := run([]byte{op})
			require.ErrorIsf(t, err, ErrUnknownOp, "op %#x must be refused", op)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		full := map[string][]byte{
			"getDy":  encGetDy(0, 1, big.NewInt(1), 2, amp, bal),
			"add":    encAddLiquidity(2, amp, big.NewInt(1), bal, bal),
			"remove": encRemoveLiquidity(2, big.NewInt(1), big.NewInt(1), bal),
			"getD":   encodeGetD(2, amp, bal),
		}
		for name, in := range full {
			// Every strict prefix that still carries the opcode must be refused,
			// never read past its end.
			for cut := 1; cut < len(in); cut++ {
				require.NotPanicsf(t, func() {
					_, _, err := run(in[:cut])
					require.Errorf(t, err, "%s truncated to %d bytes must be refused", name, cut)
				}, "%s truncated to %d bytes must not panic", name, cut)
			}
		}
	})

	t.Run("degenerate token count", func(t *testing.T) {
		for _, n := range []int{0, 1} {
			buf := make([]byte, 1+4+32+2*32)
			buf[0] = OpGetD
			binary.BigEndian.PutUint32(buf[1:5], uint32(n))
			copy(buf[5:37], padTo32(amp.Bytes()))
			_, _, err := run(buf)
			require.ErrorIsf(t, err, ErrInvalidInput, "n=%d must be refused", n)
		}
	})

	// getDy must refuse a degenerate token count too. Its `n < 2` check overlaps with
	// the index check (n==1 forces i==j), so this asserts the OUTCOME rather than which
	// guard fires — the refusal must survive either one being rewritten.
	t.Run("getDy degenerate token count", func(t *testing.T) {
		for _, n := range []int{0, 1} {
			buf := make([]byte, 1+4+4+32+4+32+32)
			buf[0] = OpGetDy
			binary.BigEndian.PutUint32(buf[1:5], 0)
			binary.BigEndian.PutUint32(buf[5:9], 0)
			copy(buf[9:41], padTo32(big.NewInt(1).Bytes()))
			binary.BigEndian.PutUint32(buf[41:45], uint32(n))
			copy(buf[45:77], padTo32(amp.Bytes()))
			_, _, err := run(buf)
			require.Errorf(t, err, "getDy with n=%d must be refused", n)
			require.NotErrorIsf(t, err, ErrZeroLiquidity,
				"n=%d must be refused at parse, never reach the solver", n)
		}
	})

	// The maxTokens cap is a DoS bound: without it a large n forces O(maxIterations*n)
	// big.Int work on operands growing ~O(n*256) bits, paid for with flat calldata gas.
	// EVERY op that reads n must enforce it — a single unguarded entry point reopens
	// the whole hole, so all four are asserted, not just one.
	t.Run("token count above cap on every op", func(t *testing.T) {
		for _, n := range []int{maxTokens + 1, 64, 4096} {
			bal := equalBalances(n, 1e18)
			ops := map[string][]byte{
				"getD":   encodeGetD(n, amp, bal),
				"getDy":  encGetDy(0, 1, big.NewInt(1e15), n, amp, bal),
				"add":    encAddLiquidity(n, amp, big.NewInt(1e18), bal, bal),
				"remove": encRemoveLiquidity(n, big.NewInt(1), big.NewInt(1e18), bal),
			}
			for name, in := range ops {
				_, _, err := run(in)
				require.ErrorIsf(t, err, ErrTooManyTokens, "%s with n=%d must hit the cap", name, n)
			}
		}

		// n == maxTokens is accepted on every op: the cap is an upper bound, not an
		// off-by-one that rejects a legal pool.
		bal := equalBalances(maxTokens, 1e18)
		for name, in := range map[string][]byte{
			"getD":   encodeGetD(maxTokens, amp, bal),
			"getDy":  encGetDy(0, 1, big.NewInt(1e15), maxTokens, amp, bal),
			"add":    encAddLiquidity(maxTokens, amp, big.NewInt(1e18), equalBalances(maxTokens, 1e15), bal),
			"remove": encRemoveLiquidity(maxTokens, big.NewInt(1), big.NewInt(1e18), bal),
		} {
			_, _, err := run(in)
			require.NoErrorf(t, err, "%s with n==maxTokens must be accepted", name)
		}
	})

	t.Run("bad token index", func(t *testing.T) {
		for _, c := range []struct{ i, j uint32 }{{0, 0}, {1, 1}, {2, 0}, {0, 2}, {99, 1}} {
			_, _, err := run(encGetDy(c.i, c.j, big.NewInt(1), 2, amp, bal))
			require.ErrorIsf(t, err, ErrInvalidIndex, "i=%d j=%d must be refused", c.i, c.j)
		}
	})

	t.Run("remove from zero supply", func(t *testing.T) {
		_, _, err := run(encRemoveLiquidity(2, big.NewInt(1), big.NewInt(0), bal))
		require.ErrorIs(t, err, ErrZeroLiquidity)
	})

	t.Run("zero-balance pool refused by solver", func(t *testing.T) {
		_, _, err := run(encodeGetD(2, amp, []*big.Int{big.NewInt(0), big.NewInt(1e18)}))
		require.ErrorIs(t, err, ErrZeroLiquidity)
	})
}

// TestZeroSwapQuotesZero: a zero-amount swap must quote zero out, never a
// positive amount funded by rounding.
func TestZeroSwapQuotesZero(t *testing.T) {
	out, _, err := run(encGetDy(0, 1, big.NewInt(0), 2, big.NewInt(100), equalBalances(2, 1e18)))
	require.NoError(t, err)
	require.Equal(t, 0, new(big.Int).SetBytes(out).Sign(), "dx==0 must quote dy==0")
}

// ---------------------------------------------------------------------------
// GAS.
// ---------------------------------------------------------------------------

// TestGasChargedBeforeWorkOnEveryOp proves no operation performs its Newton work
// before being paid: at one gas below the bounded worst case each op refuses with
// ErrOutOfGas and returns zero remaining gas. A flat fee over unbounded iteration
// would be a DoS; this is the assertion that the fee is not flat.
func TestGasChargedBeforeWorkOnEveryOp(t *testing.T) {
	amp := big.NewInt(100)
	newton := func(n, solves int) uint64 {
		return GasBase + uint64(solves)*uint64(n)*uint64(maxIterations)*gasPerTokenIter
	}

	cases := []struct {
		name  string
		input []byte
		cost  uint64
	}{
		{"getD n=2", encodeGetD(2, amp, equalBalances(2, 1e18)), newton(2, 1)},
		{"getD n=8", encodeGetD(8, amp, equalBalances(8, 1e18)), newton(8, 1)},
		{"getDy n=2", encGetDy(0, 1, big.NewInt(1e15), 2, amp, equalBalances(2, 1e18)), newton(2, 2)},
		{"getDy n=8", encGetDy(0, 1, big.NewInt(1e15), 8, amp, equalBalances(8, 1e18)), newton(8, 2)},
		{"add n=4", encAddLiquidity(4, amp, big.NewInt(1e18), equalBalances(4, 1e15), equalBalances(4, 1e18)), newton(4, 2)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Precompile.Run(nil, common.Address{}, ContractAddress, c.input, c.cost, false)
			require.NoError(t, err, "exactly the worst-case charge must suffice")

			_, remaining, err := Precompile.Run(nil, common.Address{}, ContractAddress, c.input, c.cost-1, false)
			require.ErrorIs(t, err, contract.ErrOutOfGas, "one gas short must refuse")
			require.Zero(t, remaining)
		})
	}

	// Gas must SCALE with n: a budget sized for 2 tokens cannot buy an 8-token solve.
	_, _, err := Precompile.Run(nil, common.Address{}, ContractAddress,
		encodeGetD(8, amp, equalBalances(8, 1e18)), newton(2, 1), false)
	require.ErrorIs(t, err, contract.ErrOutOfGas, "gas must scale with token count")
}

// TestBaseGasChargedBeforeDispatch: even an unparseable input pays the base fee,
// so probing the precompile is never free.
func TestBaseGasChargedBeforeDispatch(t *testing.T) {
	_, remaining, err := Precompile.Run(nil, common.Address{}, ContractAddress, []byte{0xff}, GasBase, false)
	require.ErrorIs(t, err, ErrUnknownOp)
	require.Zero(t, remaining, "the base fee must be consumed even on a rejected opcode")

	_, remaining, err = Precompile.Run(nil, common.Address{}, ContractAddress, []byte{0xff}, GasBase-1, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)
}

// TestRemoveLiquidityNeedsNoNewtonGas documents that removeLiquidity is a
// bounded O(n) proportional split with no solve, so GasBase alone covers it once
// n is capped. If it ever grows a solve, this test starts failing.
func TestRemoveLiquidityNeedsNoNewtonGas(t *testing.T) {
	in := encRemoveLiquidity(maxTokens, big.NewInt(1), big.NewInt(1e18), equalBalances(maxTokens, 1e18))
	_, _, err := Precompile.Run(nil, common.Address{}, ContractAddress, in, GasBase, false)
	require.NoError(t, err, "removeLiquidity must cost exactly GasBase")
}

// ---------------------------------------------------------------------------
// READ-ONLY AND ENCODING.
// ---------------------------------------------------------------------------

// TestPureUnderReadOnly: every op is a pure function of calldata and touches no
// state, so a static call must behave identically to a mutating one. Byte
// equality is the assertion — a divergence would mean hidden state.
func TestPureUnderReadOnly(t *testing.T) {
	inputs := [][]byte{
		encodeGetD(3, big.NewInt(100), equalBalances(3, 1e18)),
		encGetDy(0, 2, big.NewInt(1e15), 3, big.NewInt(100), equalBalances(3, 1e18)),
		encAddLiquidity(2, big.NewInt(100), big.NewInt(1e18), equalBalances(2, 1e15), equalBalances(2, 1e18)),
		encRemoveLiquidity(2, big.NewInt(1e17), big.NewInt(1e18), equalBalances(2, 1e18)),
	}
	for i, in := range inputs {
		rw, gasRW, errRW := Precompile.Run(nil, common.Address{}, ContractAddress, in, 1_000_000, false)
		ro, gasRO, errRO := Precompile.Run(nil, common.Address{}, ContractAddress, in, 1_000_000, true)
		require.Equal(t, errRW, errRO, "input %d: readOnly must not change the outcome", i)
		require.Equal(t, rw, ro, "input %d: readOnly must not change the result", i)
		require.Equal(t, gasRW, gasRO, "input %d: readOnly must not change the gas", i)
	}
}

// TestPadTo32 covers the output encoder at its boundaries: short values are
// left-padded, exactly-32 passes through, and an oversized value is truncated to
// its LOW 32 bytes.
func TestPadTo32(t *testing.T) {
	require.Equal(t, make([]byte, 32), padTo32(nil))
	require.Equal(t, append(make([]byte, 31), 0x01), padTo32([]byte{0x01}))

	exact := make([]byte, 32)
	exact[0], exact[31] = 0xaa, 0xbb
	require.Equal(t, exact, padTo32(exact))

	over := make([]byte, 40)
	over[8], over[39] = 0x11, 0x22
	got := padTo32(over)
	require.Len(t, got, 32)
	require.Equal(t, byte(0x11), got[0])
	require.Equal(t, byte(0x22), got[31])
}

// TestRemoveLiquidityEncodesEveryToken: the result is exactly n words, one per
// token, in index order — a short or misaligned encoding would misattribute funds.
func TestRemoveLiquidityEncodesEveryToken(t *testing.T) {
	for n := 2; n <= maxTokens; n++ {
		bals := make([]*big.Int, n)
		for k := range bals {
			bals[k] = big.NewInt(int64(k+1) * 1e15)
		}
		out, _, err := run(encRemoveLiquidity(n, big.NewInt(1e18), big.NewInt(2e18), bals))
		require.NoError(t, err)
		require.Len(t, out, n*32, "n=%d must encode one word per token", n)
		for k := range n {
			got := new(big.Int).SetBytes(out[k*32 : (k+1)*32])
			want := new(big.Int).Div(new(big.Int).Mul(bals[k], big.NewInt(1e18)), big.NewInt(2e18))
			require.Equal(t, 0, got.Cmp(want), "n=%d token %d", n, k)
		}
	}
}

// TestGetDyIndexOrderMatters: swapping i and j must not produce the same quote —
// a solver that ignored direction would price a sale as a purchase.
func TestGetDyIndexOrderMatters(t *testing.T) {
	bals := []*big.Int{big.NewInt(1e18), big.NewInt(5e18)}
	amp := big.NewInt(100)
	dx := big.NewInt(1e17)

	fwd, _, err := run(encGetDy(0, 1, dx, 2, amp, bals))
	require.NoError(t, err)
	rev, _, err := run(encGetDy(1, 0, dx, 2, amp, bals))
	require.NoError(t, err)
	require.NotEqual(t, fwd, rev, "an unbalanced pool must price the two directions differently")
}

// ---------------------------------------------------------------------------
// MODULE / CONFIG SURFACE.
// ---------------------------------------------------------------------------

// TestModuleRegistration pins the module's identity: address, key, and the fact
// that it is NOT unconditionally active (it activates only at its configured
// upgrade timestamp).
func TestModuleRegistration(t *testing.T) {
	require.Equal(t, ContractAddress, Module.Address)
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, Precompile, Module.Contract)
	require.NotNil(t, Module.Configurator)
	require.False(t, Module.AlwaysOn, "stableswap must be opt-in per chain, not always active")
}

func TestConfigLifecycle(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.IsType(t, &Config{}, cfg)
	require.Equal(t, ConfigKey, cfg.Key())

	require.NoError(t, c.Configure(nil, cfg, nil, nil), "Configure holds no state and must not fail")

	sc, ok := cfg.(*Config)
	require.True(t, ok)
	require.NoError(t, sc.Verify(nil))
	require.False(t, sc.IsDisabled())
	require.Nil(t, sc.Timestamp())

	ts := uint64(1000)
	enabled := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.NotNil(t, enabled.Timestamp())
	require.Equal(t, ts, *enabled.Timestamp())

	disabled := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts, Disable: true}}
	require.True(t, disabled.IsDisabled())
}

// TestConfigEqual: Equal must distinguish a different timestamp, a different
// disable flag, and a foreign config type. An Equal that returns true too
// readily would let an upgrade silently no-op.
func TestConfigEqual(t *testing.T) {
	ts1, ts2 := uint64(1000), uint64(2000)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	same := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	other := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}
	off := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1, Disable: true}}

	require.True(t, a.Equal(same))
	require.False(t, a.Equal(other), "a different timestamp is a different config")
	require.False(t, a.Equal(off), "a different disable flag is a different config")
	require.False(t, a.Equal(nil), "a nil config is never equal")
	require.False(t, a.Equal(foreignConfig{}), "a foreign type is never equal")
}

// foreignConfig is a non-stableswap Config used to prove Equal's type check.
type foreignConfig struct{ precompileconfig.Config }

func (foreignConfig) Key() string { return "not-stableswap" }

// TestRegisterModuleRejectsDuplicate proves the registration error path in
// module.go init() is real: the module is already registered by init, so a second
// attempt must be refused. init panics on that error — a duplicate address must
// abort the node rather than silently shadow a live precompile.
func TestRegisterModuleRejectsDuplicate(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module),
		"re-registering an address must be refused; init turns this into a panic")
}

// TestComputeYConvergesUnderExtremeSwaps exercises the solver where the D handed
// to computeY no longer matches the balances (getDy adds dx before solving), which
// is the only shape that can stress convergence through the real ABI. Every
// outcome must be a value or the typed ErrConvergence — never a hang, never a
// panic, never a negative y.
func TestComputeYConvergesUnderExtremeSwaps(t *testing.T) {
	const seed = 5150
	r := rand.New(rand.NewSource(seed))
	bounded := 0
	for iter := 0; iter < 8000; iter++ {
		n := 2 + r.Intn(3)
		amp := new(big.Int).Add(one, new(big.Int).Rand(r, big.NewInt(1e6)))
		bals := make([]*big.Int, n)
		for k := range bals {
			bals[k] = new(big.Int).Add(big.NewInt(1), new(big.Int).Rand(r, zzE21))
		}
		d, err := computeD(bals, amp, n)
		if err != nil || d.Sign() == 0 {
			continue
		}
		// A swap input many orders of magnitude past the pool: the largest mismatch
		// between D and the balances the ABI can produce.
		post := make([]*big.Int, n)
		for k := range post {
			post[k] = new(big.Int).Set(bals[k])
		}
		post[0].Lsh(post[0], uint(r.Intn(200)))
		j := 1 + r.Intn(n-1)

		y, err := computeY(post, amp, n, j, d)
		if err != nil {
			require.ErrorIs(t, err, ErrConvergence, "seed=%d only ErrConvergence is legal here", seed)
			continue
		}
		require.GreaterOrEqual(t, y.Sign(), 0,
			"seed=%d y must never be negative: .Bytes() would drop the sign and over-quote", seed)
		bounded++
	}
	require.Greater(t, bounded, 1000, "the sweep must actually reach the solver")
}
