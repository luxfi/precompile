// dex_swap_test exercises the StableSwap AMM precompile:
//
//  1. Compute pool invariant D from balances
//  2. Compute swap output (GetDy)
//  3. Verify invariant preservation (D stays constant through swap)
//  4. Test edge cases (zero swap, unbalanced pool)
//
// The calldata layout lives in encodeGetD/encodeGetDy and nowhere else. It used
// to be spelled out at each call site, which is how every one of them drifted
// from the precompile: they wrote a one-byte token count and put the
// amplification factor last, while stableswap reads a four-byte count and takes
// the amplification before the balances. The suite could not notice, because
// e2e/go.mod required a published github.com/luxfi/precompile rather than the
// module in this repo, so these tests ran against v0.5.27 and never saw the
// working tree.
//
// Precompiles exercised: StableSwap.
package scenarios

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/luxfi/precompile/e2e/harness"
	"github.com/luxfi/precompile/stableswap"
	"github.com/stretchr/testify/require"
)

// word left-pads v to a 32-byte EVM word.
func word(v uint64) []byte {
	return harness.PadLeft(new(big.Int).SetUint64(v).Bytes(), 32)
}

// u32 encodes v as a 4-byte big-endian count.
func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// encodeGetD builds calldata for OpGetD:
//
//	op(1) || n:uint32(4) || amp(32) || balances(n*32)
func encodeGetD(amp uint64, balances ...uint64) []byte {
	input := []byte{stableswap.OpGetD}
	input = append(input, u32(uint32(len(balances)))...)
	input = append(input, word(amp)...)
	for _, b := range balances {
		input = append(input, word(b)...)
	}
	return input
}

// encodeGetDy builds calldata for OpGetDy:
//
//	op(1) || i:uint32(4) || j:uint32(4) || dx(32) || n:uint32(4) || amp(32) || balances(n*32)
func encodeGetDy(i, j uint32, dx, amp uint64, balances ...uint64) []byte {
	input := []byte{stableswap.OpGetDy}
	input = append(input, u32(i)...)
	input = append(input, u32(j)...)
	input = append(input, word(dx)...)
	input = append(input, u32(uint32(len(balances)))...)
	input = append(input, word(amp)...)
	for _, b := range balances {
		input = append(input, word(b)...)
	}
	return input
}

func TestDEXSwap_StableSwapGetD(t *testing.T) {
	// Balanced 2-token pool, 1,000,000 units each, amplification A=100.
	out, gas, err := harness.Call(
		stableswap.Precompile,
		stableswap.ContractAddress,
		encodeGetD(100, 1_000_000, 1_000_000),
		true,
	)
	require.NoError(t, err, "GetD failed")
	require.Len(t, out, 32, "D should be 32 bytes")

	d := new(big.Int).SetBytes(out)
	require.True(t, d.Sign() > 0, "D must be positive")
	harness.GasReport(t, "StableSwap GetD", gas)

	// For a balanced pool holding 1M of each token the invariant is the total,
	// 2M, independent of the amplification factor.
	expectedD := new(big.Int).SetUint64(2_000_000)
	diff := new(big.Int).Sub(d, expectedD)
	diff.Abs(diff)
	tolerance := new(big.Int).Div(expectedD, big.NewInt(100)) // 1% for Newton rounding
	require.True(t, diff.Cmp(tolerance) <= 0,
		"D=%s should be close to 2M (diff=%s)", d.String(), diff.String())
	t.Logf("Pool invariant D = %s", d.String())
}

func TestDEXSwap_StableSwapGetDy(t *testing.T) {
	out, gas, err := harness.Call(
		stableswap.Precompile,
		stableswap.ContractAddress,
		encodeGetDy(0, 1, 1000, 100, 1_000_000, 1_000_000),
		true,
	)
	require.NoError(t, err, "GetDy failed")
	require.Len(t, out, 32, "dy should be 32 bytes")

	dy := new(big.Int).SetBytes(out)
	require.True(t, dy.Sign() > 0, "dy must be positive")
	harness.GasReport(t, "StableSwap GetDy", gas)

	// A balanced pool at A=100 trades very close to 1:1, and never above it —
	// the pool must not pay out more than it took in.
	t.Logf("Swap 1000 token0 -> %s token1", dy.String())
	require.True(t, dy.Uint64() >= 990 && dy.Uint64() <= 1000,
		"dy=%d should be ~999 for balanced pool with A=100", dy.Uint64())
}

func TestDEXSwap_InvariantPreservation(t *testing.T) {
	const (
		balA    = uint64(1_000_000)
		balB    = uint64(1_000_000)
		swapAmt = uint64(10_000)
		ampVal  = uint64(100)
	)

	dBefore := computeD(t, balA, balB, ampVal)
	dy := computeDy(t, 0, 1, swapAmt, balA, balB, ampVal)

	// Post-swap balances: the pool gains dx of token 0 and pays out dy of token 1.
	dAfter := computeD(t, balA+swapAmt, balB-dy, ampVal)

	diff := new(big.Int).Sub(dBefore, dAfter)
	diff.Abs(diff)
	require.True(t, diff.Cmp(big.NewInt(1)) <= 0,
		"D before (%s) != D after (%s), diff=%s", dBefore.String(), dAfter.String(), diff.String())

	// The invariant may only ever grow: a swap that decreased D would mean the
	// pool paid out more than the curve allows, which is how a stableswap gets
	// drained one trade at a time.
	require.True(t, dAfter.Cmp(dBefore) >= 0,
		"D decreased across a swap: before=%s after=%s", dBefore, dAfter)

	t.Logf("D_before=%s, D_after=%s (invariant preserved)", dBefore.String(), dAfter.String())
}

func TestDEXSwap_UnbalancedPool(t *testing.T) {
	// A 10:1 pool. Selling the scarce side into the deep side still pays out,
	// but the curve must charge for the imbalance rather than trading 1:1.
	const (
		balA    = uint64(10_000_000)
		balB    = uint64(1_000_000)
		swapAmt = uint64(1000)
		ampVal  = uint64(100)
	)

	dy := computeDy(t, 0, 1, swapAmt, balA, balB, ampVal)
	t.Logf("Unbalanced pool (10:1): swap 1000 token0 -> %d token1", dy)
	require.True(t, dy > 0, "dy must be positive even in unbalanced pool")

	// Pushing the pool further from balance must not be more profitable than
	// trading against a balanced one.
	balanced := computeDy(t, 0, 1, swapAmt, balA, balA, ampVal)
	require.LessOrEqual(t, dy, balanced,
		"selling into the shallow side paid %d, better than the balanced %d", dy, balanced)
}

// The precompile refuses input the balances do not back, rather than reading
// past them.
func TestDEXSwap_RefusesTruncatedBalances(t *testing.T) {
	full := encodeGetD(100, 1_000_000, 1_000_000)

	// Same header, one balance word short of what n promises.
	truncated := full[:len(full)-32]
	_, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress, truncated, true)
	require.Error(t, err, "a token count larger than the balances supplied was accepted")

	// And an empty body behind a well-formed opcode.
	_, _, err = harness.Call(stableswap.Precompile, stableswap.ContractAddress,
		[]byte{stableswap.OpGetD}, true)
	require.Error(t, err)
}

// A swap must name two distinct, in-range tokens.
func TestDEXSwap_RefusesBadIndices(t *testing.T) {
	for _, tc := range []struct {
		name string
		i, j uint32
	}{
		{"same token", 0, 0},
		{"i out of range", 2, 1},
		{"j out of range", 0, 2},
		{"both out of range", 7, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress,
				encodeGetDy(tc.i, tc.j, 1000, 100, 1_000_000, 1_000_000), true)
			require.Error(t, err)
		})
	}
}

// A zero or absent amplification factor is refused: A=0 collapses the curve.
func TestDEXSwap_RefusesZeroAmplification(t *testing.T) {
	_, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress,
		encodeGetD(0, 1_000_000, 1_000_000), true)
	require.Error(t, err, "amplification of zero was accepted")
}

// Helper functions

func computeD(t *testing.T, balA, balB, amp uint64) *big.Int {
	t.Helper()
	out, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress,
		encodeGetD(amp, balA, balB), true)
	require.NoError(t, err)
	return new(big.Int).SetBytes(out)
}

func computeDy(t *testing.T, i, j uint32, dx, balA, balB, amp uint64) uint64 {
	t.Helper()
	out, _, err := harness.Call(stableswap.Precompile, stableswap.ContractAddress,
		encodeGetDy(i, j, dx, amp, balA, balB), true)
	require.NoError(t, err)
	return new(big.Int).SetBytes(out).Uint64()
}
