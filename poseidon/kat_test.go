// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package poseidon

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// fieldModulus is r, the BN254 scalar field order and the domain of every
// element this precompile accepts.
func fieldModulus() *big.Int { return fr.Modulus() }

func elem(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

func small(n int64) []byte { return elem(big.NewInt(n)) }

func run(tb testing.TB, op byte, data ...[]byte) ([]byte, uint64, error) {
	tb.Helper()
	in := []byte{op}
	for _, d := range data {
		in = append(in, d...)
	}
	return PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, in, 1<<24, true)
}

func spongeInput(outLen uint32, elems ...[]byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, outLen)
	for _, e := range elems {
		hdr = append(hdr, e...)
	}
	return hdr
}

// TestNonCanonicalElementRejected is the regression for the defect this file
// was written around.
//
// Inputs used to go through fr.Element.SetBytes, which reduces modulo r. Two
// distinct 32-byte words -- x and x+r -- therefore hashed to the same digest,
// so a second preimage for any leaf was a single addition away. That is fatal
// for the Merkle trees and nullifier sets this hash exists to serve, where the
// leaf is a bytes32 the attacker chooses.
func TestNonCanonicalElementRejected(t *testing.T) {
	r := fieldModulus()

	for _, tc := range []struct {
		name string
		v    *big.Int
	}{
		{"r", r},
		{"r+1", new(big.Int).Add(r, big.NewInt(1))},
		{"r+7", new(big.Int).Add(r, big.NewInt(7))},
		{"2^256-1", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := elem(tc.v)
			require.Len(t, bad, 32)

			for _, c := range []struct {
				name string
				op   byte
				data [][]byte
			}{
				{"hash single", OpHash, [][]byte{bad}},
				{"hash first of two", OpHash, [][]byte{bad, small(1)}},
				{"hash second of two", OpHash, [][]byte{small(1), bad}},
				{"hashPair left", OpHashPair, [][]byte{bad, small(1)}},
				{"hashPair right", OpHashPair, [][]byte{small(1), bad}},
				{"sponge", OpSponge, [][]byte{spongeInput(32, bad)}},
				{"sponge second", OpSponge, [][]byte{spongeInput(32, small(1), bad)}},
			} {
				out, _, err := run(t, c.op, c.data...)
				require.ErrorIs(t, err, ErrInvalidInput,
					"%s must refuse a non-canonical element, not reduce it", c.name)
				require.Nil(t, out)
			}
		})
	}

	// The reduced value of each rejected word is still a perfectly good input,
	// so the refusals above come from canonicality and not from a broken shape.
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(r, big.NewInt(1))} {
		out, _, err := run(t, OpHash, elem(v))
		require.NoError(t, err)
		require.Len(t, out, 32)
	}
}

// TestDistinctInputsGiveDistinctDigests is the collision check over the whole
// accepted domain, including its two endpoints. Every one of these words used
// to have r-1 aliases; now each names itself.
func TestDistinctInputsGiveDistinctDigests(t *testing.T) {
	r := fieldModulus()
	inputs := [][]byte{
		elem(big.NewInt(0)),
		elem(big.NewInt(1)),
		elem(big.NewInt(2)),
		elem(new(big.Int).Rsh(r, 1)),
		elem(new(big.Int).Sub(r, big.NewInt(2))),
		elem(new(big.Int).Sub(r, big.NewInt(1))),
	}

	seen := map[string][]byte{}
	for _, in := range inputs {
		out, _, err := run(t, OpHash, in)
		require.NoError(t, err)
		prev, dup := seen[string(out)]
		require.False(t, dup, "collision: %x and %x share a digest", prev, in)
		seen[string(out)] = in
	}
	require.Len(t, seen, len(inputs))
}

// TestHashIsOrderSensitive: a Merkle hash that ignored argument order would let
// anyone swap siblings and keep the root.
func TestHashIsOrderSensitive(t *testing.T) {
	a, b := small(1), small(2)

	ab, _, err := run(t, OpHash, a, b)
	require.NoError(t, err)
	ba, _, err := run(t, OpHash, b, a)
	require.NoError(t, err)
	require.NotEqual(t, ab, ba, "Hash(a,b) must differ from Hash(b,a)")

	pab, _, err := run(t, OpHashPair, a, b)
	require.NoError(t, err)
	pba, _, err := run(t, OpHashPair, b, a)
	require.NoError(t, err)
	require.NotEqual(t, pab, pba)

	// HashPair is the two-element case of Hash: one function, two entry points.
	require.Equal(t, ab, pab, "HashPair(a,b) must equal Hash(a,b)")
	require.Equal(t, ba, pba)
}

// TestHashLengthIsBound: appending an element must change the digest, so a
// shorter input cannot be extended into a longer one with the same answer.
func TestHashIsLengthBound(t *testing.T) {
	seen := map[string]int{}
	var elems [][]byte
	for n := 1; n <= 16; n++ {
		elems = append(elems, small(int64(n)))
		out, _, err := run(t, OpHash, elems...)
		require.NoError(t, err)
		prev, dup := seen[string(out)]
		require.False(t, dup, "width %d collides with width %d", n, prev)
		seen[string(out)] = n
	}
	require.Len(t, seen, 16)
}

// TestAvalanche: flipping the low bit of one element must change essentially
// the whole digest. A hash that leaked its input structure would fail this.
func TestAvalanche(t *testing.T) {
	base, _, err := run(t, OpHash, small(0))
	require.NoError(t, err)
	next, _, err := run(t, OpHash, small(1))
	require.NoError(t, err)

	differing := 0
	for i := range base {
		if base[i] != next[i] {
			differing++
		}
	}
	require.Greater(t, differing, 24, "a one-bit input change must disturb the whole digest")
}

// TestSpongeMatchesAnIndependentlyDrivenPermutation reconstructs the sponge in
// the test from the raw permutation and requires the same bytes. It cannot
// catch a wrong permutation -- both sides use the same one -- but it does catch
// every wiring error the sponge can have: absorb order, a missing or extra
// permutation, squeezing the wrong lane, or zero-padding instead of squeezing.
func TestSpongeMatchesAnIndependentlyDrivenPermutation(t *testing.T) {
	for _, tc := range []struct {
		outLen uint32
		elems  []int64
	}{
		{32, nil},
		{32, []int64{7}},
		{64, []int64{7}},
		{96, []int64{1, 2, 3}},
		{MaxSpongeOutput, nil},
		{MaxSpongeOutput, []int64{9, 9, 9, 9}},
		{1, []int64{5}},
		{31, []int64{5}},
		{33, []int64{5}},
	} {
		var in [][]byte
		for _, v := range tc.elems {
			in = append(in, small(v))
		}
		got, _, err := run(t, OpSponge, spongeInput(tc.outLen, in...))
		require.NoError(t, err)
		require.Len(t, got, int(tc.outLen))

		// Rebuild it here.
		perm := poseidon2.NewPermutation(3, 6, 50)
		state := make([]fr.Element, 3)
		for _, v := range tc.elems {
			var e fr.Element
			e.SetInt64(v)
			state[0].Add(&state[0], &e)
			perm.Permutation(state)
		}
		want := make([]byte, 0, tc.outLen)
		for uint32(len(want)) < tc.outLen {
			b := state[0].Bytes()
			want = append(want, b[:]...)
			if uint32(len(want)) < tc.outLen {
				perm.Permutation(state)
			}
		}
		require.Equal(t, want[:tc.outLen], got,
			"outLen=%d elems=%v", tc.outLen, tc.elems)
	}
}

// TestSpongeSqueezesRatherThanPads: every 32-byte word of a long output must be
// distinct, which is only true if the permutation runs between squeezes.
func TestSpongeSqueezesRatherThanPads(t *testing.T) {
	out, _, err := run(t, OpSponge, spongeInput(MaxSpongeOutput, small(42)))
	require.NoError(t, err)
	require.Len(t, out, MaxSpongeOutput)

	seen := map[string]int{}
	for i := 0; i+32 <= len(out); i += 32 {
		w := string(out[i : i+32])
		require.False(t, bytes.Equal(out[i:i+32], make([]byte, 32)), "word %d is zero padding", i/32)
		prev, dup := seen[w]
		require.False(t, dup, "word %d repeats word %d: the permutation did not run", i/32, prev)
		seen[w] = i / 32
	}
	require.Len(t, seen, MaxSpongeOutput/32)

	// A shorter request is a prefix of a longer one: the same sponge, truncated.
	short, _, err := run(t, OpSponge, spongeInput(64, small(42)))
	require.NoError(t, err)
	require.Equal(t, out[:64], short)
}

// TestSpongeGasScalesWithOutput is the regression for the pricing defect: the
// squeeze permutes once per output word, but the schedule only counted input
// words, so a five-byte call bought 31 permutations for the flat base fee.
func TestSpongeGasScalesWithOutput(t *testing.T) {
	base := PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(32)...))
	require.Equal(t, uint64(GasSpongeBase+GasSpongePerIn), base,
		"one squeezed word costs one per-word unit")

	// Requesting the maximum with no input must cost far more than the base fee.
	maxOut := PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(MaxSpongeOutput)...))
	require.Equal(t, uint64(GasSpongeBase+32*GasSpongePerIn), maxOut)
	require.Greater(t, maxOut, base, "a longer squeeze must cost more")

	// Price rises by exactly one unit per output word.
	prev := uint64(0)
	for words := uint32(1); words <= 32; words++ {
		got := PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(words*32)...))
		require.Equal(t, uint64(GasSpongeBase)+uint64(words)*GasSpongePerIn, got, "words=%d", words)
		if words > 1 {
			require.Equal(t, uint64(GasSpongePerIn), got-prev)
		}
		prev = got
	}

	// A partial word still costs a whole word: the squeeze permutes either way.
	require.Equal(t,
		PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(32)...)),
		PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(1)...)))
	require.Equal(t,
		PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(64)...)),
		PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(33)...)))

	// Input and output are priced the same, because they do the same work.
	in1 := PoseidonPrecompile.RequiredGas(append([]byte{OpSponge}, spongeInput(32, small(1))...))
	require.Equal(t, uint64(GasSpongeBase+2*GasSpongePerIn), in1)

	// And the price is actually charged: the old flat fee no longer buys a
	// maximum-length squeeze.
	_, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress,
		append([]byte{OpSponge}, spongeInput(MaxSpongeOutput)...), uint64(GasSpongeBase+GasSpongePerIn), true)
	require.ErrorIs(t, err, contract.ErrOutOfGas,
		"a full squeeze must not be affordable at the one-word price")
}

// TestRefusal_Shape walks every length and selector refusal.
func TestRefusal_Shape(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		err  error
	}{
		{"nil", nil, ErrInvalidInput},
		{"empty", []byte{}, ErrInvalidInput},
		{"hash op only", []byte{OpHash}, ErrInvalidInput},
		{"hash one byte", []byte{OpHash, 0x01}, ErrInvalidInput},
		{"hash 31 bytes", append([]byte{OpHash}, make([]byte, 31)...), ErrInvalidInput},
		{"hash 33 bytes", append([]byte{OpHash}, make([]byte, 33)...), ErrInvalidInput},
		{"hash 17 elements", append([]byte{OpHash}, make([]byte, 17*32)...), ErrTooManyInputs},
		{"hash 32 elements", append([]byte{OpHash}, make([]byte, 32*32)...), ErrTooManyInputs},
		{"hashPair op only", []byte{OpHashPair}, ErrInvalidInput},
		{"hashPair one element", append([]byte{OpHashPair}, make([]byte, 32)...), ErrInvalidInput},
		{"hashPair 63 bytes", append([]byte{OpHashPair}, make([]byte, 63)...), ErrInvalidInput},
		{"sponge op only", []byte{OpSponge}, ErrInvalidInput},
		{"sponge 3-byte header", []byte{OpSponge, 0, 0, 0}, ErrInvalidInput},
		{"sponge outLen 0", append([]byte{OpSponge}, spongeInput(0)...), ErrInvalidInput},
		{"sponge outLen over max", append([]byte{OpSponge}, spongeInput(MaxSpongeOutput+1)...), ErrInvalidInput},
		{"sponge misaligned payload", append([]byte{OpSponge}, append(spongeInput(32), 0x01)...), ErrInvalidInput},
		{"sponge 17 elements", append([]byte{OpSponge}, spongeInput(32, make([]byte, 17*32))...), ErrTooManyInputs},
		{"unknown op 0x00", []byte{0x00}, ErrInvalidOp},
		{"unknown op 0x04", []byte{0x04}, ErrInvalidOp},
		{"unknown op 0xff", []byte{0xFF}, ErrInvalidOp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, tc.in, 1<<24, true)
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, out)
		})
	}

	// The boundaries either side of each refusal must work.
	out, _, err := run(t, OpHash, make([]byte, 16*32))
	require.NoError(t, err, "16 elements is the maximum width")
	require.Len(t, out, 32)

	out, _, err = run(t, OpSponge, spongeInput(MaxSpongeOutput))
	require.NoError(t, err, "the maximum squeeze is allowed")
	require.Len(t, out, MaxSpongeOutput)

	out, _, err = run(t, OpSponge, spongeInput(1))
	require.NoError(t, err, "a one-byte squeeze is allowed")
	require.Len(t, out, 1)

	// HashPair ignores trailing data past its two elements.
	a, b := small(1), small(2)
	pair, _, err := run(t, OpHashPair, a, b)
	require.NoError(t, err)
	padded, _, err := run(t, OpHashPair, a, b, []byte{0xAA})
	require.NoError(t, err)
	require.Equal(t, pair, padded)
}

// TestGas_Schedule covers every arm, and proves nothing is bought for free.
func TestGas_Schedule(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want uint64
	}{
		{"nil", nil, 0},
		{"empty", []byte{}, 0},
		{"hash op only", []byte{OpHash}, 0},
		{"hash sub-element", append([]byte{OpHash}, make([]byte, 31)...), 0},
		{"hash 1", append([]byte{OpHash}, make([]byte, 32)...), GasHashBase + GasPerElement},
		{"hash 4", append([]byte{OpHash}, make([]byte, 4*32)...), GasHashBase + 4*GasPerElement},
		{"hash 16", append([]byte{OpHash}, make([]byte, 16*32)...), GasHashBase + 16*GasPerElement},
		{"hashPair", []byte{OpHashPair}, GasHashPair},
		{"hashPair with data", append([]byte{OpHashPair}, make([]byte, 64)...), GasHashPair},
		{"sponge short header", []byte{OpSponge, 0, 0, 0}, 0},
		{"sponge outLen 0", append([]byte{OpSponge}, spongeInput(0)...), 0},
		{"sponge over max", append([]byte{OpSponge}, spongeInput(MaxSpongeOutput+1)...), 0},
		{"unknown 0x00", []byte{0x00}, 0},
		{"unknown 0x04", []byte{0x04}, 0},
		{"unknown 0xff", []byte{0xFF}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PoseidonPrecompile.RequiredGas(tc.in))
		})
	}

	// Hash is priced per element and rises monotonically.
	prev := uint64(0)
	for n := 1; n <= 16; n++ {
		got := PoseidonPrecompile.RequiredGas(append([]byte{OpHash}, make([]byte, n*32)...))
		require.Equal(t, uint64(GasHashBase+n*GasPerElement), got, "n=%d", n)
		if n > 1 {
			require.Equal(t, uint64(GasPerElement), got-prev)
		}
		prev = got
	}

	// Every zero-priced input must refuse.
	for _, in := range [][]byte{
		nil, {}, {OpHash}, append([]byte{OpHash}, make([]byte, 31)...),
		{OpSponge, 0, 0, 0}, append([]byte{OpSponge}, spongeInput(0)...),
		append([]byte{OpSponge}, spongeInput(MaxSpongeOutput+1)...),
		{0x00}, {0x04}, {0xFF},
	} {
		require.Zero(t, PoseidonPrecompile.RequiredGas(in))
		out, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
		require.Error(t, err, "a zero-gas input must not execute")
		require.Nil(t, out)
	}
}

func TestGas_Deduction(t *testing.T) {
	in := append([]byte{OpHash}, small(1)...)
	price := uint64(GasHashBase + GasPerElement)

	_, left, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, in, price+17, true)
	require.NoError(t, err)
	require.Equal(t, uint64(17), left)

	_, left, err = PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, in, price, true)
	require.NoError(t, err)
	require.Zero(t, left)

	_, left, err = PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, in, price-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, left)
}

// TestDeterminism: no clock, no randomness, no map iteration. The same call
// must give the same bytes, in any order, from any goroutine.
func TestDeterminism(t *testing.T) {
	cases := [][]byte{
		append([]byte{OpHash}, small(1)...),
		append([]byte{OpHash}, append(small(1), small(2)...)...),
		append([]byte{OpHashPair}, append(small(3), small(4)...)...),
		append([]byte{OpSponge}, spongeInput(128, small(5))...),
	}
	first := make([][]byte, len(cases))
	for i, in := range cases {
		out, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, in, 1<<24, true)
		require.NoError(t, err)
		first[i] = out
	}
	for range 8 {
		for i := len(cases) - 1; i >= 0; i-- {
			out, _, err := PoseidonPrecompile.Run(nil, common.Address{}, ContractAddress, cases[i], 1<<24, false)
			require.NoError(t, err)
			require.Equal(t, first[i], out, "case %d is not deterministic", i)
		}
	}
}

// --- module + config ----------------------------------------------------

func TestModule_Wiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
	require.Same(t, PoseidonPrecompile, Module.Contract)
	require.NotNil(t, Module.Configurator)
	require.Equal(t,
		common.HexToAddress("0x0500000000000000000000000000000000000005"),
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

	ts := uint64(41)
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, a.Timestamp())
	require.True(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	other := uint64(42)
	require.False(t, a.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.False(t, a.Equal(nil))
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestRegisterModuleIsIdempotentlyRefused(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module))
}
