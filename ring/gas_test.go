// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// The gas schedule is consensus. These tests state it as relationships --
// what the price does when the ring grows, which schemes are billed, what
// the price ignores -- so that changing a constant fails loudly and changing
// the shape fails louder.

// The billed schemes and their two constants. SchemeDualRing (0x03) is
// deliberately absent: it falls to the default arm and costs nothing.
var billed = []struct {
	name      string
	scheme    byte
	base      uint64
	perMember uint64
}{
	{"lsag secp256k1", SchemeLSAGSecp256k1, GasVerifyBase, GasVerifyPerMember},
	{"lsag ed25519", SchemeLSAGEd25519, GasVerifyBase - 1000, GasVerifyPerMember - 500},
	{"lattice lsag", SchemeLatticeLSAG, 50000, 10000},
}

func gasFor(scheme byte, ringSize int) uint64 {
	return RingSignaturePrecompile.RequiredGas([]byte{OpVerify, scheme, byte(ringSize)})
}

// Each extra ring member costs exactly one perMember, at every size. A
// schedule that were quadratic, or that saturated, would fail here.
func TestGasIsLinearInRingSize(t *testing.T) {
	for _, s := range billed {
		t.Run(s.name, func(t *testing.T) {
			require.Equal(t, s.base, gasFor(s.scheme, 0), "an empty ring costs the base")
			for k := range 255 {
				step := gasFor(s.scheme, k+1) - gasFor(s.scheme, k)
				require.Equal(t, s.perMember, step, "step from %d to %d members", k, k+1)
			}
			require.Equal(t, s.base+255*s.perMember, gasFor(s.scheme, 255),
				"the size byte saturates at 255, so this is the ceiling")
		})
	}
}

// Verification cost tracks curve operations, and the lattice scheme is an
// order of magnitude heavier than the elliptic ones. Pin the ordering rather
// than only the numbers.
func TestGasOrdersSchemesByWork(t *testing.T) {
	for _, k := range []int{2, 8, 64} {
		require.Less(t, gasFor(SchemeLSAGEd25519, k), gasFor(SchemeLSAGSecp256k1, k),
			"ed25519 is cheaper than secp256k1 at ring size %d", k)
		require.Less(t, gasFor(SchemeLSAGSecp256k1, k), gasFor(SchemeLatticeLSAG, k),
			"the lattice scheme is the dearest at ring size %d", k)
	}
}

// Three arms return zero. Each one must also make Run refuse immediately and
// hand every unit of gas back, so a zero price buys nothing but an error.
func TestGasZeroArmsBuyNothing(t *testing.T) {
	free := []struct {
		name  string
		input []byte
	}{
		{"shorter than a header", []byte{OpVerify, SchemeLSAGSecp256k1}},
		{"not the verify op", append([]byte{0x01, SchemeLSAGSecp256k1, 2}, make([]byte, 4096)...)},
		{"unbilled scheme 0x03", append([]byte{OpVerify, SchemeDualRing, 2}, make([]byte, 4096)...)},
		{"unbilled scheme 0xff", append([]byte{OpVerify, 0xFF, 255}, make([]byte, 4096)...)},
	}

	for _, tc := range free {
		t.Run(tc.name, func(t *testing.T) {
			require.Zero(t, RingSignaturePrecompile.RequiredGas(tc.input))

			const supplied = 1_000_000
			out, remaining, err := RingSignaturePrecompile.Run(
				nil, common.Address{}, ContractAddress, tc.input, supplied, false)
			require.Error(t, err, "a free call must still be refused")
			require.Nil(t, out)
			require.Equal(t, uint64(supplied), remaining, "nothing was charged")
		})
	}
}

// 0x02 and 0x10 are billed by RequiredGas and refused by verify: the caller
// pays up to 2.6M gas for a scheme that does no work. Safe for consensus,
// wrong for the caller -- pinned so the mismatch is visible.
func TestBilledSchemesThatAreAlwaysRefused(t *testing.T) {
	for _, scheme := range []byte{SchemeLSAGEd25519, SchemeLatticeLSAG} {
		in := append([]byte{OpVerify, scheme, 255}, make([]byte, 1024)...)
		cost := RingSignaturePrecompile.RequiredGas(in)
		require.NotZero(t, cost, "scheme 0x%02x is billed", scheme)

		out, remaining, err := RingSignaturePrecompile.Run(
			nil, common.Address{}, ContractAddress, in, cost+1, false)
		require.ErrorIs(t, err, ErrInvalidScheme, "scheme 0x%02x is nevertheless refused", scheme)
		require.Nil(t, out)
		require.Equal(t, uint64(1), remaining, "the full price was taken for a refusal")
	}
	require.Equal(t, uint64(2_600_000), gasFor(SchemeLatticeLSAG, 255),
		"the worst case a caller can be charged for a refusal")
}

// The price is read off the declared ring size and nothing else. The message
// is hashed once per ring member inside lsagVerify, so cost scales with
// n*len(message) while the price does not move at all: the calldata charge
// upstream is the only thing paying for that hashing.
func TestGasIgnoresEverythingButTheSizeByte(t *testing.T) {
	small := append([]byte{OpVerify, SchemeLSAGSecp256k1, 4}, make([]byte, 1)...)
	large := append([]byte{OpVerify, SchemeLSAGSecp256k1, 4}, make([]byte, 64*1024)...)
	require.Equal(t, RingSignaturePrecompile.RequiredGas(small), RingSignaturePrecompile.RequiredGas(large),
		"message length is not priced")

	// And a size byte far larger than the supplied bytes is billed in full,
	// before the input is known to be short. Over-billing, not under-billing.
	overclaim := []byte{OpVerify, SchemeLSAGSecp256k1, 255}
	require.Equal(t, uint64(GasVerifyBase+255*GasVerifyPerMember), RingSignaturePrecompile.RequiredGas(overclaim))
	_, remaining, err := RingSignaturePrecompile.Run(
		nil, common.Address{}, ContractAddress, overclaim, 1_000_000, false)
	require.ErrorIs(t, err, ErrInvalidInput)
	require.Equal(t, uint64(1_000_000)-(GasVerifyBase+255*GasVerifyPerMember), remaining)
}

// Run charges exactly RequiredGas, and one unit less than that is refused.
func TestRunChargesExactlyRequiredGas(t *testing.T) {
	_, _, in := fixture(t, "gas", 3, 0, []byte("charge me"))
	cost := RingSignaturePrecompile.RequiredGas(in)
	require.Equal(t, uint64(GasVerifyBase+3*GasVerifyPerMember), cost)

	out, remaining, err := RingSignaturePrecompile.Run(
		nil, common.Address{}, ContractAddress, in, cost+7, false)
	require.NoError(t, err)
	require.Equal(t, []byte{0x01}, out)
	require.Equal(t, uint64(7), remaining)

	_, remaining, err = RingSignaturePrecompile.Run(
		nil, common.Address{}, ContractAddress, in, cost-1, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining, "a refused call leaves nothing")
}

// Gas is taken before the input is parsed, so a call that cannot pay never
// reaches the verifier.
func TestGasZeroRejected(t *testing.T) {
	input := make([]byte, 128)
	input[0] = OpVerify
	input[1] = SchemeLSAGSecp256k1
	input[2] = 2

	_, remaining, err := RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, input, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)
}

// readOnly must not change the answer: verification touches no state.
func TestReadOnlyDoesNotChangeTheAnswer(t *testing.T) {
	_, _, in := fixture(t, "readonly", 2, 0, []byte("m"))
	cost := RingSignaturePrecompile.RequiredGas(in)

	ro, _, err := RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, in, cost, true)
	require.NoError(t, err)
	rw, _, err := RingSignaturePrecompile.Run(nil, common.Address{}, ContractAddress, in, cost, false)
	require.NoError(t, err)
	require.Equal(t, rw, ro)
	require.Equal(t, []byte{0x01}, ro)
}
