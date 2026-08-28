// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// run is the shared call shape: quote the cost, supply exactly that,
// and hand back what Run reported as left over.
func run(input []byte, supplied uint64) ([]byte, uint64, error) {
	return PulsarVerifyPrecompile.Run(
		nil, common.Address{}, ContractPulsarVerifyAddress, input, supplied, true)
}

// TestGasChargesEveryOutcome is the accounting-consistency guard. Run
// returns `remainingGas` — by the StatefulPrecompiledContract contract
// that is the gas left AFTER the precompile has charged. Every exit
// must therefore report the same thing: supplied minus the quoted
// cost. A path that hands back the full `suppliedGas` has charged
// nothing for the work it did, which is a free call.
//
// The cases below walk one input per exit in Run: success, a
// cryptographic reject, an unknown mode, an empty input, a body too
// short for the public key, and a message length that overruns the
// body.
func TestGasChargesEveryOutcome(t *testing.T) {
	pk, msg, sig := katBytes(t, katPubHex), katBytes(t, katMsgHex), katBytes(t, katSigHex)

	bad := katBytes(t, katSigHex)
	bad[0] ^= 0xff

	shortBody := append([]byte{ModePulsar65}, make([]byte, Pulsar65PublicKeySize-1)...)

	// Well-formed header, message length larger than the bytes present.
	overrun := buildInput(ModePulsar65, pk, make([]byte, 64), sig)
	overrun = overrun[:len(overrun)-1]

	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"valid", buildInput(ModePulsar65, pk, msg, sig)},
		{"bad signature", buildInput(ModePulsar65, pk, msg, bad)},
		{"unknown mode", []byte{0x99, 0x00, 0x01}},
		{"empty", nil},
		{"body shorter than pubkey", shortBody},
		{"message length overruns body", overrun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cost := PulsarVerifyPrecompile.RequiredGas(tc.input)
			require.NotZero(t, cost, "no input may be free to submit")

			const surplus = 4242
			_, remaining, _ := run(tc.input, cost+surplus)
			require.Equal(t, uint64(surplus), remaining,
				"every exit must charge exactly the quoted cost")
		})
	}
}

// TestGasRefusesUnderpayment pins the meter itself: one gas below the
// quote is refused with ErrOutOfGas and nothing is returned, and
// exactly the quote is enough.
func TestGasRefusesUnderpayment(t *testing.T) {
	input := buildInput(ModePulsar65, katBytes(t, katPubHex), katBytes(t, katMsgHex), katBytes(t, katSigHex))
	cost := PulsarVerifyPrecompile.RequiredGas(input)

	_, remaining, err := run(input, cost-1)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, err = run(input, 0)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, err = run(input, cost)
	require.NoError(t, err, "exact payment must suffice")
	require.Zero(t, remaining)
}

// TestGasOrderedByMode pins the relationship the gas table is meant to
// express: a higher NIST category costs more to verify. Pinning the
// three literals would pass just as well with the table shuffled.
func TestGasOrderedByMode(t *testing.T) {
	at := func(mode uint8, n int) uint64 {
		input := make([]byte, n)
		input[0] = mode
		return PulsarVerifyPrecompile.RequiredGas(input)
	}
	const n = 1024
	require.Less(t, at(ModePulsar44, n), at(ModePulsar65, n))
	require.Less(t, at(ModePulsar65, n), at(ModePulsar87, n))
}

// TestGasGrowsWithInput pins the per-byte adder for every accepted
// mode: each additional calldata byte costs exactly PulsarVerifyPerByteGas.
func TestGasGrowsWithInput(t *testing.T) {
	for _, mode := range []uint8{ModePulsar44, ModePulsar65, ModePulsar87} {
		for _, n := range []int{1, 2, 100, 5000} {
			a := make([]byte, n)
			a[0] = mode
			b := make([]byte, n+1)
			b[0] = mode
			require.Equal(t,
				PulsarVerifyPrecompile.RequiredGas(a)+PulsarVerifyPerByteGas,
				PulsarVerifyPrecompile.RequiredGas(b),
				"mode 0x%x: one more byte costs one more per-byte unit at n=%d", mode, n)
		}
	}
}

// TestGasUnknownModeIsFlat documents and pins the deliberate asymmetry
// in the RequiredGas default arm: the three known modes bill
// base + len*perByte, an unknown mode bills a flat base with no
// per-byte adder.
//
// That is correct rather than a gap. An unknown mode is refused by Run
// before a single byte past input[0] is examined, so there is no
// size-dependent work to price. The bytes themselves are already paid
// for at the EVM calldata tier, which is where a large-payload DoS is
// actually priced; charging per byte again for work not done would
// bill twice. The flat base still exceeds the cost of the byte
// compare, so the arm is not a free call.
//
// The property to hold is therefore: an unknown mode never bills MORE
// than the same-length known mode (it does strictly less work), and
// never bills zero.
func TestGasUnknownModeIsFlat(t *testing.T) {
	for _, n := range []int{1, 1000, 100_000} {
		unknown := make([]byte, n)
		unknown[0] = 0x00
		known := make([]byte, n)
		known[0] = ModePulsar65

		got := PulsarVerifyPrecompile.RequiredGas(unknown)
		require.Equal(t, Pulsar65VerifyBaseGas, got, "unknown mode is flat-rated at n=%d", n)
		require.NotZero(t, got, "unknown mode must not be a free call")
		require.LessOrEqual(t, got, PulsarVerifyPrecompile.RequiredGas(known),
			"refusing early must never cost more than verifying")
	}

	// The flat rate is reached through the default arm, not by
	// accident of a short input: a long unknown-mode payload and a
	// zero-length payload bill identically.
	require.Equal(t,
		PulsarVerifyPrecompile.RequiredGas(nil),
		PulsarVerifyPrecompile.RequiredGas(append([]byte{0xAB}, make([]byte, 1<<16)...)))
}
