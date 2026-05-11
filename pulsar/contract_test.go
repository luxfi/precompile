// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestPulsarPrecompile_Address pins the canonical LP-4200 address.
func TestPulsarPrecompile_Address(t *testing.T) {
	want := common.HexToAddress("0x0000000000000000000000000000000000012204")
	require.Equal(t, want, ContractPulsarVerifyAddress)
}

// TestPulsarPrecompile_RequiredGas exercises the per-mode gas table.
func TestPulsarPrecompile_RequiredGas(t *testing.T) {
	for _, tc := range []struct {
		mode uint8
		want uint64
	}{
		{ModePulsar44, Pulsar44VerifyBaseGas},
		{ModePulsar65, Pulsar65VerifyBaseGas},
		{ModePulsar87, Pulsar87VerifyBaseGas},
	} {
		input := []byte{tc.mode}
		got := PulsarVerifyPrecompile.RequiredGas(input)
		// One-byte input → base + 1 * PerByteGas.
		want := tc.want + 1*PulsarVerifyPerByteGas
		require.Equal(t, want, got, "mode=0x%x", tc.mode)
	}
}

// TestPulsarPrecompile_RoundTrip_VerifyAcceptsValid generates a real
// ML-DSA signature with the precompile context, hands the bytes to
// the Pulsar precompile, and asserts it accepts. This is the Class
// N1 manifesto test: a single-party FIPS 204 signature on the
// Pulsar context verifies through the Pulsar precompile because the
// verification operation IS FIPS 204 ML-DSA.Verify.
func TestPulsarPrecompile_RoundTrip_VerifyAcceptsValid(t *testing.T) {
	for _, mode := range []mldsa.Mode{mldsa.MLDSA44, mldsa.MLDSA65, mldsa.MLDSA87} {
		mode := mode
		t.Run(modeString(mode), func(t *testing.T) {
			priv, err := mldsa.GenerateKey(rand.Reader, mode)
			require.NoError(t, err)
			pub := priv.Public().(*mldsa.PublicKey)
			pubBytes := pub.Bytes()

			message := []byte("pulsar threshold sign roundtrip via precompile")
			sig, err := priv.SignCtx(rand.Reader, message, precompileCtx)
			require.NoError(t, err)

			// Build precompile input.
			var modeByte uint8
			switch mode {
			case mldsa.MLDSA44:
				modeByte = ModePulsar44
			case mldsa.MLDSA65:
				modeByte = ModePulsar65
			case mldsa.MLDSA87:
				modeByte = ModePulsar87
			}
			input := buildInput(modeByte, pubBytes, message, sig)
			gas := PulsarVerifyPrecompile.RequiredGas(input) * 2 // give plenty
			out, gasLeft, err := PulsarVerifyPrecompile.Run(nil, common.Address{}, ContractPulsarVerifyAddress, input, gas, true)
			require.NoError(t, err)
			require.Empty(t, out)
			require.Less(t, gasLeft, gas)
		})
	}
}

// TestPulsarPrecompile_RejectsTamperedSignature confirms that flipping
// a byte in the signature causes verification to fail.
func TestPulsarPrecompile_RejectsTamperedSignature(t *testing.T) {
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pub := priv.Public().(*mldsa.PublicKey)
	pubBytes := pub.Bytes()
	message := []byte("tamper detection")
	sig, err := priv.SignCtx(rand.Reader, message, precompileCtx)
	require.NoError(t, err)
	sig[0] ^= 0xff
	input := buildInput(ModePulsar65, pubBytes, message, sig)
	gas := PulsarVerifyPrecompile.RequiredGas(input) * 2
	_, _, err = PulsarVerifyPrecompile.Run(nil, common.Address{}, ContractPulsarVerifyAddress, input, gas, true)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// TestPulsarPrecompile_RejectsInvalidMode confirms that mode bytes
// outside {0x44, 0x65, 0x87} are rejected.
func TestPulsarPrecompile_RejectsInvalidMode(t *testing.T) {
	input := []byte{0x99} // bogus mode
	_, _, err := PulsarVerifyPrecompile.Run(nil, common.Address{}, ContractPulsarVerifyAddress, input, 1_000_000, true)
	require.ErrorIs(t, err, ErrInvalidMode)
}

func buildInput(mode uint8, pub, msg, sig []byte) []byte {
	out := make([]byte, 0, 1+len(pub)+32+len(msg)+len(sig))
	out = append(out, mode)
	out = append(out, pub...)
	var mlen [32]byte
	binary.BigEndian.PutUint64(mlen[24:], uint64(len(msg)))
	out = append(out, mlen[:]...)
	out = append(out, msg...)
	out = append(out, sig...)
	return out
}

func modeString(m mldsa.Mode) string {
	switch m {
	case mldsa.MLDSA44:
		return "Pulsar-44"
	case mldsa.MLDSA65:
		return "Pulsar-65"
	case mldsa.MLDSA87:
		return "Pulsar-87"
	default:
		return "unknown"
	}
}
