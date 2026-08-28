// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/stretchr/testify/require"
)

// feeFrame builds a mode frame whose message-length field says msgLen,
// regardless of what follows. Only the fee is under test.
func feeFrame(t *testing.T, mode uint8, msgLen uint16) []byte {
	t.Helper()
	pubSize, _, _, _, err := getModeParams(mode)
	require.NoError(t, err)

	in := make([]byte, ModeByte+PubKeyLenSize+pubSize+MessageLenSize)
	in[0] = mode
	binary.BigEndian.PutUint16(in[ModeByte:ModeByte+PubKeyLenSize], uint16(pubSize))
	at := ModeByte + PubKeyLenSize + pubSize
	binary.BigEndian.PutUint16(in[at:at+MessageLenSize], msgLen)
	return in
}

// No branch of RequiredGas is free: every mode byte, every truncation and
// the empty call all quote something. A free branch is an unmetered path.
func TestGas_EveryBranchCharges(t *testing.T) {
	for name, in := range map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"mode only":      {ModeSHA2_128s},
		"short header":   {ModeSHA2_128s, 0x00},
		"wrong pubkeyln": {ModeSHA2_128s, 0xFF, 0xFF},
	} {
		require.NotZerof(t, SLHDSAVerifyPrecompile.RequiredGas(in), "%s is an unmetered branch", name)
	}
	for m := range 256 {
		require.NotZerof(t, SLHDSAVerifyPrecompile.RequiredGas([]byte{byte(m)}),
			"mode 0x%02x is an unmetered branch", m)
	}
}

// The fee tracks the work. Within a variant, more security costs more;
// within a level, the fast variant's larger signature costs more than the
// small one; and the two hash families at identical parameters cost the
// same, because they do the same amount of work.
func TestGas_TracksParameterSet(t *testing.T) {
	fee := func(mode uint8) uint64 { return SLHDSAVerifyPrecompile.RequiredGas([]byte{mode}) }

	for _, chain := range [][3]uint8{
		{ModeSHA2_128s, ModeSHA2_192s, ModeSHA2_256s},
		{ModeSHA2_128f, ModeSHA2_192f, ModeSHA2_256f},
		{ModeSHAKE_128s, ModeSHAKE_192s, ModeSHAKE_256s},
		{ModeSHAKE_128f, ModeSHAKE_192f, ModeSHAKE_256f},
	} {
		require.Lessf(t, fee(chain[0]), fee(chain[1]), "0x%02x vs 0x%02x", chain[0], chain[1])
		require.Lessf(t, fee(chain[1]), fee(chain[2]), "0x%02x vs 0x%02x", chain[1], chain[2])
	}

	for _, pair := range [][2]uint8{
		{ModeSHA2_128s, ModeSHA2_128f},
		{ModeSHA2_192s, ModeSHA2_192f},
		{ModeSHA2_256s, ModeSHA2_256f},
	} {
		small, fast := pair[0], pair[1]
		_, smallSig, _, _, err := getModeParams(small)
		require.NoError(t, err)
		_, fastSig, _, _, err := getModeParams(fast)
		require.NoError(t, err)
		require.Greater(t, fastSig, smallSig)
		require.Greaterf(t, fee(fast), fee(small),
			"0x%02x has the larger signature but not the larger fee", fast)
	}

	for _, pair := range [][2]uint8{
		{ModeSHA2_128s, ModeSHAKE_128s}, {ModeSHA2_128f, ModeSHAKE_128f},
		{ModeSHA2_192s, ModeSHAKE_192s}, {ModeSHA2_192f, ModeSHAKE_192f},
		{ModeSHA2_256s, ModeSHAKE_256s}, {ModeSHA2_256f, ModeSHAKE_256f},
	} {
		require.Equalf(t, fee(pair[0]), fee(pair[1]),
			"0x%02x and 0x%02x do the same work and must cost the same", pair[0], pair[1])
	}
}

// The fee is base + len*k and rises with the declared message length.
func TestGas_RisesWithMessageLength(t *testing.T) {
	for _, mode := range allModes {
		_, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)

		prev := uint64(0)
		for _, n := range []uint16{0, 1, 2, 1024, 0xFFFE, 0xFFFF} {
			got := SLHDSAVerifyPrecompile.RequiredGas(feeFrame(t, mode, n))
			require.Equalf(t, baseGas+uint64(n)*SLHDSAVerifyPerByteGas, got,
				"mode 0x%02x length %d", mode, n)
			if n > 0 {
				require.Greaterf(t, got, prev, "mode 0x%02x: length %d cost no more than the one before", mode, n)
			}
			prev = got
		}
	}
}

// The length field is a uint16, so the per-byte term is bounded by
// 65535*10 and the fee cannot wrap however the field is filled. Unlike the
// ML-DSA precompile next door -- whose length field is 256 bits wide and
// therefore needs an explicit saturating cap -- this one is bounded by its
// own encoding. Assert that, so widening the field later fails here.
func TestGas_LengthFieldIsTooNarrowToWrap(t *testing.T) {
	require.Equal(t, 2, MessageLenSize, "widening the length field re-opens the overflow question")

	widest := uint64(math.MaxUint16) * SLHDSAVerifyPerByteGas
	for _, mode := range allModes {
		_, _, baseGas, _, err := getModeParams(mode)
		require.NoError(t, err)
		require.Less(t, baseGas, math.MaxUint64-widest,
			"base gas plus the widest message would wrap")

		got := SLHDSAVerifyPrecompile.RequiredGas(feeFrame(t, mode, math.MaxUint16))
		require.Equal(t, baseGas+widest, got)
		require.Greaterf(t, got, baseGas, "mode 0x%02x wrapped at the widest message", mode)
		require.Less(t, got, uint64(2_000_000), "the widest possible fee is still a sane number")
	}
}

// The quoted fee is exactly what a call consumes; one unit short is
// refused, and a refused call keeps the fee.
func TestGas_QuotedFeeIsCharged(t *testing.T) {
	mode, pk, msg, sig := katFrame(t)
	in := prepareInputWithMode(mode, pk, msg, sig)
	fee := SLHDSAVerifyPrecompile.RequiredGas(in)

	_, remaining, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{},
		ContractSLHDSAVerifyAddress, in, fee-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Zero(t, remaining)

	_, remaining, err = SLHDSAVerifyPrecompile.Run(nil, common.Address{},
		ContractSLHDSAVerifyAddress, in, fee+9, true)
	require.NoError(t, err)
	require.Equal(t, uint64(9), remaining)
}

func TestGas_RefusalConsumesTheFee(t *testing.T) {
	for name, in := range map[string][]byte{
		"unknown mode": {0xFF},
		"mode only":    {ModeSHA2_128s},
		"short header": {ModeSHA2_128s, 0x00},
	} {
		fee := SLHDSAVerifyPrecompile.RequiredGas(in)
		_, remaining, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{},
			ContractSLHDSAVerifyAddress, in, fee+4, true)
		require.Errorf(t, err, "%s", name)
		require.Equalf(t, uint64(4), remaining, "%s: fee not consumed on refusal", name)
	}
}

func TestGas_ZeroSuppliedIsRefused(t *testing.T) {
	mode, pk, msg, sig := katFrame(t)
	for name, in := range map[string][]byte{
		"valid frame":  prepareInputWithMode(mode, pk, msg, sig),
		"unknown mode": {0xFF},
		"empty":        {},
	} {
		_, remaining, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{},
			ContractSLHDSAVerifyAddress, in, 0, true)
		require.ErrorIsf(t, err, contract.ErrOutOfGas, "%s", name)
		require.Zerof(t, remaining, "%s", name)
	}
}
