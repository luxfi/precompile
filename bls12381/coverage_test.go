// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"encoding/json"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// --- Config tests ---
//
// The bls12381 module exposes seven distinct EIP-2537 precompiles. Each must
// have its OWN Config type whose Key() returns the matching ConfigKey constant.
// Sharing a single Config (the pre-v0.5.35 bug) collapsed upgrade-history
// grouping in evm/params/extras/precompile_upgrade.go and caused upgrade.json
// entries for non-G1Add sub-configs to be rejected with
// "PrecompileUpgrade (bls12381G1AddConfig) at [N]: disable should be [true]".

// configCase pairs a per-op Config zero-value-constructor with its expected key
// and the matching Configurator. Test cases iterate this table so adding a new
// sub-config (e.g. MapG1) forces exactly one table-entry edit and zero test
// duplication.
type configCase struct {
	name         string
	make         func(ts *uint64, disable bool) precompileconfig.Config
	wantKey      string
	makeOther    func(ts *uint64, disable bool) precompileconfig.Config // mismatched type
	configurator contract.Configurator
}

var configCases = []configCase{
	{"G1Add", func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, G1AddConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1MulConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &g1AddConfigurator{}},
	{"G1Mul", func(ts *uint64, d bool) precompileconfig.Config {
		return &G1MulConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, G1MulConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &g1MulConfigurator{}},
	{"G1MSM", func(ts *uint64, d bool) precompileconfig.Config {
		return &G1MSMConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, G1MSMConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &g1MSMConfigurator{}},
	{"G2Add", func(ts *uint64, d bool) precompileconfig.Config {
		return &G2AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, G2AddConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &g2AddConfigurator{}},
	{"G2Mul", func(ts *uint64, d bool) precompileconfig.Config {
		return &G2MulConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, G2MulConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &g2MulConfigurator{}},
	{"G2MSM", func(ts *uint64, d bool) precompileconfig.Config {
		return &G2MSMConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, G2MSMConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &g2MSMConfigurator{}},
	{"Pairing", func(ts *uint64, d bool) precompileconfig.Config {
		return &PairingConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, PairingConfigKey, func(ts *uint64, d bool) precompileconfig.Config {
		return &G1AddConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: d}}
	}, &pairingConfigurator{}},
}

func TestConfig_KeyPerSubConfig_NoCollision(t *testing.T) {
	// Hard regression pin for the v0.5.23..v0.5.34 bug: every sub-config must
	// report its OWN key. A shared Key() (returning G1AddConfigKey) caused
	// upgrade.json to reject the 2nd-and-later bls12381 sub-config entries.
	seen := make(map[string]string)
	for _, c := range configCases {
		key := c.make(nil, false).Key()
		require.Equal(t, c.wantKey, key, "%s.Key()", c.name)
		if prev, dup := seen[key]; dup {
			t.Fatalf("Key collision: %s and %s both return %q", prev, c.name, key)
		}
		seen[key] = c.name
	}
	require.Len(t, seen, 7, "expected exactly 7 unique bls12381 config keys")
}

func TestConfig_Timestamp_Nil(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			require.Nil(t, c.make(nil, false).Timestamp())
		})
	}
}

func TestConfig_Timestamp_Set(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			ts := uint64(999)
			require.Equal(t, &ts, c.make(&ts, false).Timestamp())
		})
	}
}

func TestConfig_IsDisabled(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			require.False(t, c.make(nil, false).IsDisabled())
			require.True(t, c.make(nil, true).IsDisabled())
		})
	}
}

func TestConfig_Equal_Same(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			ts := uint64(100)
			require.True(t, c.make(&ts, false).Equal(c.make(&ts, false)))
		})
	}
}

func TestConfig_Equal_DifferentTimestamp(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			ts1, ts2 := uint64(100), uint64(200)
			require.False(t, c.make(&ts1, false).Equal(c.make(&ts2, false)))
		})
	}
}

func TestConfig_Equal_WrongType(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			// Cross-type equality must be false: G1Add ≠ G1Mul even if their
			// Upgrade fields match byte-for-byte. This guards the type-level
			// separation that the bug previously violated.
			ts := uint64(100)
			require.False(t, c.make(&ts, false).Equal(c.makeOther(&ts, false)))
			require.False(t, c.make(nil, false).Equal(nil))
		})
	}
}

func TestConfig_Verify(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, c.make(nil, false).Verify(nil))
		})
	}
}

func TestConfigurator_MakeConfig_ReturnsMatchingType(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.configurator.MakeConfig()
			require.Equal(t, c.wantKey, cfg.Key(),
				"%s configurator MakeConfig().Key() must equal %s", c.name, c.wantKey)
		})
	}
}

func TestConfigurator_Configure(t *testing.T) {
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			require.NoError(t, c.configurator.Configure(nil, nil, nil, nil))
		})
	}
}

// TestModule_ConfigKey_MatchesConfigKey is the end-to-end pin: the key under
// which a Module registers in the global registry MUST equal the key its
// MakeConfig().Key() reports. If these diverge, JSON round-trip in
// upgrade.PrecompileUpgrade.UnmarshalJSON → MarshalJSON breaks (the upstream
// failure that surfaced this bug).
func TestModule_ConfigKey_MatchesConfigKey(t *testing.T) {
	mods := []struct {
		name string
		key  string
		mod  modules.Module
	}{
		{"G1Add", G1AddConfigKey, G1AddModule},
		{"G1Mul", G1MulConfigKey, G1MulModule},
		{"G1MSM", G1MSMConfigKey, G1MSMModule},
		{"G2Add", G2AddConfigKey, G2AddModule},
		{"G2Mul", G2MulConfigKey, G2MulModule},
		{"G2MSM", G2MSMConfigKey, G2MSMModule},
		{"Pairing", PairingConfigKey, PairingModule},
	}
	for _, m := range mods {
		t.Run(m.name, func(t *testing.T) {
			require.Equal(t, m.key, m.mod.ConfigKey, "%s Module.ConfigKey", m.name)
			require.Equal(t, m.key, m.mod.MakeConfig().Key(),
				"%s MakeConfig().Key() must equal Module.ConfigKey — divergence breaks upgrade.json round-trip", m.name)
		})
	}
}

// TestConfig_JSONRoundTrip_PerSubConfig pins that a real upgrade.json blob for
// each sub-config marshals back to itself. This is the precise reproducer for
// Lux Neo PR #114's "disable should be [true]" surface: with the shared-Key
// bug, the second sub-config in the array round-tripped to G1AddConfig and
// collided in lastPrecompileUpgrades grouping.
func TestConfig_JSONRoundTrip_PerSubConfig(t *testing.T) {
	ts := uint64(1766708400) // Quasar activation
	for _, c := range configCases {
		t.Run(c.name, func(t *testing.T) {
			orig := c.make(&ts, false)

			// Marshal then unmarshal through the configurator's MakeConfig.
			body, err := json.Marshal(orig)
			require.NoError(t, err)

			rt := c.configurator.MakeConfig()
			require.NoError(t, json.Unmarshal(body, rt))

			require.Equal(t, c.wantKey, rt.Key())
			require.True(t, orig.Equal(rt), "JSON round-trip must preserve Equal")
		})
	}
}

// --- msmGas discount table ---

// --- Infinity point handling ---

func TestDecodeG1_InfinityPoint(t *testing.T) {
	// Infinity is all zeros
	input := make([]byte, G1PointLen)
	pt, err := decodeG1(input)
	require.NoError(t, err)
	require.True(t, pt.IsInfinity())
}

func TestDecodeG2_InfinityPoint(t *testing.T) {
	input := make([]byte, G2PointLen)
	pt, err := decodeG2(input)
	require.NoError(t, err)
	require.True(t, pt.IsInfinity())
}

// --- decodeG1 field element padding ---

func TestDecodeG1_NonZeroPadding_X(t *testing.T) {
	input := make([]byte, G1PointLen)
	input[0] = 0x01 // first padding byte non-zero
	_, err := decodeG1(input)
	require.ErrorIs(t, err, ErrInvalidFieldElem)
}

func TestDecodeG1_NonZeroPadding_Y(t *testing.T) {
	input := make([]byte, G1PointLen)
	input[64] = 0x01 // first Y padding byte non-zero
	_, err := decodeG1(input)
	require.ErrorIs(t, err, ErrInvalidFieldElem)
}

func TestDecodeG1_ShortInput(t *testing.T) {
	_, err := decodeG1(make([]byte, G1PointLen-1))
	require.ErrorIs(t, err, ErrInvalidInput)
}

// --- decodeG2 field element padding ---

func TestDecodeG2_NonZeroPadding(t *testing.T) {
	for _, offset := range []int{0, 64, 128, 192} {
		input := make([]byte, G2PointLen)
		input[offset] = 0x01
		_, err := decodeG2(input)
		require.ErrorIs(t, err, ErrInvalidFieldElem, "offset=%d", offset)
	}
}

func TestDecodeG2_ShortInput(t *testing.T) {
	_, err := decodeG2(make([]byte, G2PointLen-1))
	require.ErrorIs(t, err, ErrInvalidInput)
}

// --- decodeScalar ---

func TestDecodeScalar_Short(t *testing.T) {
	_, err := decodeScalar(make([]byte, ScalarLen-1))
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestDecodeScalar_Valid(t *testing.T) {
	input := make([]byte, ScalarLen)
	input[31] = 1
	s, err := decodeScalar(input)
	require.NoError(t, err)
	require.False(t, s.IsZero())
}

// --- G1 operations with generator point ---

func TestG1Add_Generator(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, 2*G1PointLen)
	copy(input[:G1PointLen], enc)
	copy(input[G1PointLen:], enc)

	result, _, err := blsOps.g1Add(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G1PointLen, len(result))
}

func TestG1Mul_Generator(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, G1PointLen+ScalarLen)
	copy(input[:G1PointLen], enc)
	input[G1PointLen+ScalarLen-1] = 2 // scalar = 2

	result, _, err := blsOps.g1Mul(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G1PointLen, len(result))
}

func TestG1MSM_EmptyInput(t *testing.T) {
	_, _, err := blsOps.g1MSM(nil, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG1MSM_BadAlignment(t *testing.T) {
	_, _, err := blsOps.g1MSM(make([]byte, 1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG1MSM_Generator(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, G1PointLen+ScalarLen)
	copy(input[:G1PointLen], enc)
	input[G1PointLen+ScalarLen-1] = 3

	result, _, err := blsOps.g1MSM(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G1PointLen, len(result))
}

// --- G2 operations ---

func TestG2Add_Generator(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, 2*G2PointLen)
	copy(input[:G2PointLen], enc)
	copy(input[G2PointLen:], enc)

	result, _, err := blsOps.g2Add(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G2PointLen, len(result))
}

func TestG2Mul_Generator(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, G2PointLen+ScalarLen)
	copy(input[:G2PointLen], enc)
	input[G2PointLen+ScalarLen-1] = 2

	result, _, err := blsOps.g2Mul(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G2PointLen, len(result))
}

func TestG2MSM_EmptyInput(t *testing.T) {
	_, _, err := blsOps.g2MSM(nil, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2MSM_BadAlignment(t *testing.T) {
	_, _, err := blsOps.g2MSM(make([]byte, 1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2MSM_Generator(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, G2PointLen+ScalarLen)
	copy(input[:G2PointLen], enc)
	input[G2PointLen+ScalarLen-1] = 3

	result, _, err := blsOps.g2MSM(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, G2PointLen, len(result))
}

// --- Pairing ---

func TestPairing_EmptyInputDirect(t *testing.T) {
	_, _, err := blsOps.pairing(nil, 1_000_000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
}

func TestPairing_BadAlignment(t *testing.T) {
	_, _, err := blsOps.pairing(make([]byte, 1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
}

func TestPairing_InfinityPair(t *testing.T) {
	// Pair of infinity points
	input := make([]byte, PairingPair)
	result, _, err := blsOps.pairing(input, 1_000_000)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31], "pairing of identity points should be 1")
}

// --- PairingGas ---

// A length that is not a whole number of pairs is still priced: EIP-2537
// takes the pair count from a floor division and never rejects, leaving the
// refusal to the pairing routine. Charging nothing here would make a
// malformed call free.
func TestPairingGas_InvalidLen(t *testing.T) {
	require.Equal(t, uint64(GasPairingBase), PairingGas(0))
	require.Equal(t, uint64(GasPairingBase), PairingGas(1))
	require.Equal(t, uint64(GasPairingBase), PairingGas(PairingPair-1))
	require.Equal(t, uint64(GasPairingBase+GasPairingPerPair), PairingGas(PairingPair+1))

	// And the routine takes it before refusing.
	_, remaining, err := blsOps.pairing(make([]byte, PairingPair+1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidPairingLen)
	require.Equal(t, uint64(1_000_000)-PairingGas(PairingPair+1), remaining)
}

func TestPairingGas_OnePair(t *testing.T) {
	expected := uint64(GasPairingBase + GasPairingPerPair)
	require.Equal(t, expected, PairingGas(PairingPair))
}

func TestPairingGas_TwoPairs(t *testing.T) {
	expected := uint64(GasPairingBase + 2*GasPairingPerPair)
	require.Equal(t, expected, PairingGas(2*PairingPair))
}

// --- G1/G2 operation error paths ---

func TestG1Add_ShortInputCoverage(t *testing.T) {
	_, _, err := blsOps.g1Add(make([]byte, 2*G1PointLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG1Mul_ShortInput(t *testing.T) {
	_, _, err := blsOps.g1Mul(make([]byte, G1PointLen+ScalarLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2Add_ShortInputCoverage(t *testing.T) {
	_, _, err := blsOps.g2Add(make([]byte, 2*G2PointLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestG2Mul_ShortInput(t *testing.T) {
	_, _, err := blsOps.g2Mul(make([]byte, G2PointLen+ScalarLen-1), 1_000_000)
	require.ErrorIs(t, err, ErrInvalidInput)
}

// --- Out of gas ---

func TestG1Add_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g1Add(make([]byte, 2*G1PointLen), GasG1Add-1)
	require.Error(t, err)
}

func TestG1Mul_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g1Mul(make([]byte, G1PointLen+ScalarLen), GasG1Mul-1)
	require.Error(t, err)
}

func TestG2Add_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g2Add(make([]byte, 2*G2PointLen), GasG2Add-1)
	require.Error(t, err)
}

func TestG2Mul_OutOfGas(t *testing.T) {
	_, _, err := blsOps.g2Mul(make([]byte, G2PointLen+ScalarLen), GasG2Mul-1)
	require.Error(t, err)
}

func TestPairing_OutOfGas(t *testing.T) {
	_, _, err := blsOps.pairing(make([]byte, PairingPair), 1)
	require.Error(t, err)
}

// --- Point not on curve ---

func TestDecodeG1_NotOnCurve(t *testing.T) {
	input := make([]byte, G1PointLen)
	// Set x = 1, y = 1 (not on BLS12-381 G1)
	input[63] = 1
	input[127] = 1
	_, err := decodeG1(input)
	require.ErrorIs(t, err, ErrPointNotOnCurve)
}

func TestDecodeG2_NotOnCurve(t *testing.T) {
	input := make([]byte, G2PointLen)
	// Set some non-trivial point not on G2
	input[63] = 1
	input[127] = 1
	input[191] = 1
	input[255] = 1
	_, err := decodeG2(input)
	require.ErrorIs(t, err, ErrPointNotOnCurve)
}

// --- G1 Add with invalid second point ---

func TestG1Add_SecondPointInvalid(t *testing.T) {
	_, _, g1Aff, _ := bls.Generators()
	enc := encodeG1(&g1Aff)

	input := make([]byte, 2*G1PointLen)
	copy(input[:G1PointLen], enc) // valid first point

	// Invalid second point (1,1)
	input[G1PointLen+63] = 1
	input[G1PointLen+127] = 1

	_, _, err := blsOps.g1Add(input, 1_000_000)
	require.Error(t, err)
}

func TestG1Mul_InvalidPoint(t *testing.T) {
	input := make([]byte, G1PointLen+ScalarLen)
	input[63] = 1
	input[127] = 1
	input[G1PointLen+ScalarLen-1] = 1
	_, _, err := blsOps.g1Mul(input, 1_000_000)
	require.Error(t, err)
}

func TestG2Add_SecondPointInvalid(t *testing.T) {
	_, _, _, g2Aff := bls.Generators()
	enc := encodeG2(&g2Aff)

	input := make([]byte, 2*G2PointLen)
	copy(input[:G2PointLen], enc)
	input[G2PointLen+63] = 1
	input[G2PointLen+127] = 1
	input[G2PointLen+191] = 1
	input[G2PointLen+255] = 1

	_, _, err := blsOps.g2Add(input, 1_000_000)
	require.Error(t, err)
}
