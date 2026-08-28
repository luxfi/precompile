// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package xwing

import (
	"testing"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// --- Config tests ---

func TestConfig_Key(t *testing.T) {
	require.Equal(t, ConfigKey, (&Config{}).Key())
}

func TestConfig_Timestamp_Nil(t *testing.T) {
	require.Nil(t, (&Config{}).Timestamp())
}

func TestConfig_Timestamp_Set(t *testing.T) {
	ts := uint64(999)
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, c.Timestamp())
}

func TestConfig_IsDisabled(t *testing.T) {
	require.False(t, (&Config{}).IsDisabled())
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

func TestConfig_Equal_Same(t *testing.T) {
	ts := uint64(100)
	c1 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	c2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.True(t, c1.Equal(c2))
}

func TestConfig_Equal_Different(t *testing.T) {
	ts1, ts2 := uint64(100), uint64(200)
	c1 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	c2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}
	require.False(t, c1.Equal(c2))
}

func TestConfig_Equal_WrongType(t *testing.T) {
	require.False(t, (&Config{}).Equal(nil))
}

func TestConfig_Verify(t *testing.T) {
	require.NoError(t, (&Config{}).Verify(nil))
}

func TestConfigurator_MakeConfig(t *testing.T) {
	cfg := (&configurator{}).MakeConfig()
	_, ok := cfg.(*Config)
	require.True(t, ok)
}

func TestConfigurator_Configure(t *testing.T) {
	require.NoError(t, (&configurator{}).Configure(nil, nil, nil, nil))
}

// --- RequiredGas edge cases ---

func TestRequiredGas_EmptyInput(t *testing.T) {
	require.Equal(t, uint64(GasRefuse), XWingPrecompile.RequiredGas(nil))
	require.Equal(t, uint64(GasRefuse), XWingPrecompile.RequiredGas([]byte{}))
}

func TestRequiredGas_Encapsulate(t *testing.T) {
	require.Equal(t, uint64(GasEncapsulate), XWingPrecompile.RequiredGas([]byte{OpEncapsulate}))
}

func TestRequiredGas_UnknownOp(t *testing.T) {
	require.Equal(t, uint64(GasRefuse), XWingPrecompile.RequiredGas([]byte{0xFF}))
}

// --- Run edge cases ---

func TestRun_EmptyInput(t *testing.T) {
	_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, nil, 100_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestRun_EmptySlice(t *testing.T) {
	_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{}, 100_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestRun_InvalidOp(t *testing.T) {
	_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{0xFF}, 100_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidOp)
}

func TestRun_OutOfGas(t *testing.T) {
	_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{OpEncapsulate}, 1, true)
	require.Error(t, err)
}

func TestRun_EncapsulateTooShort(t *testing.T) {
	// Op byte but no public key
	_, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{OpEncapsulate, 0x01}, 100_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestRun_EncapsulateInvalidPK(t *testing.T) {
	scheme := xwing.Scheme()
	pkSize := scheme.PublicKeySize()
	// Full frame -- op + seed + a pk-sized run of garbage. X-Wing's ML-KEM-768
	// half runs the FIPS 203 encapsulation-key check (ByteEncode(ByteDecode(ek))
	// == ek), which random bytes fail with overwhelming probability, so this
	// reaches UnmarshalBinaryPublicKey's error return rather than the length
	// guard in front of it.
	input := make([]byte, 1+SeedSize+pkSize)
	input[0] = OpEncapsulate
	for i := 1; i < len(input); i++ {
		input[i] = 0xFF
	}
	result, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, input, 100_000, true)
	require.Error(t, err, "a pk failing the FIPS 203 modulus check must be refused")
	require.Nil(t, result)
}

func TestRun_EncapsulateValid(t *testing.T) {
	scheme := xwing.Scheme()
	pk, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)

	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	input := make([]byte, 1+SeedSize+len(pkBytes))
	input[0] = OpEncapsulate
	copy(input[1+SeedSize:], pkBytes)

	result, _, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, input, 100_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Result format: [2 bytes ct_len][ct][ss]
	ctLen := int(result[0])<<8 | int(result[1])
	require.Equal(t, scheme.CiphertextSize(), ctLen)
	require.Equal(t, 2+ctLen+scheme.SharedKeySize(), len(result))
}

// An unknown op is metered, so a caller who supplies nothing is stopped at
// the meter and never reaches the dispatch. Supplying the refusal fee gets
// the refusal itself.
func TestRun_UnknownOpIsMetered(t *testing.T) {
	gas := XWingPrecompile.RequiredGas([]byte{0xFF})
	require.Equal(t, uint64(GasRefuse), gas)

	_, remaining, err := XWingPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{0xFF}, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas, "free refusal is an unmetered path")
	require.Zero(t, remaining)

	_, remaining, err = XWingPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{0xFF}, gas, true)
	require.ErrorIs(t, err, ErrInvalidOp)
	require.Zero(t, remaining, "the whole refusal fee is consumed")
}
