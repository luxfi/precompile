// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sr25519

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// --- Config tests ---

func TestConfig_Key(t *testing.T) {
	c := &Config{}
	require.Equal(t, ConfigKey, c.Key())
}

func TestConfig_Timestamp_Nil(t *testing.T) {
	c := &Config{}
	require.Nil(t, c.Timestamp())
}

func TestConfig_Timestamp_Set(t *testing.T) {
	ts := uint64(12345)
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, c.Timestamp())
}

func TestConfig_IsDisabled_False(t *testing.T) {
	c := &Config{}
	require.False(t, c.IsDisabled())
}

func TestConfig_IsDisabled_True(t *testing.T) {
	c := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, c.IsDisabled())
}

func TestConfig_Equal_Same(t *testing.T) {
	ts := uint64(100)
	c1 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	c2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.True(t, c1.Equal(c2))
}

func TestConfig_Equal_Different(t *testing.T) {
	ts1 := uint64(100)
	ts2 := uint64(200)
	c1 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	c2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}
	require.False(t, c1.Equal(c2))
}

func TestConfig_Equal_WrongType(t *testing.T) {
	c := &Config{}
	require.False(t, c.Equal(nil))
}

func TestConfig_Verify(t *testing.T) {
	c := &Config{}
	require.NoError(t, c.Verify(nil))
}

// --- Configurator tests ---

func TestConfigurator_MakeConfig(t *testing.T) {
	cfg := (&configurator{}).MakeConfig()
	require.NotNil(t, cfg)
	_, ok := cfg.(*Config)
	require.True(t, ok)
}

func TestConfigurator_Configure(t *testing.T) {
	err := (&configurator{}).Configure(nil, nil, nil, nil)
	require.NoError(t, err)
}

// --- verifySR25519 edge cases ---

func TestVerifySR25519_WrongPubKeyLen(t *testing.T) {
	require.False(t, verifySR25519(make([]byte, 31), make([]byte, 64), []byte("msg")))
	require.False(t, verifySR25519(make([]byte, 33), make([]byte, 64), []byte("msg")))
}

func TestVerifySR25519_WrongSigLen(t *testing.T) {
	require.False(t, verifySR25519(make([]byte, 32), make([]byte, 63), []byte("msg")))
	require.False(t, verifySR25519(make([]byte, 32), make([]byte, 65), []byte("msg")))
}

func TestVerifySR25519_EmptyMessage(t *testing.T) {
	require.False(t, verifySR25519(make([]byte, 32), make([]byte, 64), nil))
	require.False(t, verifySR25519(make([]byte, 32), make([]byte, 64), []byte{}))
}

// --- Gas edge cases ---

func TestRequiredGas_NilInput(t *testing.T) {
	require.Equal(t, SR25519VerifyBaseGas, SR25519VerifyPrecompile.RequiredGas(nil))
}

func TestRequiredGas_ExactPubkeySig(t *testing.T) {
	// Exactly pubkey+sig size, no message
	input := make([]byte, PublicKeySize+SignatureSize)
	require.Equal(t, SR25519VerifyBaseGas, SR25519VerifyPrecompile.RequiredGas(input))
}

func TestRequiredGas_ShortInput(t *testing.T) {
	input := make([]byte, 10)
	require.Equal(t, SR25519VerifyBaseGas, SR25519VerifyPrecompile.RequiredGas(input))
}

// --- Run edge cases ---

func TestRun_ExactMinInputSize(t *testing.T) {
	// MinInputSize = 97 (32+64+1)
	input := make([]byte, MinInputSize)
	gas := SR25519VerifyPrecompile.RequiredGas(input)
	result, remaining, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress, input, gas+10000, true)
	require.NoError(t, err)
	// Should not verify (random bytes) but should not error
	require.Equal(t, byte(0), result[31])
	require.Equal(t, uint64(10000), remaining)
}

func TestRun_LargeMessage(t *testing.T) {
	// Test with a larger message (1KB)
	msg := make([]byte, 1024)
	for i := range msg {
		msg[i] = byte(i % 256)
	}
	input := make([]byte, PublicKeySize+SignatureSize+len(msg))
	copy(input[PublicKeySize+SignatureSize:], msg)

	gas := SR25519VerifyPrecompile.RequiredGas(input)
	expected := SR25519VerifyBaseGas + uint64(len(msg))*SR25519VerifyPerByteGas
	require.Equal(t, expected, gas)
}
