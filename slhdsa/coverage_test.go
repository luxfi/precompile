// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package slhdsa

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/geth/common"
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

// --- ModeName ---

func TestModeName_AllModes(t *testing.T) {
	tests := []struct {
		mode uint8
		name string
	}{
		{ModeSHA2_128s, "SLH-DSA-SHA2-128s"},
		{ModeSHA2_128f, "SLH-DSA-SHA2-128f"},
		{ModeSHA2_192s, "SLH-DSA-SHA2-192s"},
		{ModeSHA2_192f, "SLH-DSA-SHA2-192f"},
		{ModeSHA2_256s, "SLH-DSA-SHA2-256s"},
		{ModeSHA2_256f, "SLH-DSA-SHA2-256f"},
		{ModeSHAKE_128s, "SLH-DSA-SHAKE-128s"},
		{ModeSHAKE_128f, "SLH-DSA-SHAKE-128f"},
		{ModeSHAKE_192s, "SLH-DSA-SHAKE-192s"},
		{ModeSHAKE_192f, "SLH-DSA-SHAKE-192f"},
		{ModeSHAKE_256s, "SLH-DSA-SHAKE-256s"},
		{ModeSHAKE_256f, "SLH-DSA-SHAKE-256f"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.name, ModeName(tt.mode))
	}
}

func TestModeName_Unknown(t *testing.T) {
	require.Equal(t, "unknown", ModeName(0xFF))
}

// --- RequiredGas edge cases ---

func TestRequiredGas_EmptyInput(t *testing.T) {
	require.Equal(t, SLHDSADefaultGas, SLHDSAVerifyPrecompile.RequiredGas(nil))
	require.Equal(t, SLHDSADefaultGas, SLHDSAVerifyPrecompile.RequiredGas([]byte{}))
}

func TestRequiredGas_InvalidMode(t *testing.T) {
	require.Equal(t, SLHDSADefaultGas, SLHDSAVerifyPrecompile.RequiredGas([]byte{0xFF}))
}

func TestRequiredGas_ShortHeader(t *testing.T) {
	// Only mode byte, no pubkey length
	_, _, baseGas, _, _ := getModeParams(ModeSHA2_128s)
	require.Equal(t, baseGas, SLHDSAVerifyPrecompile.RequiredGas([]byte{ModeSHA2_128s}))
}

func TestRequiredGas_WrongPubKeySize(t *testing.T) {
	input := make([]byte, 3)
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], 999) // wrong size for mode
	_, _, baseGas, _, _ := getModeParams(ModeSHA2_128s)
	require.Equal(t, baseGas, SLHDSAVerifyPrecompile.RequiredGas(input))
}

func TestRequiredGas_ShortForMsgLen(t *testing.T) {
	input := make([]byte, 1+2+SLH128PublicKeySize) // mode + pkLen + pk, no msgLen
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], SLH128PublicKeySize)
	_, _, baseGas, _, _ := getModeParams(ModeSHA2_128s)
	require.Equal(t, baseGas, SLHDSAVerifyPrecompile.RequiredGas(input))
}

func TestRequiredGas_WithMessage(t *testing.T) {
	msgLen := uint16(100)
	input := make([]byte, 1+2+SLH128PublicKeySize+2)
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], SLH128PublicKeySize)
	binary.BigEndian.PutUint16(input[1+2+SLH128PublicKeySize:], msgLen)
	expected := SLH128sVerifyBaseGas + uint64(msgLen)*SLHDSAVerifyPerByteGas
	require.Equal(t, expected, SLHDSAVerifyPrecompile.RequiredGas(input))
}

// --- Run edge cases ---

func TestRun_EmptyInput(t *testing.T) {
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, nil, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_UnsupportedMode(t *testing.T) {
	input := make([]byte, 3)
	input[0] = 0xFF
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedMode)
}

func TestRun_WrongPubKeySize(t *testing.T) {
	input := make([]byte, 3)
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], 999)
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_ShortForMsgLen(t *testing.T) {
	input := make([]byte, 1+2+SLH128PublicKeySize)
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], SLH128PublicKeySize)
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_TruncatedAtSig(t *testing.T) {
	input := make([]byte, 1+2+SLH128PublicKeySize+2)
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], SLH128PublicKeySize)
	binary.BigEndian.PutUint16(input[1+2+SLH128PublicKeySize:], 0) // msg len = 0
	// Need sig, but input is too short
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_InvalidPubKey(t *testing.T) {
	// All-zero key+sig doesn't error; verify just returns 0 in result[31].
	msg := []byte("test")
	input := buildSlhdsaInput(ModeSHA2_128s, make([]byte, SLH128PublicKeySize), msg, make([]byte, SLHSHA2_128sSignatureSize))
	result, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(0), result[31], "garbage inputs must not verify")
}

func TestRun_OutOfGas(t *testing.T) {
	input := make([]byte, 3)
	input[0] = ModeSHA2_128s
	binary.BigEndian.PutUint16(input[1:], SLH128PublicKeySize)
	_, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1, true)
	require.Error(t, err)
}

// Test a valid signature with SHA2-128s (fastest mode)
func TestRun_SHA2_128s_Valid(t *testing.T) {
	testValidMode(t, ModeSHA2_128s, slhdsa.SHA2_128s, SLH128PublicKeySize, SLHSHA2_128sSignatureSize)
}

func TestRun_SHA2_128f_Valid(t *testing.T) {
	testValidMode(t, ModeSHA2_128f, slhdsa.SHA2_128f, SLH128PublicKeySize, SLHSHA2_128fSignatureSize)
}

func testValidMode(t *testing.T, modeByte uint8, mode slhdsa.Mode, pkSize, sigSize int) {
	t.Helper()

	priv, err := slhdsa.GenerateKey(rand.Reader, mode)
	require.NoError(t, err)

	message := []byte("test message for SLH-DSA")
	sig, err := priv.SignCtx(rand.Reader, message, precompileCtx)
	require.NoError(t, err)

	pk := priv.PublicKey.Bytes()
	require.Equal(t, pkSize, len(pk))
	require.Equal(t, sigSize, len(sig))

	input := buildSlhdsaInput(modeByte, pk, message, sig)

	result, _, err := SLHDSAVerifyPrecompile.Run(nil, common.Address{}, ContractSLHDSAVerifyAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31])
}

// buildSlhdsaInput constructs precompile input: mode(1) + pkLen(2) + pk + msgLen(2) + msg + sig
func buildSlhdsaInput(mode uint8, pk, msg, sig []byte) []byte {
	input := make([]byte, 0, 1+2+len(pk)+2+len(msg)+len(sig))
	input = append(input, mode)

	pkLen := make([]byte, 2)
	binary.BigEndian.PutUint16(pkLen, uint16(len(pk)))
	input = append(input, pkLen...)
	input = append(input, pk...)

	msgLen := make([]byte, 2)
	binary.BigEndian.PutUint16(msgLen, uint16(len(msg)))
	input = append(input, msgLen...)
	input = append(input, msg...)
	input = append(input, sig...)

	return input
}
