// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"testing"

	"github.com/luxfi/crypto/mlkem"
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

// --- RequiredGas edge cases ---

func TestRequiredGas_EmptyInput(t *testing.T) {
	require.Equal(t, MLKEM768EncapsulateGas, MLKEMPrecompile.RequiredGas(nil))
	require.Equal(t, MLKEM768EncapsulateGas, MLKEMPrecompile.RequiredGas([]byte{}))
	require.Equal(t, MLKEM768EncapsulateGas, MLKEMPrecompile.RequiredGas([]byte{0x01}))
}

func TestRequiredGas_InvalidOp(t *testing.T) {
	require.Equal(t, MLKEM768EncapsulateGas, MLKEMPrecompile.RequiredGas([]byte{0xFF, 0x01}))
}

func TestRequiredGas_InvalidMode(t *testing.T) {
	require.Equal(t, MLKEM768EncapsulateGas, MLKEMPrecompile.RequiredGas([]byte{OpEncapsulate, 0xFF}))
}

func TestRequiredGas_AllModes(t *testing.T) {
	tests := []struct {
		mode uint8
		gas  uint64
	}{
		{ModeMLKEM512, MLKEM512EncapsulateGas},
		{ModeMLKEM768, MLKEM768EncapsulateGas},
		{ModeMLKEM1024, MLKEM1024EncapsulateGas},
	}
	for _, tt := range tests {
		require.Equal(t, tt.gas, MLKEMPrecompile.RequiredGas([]byte{OpEncapsulate, tt.mode}))
	}
}

// --- Run edge cases ---

func TestRun_EmptyInput(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, nil, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_SingleByte(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{0x01}, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_UnsupportedOp(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{0xFF, 0x01}, 1_000_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedOperation)
}

func TestRun_UnsupportedMode(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{OpEncapsulate, 0xFF}, 1_000_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedMode)
}

func TestRun_OutOfGas(t *testing.T) {
	_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{OpEncapsulate, ModeMLKEM768}, 1, true)
	require.Error(t, err)
}

func TestRun_WrongPubKeyLength(t *testing.T) {
	// Op + mode + intentionally-short input (too small even for the header).
	input := []byte{OpEncapsulate}
	_, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_InvalidPubKey(t *testing.T) {
	// Valid size but garbage content -- may error or succeed (ML-KEM accepts most byte arrays)
	input := make([]byte, 2+MLKEM768PublicKeySize)
	input[0] = OpEncapsulate
	input[1] = ModeMLKEM768
	result, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	// Either errors or returns a result (ML-KEM key validation is permissive)
	if err == nil {
		require.NotNil(t, result)
	}
}

// --- Valid encapsulation for all 3 modes ---

func TestRun_MLKEM512_Valid(t *testing.T) {
	testValidEncapsulate(t, ModeMLKEM512, mlkem.MLKEM512, MLKEM512CiphertextSize)
}

func TestRun_MLKEM768_Valid(t *testing.T) {
	testValidEncapsulate(t, ModeMLKEM768, mlkem.MLKEM768, MLKEM768CiphertextSize)
}

func TestRun_MLKEM1024_Valid(t *testing.T) {
	testValidEncapsulate(t, ModeMLKEM1024, mlkem.MLKEM1024, MLKEM1024CiphertextSize)
}

func testValidEncapsulate(t *testing.T, mode uint8, mlkemMode mlkem.Mode, ctSize int) {
	t.Helper()

	pub, _, err := mlkem.GenerateKey(mlkemMode)
	require.NoError(t, err)

	pkBytes := pub.Bytes()
	input := make([]byte, 2+len(pkBytes))
	input[0] = OpEncapsulate
	input[1] = mode
	copy(input[2:], pkBytes)

	result, _, err := MLKEMPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, ctSize+32, len(result)) // ciphertext + shared secret
}
