// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"

	"github.com/luxfi/crypto/mldsa"
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

// --- readUint256 edge cases ---

func TestReadUint256_WrongLen(t *testing.T) {
	require.Equal(t, uint64(0), readUint256(nil))
	require.Equal(t, uint64(0), readUint256(make([]byte, 31)))
	require.Equal(t, uint64(0), readUint256(make([]byte, 33)))
}

func TestReadUint256_Zero(t *testing.T) {
	require.Equal(t, uint64(0), readUint256(make([]byte, 32)))
}

func TestReadUint256_SmallValue(t *testing.T) {
	b := make([]byte, 32)
	b[31] = 42
	require.Equal(t, uint64(42), readUint256(b))
}

func TestReadUint256_LargeValue(t *testing.T) {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], 0x123456789ABCDEF0)
	require.Equal(t, uint64(0x123456789ABCDEF0), readUint256(b))
}

// Legacy format tests removed along with the legacy production code.
// Only the explicit mode-byte format is supported.

// --- RequiredGas edge cases ---

func TestRequiredGas_EmptyInput(t *testing.T) {
	require.Equal(t, MLDSA65VerifyBaseGas, MLDSAVerifyPrecompile.RequiredGas(nil))
	require.Equal(t, MLDSA65VerifyBaseGas, MLDSAVerifyPrecompile.RequiredGas([]byte{}))
}

func TestRequiredGas_InvalidMode(t *testing.T) {
	require.Equal(t, MLDSA65VerifyBaseGas, MLDSAVerifyPrecompile.RequiredGas([]byte{0xFF}))
}

func TestRequiredGas_BatchOp(t *testing.T) {
	// op=0x10, mode=0x65, count=3
	input := []byte{OpBatchVerify, ModeMLDSA65, 0x00, 0x03}
	expected := BatchVerifyBaseGas + 3*BatchVerifyPerSigGas
	require.Equal(t, expected, MLDSAVerifyPrecompile.RequiredGas(input))
}

func TestRequiredGas_BatchOpShortInput(t *testing.T) {
	input := []byte{OpBatchVerify, ModeMLDSA65}
	require.Equal(t, BatchVerifyBaseGas, MLDSAVerifyPrecompile.RequiredGas(input))
}

func TestRequiredGas_ShortForMsgLen(t *testing.T) {
	// Mode byte + short input (not enough for pubkey + msg length)
	input := []byte{ModeMLDSA65}
	_, _, baseGas, _, _ := getModeParams(ModeMLDSA65)
	require.Equal(t, baseGas, MLDSAVerifyPrecompile.RequiredGas(input))
}

func TestRequiredGas_OverflowMsgLen(t *testing.T) {
	// Build input with mode + full pubkey + msg length that overflows
	input := make([]byte, 1+MLDSA65PublicKeySize+32)
	input[0] = ModeMLDSA65
	// Set msg length to overflow value
	for i := range 8 {
		input[1+MLDSA65PublicKeySize+24+i] = 0xFF
	}
	require.Equal(t, uint64(math.MaxUint64), MLDSAVerifyPrecompile.RequiredGas(input))
}

// --- Run edge cases ---

func TestRun_EmptyInput(t *testing.T) {
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, nil, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_UnsupportedMode(t *testing.T) {
	input := []byte{0xFF}
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedMode)
}

func TestRun_TruncatedInput(t *testing.T) {
	input := []byte{ModeMLDSA65, 0x01} // too short for pubkey
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_WrongMessageLength(t *testing.T) {
	// Truncate an otherwise-valid input to below the minimum header size.
	input := []byte{ModeMLDSA44}
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err, "input below header size must error")
}

func TestRun_InvalidPubKey(t *testing.T) {
	// Valid format but garbage public key -- may error or return invalid
	pk := make([]byte, MLDSA44PublicKeySize)
	sig := make([]byte, MLDSA44SignatureSize)
	message := []byte("test")

	input := createInputWithMode(ModeMLDSA44, pk, sig, message)
	result, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	if err == nil {
		require.Equal(t, byte(0), result[31], "garbage key must not verify")
	}
}

// --- Batch verify edge cases ---

func TestBatchVerify_EmptyBatch(t *testing.T) {
	// op=0x10, mode=0x65, count=0
	input := []byte{OpBatchVerify, ModeMLDSA65, 0x00, 0x00}
	result, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, 32, len(result))
}

func TestBatchVerify_TooShortHeader(t *testing.T) {
	input := []byte{OpBatchVerify, ModeMLDSA65}
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_UnsupportedMode(t *testing.T) {
	input := []byte{OpBatchVerify, 0xFF, 0x00, 0x01}
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_TruncatedAtPubkey(t *testing.T) {
	// count=1 but no data
	input := []byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x01}
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_TruncatedAtMsgLen(t *testing.T) {
	input := make([]byte, 4+MLDSA44PublicKeySize) // header + pubkey but no msglen
	input[0] = OpBatchVerify
	input[1] = ModeMLDSA44
	input[3] = 1
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 10_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_TruncatedAtSig(t *testing.T) {
	input := make([]byte, 4+MLDSA44PublicKeySize+32) // header + pubkey + msglen but no sig
	input[0] = OpBatchVerify
	input[1] = ModeMLDSA44
	input[3] = 1
	// msglen = 0
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 10_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_TruncatedAtMessage(t *testing.T) {
	input := make([]byte, 4+MLDSA44PublicKeySize+32+MLDSA44SignatureSize)
	input[0] = OpBatchVerify
	input[1] = ModeMLDSA44
	input[3] = 1
	// msglen = 10 but no message data
	input[4+MLDSA44PublicKeySize+31] = 10
	_, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 10_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_TrailingBytes(t *testing.T) {
	message := []byte("test")
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
	require.NoError(t, err)
	sig, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	pk := priv.PublicKey.Bytes()

	// Build valid batch entry
	entry := make([]byte, 0)
	entry = append(entry, pk...)
	msgLen := make([]byte, 32)
	msgLen[31] = byte(len(message))
	entry = append(entry, msgLen...)
	entry = append(entry, sig...)
	entry = append(entry, message...)

	header := []byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x01}
	input := append(header, entry...)
	input = append(input, 0xFF) // trailing byte

	_, _, err = MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 10_000_000, true)
	require.Error(t, err)
}

func TestBatchVerify_SingleValid(t *testing.T) {
	message := []byte("batch test")
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA44)
	require.NoError(t, err)
	sig, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	pk := priv.PublicKey.Bytes()

	entry := make([]byte, 0)
	entry = append(entry, pk...)
	msgLen := make([]byte, 32)
	msgLen[31] = byte(len(message))
	entry = append(entry, msgLen...)
	entry = append(entry, sig...)
	entry = append(entry, message...)

	header := []byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x01}
	input := append(header, entry...)

	result, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 10_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31])
}

func TestBatchVerify_SingleInvalid(t *testing.T) {
	pk := make([]byte, MLDSA44PublicKeySize)   // garbage key
	sig := make([]byte, MLDSA44SignatureSize)   // garbage sig
	message := []byte("test")

	entry := make([]byte, 0)
	entry = append(entry, pk...)
	msgLen := make([]byte, 32)
	msgLen[31] = byte(len(message))
	entry = append(entry, msgLen...)
	entry = append(entry, sig...)
	entry = append(entry, message...)

	header := []byte{OpBatchVerify, ModeMLDSA44, 0x00, 0x01}
	input := append(header, entry...)

	result, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 10_000_000, true)
	// Garbage pubkey might error or return invalid
	if err == nil {
		require.Equal(t, byte(0), result[31])
	}
}

// --- All 3 modes single verify ---

func TestRun_MLDSA44_Valid(t *testing.T) {
	message := []byte("ML-DSA-44 test")
	pk, sig, msg := createTestSig(t, mldsa.MLDSA44, message)
	input := createInputWithMode(ModeMLDSA44, pk, sig, msg)
	result, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31])
}

func TestRun_MLDSA87_Valid(t *testing.T) {
	message := []byte("ML-DSA-87 test")
	pk, sig, msg := createTestSig(t, mldsa.MLDSA87, message)
	input := createInputWithMode(ModeMLDSA87, pk, sig, msg)
	result, _, err := MLDSAVerifyPrecompile.Run(nil, common.Address{}, ContractMLDSAVerifyAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), result[31])
}

func createTestSig(t testing.TB, mode mldsa.Mode, message []byte) ([]byte, []byte, []byte) {
	priv, err := mldsa.GenerateKey(rand.Reader, mode)
	require.NoError(t, err)
	sig, err := priv.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	return priv.PublicKey.Bytes(), sig, message
}

// createInputWithMode is defined in contract_test.go
