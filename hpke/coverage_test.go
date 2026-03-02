// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hpke

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/hpke"
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

// --- deterministicReader ---

func TestDeterministicReader_Determinism(t *testing.T) {
	seed := sha256.Sum256([]byte("test seed"))
	r1 := newDeterministicReader(seed)
	r2 := newDeterministicReader(seed)

	buf1 := make([]byte, 100)
	buf2 := make([]byte, 100)
	n1, err1 := r1.Read(buf1)
	n2, err2 := r2.Read(buf2)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, n1, n2)
	require.Equal(t, buf1, buf2)
}

func TestDeterministicReader_LargeRead(t *testing.T) {
	seed := sha256.Sum256([]byte("large read"))
	r := newDeterministicReader(seed)

	// Read more than 32 bytes (forces state refresh)
	buf := make([]byte, 100)
	n, err := r.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 100, n)

	// Ensure no zero runs (deterministic but not trivially zero)
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero)
}

// --- kemGas ---

func TestKemGas_AllKEMs(t *testing.T) {
	tests := []struct {
		kemID uint16
		gas   uint64
	}{
		{KEMP256, GasKEMEncapsP256},
		{KEMP384, GasKEMEncapsP384},
		{KEMP521, GasKEMEncapsP521},
		{KEMX25519, GasKEMEncapsX25519},
		{KEMX25519Kyber768, GasKEMEncapsX25519Kyber768},
		{KEMXWing, GasKEMEncapsXWing},
		{0xFFFF, GasKEMEncapsX25519}, // unknown defaults to X25519
	}
	for _, tt := range tests {
		require.Equal(t, tt.gas, kemGas(tt.kemID))
	}
}

// --- isKyberKEM ---

func TestIsKyberKEM(t *testing.T) {
	require.True(t, isKyberKEM(KEMX25519Kyber768))
	require.True(t, isKyberKEM(KEMXWing))
	require.False(t, isKyberKEM(KEMX25519))
	require.False(t, isKyberKEM(KEMP256))
}

// --- parseSuite edge cases ---

func TestParseSuite_TooShort(t *testing.T) {
	p := HPKEPrecompile
	_, err := p.parseSuite([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

func TestParseSuite_InvalidKEM(t *testing.T) {
	p := HPKEPrecompile
	input := []byte{0xFF, 0xFF, 0x00, 0x01, 0x00, 0x01}
	_, err := p.parseSuite(input)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCipherSuite)
}

func TestParseSuite_InvalidKDF(t *testing.T) {
	p := HPKEPrecompile
	input := []byte{0x00, 0x20, 0xFF, 0xFF, 0x00, 0x01} // valid KEM, invalid KDF
	_, err := p.parseSuite(input)
	require.Error(t, err)
}

func TestParseSuite_InvalidAEAD(t *testing.T) {
	p := HPKEPrecompile
	input := []byte{0x00, 0x20, 0x00, 0x01, 0xFF, 0xFF} // valid KEM+KDF, invalid AEAD
	_, err := p.parseSuite(input)
	require.Error(t, err)
}

func TestParseSuite_AllKEMs(t *testing.T) {
	p := HPKEPrecompile
	kems := []uint16{KEMP256, KEMP384, KEMP521, KEMX25519, KEMX25519Kyber768, KEMXWing}
	for _, kemID := range kems {
		input := make([]byte, 6)
		binary.BigEndian.PutUint16(input[0:], kemID)
		input[2], input[3] = 0x00, 0x01 // KDF_HKDF_SHA256
		input[4], input[5] = 0x00, 0x01 // AEAD_AES128GCM
		_, err := p.parseSuite(input)
		require.NoError(t, err, "KEM 0x%04x", kemID)
	}
}

func TestParseSuite_AllKDFs(t *testing.T) {
	p := HPKEPrecompile
	kdfs := []uint16{0x0001, 0x0002, 0x0003}
	for _, kdf := range kdfs {
		input := make([]byte, 6)
		input[0], input[1] = 0x00, 0x20 // KEMX25519
		binary.BigEndian.PutUint16(input[2:], kdf)
		input[4], input[5] = 0x00, 0x01 // AEAD_AES128GCM
		_, err := p.parseSuite(input)
		require.NoError(t, err, "KDF 0x%04x", kdf)
	}
}

func TestParseSuite_AllAEADs(t *testing.T) {
	p := HPKEPrecompile
	aeads := []uint16{0x0001, 0x0002, 0x0003}
	for _, aead := range aeads {
		input := make([]byte, 6)
		input[0], input[1] = 0x00, 0x20 // KEMX25519
		input[2], input[3] = 0x00, 0x01 // KDF_HKDF_SHA256
		binary.BigEndian.PutUint16(input[4:], aead)
		_, err := p.parseSuite(input)
		require.NoError(t, err, "AEAD 0x%04x", aead)
	}
}

// --- parseSealParams edge cases ---

func TestParseSealParams_TooShort(t *testing.T) {
	p := HPKEPrecompile
	_, err := p.parseSealParams([]byte{0x00})
	require.Error(t, err)
}

func TestParseSealParams_ShortRecipientPK(t *testing.T) {
	p := HPKEPrecompile
	input := make([]byte, 6+SeedSize+2)
	input[0], input[1] = 0x00, 0x20 // KEMX25519
	input[2], input[3] = 0x00, 0x01 // KDF
	input[4], input[5] = 0x00, 0x01 // AEAD
	// seed (32 bytes zero)
	// pkLen = 100 but no data
	input[6+SeedSize] = 0
	input[6+SeedSize+1] = 100
	_, err := p.parseSealParams(input)
	require.Error(t, err)
}

func TestParseSealParams_ShortInfoLen(t *testing.T) {
	p := HPKEPrecompile
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pkSize := kemID.Scheme().PublicKeySize()

	// Build input with pk but missing info length
	input := make([]byte, 6+SeedSize+2+pkSize)
	input[0], input[1] = 0x00, 0x20 // KEMX25519
	input[2], input[3] = 0x00, 0x01
	input[4], input[5] = 0x00, 0x01
	binary.BigEndian.PutUint16(input[6+SeedSize:], uint16(pkSize))
	_, err := p.parseSealParams(input)
	require.Error(t, err)
}

func TestParseSealParams_ShortInfoData(t *testing.T) {
	p := HPKEPrecompile
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pkSize := kemID.Scheme().PublicKeySize()

	input := make([]byte, 6+SeedSize+2+pkSize+2)
	input[0], input[1] = 0x00, 0x20
	input[2], input[3] = 0x00, 0x01
	input[4], input[5] = 0x00, 0x01
	binary.BigEndian.PutUint16(input[6+SeedSize:], uint16(pkSize))
	// info len = 10 but no data
	offset := 6 + SeedSize + 2 + pkSize
	binary.BigEndian.PutUint16(input[offset:], 10)
	_, err := p.parseSealParams(input)
	require.Error(t, err)
}

func TestParseSealParams_ShortAADLen(t *testing.T) {
	p := HPKEPrecompile
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pkSize := kemID.Scheme().PublicKeySize()

	// input with pk + infoLen=0 but missing aadLen
	input := make([]byte, 6+SeedSize+2+pkSize+2)
	input[0], input[1] = 0x00, 0x20
	input[2], input[3] = 0x00, 0x01
	input[4], input[5] = 0x00, 0x01
	binary.BigEndian.PutUint16(input[6+SeedSize:], uint16(pkSize))
	// info len = 0 -> next should be aad len, but not enough room
	_, err := p.parseSealParams(input)
	require.Error(t, err)
}

func TestParseSealParams_ShortAADData(t *testing.T) {
	p := HPKEPrecompile
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pkSize := kemID.Scheme().PublicKeySize()

	input := make([]byte, 6+SeedSize+2+pkSize+2+2)
	input[0], input[1] = 0x00, 0x20
	input[2], input[3] = 0x00, 0x01
	input[4], input[5] = 0x00, 0x01
	binary.BigEndian.PutUint16(input[6+SeedSize:], uint16(pkSize))
	offset := 6 + SeedSize + 2 + pkSize
	binary.BigEndian.PutUint16(input[offset:], 0)   // info len = 0
	binary.BigEndian.PutUint16(input[offset+2:], 10) // aad len = 10 but no data
	_, err := p.parseSealParams(input)
	require.Error(t, err)
}

// --- RequiredGas edge cases ---

func TestRequiredGas_EmptyInput(t *testing.T) {
	require.Equal(t, uint64(0), HPKEPrecompile.RequiredGas(nil))
}

func TestRequiredGas_UnknownOp(t *testing.T) {
	require.Equal(t, uint64(0), HPKEPrecompile.RequiredGas([]byte{0xFF}))
}

func TestRequiredGas_SealShortInput(t *testing.T) {
	// Op = Seal but too short for suite+seed — exact value fixed by contract.go.
	gas := HPKEPrecompile.RequiredGas([]byte{OpSingleShotSeal, 0x00})
	require.Greater(t, gas, uint64(0), "short seal input still consumes gas")
}

func TestRequiredGas_SealWithKEM(t *testing.T) {
	input := make([]byte, 1+6+SeedSize+6)
	input[0] = OpSingleShotSeal
	input[1], input[2] = 0x00, 0x10 // KEMP256
	input[3], input[4] = 0x00, 0x01
	input[5], input[6] = 0x00, 0x01
	gas := HPKEPrecompile.RequiredGas(input)
	require.True(t, gas >= GasKEMEncapsP256+GasKDFExtract+GasAEADBase)
}

// --- Run edge cases ---

func TestRun_EmptyInput(t *testing.T) {
	_, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, nil, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_UnknownOp(t *testing.T) {
	_, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, []byte{0xFF}, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_SealInvalidPK(t *testing.T) {
	seed := sha256.Sum256([]byte("invalid pk test"))
	sealData := buildSealInput(KEMX25519, 0x0001, 0x0001, make([]byte, 32), seed, nil, nil, []byte("plaintext"))
	input := append([]byte{OpSingleShotSeal}, sealData...)
	_, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.Error(t, err)
}

func TestRun_SealValid_X25519(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pk, _, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := sha256.Sum256([]byte("deterministic seed"))
	sealData := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed, []byte("info"), []byte("aad"), []byte("hello"))
	input := append([]byte{OpSingleShotSeal}, sealData...)
	result, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, len(result) > 0)
}

func TestRun_SealValid_P256(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pk, _, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := sha256.Sum256([]byte("p256 seed"))
	sealData := buildSealInput(KEMP256, 0x0001, 0x0001, pkBytes, seed, nil, nil, []byte("encrypted"))
	input := append([]byte{OpSingleShotSeal}, sealData...)
	result, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRun_SealValid_P384(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_P384_HKDF_SHA384, hpke.KDF_HKDF_SHA384, hpke.AEAD_AES256GCM)
	kemID, _, _ := suite.Params()
	pk, _, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := sha256.Sum256([]byte("p384 seed"))
	sealData := buildSealInput(KEMP384, 0x0002, 0x0002, pkBytes, seed, nil, nil, []byte("data"))
	input := append([]byte{OpSingleShotSeal}, sealData...)
	result, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRun_SealValid_P521(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_P521_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_ChaCha20Poly1305)
	kemID, _, _ := suite.Params()
	pk, _, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := sha256.Sum256([]byte("p521 seed"))
	sealData := buildSealInput(KEMP521, 0x0003, 0x0003, pkBytes, seed, nil, nil, []byte("secret"))
	input := append([]byte{OpSingleShotSeal}, sealData...)
	result, _, err := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRun_SealDeterministic(t *testing.T) {
	suite := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kemID, _, _ := suite.Params()
	pk, _, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)

	seed := sha256.Sum256([]byte("deterministic"))
	sealData := buildSealInput(KEMX25519, 0x0001, 0x0001, pkBytes, seed, nil, nil, []byte("test"))
	input := append([]byte{OpSingleShotSeal}, sealData...)

	r1, _, err1 := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	r2, _, err2 := HPKEPrecompile.Run(nil, common.Address{}, ContractAddress, input, 1_000_000, true)
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, r1, r2)
}

// buildSealInput is defined in contract_test.go
