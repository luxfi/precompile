// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blake3

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

type fakeConfig struct{}

func (f *fakeConfig) Key() string                               { return "fake" }
func (f *fakeConfig) Timestamp() *uint64                        { return nil }
func (f *fakeConfig) IsDisabled() bool                          { return false }
func (f *fakeConfig) Equal(precompileconfig.Config) bool        { return false }
func (f *fakeConfig) Verify(precompileconfig.ChainConfig) error { return nil }

type testChainCfg struct{}

func (t *testChainCfg) IsDurango(uint64) bool { return true }

func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&testChainCfg{}))
	require.True(t, cfg.Equal(&Config{}))
	require.False(t, cfg.Equal(&fakeConfig{}))

	ts := uint64(42)
	cfg2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg2.Timestamp())

	cfg3 := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, cfg3.IsDisabled())
	require.False(t, cfg.Equal(cfg3))
}

func TestConfigurator(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, c.Configure(&testChainCfg{}, cfg, nil, nil))
}

func TestModuleRegistered(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)
}

// --- Run paths for full coverage ---

func TestRunEmptyInput(t *testing.T) {
	p := &blake3Precompile{}
	_, _, err := p.Run(nil, common.Address{}, ContractAddress, []byte{}, 1000000, true)
	require.Error(t, err)
	require.Equal(t, ErrInvalidInput, err)
}

func TestRunHash256(t *testing.T) {
	p := &blake3Precompile{}
	input := append([]byte{OpHash256}, []byte("hello world")...)
	ret, gas, err := p.Run(nil, common.Address{}, ContractAddress, input, 1000000, true)
	require.NoError(t, err)
	require.Len(t, ret, DigestLength32)
	require.Less(t, gas, uint64(1000000))
}

func TestRunHash512(t *testing.T) {
	p := &blake3Precompile{}
	input := append([]byte{OpHash512}, []byte("hello world")...)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, input, 1000000, true)
	require.NoError(t, err)
	require.Len(t, ret, DigestLength64)
}

func TestRunHashXOF(t *testing.T) {
	p := &blake3Precompile{}
	data := make([]byte, 5+10)
	data[0] = OpHashXOF
	binary.BigEndian.PutUint32(data[1:5], 64) // output 64 bytes
	copy(data[5:], []byte("test input"))
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, data, 1000000, true)
	require.NoError(t, err)
	require.Len(t, ret, 64)
}

func TestRunHashWithDomain(t *testing.T) {
	p := &blake3Precompile{}
	domain := "test.domain"
	payload := []byte("data")
	data := make([]byte, 1+1+len(domain)+len(payload))
	data[0] = OpHashWithDomain
	data[1] = byte(len(domain))
	copy(data[2:], domain)
	copy(data[2+len(domain):], payload)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, data, 1000000, true)
	require.NoError(t, err)
	require.Len(t, ret, DigestLength32)
}

func TestRunMerkleRoot(t *testing.T) {
	p := &blake3Precompile{}
	data := make([]byte, 1+4+3*32)
	data[0] = OpMerkleRoot
	binary.BigEndian.PutUint32(data[1:5], 3) // 3 leaves (odd)
	for i := 0; i < 3; i++ {
		h := p.hash256([]byte{byte(i)})
		copy(data[5+i*32:], h)
	}
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, data, 1000000, true)
	require.NoError(t, err)
	require.Len(t, ret, DigestLength32)
}

func TestRunDeriveKey(t *testing.T) {
	p := &blake3Precompile{}
	ctx := "my.context"
	key := make([]byte, 32)
	data := make([]byte, 1+1+len(ctx)+32)
	data[0] = OpDeriveKey
	data[1] = byte(len(ctx))
	copy(data[2:], ctx)
	copy(data[2+len(ctx):], key)
	ret, _, err := p.Run(nil, common.Address{}, ContractAddress, data, 1000000, true)
	require.NoError(t, err)
	require.Len(t, ret, DigestLength32)
}

// --- RequiredGas edge cases ---

func TestRequiredGasEdgeCases(t *testing.T) {
	p := &blake3Precompile{}

	// Empty
	require.Equal(t, uint64(0), p.RequiredGas(nil))

	// XOF with short input
	require.Equal(t, uint64(0), p.RequiredGas([]byte{OpHashXOF, 0, 0}))

	// MerkleRoot short
	require.Equal(t, uint64(0), p.RequiredGas([]byte{OpMerkleRoot, 0, 0}))

	// Unknown op
	require.Equal(t, uint64(0), p.RequiredGas([]byte{0xFF}))

	// EvaluatePolynomial (OpEvaluatePolynomial is not defined in blake3)
}

// --- hash256 large input ---

func TestHash256LargeInput(t *testing.T) {
	p := &blake3Precompile{}
	// Input exceeding MaxInputLength
	large := make([]byte, MaxInputLength+100)
	for i := range large {
		large[i] = byte(i)
	}
	result := p.hash256(large)
	require.Len(t, result, DigestLength32)
}

// --- hash512 large input ---

func TestHash512LargeInput(t *testing.T) {
	p := &blake3Precompile{}
	large := make([]byte, MaxInputLength+100)
	result := p.hash512(large)
	require.Len(t, result, DigestLength64)
}

// --- hashXOF errors ---

func TestHashXOFErrors(t *testing.T) {
	p := &blake3Precompile{}
	// Short data
	_, _, err := p.hashXOF([]byte{0, 0})
	require.Error(t, err)
}

// --- hashWithDomain errors ---

func TestHashWithDomainErrors(t *testing.T) {
	p := &blake3Precompile{}
	// Empty
	_, _, err := p.hashWithDomain(nil)
	require.Error(t, err)

	// Domain length exceeds data
	_, _, err = p.hashWithDomain([]byte{10}) // says 10 bytes but only 0 follow
	require.Error(t, err)
}

// --- merkleRoot errors ---

func TestMerkleRootErrors(t *testing.T) {
	p := &blake3Precompile{}
	// Short
	_, _, err := p.merkleRoot([]byte{0, 0})
	require.Error(t, err)

	// Data too short for declared leaves
	data := make([]byte, 4+10)
	binary.BigEndian.PutUint32(data[:4], 5) // says 5 leaves but only 10 bytes follow
	_, _, err = p.merkleRoot(data)
	require.Error(t, err)
}

// --- deriveKey errors ---

func TestDeriveKeyErrors(t *testing.T) {
	p := &blake3Precompile{}
	// Empty
	_, _, err := p.deriveKey(nil)
	require.Error(t, err)

	// Context length exceeds data
	_, _, err = p.deriveKey([]byte{50}) // says 50 bytes context but nothing follows
	require.Error(t, err)
}

// --- computeMerkleRoot edge ---

func TestComputeMerkleRootSingleLeaf(t *testing.T) {
	p := &blake3Precompile{}
	leaf := make([]byte, 32)
	copy(leaf, []byte("single leaf"))
	result := p.computeMerkleRoot([][]byte{leaf})
	require.Equal(t, leaf, result)
}

func TestComputeMerkleRootEmpty(t *testing.T) {
	p := &blake3Precompile{}
	result := p.computeMerkleRoot(nil)
	require.Len(t, result, DigestLength32)
}
