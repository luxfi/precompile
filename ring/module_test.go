// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"testing"

	"github.com/luxfi/precompile/modules"
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
	require.Equal(t, "ringConfig", cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&testChainCfg{}))
	require.True(t, cfg.Equal(&Config{}))
	require.False(t, cfg.Equal(&fakeConfig{}), "a config of another type is never equal")
	require.False(t, cfg.Equal(nil), "nil is never equal")

	ts := uint64(42)
	cfg2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg2.Timestamp())
	require.False(t, cfg.Equal(cfg2), "configs differing in timestamp are not equal")
	require.False(t, cfg2.Equal(cfg))

	cfg3 := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, cfg3.IsDisabled())
	require.False(t, cfg.Equal(cfg3), "configs differing in disable are not equal")
}

func TestConfigurator(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NotSame(t, cfg, c.MakeConfig(), "MakeConfig hands out a fresh value each call")
	require.NoError(t, c.Configure(&testChainCfg{}, cfg, nil, nil))
}

// The init() registration is what makes the precompile reachable at all;
// assert the registry actually holds this address, key and contract.
func TestModuleRegistered(t *testing.T) {
	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractAddress)
	require.True(t, ok, "no module registered at 0x9202")
	require.Equal(t, ConfigKey, byAddr.ConfigKey)
	require.Same(t, RingSignaturePrecompile, byAddr.Contract)

	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, ContractAddress, byKey.Address)
	require.Equal(t, ContractAddress, RingSignaturePrecompile.Address(),
		"the contract must answer with the address it is registered under")
}
