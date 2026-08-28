// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"testing"

	"github.com/luxfi/geth/common"
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
	require.Equal(t, "cggmp21Verify", cfg.Key())
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
}

func TestConfigurator(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.Equal(t, "cggmp21Verify", cfg.Key())
	require.NoError(t, c.Configure(&testChainCfg{}, cfg, nil, nil))
}

// TestModuleRegistration: init() registers the precompile, and the only way to
// see that it did is to look it up. The address and the config key are both
// consensus-visible -- the address is where the EVM dispatches and the key is
// how a chain config turns the precompile on -- so both are asserted, by
// address and by key, and the two lookups must agree.
//
// The duplicate registration asserts the guard init() relies on: a second
// module claiming this address or key is refused rather than silently
// shadowing. init()'s own panic(err) statement cannot be reached from a test
// (it runs once, before any test, and only fires on a collision that cannot
// exist by then), so this is the closest reachable statement of the same
// property.
func TestModuleRegistration(t *testing.T) {
	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractCGGMP21VerifyAddress)
	require.True(t, ok, "the CGGMP21 module must be registered at its address")
	byKey, ok := modules.GetPrecompileModule("cggmp21Verify")
	require.True(t, ok, "the CGGMP21 module must be registered under its config key")
	require.Equal(t, byAddr, byKey, "address and key must name the same module")
	require.Equal(t, CGGMP21VerifyPrecompile, byAddr.Contract)
	require.Equal(t, "cggmp21Verify", byAddr.ConfigKey)

	require.Error(t, modules.RegisterModule(modules.Module{
		ConfigKey:    "cggmp21Verify",
		Address:      common.HexToAddress("0x0800000000000000000000000000000000000043"),
		Contract:     CGGMP21VerifyPrecompile,
		Configurator: &configurator{},
	}), "a second module must not be able to claim this config key")

	require.Error(t, modules.RegisterModule(modules.Module{
		ConfigKey:    "cggmp21VerifyImpostor",
		Address:      ContractCGGMP21VerifyAddress,
		Contract:     CGGMP21VerifyPrecompile,
		Configurator: &configurator{},
	}), "a second module must not be able to claim this address")
}
