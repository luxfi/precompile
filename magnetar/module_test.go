// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

import (
	"testing"

	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// fakeConfig is a Config-shaped value from another precompile. Equal must
// refuse it: two precompiles whose configs compared equal would let an upgrade
// for one be accepted as an upgrade for the other.
type fakeConfig struct{}

func (f *fakeConfig) Key() string                               { return "fake" }
func (f *fakeConfig) Timestamp() *uint64                        { return nil }
func (f *fakeConfig) IsDisabled() bool                          { return false }
func (f *fakeConfig) Equal(precompileconfig.Config) bool        { return false }
func (f *fakeConfig) Verify(precompileconfig.ChainConfig) error { return nil }

type testChainCfg struct{}

func (t *testChainCfg) IsDurango(uint64) bool { return true }

// TestConfigLifecycle covers the upgrade surface the chain config machinery
// drives: the key it is filed under, the activation timestamp, the disable
// switch, and the equality the upgrade reconciler uses to decide whether a
// config changed.
func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Equal(t, "magnetarVerify", cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&testChainCfg{}))

	require.True(t, cfg.Equal(&Config{}))
	require.False(t, cfg.Equal(&fakeConfig{}), "a foreign config type is never equal")
	require.False(t, cfg.Equal(nil), "a nil config is never equal")

	ts := uint64(42)
	at := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, at.Timestamp())
	require.False(t, at.IsDisabled())
	require.False(t, cfg.Equal(at), "configs activating at different times differ")
	require.False(t, at.Equal(cfg))

	other := uint64(43)
	require.False(t, at.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}))
	require.True(t, at.Equal(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}))

	off := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, off.IsDisabled())
	require.False(t, cfg.Equal(off), "a disabling config differs from an enabling one")
}

// TestConfigurator covers the two calls the module machinery makes: minting a
// fresh config to decode JSON into, and applying it at the activation block.
// Magnetar is a pure verifier with no genesis state, so Configure writes
// nothing and must succeed even with a nil StateDB.
func TestConfigurator(t *testing.T) {
	c := &configurator{}

	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.IsType(t, &Config{}, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NotSame(t, cfg, c.MakeConfig(), "each call must mint a fresh config")

	require.NoError(t, c.Configure(&testChainCfg{}, cfg, nil, nil))
}

// TestModuleRegistration checks that init put the precompile in the registry
// under its own key and its own address, and that both lookups return the same
// module -- the address is what the EVM dispatches on, the key is what the
// chain config names.
func TestModuleRegistration(t *testing.T) {
	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok, "module %q is not registered", ConfigKey)
	require.Equal(t, ContractMagnetarVerifyAddress, byKey.Address)
	require.Equal(t, MagnetarVerifyPrecompile, byKey.Contract)

	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractMagnetarVerifyAddress)
	require.True(t, ok, "no module at slot 0x012207")
	require.Equal(t, ConfigKey, byAddr.ConfigKey)
	require.Equal(t, byKey, byAddr)

	require.IsType(t, &Config{}, byKey.Configurator.MakeConfig())

	// The registry refuses a second module on the same key or address, which
	// is what makes init's panic arm the right response to a collision.
	require.Error(t, modules.RegisterModule(modules.Module{
		ConfigKey:    ConfigKey,
		Address:      ContractMagnetarVerifyAddress,
		Contract:     MagnetarVerifyPrecompile,
		Configurator: &configurator{},
	}), "registering the same key twice must be refused")
}
