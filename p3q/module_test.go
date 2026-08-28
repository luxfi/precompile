// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"testing"

	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// foreignConfig stands in for another precompile's config so Equal's
// type discrimination is testable.
type foreignConfig struct{}

func (*foreignConfig) Key() string                               { return "foreign" }
func (*foreignConfig) Timestamp() *uint64                        { return nil }
func (*foreignConfig) IsDisabled() bool                          { return false }
func (*foreignConfig) Equal(precompileconfig.Config) bool        { return false }
func (*foreignConfig) Verify(precompileconfig.ChainConfig) error { return nil }

type chainCfg struct{}

func (*chainCfg) IsDurango(uint64) bool { return true }

// TestConfigLifecycle walks the activation surface: the key the config
// is addressed by, the timestamp that gates it, the disable switch,
// and self-verification.
func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Equal(t, "p3qVerify", cfg.Key(),
		"the config key is chain-config-visible; renaming it silently disables the precompile")
	require.Nil(t, cfg.Timestamp(), "unset is nil, not zero")
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&chainCfg{}))

	// LP-218 pins activation to the genesis of the new final network.
	ts := uint64(1766708400)
	at := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, at.Timestamp())

	off := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, off.IsDisabled())
	require.False(t, (&Config{}).IsDisabled())
}

// TestConfigEqualDiscriminates pins both directions of Equal. An
// over-permissive comparison would let two nodes disagree about the
// activation height without either noticing, which is a fork.
func TestConfigEqualDiscriminates(t *testing.T) {
	a, b := uint64(100), uint64(200)
	up := func(ts *uint64, dis bool) *Config {
		return &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ts, Disable: dis}}
	}

	require.True(t, (&Config{}).Equal(&Config{}))
	require.True(t, up(&a, false).Equal(up(&a, false)))
	require.False(t, up(&a, false).Equal(up(&b, false)), "different activation timestamps differ")
	require.False(t, up(&a, false).Equal(up(nil, false)), "set is not equal to unset")
	require.False(t, up(nil, true).Equal(up(nil, false)), "disabled is not equal to enabled")
	require.False(t, (&Config{}).Equal(&foreignConfig{}), "another precompile's config is never equal")
	require.False(t, (&Config{}).Equal(nil))
}

// TestConfiguratorMakesOwnConfig pins that the configurator hands back
// this precompile's config type, keyed to this precompile, and a fresh
// value each call.
func TestConfiguratorMakesOwnConfig(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.IsType(t, &Config{}, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, c.Configure(&chainCfg{}, cfg, nil, nil))
	require.NotSame(t, cfg, c.MakeConfig(), "each config must be independent")
}

// TestModuleRegisteredAtCanonicalSlot pins what init() registered.
// P3Q's slot is consensus-visible and sits inside a dense block of
// sibling PQ precompiles (0x012204 Pulsar either side of it, 0x012206
// Corona), so an address typo routes rollup-commit verification to a
// different primitive entirely.
func TestModuleRegisteredAtCanonicalSlot(t *testing.T) {
	m, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok, "init() must have registered %q", ConfigKey)
	require.Equal(t, ContractP3QVerifyAddress, m.Address)
	require.Same(t, P3QVerifyPrecompile, m.Contract)
	require.NotNil(t, m.Configurator)

	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractP3QVerifyAddress)
	require.True(t, ok)
	require.Equal(t, ConfigKey, byAddr.ConfigKey,
		"0x012205 must resolve to P3Q, not to a neighbouring slot")
}
