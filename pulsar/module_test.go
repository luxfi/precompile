// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"testing"

	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// otherConfig is a Config from a different precompile, used to pin
// that Equal refuses to compare across types.
type otherConfig struct{}

func (*otherConfig) Key() string                               { return "other" }
func (*otherConfig) Timestamp() *uint64                        { return nil }
func (*otherConfig) IsDisabled() bool                          { return false }
func (*otherConfig) Equal(precompileconfig.Config) bool        { return false }
func (*otherConfig) Verify(precompileconfig.ChainConfig) error { return nil }

type chainCfg struct{}

func (*chainCfg) IsDurango(uint64) bool { return true }

// TestConfigLifecycle walks the activation surface a chain config
// drives: the key it is addressed by, the timestamp that gates it, the
// disable switch, and equality.
func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp(), "no upgrade timestamp means unset, not zero")
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(&chainCfg{}))

	ts := uint64(1766708400)
	at := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, at.Timestamp())

	off := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, off.IsDisabled())
}

// TestConfigEqualDiscriminates is the half of Equal that matters. A
// config comparison that returned true too readily would let an
// upgrade schedule change without the node noticing a fork, so pin
// both directions: same timestamp equal, different timestamp not
// equal, disabled not equal to enabled, and a foreign config type
// never equal regardless of its contents.
func TestConfigEqualDiscriminates(t *testing.T) {
	a, b := uint64(100), uint64(200)

	require.True(t, (&Config{}).Equal(&Config{}))
	require.True(t,
		(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &a}}).Equal(
			&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &a}}))
	require.False(t,
		(&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &a}}).Equal(
			&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &b}}),
		"different activation timestamps are different configs")
	require.False(t,
		(&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).Equal(&Config{}),
		"disabled is not equal to enabled")
	require.False(t, (&Config{}).Equal(&otherConfig{}),
		"a config of another precompile is never equal")
	require.False(t, (&Config{}).Equal(nil))
}

// TestConfiguratorMakesOwnConfig pins that the configurator hands back
// a config addressed by THIS precompile's key. A copy-paste that
// returned a sibling's config would silently bind the wrong upgrade
// schedule to this address.
func TestConfiguratorMakesOwnConfig(t *testing.T) {
	c := &configurator{}
	cfg := c.MakeConfig()
	require.NotNil(t, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
	require.IsType(t, &Config{}, cfg)
	require.NoError(t, c.Configure(&chainCfg{}, cfg, nil, nil))

	// Each call yields a fresh value: a shared instance would let one
	// chain config mutate another's activation.
	require.NotSame(t, cfg, c.MakeConfig())
}

// TestModuleRegisteredAtCanonicalAddress pins the registration that
// init() performed. The address is consensus-visible: a module bound
// to the wrong slot routes calls meant for Pulsar somewhere else.
func TestModuleRegisteredAtCanonicalAddress(t *testing.T) {
	m, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok, "init() must have registered %q", ConfigKey)
	require.Equal(t, ContractPulsarVerifyAddress, m.Address)
	require.Same(t, PulsarVerifyPrecompile, m.Contract)

	byAddr, ok := modules.GetPrecompileModuleByAddress(ContractPulsarVerifyAddress)
	require.True(t, ok)
	require.Equal(t, ConfigKey, byAddr.ConfigKey,
		"the address must resolve back to this module, not a neighbour")
}
