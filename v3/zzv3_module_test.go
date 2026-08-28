// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"testing"

	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// TestConfig_UpgradeSurface pins the activation config's contract: the key is the
// module key, the timestamp and disable flag pass through the embedded Upgrade,
// and Verify accepts (the AMM has no operator-supplied parameter to reject).
func TestConfig_UpgradeSurface(t *testing.T) {
	ts := uint64(1234)
	c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}

	require.Equal(t, ConfigKey, c.Key())
	require.Equal(t, Module.ConfigKey, c.Key())
	require.NotNil(t, c.Timestamp())
	require.Equal(t, ts, *c.Timestamp())
	require.False(t, c.IsDisabled())
	require.NoError(t, c.Verify(nil))

	// nil timestamp means "never enabled" and must survive the pass-through.
	require.Nil(t, (&Config{}).Timestamp())

	// Disable is the only other bit and it passes through unmodified.
	require.True(t, (&Config{Upgrade: precompileconfig.Upgrade{Disable: true}}).IsDisabled())
}

// TestConfig_Equal proves Equal discriminates on BOTH upgrade fields and refuses
// a foreign config type outright — a config from another precompile must never
// compare equal to this one, or an upgrade could be silently mistaken for a no-op.
func TestConfig_Equal(t *testing.T) {
	ts1, ts2 := uint64(10), uint64(20)

	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	same := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	otherTs := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}
	disabled := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1, Disable: true}}

	require.True(t, a.Equal(same))
	require.False(t, a.Equal(otherTs), "a different activation timestamp is a different config")
	require.False(t, a.Equal(disabled), "the disable flag is part of config identity")

	// A different concrete type sharing the interface must NOT compare equal.
	require.False(t, a.Equal(foreignConfig{}))
	// A typed nil *Config is a different type-assertion outcome than a foreign type;
	// it asserts through, and its zero Upgrade differs from a's.
	require.False(t, a.Equal(&Config{}))
}

// foreignConfig is some other precompile's config: it satisfies the interface but
// is not *v3.Config, so Config.Equal must reject it on the type assertion.
type foreignConfig struct{}

func (foreignConfig) Key() string                               { return "notV3" }
func (foreignConfig) Timestamp() *uint64                        { return nil }
func (foreignConfig) IsDisabled() bool                          { return false }
func (foreignConfig) Equal(precompileconfig.Config) bool        { return false }
func (foreignConfig) Verify(precompileconfig.ChainConfig) error { return nil }

// TestConfigurator proves MakeConfig hands back a fresh, zero *Config (never a
// shared instance) and that Configure accepts exactly that type and refuses any
// other — the activation path must not run against a foreign config.
func TestConfigurator(t *testing.T) {
	cfg := &configurator{}

	made := cfg.MakeConfig()
	typed, ok := made.(*Config)
	require.True(t, ok, "MakeConfig must produce a *v3.Config")
	require.Nil(t, typed.Timestamp())
	require.False(t, typed.IsDisabled())

	// Fresh instance each call: mutating one must not be visible in the next.
	ts := uint64(7)
	typed.BlockTimestamp = &ts
	require.Nil(t, cfg.MakeConfig().Timestamp(), "MakeConfig must not return a shared instance")

	db := newMockState()
	require.NoError(t, cfg.Configure(nil, &Config{}, db, &mockBlock{ts: 1}))
	// Configure writes NO state: the AMM has no genesis allocation or admin slot.
	require.Empty(t, db.storage, "Configure must not touch state")

	require.Error(t, cfg.Configure(nil, foreignConfig{}, db, &mockBlock{ts: 1}))
}

// TestModuleRegistration proves the module is in the global registry under its
// address and key, and that re-registering it is refused (the collision check
// init() relies on to fail fast rather than shadowing another precompile).
func TestModuleRegistration(t *testing.T) {
	got, ok := modules.GetPrecompileModuleByAddress(v3Addr)
	require.True(t, ok, "LP-90A1 must be registered at %s", v3Addr)
	require.Equal(t, ConfigKey, got.ConfigKey)
	require.Same(t, Precompile, got.Contract)

	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, v3Addr, byKey.Address)

	// The exact call init() makes: a second registration must ERROR, which is what
	// makes init()'s panic a fail-fast rather than a silent double-register.
	require.Error(t, modules.RegisterModule(Module))
}
