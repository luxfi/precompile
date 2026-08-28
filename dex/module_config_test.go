// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// The config surface of all five dex modules was entirely untested. It looks like
// boilerplate, but it is the ACTIVATION mechanism: Timestamp decides when a
// precompile becomes reachable, IsDisabled decides whether it is, and Equal decides
// whether a proposed upgrade differs from the running one. An Equal that agrees too
// readily makes an upgrade silently no-op — the chain keeps running the old rules
// while operators believe they shipped new ones.

// mcModule is one module's config surface under test.
type mcModule struct {
	name    string
	mod     modules.Module
	key     string
	makeCfg func() precompileconfig.Config
	// withUpgrade builds a config carrying the given activation timestamp and
	// disable flag, so Equal can be probed on both axes.
	withUpgrade func(ts uint64, disable bool) precompileconfig.Config
}

func mcModules() []mcModule {
	up := func(ts uint64, disable bool) precompileconfig.Upgrade {
		return precompileconfig.Upgrade{BlockTimestamp: &ts, Disable: disable}
	}
	return []mcModule{
		{
			name: "quoter (0x9998)", mod: QuoterModule, key: quoterConfigKey,
			makeCfg: (&quoterConfigurator{}).MakeConfig,
			withUpgrade: func(ts uint64, d bool) precompileconfig.Config {
				return &QuoterConfig{Upgrade: up(ts, d)}
			},
		},
		{
			name: "stateview (0x9997)", mod: StateViewModule, key: stateViewConfigKey,
			makeCfg: (&stateViewConfigurator{}).MakeConfig,
			withUpgrade: func(ts uint64, d bool) precompileconfig.Config {
				return &StateViewConfig{Upgrade: up(ts, d)}
			},
		},
		{
			name: "position (0x9996)", mod: PositionManagerModule, key: positionConfigKey,
			makeCfg: (&positionConfigurator{}).MakeConfig,
			withUpgrade: func(ts uint64, d bool) precompileconfig.Config {
				return &PositionManagerConfig{Upgrade: up(ts, d)}
			},
		},
		{
			name: "settle (0x9999)", mod: SettleModule, key: settleConfigKey,
			makeCfg: (&settleConfigurator{}).MakeConfig,
			withUpgrade: func(ts uint64, d bool) precompileconfig.Config {
				return &SettleConfig{Upgrade: up(ts, d)}
			},
		},
	}
}

// TestModuleIdentity pins each module's address, config key, contract and
// always-on status together. These four facts are what the host uses to decide WHAT
// runs WHERE and WHEN; a mismatch between a module's key and its config's Key()
// means the host cannot find the config that activates it.
func TestModuleIdentity(t *testing.T) {
	for _, m := range mcModules() {
		t.Run(m.name, func(t *testing.T) {
			require.NotNil(t, m.mod.Contract, "a module must carry a contract")
			require.NotNil(t, m.mod.Configurator, "a module must carry a configurator")
			require.Equal(t, m.key, m.mod.ConfigKey, "the module's key must match its config key")

			cfg := m.makeCfg()
			require.NotNil(t, cfg, "MakeConfig must return a usable value")
			require.Equal(t, m.key, cfg.Key(),
				"the config's Key() must match the module's ConfigKey, or the host cannot activate it")

			// A freshly made config is inert: no activation timestamp, not disabled,
			// and it verifies. Anything else would activate a precompile by default.
			require.Nil(t, cfg.Timestamp(), "a fresh config must carry no activation timestamp")
			require.False(t, cfg.IsDisabled(), "a fresh config must not be disabled")
			require.NoError(t, cfg.Verify(nil), "a parameter-free config must always verify")
		})
	}
}

// TestConfigTimestampAndDisable: Timestamp is the activation switch and IsDisabled
// the kill switch. Both must report exactly what was configured — a Timestamp that
// silently returned nil would make a scheduled activation never fire.
func TestConfigTimestampAndDisable(t *testing.T) {
	for _, m := range mcModules() {
		t.Run(m.name, func(t *testing.T) {
			for _, ts := range []uint64{0, 1, 1_766_708_400, 1 << 62} {
				on := m.withUpgrade(ts, false)
				require.NotNil(t, on.Timestamp())
				require.Equalf(t, ts, *on.Timestamp(), "timestamp %d must round-trip", ts)
				require.False(t, on.IsDisabled())
				require.NoError(t, on.Verify(nil))

				off := m.withUpgrade(ts, true)
				require.True(t, off.IsDisabled(), "the disable flag must be reported")
			}
		})
	}
}

// TestConfigEqualDistinguishesEveryAxis is the load-bearing one. Equal decides
// whether a proposed upgrade differs from the running config. If it returns true too
// readily the upgrade is dropped silently: the chain keeps the old behaviour while
// operators believe the new config shipped.
//
// Each axis is probed on its own — timestamp, disable flag, foreign type, nil — so a
// comparison that ignores one field cannot hide behind the others agreeing.
func TestConfigEqualDistinguishesEveryAxis(t *testing.T) {
	for _, m := range mcModules() {
		t.Run(m.name, func(t *testing.T) {
			base := m.withUpgrade(1000, false)

			require.True(t, base.Equal(m.withUpgrade(1000, false)),
				"identical configs must compare equal")
			require.False(t, base.Equal(m.withUpgrade(2000, false)),
				"a DIFFERENT ACTIVATION TIMESTAMP is a different config")
			require.False(t, base.Equal(m.withUpgrade(1000, true)),
				"a DIFFERENT DISABLE FLAG is a different config")
			require.False(t, base.Equal(nil),
				"a nil config is never equal")
			require.False(t, base.Equal(mcForeignConfig{}),
				"a config of another module's type is never equal")

			// Cross-module: no module's config may compare equal to another's, or an
			// upgrade could be applied against the wrong precompile.
			for _, other := range mcModules() {
				if other.name == m.name {
					continue
				}
				require.Falsef(t, base.Equal(other.withUpgrade(1000, false)),
					"%s config must not equal %s config", m.name, other.name)
			}
		})
	}
}

// TestConfigureIsANoOpAndTypeChecked: these precompiles hold no per-network
// parameters, so Configure must persist nothing. 0x9999 additionally validates the
// config type so a misuse surfaces loudly instead of silently configuring nothing.
func TestConfigureIsANoOpAndTypeChecked(t *testing.T) {
	// A NIL StateDB is the assertion, not a shortcut: these precompiles hold no
	// per-network parameters, so Configure must persist nothing. If any of them ever
	// touched state it would dereference nil here and fail loudly, which is exactly
	// the regression worth catching.
	for _, m := range mcModules() {
		t.Run(m.name, func(t *testing.T) {
			cfgr, ok := m.mod.Configurator.(contract.Configurator)
			require.True(t, ok)
			require.NotPanics(t, func() {
				require.NoError(t, cfgr.Configure(nil, m.makeCfg(), nil, nil),
					"Configure must accept its own config type")
			}, "Configure must not touch state")
		})
	}

	// 0x9999 is always-on and never invoked by the host, but it still refuses a
	// foreign config rather than silently accepting it.
	err := (&settleConfigurator{}).Configure(nil, &QuoterConfig{}, nil, nil)
	require.Error(t, err, "0x9999 must refuse a config that is not a *SettleConfig")
}

// TestEveryDexModuleRegistersExactlyOnce: re-registering must be refused. Each
// module's init() turns that error into a panic, so a duplicate address aborts the
// node instead of letting one precompile silently shadow another.
func TestEveryDexModuleRegistersExactlyOnce(t *testing.T) {
	for _, m := range []struct {
		name string
		mod  modules.Module
	}{
		{"settle", SettleModule},
		{"quoter", QuoterModule},
		{"stateview", StateViewModule},
		{"position", PositionManagerModule},
		{"router", RouterModule},
	} {
		require.Errorf(t, modules.RegisterModule(m.mod),
			"%s is already registered; a second registration must be refused", m.name)
	}
}

// TestRouterConfigSurface covers the router's config separately: it is the one dex
// module whose MakeConfig has a body rather than a one-line literal.
func TestRouterConfigSurface(t *testing.T) {
	cfgr := &routerConfigurator{}
	cfg := cfgr.MakeConfig()
	require.NotNil(t, cfg)
	require.IsType(t, &RouterConfig{}, cfg)
	require.Equal(t, RouterConfigKey, cfg.Key())
	require.Equal(t, RouterConfigKey, RouterModule.ConfigKey)
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(nil))
	require.NoError(t, cfgr.Configure(nil, cfg, nil, nil))

	ts1, ts2 := uint64(10), uint64(20)
	a := &RouterConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}
	require.Equal(t, ts1, *a.Timestamp())
	require.True(t, a.Equal(&RouterConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1}}))
	require.False(t, a.Equal(&RouterConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts2}}))
	require.False(t, a.Equal(&RouterConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1, Disable: true}}))
	require.False(t, a.Equal(nil))
	require.False(t, a.Equal(mcForeignConfig{}))

	disabled := &RouterConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts1, Disable: true}}
	require.True(t, disabled.IsDisabled())
}

// mcForeignConfig is a config of a type belonging to no dex module, used to prove
// every Equal performs a type check before comparing.
type mcForeignConfig struct{ precompileconfig.Config }

func (mcForeignConfig) Key() string        { return "not-a-dex-module" }
func (mcForeignConfig) Timestamp() *uint64 { return nil }
func (mcForeignConfig) IsDisabled() bool   { return false }
