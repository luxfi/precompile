// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"strings"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// zzForeignConfig is a precompileconfig.Config that is NOT *swap.Config. Equal and
// Configure must both discriminate on the concrete type, never on the interface.
type zzForeignConfig struct{ precompileconfig.Upgrade }

func (c *zzForeignConfig) Key() string                               { return "notSwapConfig" }
func (c *zzForeignConfig) Equal(precompileconfig.Config) bool        { return false }
func (c *zzForeignConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *zzForeignConfig) IsDisabled() bool                          { return c.Upgrade.Disable }

var _ precompileconfig.Config = (*zzForeignConfig)(nil)

func zzTS(v uint64) *uint64 { return &v }

// ---------------------------------------------------------------------------
// Config surface. The HTLC has no administrative parameters by design, so the
// whole config is the standard activation Upgrade — and these assertions pin
// that no parameter has quietly grown one.
// ---------------------------------------------------------------------------

func TestZZConfigKeyAndTimestamp(t *testing.T) {
	c := new(Config)
	require.Equal(t, ConfigKey, c.Key())
	require.Equal(t, "swapConfig", c.Key())
	require.Nil(t, c.Timestamp(), "a config with no blockTimestamp is never enabled")
	require.False(t, c.IsDisabled())

	at := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0)}}
	require.NotNil(t, at.Timestamp())
	require.Equal(t, t0, *at.Timestamp())
	require.False(t, at.IsDisabled())

	off := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0), Disable: true}}
	require.True(t, off.IsDisabled(), "Disable must surface through the precompile's own accessor")
	require.Equal(t, t0, *off.Timestamp())

	// Genesis activation is timestamp 0, which must be distinguishable from "never".
	genesis := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(0)}}
	require.NotNil(t, genesis.Timestamp())
	require.Equal(t, uint64(0), *genesis.Timestamp())
}

func TestZZConfigEqual(t *testing.T) {
	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0)}}
	same := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0)}}
	laterTS := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0 + 1)}}
	disabled := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0), Disable: true}}
	never := new(Config)

	require.True(t, a.Equal(same), "identical activation configs are equal")
	require.True(t, a.Equal(a))
	require.False(t, a.Equal(laterTS), "a different activation timestamp is a different config")
	require.False(t, a.Equal(disabled), "the disable flag is part of config identity")
	require.False(t, a.Equal(never), "a set timestamp never equals an unset one")
	require.False(t, never.Equal(a))
	require.True(t, never.Equal(new(Config)), "two unset configs are equal")

	// A config of a foreign type is never equal, whatever its Upgrade holds.
	require.False(t, a.Equal(&zzForeignConfig{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0)}}))
	require.False(t, a.Equal(nil), "a nil Config is not equal to a real one")
}

func TestZZConfigVerifyAcceptsAnyChain(t *testing.T) {
	// The HTLC takes no operator-supplied parameter, so there is nothing a chain
	// config could invalidate: Verify is total.
	require.NoError(t, new(Config).Verify(nil))
	require.NoError(t, (&Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: zzTS(t0), Disable: true}}).Verify(nil))
}

// ---------------------------------------------------------------------------
// Configurator.
// ---------------------------------------------------------------------------

func TestZZMakeConfigProducesFreshSwapConfig(t *testing.T) {
	cfgr := &configurator{}
	got := cfgr.MakeConfig()
	require.IsType(t, &Config{}, got)
	require.Equal(t, ConfigKey, got.Key())
	require.Nil(t, got.Timestamp())
	require.False(t, got.IsDisabled())

	// Fresh every call — a shared instance would let one chain's unmarshalled
	// config bleed into another's.
	other := cfgr.MakeConfig()
	require.NotSame(t, got, other)
	require.True(t, got.Equal(other))
}

func TestZZConfigureAcceptsOwnConfigRefusesForeign(t *testing.T) {
	cfgr := &configurator{}
	e := newEnv(t0)

	require.NoError(t, cfgr.Configure(nil, new(Config), e.db(), e.st.blk))
	require.NoError(t, cfgr.Configure(nil, cfgr.MakeConfig(), e.db(), e.st.blk))

	err := cfgr.Configure(nil, &zzForeignConfig{}, e.db(), e.st.blk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected config type")

	// Configure writes NOTHING: activation installs no state, so a chain that
	// activates the precompile twice cannot end up with a half-built ledger.
	require.Empty(t, e.db().storage)
	require.Empty(t, e.db().Logs())
}

// ---------------------------------------------------------------------------
// Registration. init() already ran when this binary loaded; these assertions
// read the registry back to prove what it registered.
// ---------------------------------------------------------------------------

func TestZZModuleRegisteredAtLP90A0(t *testing.T) {
	byAddr, ok := modules.GetPrecompileModuleByAddress(swapAddr)
	require.True(t, ok, "init must have registered the module at LP-90A0")
	require.Equal(t, ConfigKey, byAddr.ConfigKey)

	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, swapAddr, byKey.Address)

	require.Same(t, SwapPrecompile, byKey.Contract, "the registered contract is the singleton")
	var _ contract.StatefulPrecompiledContract = SwapPrecompile
	require.IsType(t, &configurator{}, byKey.Configurator)

	// NOT always-on: the HTLC activates through a config entry like every other
	// value-bearing precompile, never implicitly at genesis.
	require.False(t, byKey.AlwaysOn)
	for _, m := range modules.AlwaysOnModules() {
		require.NotEqual(t, swapAddr, m.Address)
	}
}

func TestZZDuplicateRegistrationRefused(t *testing.T) {
	// The registry is keyed by BOTH address and config key; registering the same
	// module twice must fail (and must not corrupt the registry that init built).
	before := len(modules.RegisteredModules())
	require.Error(t, modules.RegisterModule(Module))
	require.Len(t, modules.RegisteredModules(), before)

	still, ok := modules.GetPrecompileModuleByAddress(swapAddr)
	require.True(t, ok)
	require.Equal(t, ConfigKey, still.ConfigKey)
}

// ---------------------------------------------------------------------------
// Address authority: the precompile lives at LP-90A0 and nowhere else.
// ---------------------------------------------------------------------------

func TestZZAddressIsLP90A0(t *testing.T) {
	require.Equal(t, common.HexToAddress(LXSwapAddress), swapAddr)
	require.Equal(t, strings.ToLower(LXSwapAddress), strings.ToLower(swapAddr.Hex()))
	require.Equal(t, swapAddr, Module.Address)
	require.True(t, modules.ReservedAddress(swapAddr), "LP-90A0 must sit inside a reserved range")
	require.NotEqual(t, modules.BlackholeAddr, swapAddr)
}
