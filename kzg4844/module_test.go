// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"encoding/json"
	"testing"

	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

func TestModule_RegisteredAtTheAdvertisedAddress(t *testing.T) {
	m, ok := modules.GetPrecompileModuleByAddress(ContractAddress)
	require.True(t, ok, "kzg4844 is not registered at %s", ContractAddress)
	require.Equal(t, ConfigKey, m.ConfigKey)
	require.Equal(t, KZG4844Precompile, m.Contract)

	byKey, ok := modules.GetPrecompileModule(ConfigKey)
	require.True(t, ok)
	require.Equal(t, ContractAddress, byKey.Address)
}

func TestModule_RegisteringTwiceIsRejected(t *testing.T) {
	require.Error(t, modules.RegisterModule(Module))
}

func TestConfig_MakeConfigMatchesKey(t *testing.T) {
	cfg := Module.Configurator.MakeConfig()
	require.IsType(t, &Config{}, cfg)
	require.Equal(t, ConfigKey, cfg.Key())
}

func TestConfig_Timestamp(t *testing.T) {
	var cfg Config
	require.Nil(t, cfg.Timestamp())

	at := uint64(1700000000)
	cfg.Upgrade.BlockTimestamp = &at
	require.Equal(t, at, *cfg.Timestamp())
}

func TestConfig_IsDisabled(t *testing.T) {
	var cfg Config
	require.False(t, cfg.IsDisabled())

	cfg.Upgrade.Disable = true
	require.True(t, cfg.IsDisabled())
}

func TestConfig_Equal(t *testing.T) {
	at, other := uint64(10), uint64(11)

	a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &at}}
	same := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &at}}
	later := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &other}}
	disabled := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &at, Disable: true}}

	require.True(t, a.Equal(same))
	require.False(t, a.Equal(later))
	require.False(t, a.Equal(disabled))
	require.False(t, a.Equal(nil))
	require.False(t, a.Equal(otherConfig{}))
}

// otherConfig is a Config of a different concrete type, which Equal must
// refuse rather than treat as a match.
type otherConfig struct{ precompileconfig.Config }

func (otherConfig) Key() string { return "not-kzg4844" }

func TestConfig_VerifyAndConfigureAreTotal(t *testing.T) {
	cfg := &Config{}
	require.NoError(t, cfg.Verify(nil))
	require.NoError(t, Module.Configurator.Configure(nil, cfg, nil, nil))
}

func TestConfig_JSONRoundTrip(t *testing.T) {
	at := uint64(42)
	in := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &at}}

	raw, err := json.Marshal(in)
	require.NoError(t, err)

	out := Module.Configurator.MakeConfig()
	require.NoError(t, json.Unmarshal(raw, out))
	require.True(t, in.Equal(out))
}
