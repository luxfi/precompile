// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"testing"

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

// Module registration is verified by init() panicking on duplicate register.
// Package-level Module var isn't exported, so the lookup happens via
// precompile/modules.GetPrecompileModuleByAddress() at runtime.
