// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"fmt"

	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var (
	_ contract.Configurator   = (*configurator)(nil)
	_ precompileconfig.Config = (*Config)(nil)
)

// ConfigKey is the JSON config key for the LXSwap (LP-90A0) precompile.
const ConfigKey = "swapConfig"

// SwapPrecompile is the singleton stateful contract. It holds no mutable Go state.
var SwapPrecompile = &SwapContract{}

// Module is the LP-90A0 LXSwap precompile module.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      swapAddr,
	Contract:     SwapPrecompile,
	Configurator: &configurator{},
}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

// Config is the activation config. The HTLC has NO administrative parameters by
// design (no owner, no pause, no fee controller) — only the standard upgrade
// timestamp / disable flags.
type Config struct {
	precompileconfig.Upgrade
}

func (c *Config) Key() string        { return ConfigKey }
func (c *Config) Timestamp() *uint64 { return c.Upgrade.Timestamp() }
func (c *Config) IsDisabled() bool   { return c.Upgrade.Disable }

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error { return nil }

// configurator implements contract.Configurator. There is nothing to configure:
// the precompile's behaviour is fully determined by its code and the on-chain
// state, never by an operator-supplied parameter.
type configurator struct{}

func (*configurator) MakeConfig() precompileconfig.Config { return new(Config) }

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	if _, ok := cfg.(*Config); !ok {
		return fmt.Errorf("expected config type %T, got %T", &Config{}, cfg)
	}
	return nil
}
