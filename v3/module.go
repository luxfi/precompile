// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

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

// ConfigKey is the JSON config key for the LXConcentrated (LP-90A1) precompile.
const ConfigKey = "v3Config"

// Precompile is the singleton stateful contract. It holds no mutable Go state.
var Precompile = &V3Contract{}

// Module is the LP-90A1 LXConcentrated precompile module.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      v3Addr,
	Contract:     Precompile,
	Configurator: &configurator{},
}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

// Config is the activation config. The AMM has NO administrative parameters by design
// (no owner, no pause, no protocol-fee controller) — only the standard upgrade
// timestamp / disable flags, exactly like the swap (LP-90A0) Config.
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

// configurator implements contract.Configurator. There is nothing to configure: the
// precompile's behaviour is fully determined by its code and the on-chain state, never
// by an operator-supplied parameter.
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
