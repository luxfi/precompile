// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dead

import (
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// Config keys for each dead address
const (
	ConfigKeyZero = "deadZeroConfig"
	ConfigKeyDead = "deadConfig"
	ConfigKeyFull = "deadFullConfig"
)

// Modules for each dead address
var (
	ModuleZero = modules.Module{
		ConfigKey:    ConfigKeyZero,
		Address:      ZeroAddress,
		Contract:     DeadPrecompile,
		Configurator: &configurator{key: ConfigKeyZero},
	}

	ModuleDead = modules.Module{
		ConfigKey:    ConfigKeyDead,
		Address:      DeadAddress,
		Contract:     DeadPrecompile,
		Configurator: &configurator{key: ConfigKeyDead},
	}

	ModuleFull = modules.Module{
		ConfigKey:    ConfigKeyFull,
		Address:      DeadFullAddress,
		Contract:     DeadPrecompile,
		Configurator: &configurator{key: ConfigKeyFull},
	}
)

type configurator struct {
	key string
}

func init() {
	// Register the Dead Precompile at ALL dead addresses
	// This way transfers to 0x0 or 0xdead call the precompile directly
	for _, m := range []modules.Module{ModuleZero, ModuleDead, ModuleFull} {
		if err := modules.RegisterModule(m); err != nil {
			panic(err)
		}
	}
}

func (c *configurator) MakeConfig() precompileconfig.Config {
	return &Config{key: c.key}
}

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

// Config implements the precompileconfig.Config interface
type Config struct {
	key     string
	Upgrade precompileconfig.Upgrade `json:"upgrade,omitempty"`
}

func (c *Config) Key() string {
	return c.key
}

func (c *Config) Timestamp() *uint64 {
	return c.Upgrade.Timestamp()
}

func (c *Config) IsDisabled() bool {
	return c.Upgrade.Disable
}

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.key == other.key && c.Upgrade.Equal(&other.Upgrade)
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}
