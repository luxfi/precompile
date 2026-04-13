// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quasar

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

const ConfigKey = "quasarConfig"

// VerklePrecompile is the primary registered precompile (Verkle verify at 0x0300..20)
var VerklePrecompile contract.StatefulPrecompiledContract = &verklePrecompile{}

var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      common.HexToAddress(VerkleVerifyAddress),
	Contract:     VerklePrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config { return new(Config) }

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade,omitempty"`
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
func (c *Config) Verify(precompileconfig.ChainConfig) error { return nil }
