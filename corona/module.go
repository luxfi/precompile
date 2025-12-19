// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronathreshold

import (
	"github.com/luxfi/precompiles/contract"
	"github.com/luxfi/precompiles/modules"
	"github.com/luxfi/geth/common"
)

var _ contract.Configurator = &configurator{}

// ConfigKey is the key used in the precompile config file to configure this precompile
const ConfigKey = "coronaThresholdConfig"

type configurator struct{}

// NewConfigurator creates a new configurator for the Corona threshold signature precompile
func NewConfigurator() contract.Configurator {
	return &configurator{}
}

// MakeConfig returns a new Corona threshold config instance
func (c *configurator) MakeConfig() contract.Config {
	return &Config{}
}

// Configure configures the Corona threshold signature precompile
func (c *configurator) Configure(
	chainConfig contract.ChainConfig,
	cfg contract.Config,
	state contract.StateDB,
	blockContext contract.BlockContext,
) error {
	// No special configuration needed for Corona threshold
	// The precompile is stateless and requires no initialization
	return nil
}

// Config implements the StatefulPrecompileConfig interface
type Config struct {
	contract.UpgradeableConfig
}

// Address returns the address of the Corona threshold signature precompile
func (c *Config) Address() common.Address {
	return ContractCoronaThresholdAddress
}

// Contract returns the precompile contract instance
func (c *Config) Contract() contract.StatefulPrecompiledContract {
	return CoronaThresholdPrecompile
}

// Configure implements the StatefulPrecompileConfig interface
func (c *Config) Configure(
	chainConfig contract.ChainConfig,
	cfg contract.Config,
	state contract.StateDB,
	blockContext contract.BlockContext,
) error {
	return NewConfigurator().Configure(chainConfig, cfg, state, blockContext)
}

// Equal returns true if the two configs are equal
func (c *Config) Equal(other contract.Config) bool {
	otherConfig, ok := other.(*Config)
	if !ok {
		return false
	}
	return c.UpgradeableConfig.Equal(&otherConfig.UpgradeableConfig)
}

// String returns a string representation of the config
func (c *Config) String() string {
	return "CoronaThresholdConfig"
}

// Key returns the config key
func (c *Config) Key() string {
	return ConfigKey
}

func init() {
	// Register the Corona threshold precompile module
	modules.RegisterModule(ConfigKey, NewConfigurator())
}
