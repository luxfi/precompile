// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"github.com/luxfi/precompiles/contract"
	"github.com/luxfi/precompiles/modules"
	"github.com/luxfi/precompiles/precompileconfig"
)

var _ contract.Configurator = &configurator{}

type configurator struct{}

func init() {
	// Register CGGMP21 precompile module
	if err := modules.RegisterModule(modules.Module{
		ConfigKey:    "cggmp21Verify",
		Address:      ContractCGGMP21VerifyAddress,
		Contract:     CGGMP21VerifyPrecompile,
		Configurator: &configurator{},
	}); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return &Config{}
}

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	// No state initialization required for CGGMP21 verification
	return nil
}

// Config implements the precompileconfig.Config interface for CGGMP21
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade,omitempty"`
}

func (c *Config) Key() string {
	return "cggmp21Verify"
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
	return c.Upgrade.Equal(&other.Upgrade)
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	// No additional verification required
	return nil
}
