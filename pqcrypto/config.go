// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// Post-Quantum Cryptography Precompile Configuration

package pqcrypto

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ precompileconfig.Config = &Config{}

const ConfigKey = "pqcryptoConfig"

// Address of the PQ crypto precompile (Lux Crypto PQ range 0x9003)
var (
	ContractAddress = common.HexToAddress("0x9003")
)

// Config implements the precompileconfig.Config interface
type Config struct {
	precompileconfig.Upgrade
}

// NewConfig returns a new PQ crypto precompile config
func NewConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{
			BlockTimestamp: blockTimestamp,
		},
	}
}

// NewDisableConfig returns a config that disables the PQ crypto precompile
func NewDisableConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{
			BlockTimestamp: blockTimestamp,
			Disable:        true,
		},
	}
}

// Key returns the unique key for the PQ crypto precompile config
func (*Config) Key() string { return ConfigKey }

// Verify returns an error if the config is invalid
func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}

// Equal returns true if the provided config is equivalent
func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := (cfg).(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

// String returns a string representation of the config
func (c *Config) String() string {
	return "PQCrypto"
}
