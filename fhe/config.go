// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"github.com/luxfi/precompiles/precompileconfig"
)

var _ precompileconfig.Config = (*Config)(nil)

// Config implements the precompileconfig.Config interface for FHE.
type Config struct {
	precompileconfig.Upgrade
	// NetworkKeyPath specifies the path to the network TFHE key (optional)
	NetworkKeyPath string `json:"networkKeyPath,omitempty"`
	// CoprocessorEndpoint specifies the Z-Chain coprocessor endpoint for threshold decryption
	CoprocessorEndpoint string `json:"coprocessorEndpoint,omitempty"`
}

// NewConfig returns a config for a network upgrade at [blockTimestamp] that enables FHE.
func NewConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{BlockTimestamp: blockTimestamp},
	}
}

// NewDisableConfig returns config for a network upgrade at [blockTimestamp] that disables FHE.
func NewDisableConfig(blockTimestamp *uint64) *Config {
	return &Config{
		Upgrade: precompileconfig.Upgrade{
			BlockTimestamp: blockTimestamp,
			Disable:        true,
		},
	}
}

// Key returns the key for the FHE precompileconfig.
func (*Config) Key() string { return ConfigKey }

// Verify tries to verify Config and returns an error accordingly.
func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	// FHE has no special verification requirements beyond base config
	return nil
}

// Equal returns true if [s] is a [*Config] and it has been configured identical to [c].
func (c *Config) Equal(s precompileconfig.Config) bool {
	other, ok := (s).(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade) &&
		c.NetworkKeyPath == other.NetworkKeyPath &&
		c.CoprocessorEndpoint == other.CoprocessorEndpoint
}
