// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kzg4844

import (
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// ConfigKey is the upgrade.json key for the EIP-4844 KZG point-evaluation
// extension precompile (LP-3665). The standard EVM precompile at 0x0a is
// always-on; this one provides the extended op-codes (BlobToCommitment,
// ComputeProof, batch verify, etc.) at 0xB002.
const ConfigKey = "kzg4844Config"

// Module is the registry entry for the KZG-4844 extension precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     KZG4844Precompile,
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
	_ precompileconfig.ChainConfig,
	_ precompileconfig.Config,
	_ contract.StateDB,
	_ contract.ConfigurationBlockContext,
) error {
	return nil
}

// Config is the upgrade-gated config for the KZG-4844 extension precompile.
// No tunable parameters — the precompile is either active or not.
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
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
