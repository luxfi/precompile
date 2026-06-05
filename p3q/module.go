// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = &configurator{}

// ConfigKey is the globally unique JSON config key for this
// precompile. Distinct from "pulsarVerify" (slot 0x012204) so a
// chain config can independently enable/disable the LP-218 rollup-
// commit verifier.
const ConfigKey = "p3qVerify"

type configurator struct{}

func init() {
	if err := modules.RegisterModule(modules.Module{
		ConfigKey:    ConfigKey,
		Address:      ContractP3QVerifyAddress,
		Contract:     P3QVerifyPrecompile,
		Configurator: &configurator{},
	}); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config { return &Config{} }

func (*configurator) Configure(
	_ precompileconfig.ChainConfig,
	_ precompileconfig.Config,
	_ contract.StateDB,
	_ contract.ConfigurationBlockContext,
) error {
	return nil
}

// Config is the precompileconfig.Config for the P3Q (Post-Quantum
// Pulsar Proof) verify precompile at slot 0x012205.
//
// Activation: per LP-218, P3Q is callable from the genesis block of
// the new final Lux network (2025-12-25 16:20 Pacific, unix
// 1766708400). Chain configs that wire a non-zero Upgrade.Timestamp
// can defer activation to later heights; the canonical mainnet
// config pins the activation timestamp to the LP-218 genesis.
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
