// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// ConfigKey is the upgrade.json key for the Ed25519 verify precompile.
// Activated at the Quasar Edition timestamp; once active, contracts can
// natively verify Solana/Ed25519, TON, XRP (Ed25519 mode), and any other
// Ed25519-rooted external chain signature inside EVM execution.
const ConfigKey = "ed25519Config"

// RegistryModule is the registry entry for the Ed25519 precompile.
// Distinct identifier from the legacy `Module` metadata struct that older
// callers depend on (see NewModule()/Module type below).
var RegistryModule = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     Ed25519VerifyPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

var _ contract.Configurator = (*configurator)(nil)

func init() {
	if err := modules.RegisterModule(RegistryModule); err != nil {
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

// Config is the upgrade-gated config for the Ed25519 verify precompile.
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

// --- Legacy metadata-style module wrapper (kept for backward compatibility) ---
//
// These functions predate the modules.Module registry pattern. They are
// preserved so existing callers and tests continue to compile.

// Module provides the ed25519 precompile module information.
type Module struct{}

// NewModule creates a new ed25519 module.
func NewModule() *Module {
	return &Module{}
}

// Address returns the precompile address.
func (m *Module) Address() common.Address {
	return ContractAddress
}

// Contract returns the singleton contract instance.
func (m *Module) Contract() *ed25519VerifyPrecompile {
	return Ed25519VerifyPrecompile
}

// ConfigKey returns the configuration key for this module.
func (m *Module) ConfigKey() string {
	return ConfigKey
}

// Name returns the module name.
func (m *Module) Name() string {
	return "ed25519"
}
