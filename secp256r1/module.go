// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package secp256r1

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// ConfigKey is the upgrade.json key for the EIP-7212 secp256r1/P-256
// signature verification precompile. Activated at the Quasar Edition
// timestamp; once active, smart contracts can verify WebAuthn / passkey
// signatures natively (no Solidity P-256 emulation).
const ConfigKey = "secp256r1Config"

// stateful is a thin StatefulPrecompiledContract wrapper around the
// minimal-interface Contract so we can register the precompile in the
// modules.Module registry. The wrapper deducts gas first (uniform with
// every other Lux precompile), enforces RefuseUnderStrictPQ, then delegates
// to the existing classical verifier.
type stateful struct{ c Contract }

var (
	// StatefulPrecompile is the singleton used by modules.Module.Contract.
	StatefulPrecompile contract.StatefulPrecompiledContract = &stateful{}

	_ contract.StatefulPrecompiledContract = (*stateful)(nil)
)

// RequiredGas is delegated to the wrapped Contract.
func (s *stateful) RequiredGas(input []byte) uint64 { return s.c.RequiredGas(input) }

// Run satisfies StatefulPrecompiledContract. Gas deduction, strict-PQ
// gating, then delegation to the classical EIP-7212 verifier.
func (s *stateful) Run(
	accessibleState contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	remainingGas, err := contract.DeductGas(suppliedGas, s.c.RequiredGas(input))
	if err != nil {
		return nil, 0, err
	}
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, remainingGas, err
	}
	out, err := s.c.Run(input)
	return out, remainingGas, err
}

// RegistryModule is the precompile registry entry for secp256r1.
var RegistryModule = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      Address,
	Contract:     StatefulPrecompile,
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

// Config is the upgrade-gated config for the secp256r1 precompile.
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

// Module provides the secp256r1 precompile module information.
type Module struct{}

// NewModule creates a new secp256r1 module.
func NewModule() *Module { return &Module{} }

// Address returns the precompile address.
func (m *Module) Address() common.Address { return Address }

// Contract returns a new contract instance.
func (m *Module) Contract() *Contract { return &Contract{} }

// ConfigKey returns the configuration key for this module.
func (m *Module) ConfigKey() string { return ConfigKey }

// Name returns the module name.
func (m *Module) Name() string { return "secp256r1" }

// Description returns the module description.
func (m *Module) Description() string {
	return "secp256r1 (P-256) signature verification precompile for biometric authentication and WebAuthn"
}

// Version returns the module version.
func (m *Module) Version() string { return "1.0.0" }

// EIPs returns the related EIP numbers.
func (m *Module) EIPs() []int { return []int{7212} }

// LPs returns the related LP numbers.
func (m *Module) LPs() []int { return []int{3651} }
