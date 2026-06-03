// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// Compile-time guarantees that every per-operation configurator satisfies
// contract.Configurator and every per-operation Config satisfies
// precompileconfig.Config. These are intentionally repeated per type so a
// future renaming caught by the compiler instead of by a runtime config-key
// collision (the precise bug this file was rewritten to fix).
var (
	_ contract.Configurator   = (*g1AddConfigurator)(nil)
	_ contract.Configurator   = (*g1MulConfigurator)(nil)
	_ contract.Configurator   = (*g1MSMConfigurator)(nil)
	_ contract.Configurator   = (*g2AddConfigurator)(nil)
	_ contract.Configurator   = (*g2MulConfigurator)(nil)
	_ contract.Configurator   = (*g2MSMConfigurator)(nil)
	_ contract.Configurator   = (*pairingConfigurator)(nil)
	_ precompileconfig.Config = (*G1AddConfig)(nil)
	_ precompileconfig.Config = (*G1MulConfig)(nil)
	_ precompileconfig.Config = (*G1MSMConfig)(nil)
	_ precompileconfig.Config = (*G2AddConfig)(nil)
	_ precompileconfig.Config = (*G2MulConfig)(nil)
	_ precompileconfig.Config = (*G2MSMConfig)(nil)
	_ precompileconfig.Config = (*PairingConfig)(nil)
)

// Config keys for each EIP-2537 operation (unique per module).
// These are the JSON identity of each precompile in upgrade.json. Every
// sub-config returns exactly one of these from its Key() method — one value,
// named at exactly one site.
const (
	G1AddConfigKey   = "bls12381G1AddConfig"
	G1MulConfigKey   = "bls12381G1MulConfig"
	G1MSMConfigKey   = "bls12381G1MSMConfig"
	G2AddConfigKey   = "bls12381G2AddConfig"
	G2MulConfigKey   = "bls12381G2MulConfig"
	G2MSMConfigKey   = "bls12381G2MSMConfig"
	PairingConfigKey = "bls12381PairingConfig"
)

// Modules registers one module per EIP-2537 address (0x0B-0x11). Each
// module gets its own Configurator so MakeConfig() returns a Config whose
// Key() matches the module's ConfigKey — this is what allows upgrade.json
// to list all seven sub-configs without the upgrade-history grouping
// collapsing them into one entry.
var (
	G1AddModule = modules.Module{
		ConfigKey:    G1AddConfigKey,
		Address:      G1AddAddress,
		Contract:     &g1AddPrecompile{},
		Configurator: &g1AddConfigurator{},
	}
	G1MulModule = modules.Module{
		ConfigKey:    G1MulConfigKey,
		Address:      G1MulAddress,
		Contract:     &g1MulPrecompile{},
		Configurator: &g1MulConfigurator{},
	}
	G1MSMModule = modules.Module{
		ConfigKey:    G1MSMConfigKey,
		Address:      G1MSMAddress,
		Contract:     &g1MSMPrecompile{},
		Configurator: &g1MSMConfigurator{},
	}
	G2AddModule = modules.Module{
		ConfigKey:    G2AddConfigKey,
		Address:      G2AddAddress,
		Contract:     &g2AddPrecompile{},
		Configurator: &g2AddConfigurator{},
	}
	G2MulModule = modules.Module{
		ConfigKey:    G2MulConfigKey,
		Address:      G2MulAddress,
		Contract:     &g2MulPrecompile{},
		Configurator: &g2MulConfigurator{},
	}
	G2MSMModule = modules.Module{
		ConfigKey:    G2MSMConfigKey,
		Address:      G2MSMAddress,
		Contract:     &g2MSMPrecompile{},
		Configurator: &g2MSMConfigurator{},
	}
	PairingModule = modules.Module{
		ConfigKey:    PairingConfigKey,
		Address:      PairingAddress,
		Contract:     &pairingPrecompile{},
		Configurator: &pairingConfigurator{},
	}
)

func init() {
	for _, m := range []modules.Module{
		G1AddModule,
		G1MulModule,
		G1MSMModule,
		G2AddModule,
		G2MulModule,
		G2MSMModule,
		PairingModule,
	} {
		if err := modules.RegisterModule(m); err != nil {
			panic(err)
		}
	}
}

// Per-operation precompile structs. Each delegates to the shared implementation
// in contract.go but knows its own address for correct gas dispatch.

type g1AddPrecompile struct{}

func (p *g1AddPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.g1Add(input, suppliedGas)
}

type g1MulPrecompile struct{}

func (p *g1MulPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.g1Mul(input, suppliedGas)
}

type g1MSMPrecompile struct{}

func (p *g1MSMPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.g1MSM(input, suppliedGas)
}

type g2AddPrecompile struct{}

func (p *g2AddPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.g2Add(input, suppliedGas)
}

type g2MulPrecompile struct{}

func (p *g2MulPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.g2Mul(input, suppliedGas)
}

type g2MSMPrecompile struct{}

func (p *g2MSMPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.g2MSM(input, suppliedGas)
}

type pairingPrecompile struct{}

func (p *pairingPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if err := contract.RefuseUnderStrictPQ(accessibleState); err != nil {
		return nil, suppliedGas, err
	}
	return blsOps.pairing(input, suppliedGas)
}

// Per-operation Config types. Each composes the shared precompileconfig.Upgrade
// (timestamp + disable flag) and overrides Key() to return its own JSON
// identity. All other Config-interface methods are mechanically identical;
// implementing them per-type costs ~10 lines each but keeps the value-naming
// invariant (one Config type, one Key) inviolate at the type level.

type G1AddConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *G1AddConfig) Key() string                               { return G1AddConfigKey }
func (c *G1AddConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *G1AddConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *G1AddConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *G1AddConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*G1AddConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

type G1MulConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *G1MulConfig) Key() string                               { return G1MulConfigKey }
func (c *G1MulConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *G1MulConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *G1MulConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *G1MulConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*G1MulConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

type G1MSMConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *G1MSMConfig) Key() string                               { return G1MSMConfigKey }
func (c *G1MSMConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *G1MSMConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *G1MSMConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *G1MSMConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*G1MSMConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

type G2AddConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *G2AddConfig) Key() string                               { return G2AddConfigKey }
func (c *G2AddConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *G2AddConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *G2AddConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *G2AddConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*G2AddConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

type G2MulConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *G2MulConfig) Key() string                               { return G2MulConfigKey }
func (c *G2MulConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *G2MulConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *G2MulConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *G2MulConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*G2MulConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

type G2MSMConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *G2MSMConfig) Key() string                               { return G2MSMConfigKey }
func (c *G2MSMConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *G2MSMConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *G2MSMConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *G2MSMConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*G2MSMConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

type PairingConfig struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *PairingConfig) Key() string                               { return PairingConfigKey }
func (c *PairingConfig) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *PairingConfig) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *PairingConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (c *PairingConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*PairingConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

// Per-operation Configurators. Each MakeConfig() returns the matching Config
// type so JSON unmarshal into upgrade.PrecompileUpgrade lands the right Key().

type g1AddConfigurator struct{}

func (*g1AddConfigurator) MakeConfig() precompileconfig.Config { return new(G1AddConfig) }
func (*g1AddConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type g1MulConfigurator struct{}

func (*g1MulConfigurator) MakeConfig() precompileconfig.Config { return new(G1MulConfig) }
func (*g1MulConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type g1MSMConfigurator struct{}

func (*g1MSMConfigurator) MakeConfig() precompileconfig.Config { return new(G1MSMConfig) }
func (*g1MSMConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type g2AddConfigurator struct{}

func (*g2AddConfigurator) MakeConfig() precompileconfig.Config { return new(G2AddConfig) }
func (*g2AddConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type g2MulConfigurator struct{}

func (*g2MulConfigurator) MakeConfig() precompileconfig.Config { return new(G2MulConfig) }
func (*g2MulConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type g2MSMConfigurator struct{}

func (*g2MSMConfigurator) MakeConfig() precompileconfig.Config { return new(G2MSMConfig) }
func (*g2MSMConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type pairingConfigurator struct{}

func (*pairingConfigurator) MakeConfig() precompileconfig.Config { return new(PairingConfig) }
func (*pairingConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}
