// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls12381

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// Config keys for each EIP-2537 operation (unique per module).
const (
	G1AddConfigKey   = "bls12381G1AddConfig"
	G1MulConfigKey   = "bls12381G1MulConfig"
	G1MSMConfigKey   = "bls12381G1MSMConfig"
	G2AddConfigKey   = "bls12381G2AddConfig"
	G2MulConfigKey   = "bls12381G2MulConfig"
	G2MSMConfigKey   = "bls12381G2MSMConfig"
	PairingConfigKey = "bls12381PairingConfig"
)

// Modules registers one module per EIP-2537 address (0x0B-0x11).
var (
	G1AddModule = modules.Module{
		ConfigKey:    G1AddConfigKey,
		Address:      G1AddAddress,
		Contract:     &g1AddPrecompile{},
		Configurator: &configurator{},
	}
	G1MulModule = modules.Module{
		ConfigKey:    G1MulConfigKey,
		Address:      G1MulAddress,
		Contract:     &g1MulPrecompile{},
		Configurator: &configurator{},
	}
	G1MSMModule = modules.Module{
		ConfigKey:    G1MSMConfigKey,
		Address:      G1MSMAddress,
		Contract:     &g1MSMPrecompile{},
		Configurator: &configurator{},
	}
	G2AddModule = modules.Module{
		ConfigKey:    G2AddConfigKey,
		Address:      G2AddAddress,
		Contract:     &g2AddPrecompile{},
		Configurator: &configurator{},
	}
	G2MulModule = modules.Module{
		ConfigKey:    G2MulConfigKey,
		Address:      G2MulAddress,
		Contract:     &g2MulPrecompile{},
		Configurator: &configurator{},
	}
	G2MSMModule = modules.Module{
		ConfigKey:    G2MSMConfigKey,
		Address:      G2MSMAddress,
		Contract:     &g2MSMPrecompile{},
		Configurator: &configurator{},
	}
	PairingModule = modules.Module{
		ConfigKey:    PairingConfigKey,
		Address:      PairingAddress,
		Contract:     &pairingPrecompile{},
		Configurator: &configurator{},
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

// configurator is shared across all 7 modules (no per-op config needed).
type configurator struct{}

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
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *Config) Key() string        { return G1AddConfigKey }
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
