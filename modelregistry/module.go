// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Package modelregistry is the on-chain registry of the network's current AI model —
// the "continuously evolving" mechanism for a thinking chain (e.g. Zoo L3 Beluga / BLG).
// Admins (a DAO/multisig, seeded at genesis) ADOPT new model versions by weight-commitment
// hash; the inference precompile (0x0300…0003) reads the approved commitment. The model
// evolves through on-chain governance — versioned, auditable, and immutable once adopted
// (you can't slip in a backdoor without a recorded adopt by an admin).
//
// Precompile address 0x0300…0002 (AI range slot 0x02 = MODEL_REGISTRY).

package modelregistry

import (
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*ModelRegistryContract)(nil)

const ConfigKey = "modelRegistryConfig"

// ContractAddress — AI reserved range 0x0300…0000..00FF; slot 0x02 = MODEL_REGISTRY
// (0x00 AI_MINING, 0x01 NV_TRUST, 0x02 MODEL_REGISTRY, 0x03 AI_INFERENCE).
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000002")

var ModelRegistryPrecompile = &ModelRegistryContract{}

var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     ModelRegistryPrecompile,
	Configurator: &configurator{},
}

// Method selectors (first 4 bytes).
const (
	SelectorAdopt       uint32 = 0x01000000 // adopt(bytes32 name, uint256 version, bytes32 weightHash)
	SelectorGetApproved uint32 = 0x02000000 // getApproved(bytes32 name) -> (uint256, bytes32)
	SelectorIsAdmin     uint32 = 0x03000000 // isAdmin(address) -> bool
	SelectorSetAdmin    uint32 = 0x04000000 // setAdmin(address, bool) -> bool
)

const (
	GasAdopt       uint64 = 25_000 // two state writes (version + weight)
	GasGetApproved uint64 = 5_000  // two state reads
	GasIsAdmin     uint64 = 3_000
	GasSetAdmin    uint64 = 10_000
)

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config { return new(Config) }

// Configure seeds the initial admin (governance) set into state at activation.
func (*configurator) Configure(
	_ precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	_ contract.ConfigurationBlockContext,
) error {
	c, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("modelregistry: unexpected config type %T", cfg)
	}
	for _, a := range c.Admins {
		setAdminState(state, a, true)
	}
	return nil
}

// Config is the upgrade config; Admins is the initial governance set (a DAO/multisig).
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
	Admins  []common.Address         `json:"admins,omitempty"`
}

func (c *Config) Key() string                               { return ConfigKey }
func (c *Config) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *Config) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *Config) Verify(precompileconfig.ChainConfig) error { return nil }

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	if !c.Upgrade.Equal(&other.Upgrade) || len(c.Admins) != len(other.Admins) {
		return false
	}
	for i := range c.Admins {
		if c.Admins[i] != other.Admins[i] {
			return false
		}
	}
	return true
}
