// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zk

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*zkVerifyPrecompile)(nil)

// ConfigKey is the key used in json config files to specify this precompile config.
const ConfigKey = "zkConfig"

// Precompile contract addresses (Lux ZK range 0x0900)
var (
	// Core ZK verification (0x0900...00-0F)
	ZKVerifyContractAddress = common.HexToAddress("0x0900000000000000000000000000000000000000")
	Groth16ContractAddress  = common.HexToAddress("0x0900000000000000000000000000000000000001")
	PlonkContractAddress    = common.HexToAddress("0x0900000000000000000000000000000000000002")
	FflonkContractAddress   = common.HexToAddress("0x0900000000000000000000000000000000000003")
	Halo2ContractAddress    = common.HexToAddress("0x0900000000000000000000000000000000000004")

	// Commitment schemes (0x0900...10-1F)
	KZGContractAddress = common.HexToAddress("0x0900000000000000000000000000000000000010")
	IPAContractAddress = common.HexToAddress("0x0900000000000000000000000000000000000012")

	// Privacy operations (0x0900...20-2F)
	PrivacyPoolContractAddress = common.HexToAddress("0x0900000000000000000000000000000000000020")
	NullifierContractAddress   = common.HexToAddress("0x0900000000000000000000000000000000000021")
	CommitmentContractAddress  = common.HexToAddress("0x0900000000000000000000000000000000000022")
	RangeProofContractAddress  = common.HexToAddress("0x0900000000000000000000000000000000000023")

	// Rollup support (0x0900...30-3F)
	RollupVerifyContractAddress = common.HexToAddress("0x0900000000000000000000000000000000000030")
	StateRootContractAddress    = common.HexToAddress("0x0900000000000000000000000000000000000031")
	BatchProofContractAddress   = common.HexToAddress("0x0900000000000000000000000000000000000032")
)

// Hashing precompile addresses (Lux Hashing range 0x0500...01-03)
var (
	Poseidon2ContractAddress = common.HexToAddress("0x0500000000000000000000000000000000000001")
	Poseidon2SpongeAddress   = common.HexToAddress("0x0500000000000000000000000000000000000002")
	PedersenContractAddress  = common.HexToAddress("0x0500000000000000000000000000000000000003")
	// Blake3 is at 0x0500...04, defined in blake3/contract.go
)

// ZKVerifyPrecompile is the singleton instance of the ZK verify precompile
var ZKVerifyPrecompile = &zkVerifyPrecompile{}

// Module is the precompile module
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ZKVerifyContractAddress,
	Contract:     ZKVerifyPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	// No state initialization required
	return nil
}

// Config implements the precompileconfig.Config interface
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade,omitempty"`
}

func (c *Config) Key() string {
	return ConfigKey
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
	return nil
}
