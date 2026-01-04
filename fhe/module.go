// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// ConfigKey is the key used in json config files to specify this precompile config.
// Must be unique across all precompiles.
const ConfigKey = "fheConfig"

// FHE Precompile Addresses (Lux Privacy range 0x0700)
var (
	// Main FHE operations precompile
	ContractAddress = common.HexToAddress("0x0700000000000000000000000000000000000000")
	// ACL (Access Control List) precompile
	ACLContractAddress = common.HexToAddress("0x0700000000000000000000000000000000000001")
	// Input Verifier precompile
	InputVerifierAddress = common.HexToAddress("0x0700000000000000000000000000000000000002")
	// Decryption Gateway precompile
	GatewayContractAddress = common.HexToAddress("0x0700000000000000000000000000000000000003")
)

// FHEPrecompile is a thread-safe singleton instance of FHEContract
var FHEPrecompile contract.StatefulPrecompiledContract = &FHEContract{}

// Module is the precompile module. It is used to register the precompile contract.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     FHEPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	// Register the precompile module.
	// Each precompile contract registers itself through [RegisterModule] function.
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

// MakeConfig returns a new precompile config instance.
// This is required to Marshal/Unmarshal the precompile config.
func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

// Configure configures the FHE precompile when enabled
func (*configurator) Configure(chainConfig precompileconfig.ChainConfig, cfg precompileconfig.Config, state contract.StateDB, blockContext contract.ConfigurationBlockContext) error {
	config, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &Config{}, cfg, cfg)
	}

	// Initialize TFHE parameters if network key path is specified
	if config.NetworkKeyPath != "" {
		// TODO: Load network key from path
		// This would be used for production deployments with shared network keys
	}

	// Initialize coprocessor connection if endpoint is specified
	if config.CoprocessorEndpoint != "" {
		// TODO: Connect to Z-Chain coprocessor for threshold decryption
	}

	return nil
}
