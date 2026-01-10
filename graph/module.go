// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graph

import (
	"fmt"
	"time"

	"github.com/luxfi/database"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	gvm "github.com/luxfi/vm/manager/graphvm"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*GraphQLContract)(nil)

// ConfigKey is the key used in json config files to specify this precompile config.
const ConfigKey = "graphConfig"

// Contract addresses for Graph/Query layer (0x0500-0x05FF)
// Note: Hashing precompiles (Poseidon2, Pedersen, Blake3) use 0x0500...0001-0004
// Graph precompiles start at 0x0500...0010 to avoid conflicts
var (
	ContractGraphQLAddress   = common.HexToAddress("0x0500000000000000000000000000000000000010")
	ContractSubscribeAddress = common.HexToAddress("0x0500000000000000000000000000000000000011")
	ContractCacheAddress     = common.HexToAddress("0x0500000000000000000000000000000000000012")
	ContractIndexAddress     = common.HexToAddress("0x0500000000000000000000000000000000000013")
)

// GraphQLContract wraps GraphQLPrecompile to implement StatefulPrecompiledContract
type GraphQLContract struct {
	precompile *GraphQLPrecompile
}

// GraphContractInstance is the singleton
var GraphContractInstance = &GraphQLContract{
	precompile: NewGraphQLPrecompile(nil),
}

// SetGraphVMClient configures the Graph precompile to use a real GraphVM client.
// This should be called during VM initialization when the database is available.
func SetGraphVMClient(db database.Database, config *gvm.GConfig) {
	client := NewGraphVMClient(db, config)
	GraphContractInstance.precompile.client = client
}

// SetGraphVMClientWithChainID configures the client for a specific chain.
func SetGraphVMClientWithChainID(db database.Database, config *gvm.GConfig, chainID uint64) {
	client := NewGraphVMClientWithChainID(db, config, chainID)
	GraphContractInstance.precompile.client = client
}

// Module is the precompile module
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractGraphQLAddress,
	Contract:     GraphContractInstance,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(GraphConfig)
}

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	config, ok := cfg.(*GraphConfig)
	if !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &GraphConfig{}, cfg, cfg)
	}

	// Update precompile configuration
	if config.GChainEndpoint != "" {
		GraphContractInstance.precompile.config.GChainEndpoint = config.GChainEndpoint
	}
	if config.QueryTimeout > 0 {
		GraphContractInstance.precompile.config.QueryTimeout = time.Duration(config.QueryTimeout) * time.Second
	}
	if config.MaxCacheSize > 0 {
		GraphContractInstance.precompile.config.MaxCacheSize = config.MaxCacheSize
	}

	return nil
}

// GraphConfig implements the precompileconfig.Config interface
type GraphConfig struct {
	Upgrade        precompileconfig.Upgrade `json:"upgrade,omitempty"`
	GChainEndpoint string                   `json:"gChainEndpoint,omitempty"`
	QueryTimeout   int                      `json:"queryTimeout,omitempty"`
	MaxCacheSize   int                      `json:"maxCacheSize,omitempty"`
}

func (c *GraphConfig) Key() string {
	return ConfigKey
}

func (c *GraphConfig) Timestamp() *uint64 {
	return c.Upgrade.Timestamp()
}

func (c *GraphConfig) IsDisabled() bool {
	return c.Upgrade.Disable
}

func (c *GraphConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*GraphConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade) &&
		c.GChainEndpoint == other.GChainEndpoint &&
		c.QueryTimeout == other.QueryTimeout &&
		c.MaxCacheSize == other.MaxCacheSize
}

func (c *GraphConfig) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}

// Run implements StatefulPrecompiledContract
func (c *GraphQLContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	requiredGas := c.precompile.RequiredGas(input)
	if suppliedGas < requiredGas {
		return nil, 0, fmt.Errorf("out of gas: required %d, supplied %d", requiredGas, suppliedGas)
	}

	result, runErr := c.precompile.Run(input)
	if runErr != nil {
		return nil, suppliedGas - requiredGas, runErr
	}

	return result, suppliedGas - requiredGas, nil
}
