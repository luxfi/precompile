// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pqcrypto

import (
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = &configurator{}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(modules.Module{
		ConfigKey:    ConfigKey,
		Address:      ContractAddress,
		Contract:     PQCryptoPrecompile,
		Configurator: &configurator{},
	}); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config { return &Config{} }

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}
