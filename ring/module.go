// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompiles/contract"
)

var (
	// Module is the precompile module singleton
	Module = &module{
		address:  ContractAddress,
		contract: RingSignaturePrecompile,
	}
)

type module struct {
	address  common.Address
	contract contract.StatefulPrecompiledContract
}

// Address returns the address where the stateful precompile is accessible.
func (m *module) Address() common.Address {
	return m.address
}

// Contract returns a thread-safe singleton that can be used as the StatefulPrecompiledContract
func (m *module) Contract() contract.StatefulPrecompiledContract {
	return m.contract
}

// Configure is a no-op for Ring Signatures as it has no configuration
func (m *module) Configure(
	_ contract.StateDB,
	_ common.Address,
) error {
	return nil
}
