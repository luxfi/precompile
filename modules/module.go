// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package modules

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

type Module struct {
	// ConfigKey is the key used in json config files to specify this precompile config.
	ConfigKey string
	// Address returns the address where the stateful precompile is accessible.
	Address common.Address
	// Contract returns a thread-safe singleton that can be used as the StatefulPrecompiledContract when
	// this config is enabled.
	Contract contract.StatefulPrecompiledContract
	// Configurator is used to configure the stateful precompile when the config is enabled.
	contract.Configurator
	// AlwaysOn marks a precompile that is ACTIVE on every chain from genesis with NO
	// config entry (neither a genesis-inlined precompile nor a precompileUpgrades
	// timestamp). It is the one-way activation for system precompiles that take no
	// per-network parameters and resolve everything they need from the runtime
	// (consensus context / atomic state). The DEX settlement precompile (0x9999) is
	// the canonical case: it is the money path and must be present + callable the
	// instant the EVM plugin loads, with zero per-net configuration. An always-on
	// module's Configurator is never invoked (there is no activating config); the host
	// gives it the EXTCODESIZE marker at genesis and dispatches its Run unconditionally.
	AlwaysOn bool
}
