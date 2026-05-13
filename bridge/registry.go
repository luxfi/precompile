// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

import "github.com/luxfi/geth/common"

// ChainID is the canonical numeric chain identifier (EIP-155 for EVM chains;
// virtual ids >= 900_000 for non-EVM bookkeeping).
type ChainID uint32

// Chain is one row in the supported-chain registry. Pure data, no behavior.
type Chain struct {
	ID        ChainID        // canonical numeric id
	Name      string         // short canonical name (e.g. "lux", "zoo-test")
	EVM       bool           // native EVM (eth_chainId) vs virtual / bookkeeping
	GatewayAt common.Address // optional bridge gateway address on that chain
}

// Registry resolves chains by id and enumerates the supported set.
//
// Implementations:
//   - staticRegistry: compile-time immutable list, used in tests and as the
//     production seed.
//   - stateRegistry: reads rows from the bridge contract's EVM storage so
//     operators can governance-tx new chains in or out at runtime.
type Registry interface {
	// Get returns the chain row for id and ok=true if registered.
	Get(id ChainID) (Chain, bool)
	// All returns every registered chain, in registry order.
	All() []Chain
}
