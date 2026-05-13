// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package bridge

// staticRegistry is an immutable in-memory Registry. Cheap lookups via id map,
// stable enumeration order via the slice.
type staticRegistry struct {
	chains []Chain
	byID   map[ChainID]Chain
}

// NewStatic returns a Registry over an immutable list. Used in tests and as
// the default seed loaded into the on-chain registry at deployment.
func NewStatic(chains []Chain) Registry {
	byID := make(map[ChainID]Chain, len(chains))
	out := make([]Chain, len(chains))
	for i, c := range chains {
		out[i] = c
		byID[c.ID] = c
	}
	return &staticRegistry{chains: out, byID: byID}
}

func (r *staticRegistry) Get(id ChainID) (Chain, bool) {
	c, ok := r.byID[id]
	return c, ok
}

func (r *staticRegistry) All() []Chain {
	out := make([]Chain, len(r.chains))
	copy(out, r.chains)
	return out
}

// DefaultSeed is the initial registry contents that ship with a fresh bridge
// contract. Operators governance-tx new chains in or out at runtime via the
// state-backed registry; this list is the canonical day-zero set.
func DefaultSeed() []Chain {
	return []Chain{
		// Lux ecosystem
		{ID: 96369, Name: "lux", EVM: true},
		{ID: 96368, Name: "lux-test", EVM: true},
		{ID: 36963, Name: "hanzo", EVM: true},
		{ID: 36962, Name: "hanzo-test", EVM: true},
		{ID: 200200, Name: "zoo", EVM: true},
		{ID: 200201, Name: "zoo-test", EVM: true},
		{ID: 36911, Name: "spc", EVM: true},
		{ID: 36910, Name: "spc-test", EVM: true},
		{ID: 6133, Name: "pars", EVM: true},
		{ID: 6132, Name: "pars-test", EVM: true},

		// External EVM chains
		{ID: 1, Name: "ethereum", EVM: true},
		{ID: 42161, Name: "arbitrum", EVM: true},
		{ID: 10, Name: "optimism", EVM: true},
		{ID: 8453, Name: "base", EVM: true},
		{ID: 137, Name: "polygon", EVM: true},
		{ID: 56, Name: "bsc", EVM: true},
		{ID: 43114, Name: "avalanche", EVM: true},

		// Non-EVM chains (virtual ids for bookkeeping)
		{ID: 900001, Name: "solana", EVM: false},
		{ID: 900002, Name: "bitcoin", EVM: false},
		{ID: 900003, Name: "xrp", EVM: false},
		{ID: 900004, Name: "ton", EVM: false},
	}
}
