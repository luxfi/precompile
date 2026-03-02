// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"github.com/luxfi/geth/common"
)

// Module provides the ed25519 precompile module information
type Module struct{}

// NewModule creates a new ed25519 module
func NewModule() *Module {
	return &Module{}
}

// Address returns the precompile address
func (m *Module) Address() common.Address {
	return ContractAddress
}

// Contract returns the singleton contract instance
func (m *Module) Contract() *ed25519VerifyPrecompile {
	return Ed25519VerifyPrecompile
}

// ConfigKey returns the configuration key for this module
func (m *Module) ConfigKey() string {
	return "ed25519Config"
}

// Name returns the module name
func (m *Module) Name() string {
	return "ed25519"
}
