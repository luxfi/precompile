// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

package secp256r1

import (
	"github.com/ethereum/go-ethereum/common"
)

// Module provides the secp256r1 precompile module information
type Module struct{}

// NewModule creates a new secp256r1 module
func NewModule() *Module {
	return &Module{}
}

// Address returns the precompile address
func (m *Module) Address() common.Address {
	return Address
}

// Contract returns a new contract instance
func (m *Module) Contract() *Contract {
	return &Contract{}
}

// ConfigKey returns the configuration key for this module
func (m *Module) ConfigKey() string {
	return "secp256r1Config"
}

// Name returns the module name
func (m *Module) Name() string {
	return "secp256r1"
}

// Description returns the module description
func (m *Module) Description() string {
	return "secp256r1 (P-256) signature verification precompile for biometric authentication and WebAuthn"
}

// Version returns the module version
func (m *Module) Version() string {
	return "1.0.0"
}

// EIPs returns the related EIP numbers
func (m *Module) EIPs() []int {
	return []int{7212}
}

// LPs returns the related LP numbers
func (m *Module) LPs() []int {
	return []int{3651}
}
