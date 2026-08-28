// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package attestation

import (
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = Precompile

const ConfigKey = "attestationConfig"

// ContractAddress is the primary registered address for the attestation precompile.
// AI attestation range: 0x0300..01-05 (within the 0x0300 AI block).
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000001")

// Precompile is the singleton stateful precompile instance.
var Precompile = &attestationPrecompile{}

var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     Precompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config { return new(Config) }

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	return nil
}

type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *Config) Key() string        { return ConfigKey }
func (c *Config) Timestamp() *uint64 { return c.Upgrade.Timestamp() }
func (c *Config) IsDisabled() bool   { return c.Upgrade.Disable }
func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}
func (c *Config) Verify(precompileconfig.ChainConfig) error { return nil }

// attestationPrecompile wraps the attestation library functions into the
// StatefulPrecompiledContract interface required for EVM precompile registration.
//
// Selector dispatch (first 4 bytes of input):
//
//	0x01000000 - VerifyNVTrust (GPU attestation)
//	0x02000000 - VerifyTPM (SGX/SEV-SNP/TDX)
//	0x03000000 - VerifyCompute (AI compute result)
//	0x04000000 - CreateAttestation (register device)
//	0x05000000 - GetDeviceStatus (query status)
type attestationPrecompile struct{}

func (p *attestationPrecompile) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if len(input) < 4 {
		return nil, suppliedGas, ErrInvalidInput
	}

	gasNeeded := RequiredGas(input)
	gas, err := contract.DeductGas(suppliedGas, gasNeeded)
	if err != nil {
		return nil, 0, err
	}

	// Deterministic block timestamp from consensus state; used only for
	// attestation expiry. Never time.Now().
	var blockTS uint64
	if accessibleState != nil {
		if bc := accessibleState.GetBlockContext(); bc != nil {
			blockTS = bc.Timestamp()
		}
	}

	result, err := Run(input, blockTS)
	if err != nil {
		return nil, gas, err
	}
	return result, gas, nil
}
