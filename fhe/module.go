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

// FHE Precompile Addresses (0x0700 Privacy/Encryption reserved range).
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

// Configure configures the FHE precompile when enabled.
//
// Activation gate (DoS prevention):
//
//	The FHE precompile cannot ship safely on a chain whose block gas limit
//	is too small to absorb the per-op wall-clock budget of one Mul. With the
//	bench-derived GasMul (936M) and MinSafeGasMulRatio=1, a chain whose
//	effective gasLimit is below GasMul refuses to activate the precompile
//	rather than silently bricking finality at the activation block.
//
//	The gate fires only when the ChainConfig implements FeeConfigReporter
//	(luxd integration); non-Lux integrators that wire only the empty
//	ChainConfig interface remain permissive.
//
// Recovery is operator-side: raise gasLimit via feeConfigManagerConfig
// before re-running the upgrade, or remove fheConfig from upgrade.json.
func (*configurator) Configure(chainConfig precompileconfig.ChainConfig, cfg precompileconfig.Config, state contract.StateDB, blockContext contract.ConfigurationBlockContext) error {
	config, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &Config{}, cfg, cfg)
	}

	// Refuse activation if the chain's effective gasLimit cannot
	// safely absorb the FHE compute budget. Permissive when the chain
	// does not implement FeeConfigReporter (cross-chain integrators).
	minGasLimit := GasMul * MinSafeGasMulRatio
	if err := contract.RequireGasLimit(chainConfig, blockContext, minGasLimit); err != nil {
		return fmt.Errorf("%w: GasMul=%d × MinSafeGasMulRatio=%d = %d gas required",
			err, GasMul, MinSafeGasMulRatio, minGasLimit)
	}

	// Network FHE keys are installed in-process via SetNetworkKeys by the node's
	// VM layer, which shares the F-Chain (ThresholdVM) DKG's live public key
	// material (encryption + bootstrap keys) with this precompile. The secret
	// key is threshold-shared on the F-Chain and is never held here. Until keys
	// are installed the precompile runs key-less: encrypt/compute fail closed
	// and decrypt/seal require the F-Chain threshold ceremony — no insecure
	// default key is ever fabricated.
	//
	// Keys are passed as live objects rather than loaded from NetworkKeyPath:
	// luxfi/fhe v1.8.2 cannot serialize a BootstrapKey for cross-process
	// transport (its MarshalBinary omits the KSK field and gob-fails on the
	// blind-rotation key set). NetworkKeyPath/CoprocessorEndpoint remain
	// reserved for when that upstream serialization is complete.
	_ = config
	return nil
}
