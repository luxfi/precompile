// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// module.go — the A-Chain inference BRIDGE precompile. It is a SEPARATE precompile
// at its own address in the AI range (0x0300…0004), DISJOINT from the deterministic
// in-consensus inference precompile (0x0300…0003) and the AI-mining precompile
// (0x0300…0000). It on-ramps an EVM contract to the node-LOCAL A-Chain (aivm) via
// two consensus-safe ops:
//
//   - SubmitInferenceIntent (Pattern A): write a committed C-side outbox intent +
//     return a deterministic id. No A query, no A mutation.
//   - VerifyInferenceReceipt (Pattern B): verify a committed A receipt + proof against
//     a committed receipt root C holds. No A query.
//
// The C-Chain state root is derivable WITHOUT observing any live A process — that is
// the #1 law and the reason this is a bridge of COMMITTED objects, never a live RPC.

package aivmbridge

import (
	"encoding/binary"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*BridgeContract)(nil)

// ConfigKey is the json key for this precompile's upgrade config.
const ConfigKey = "aivmBridgeConfig"

// ContractAddress — the AI range is 0x0300…0000 .. 0x0300…00FF (the significant byte
// is 0x03 at the front; the slot is the LAST byte). 0x00 = AI_MINING, 0x03 =
// AI_INFERENCE (the deterministic precompile). This bridge takes slot 0x04 →
// 0x0300…0004, distinct from both.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000004")

// BridgePrecompile is the singleton.
var BridgePrecompile = &BridgeContract{}

// Module registers the precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     BridgePrecompile,
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
	_ precompileconfig.ChainConfig,
	_ precompileconfig.Config,
	_ contract.StateDB,
	_ contract.ConfigurationBlockContext,
) error {
	return nil // no genesis state initialization
}

// Config is the upgrade config for the precompile.
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *Config) Key() string                               { return ConfigKey }
func (c *Config) Timestamp() *uint64                        { return c.Upgrade.Timestamp() }
func (c *Config) IsDisabled() bool                          { return c.Upgrade.Disable }
func (c *Config) Verify(precompileconfig.ChainConfig) error { return nil }

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

// BridgeContract implements the A-Chain inference bridge precompile.
type BridgeContract struct{}

// RequiredGas is a deterministic function of the selector (and, for verify, the proof
// depth declared in calldata). It NEVER depends on any A-Chain observation.
//
// For verify, gas scales with the merkle proof depth so a deep proof pays for its
// hashing; the depth is read from the calldata frame (and hard-capped by MaxProofDepth
// at decode time). A malformed/short frame falls back to the base verify gas.
func (c *BridgeContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasVerifyInferenceReceiptBase // cheapest op's base; the call will revert on decode anyway
	}
	sel := binary.BigEndian.Uint32(input[:4])
	switch sel {
	case SelectorSubmitInferenceIntent:
		return GasSubmitInferenceIntent
	case SelectorVerifyInferenceReceipt:
		args := input[4:]
		// Frame: [0:2] receiptLen, [2:4] proofLen, then bytes. The proof's own header
		// holds the pathLen at proofBytes[40:42]. Compute gas from the declared pathLen
		// when the frame is well-formed; else the base.
		if len(args) < 4 {
			return GasVerifyInferenceReceiptBase
		}
		receiptLen := int(binary.BigEndian.Uint16(args[0:2]))
		proofLen := int(binary.BigEndian.Uint16(args[2:4]))
		if len(args) != 4+receiptLen+proofLen {
			return GasVerifyInferenceReceiptBase
		}
		proofBytes := args[4+receiptLen:]
		// proof header is ReceiptRoot(32)|Index(8)|pathLen(2) = 42 bytes.
		if len(proofBytes) < 42 {
			return GasVerifyInferenceReceiptBase
		}
		pathLen := int(binary.BigEndian.Uint16(proofBytes[40:42]))
		if pathLen > MaxProofDepth {
			return GasVerifyInferenceReceiptBase
		}
		return verifyGas(pathLen)
	case SelectorVerifyComputeProof:
		return computeProofRequiredGas(input[4:])
	default:
		return GasVerifyInferenceReceiptBase
	}
}

// Run executes the precompile. It charges gas per op and routes to the consensus-safe
// Pattern A / Pattern B handlers (bridge.go). It NEVER calls into aivm.
func (c *BridgeContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	return runBridge(accessibleState, caller, input, suppliedGas, readOnly)
}
