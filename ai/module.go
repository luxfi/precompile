// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ai

import (
	"encoding/binary"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*AIMiningContract)(nil)

// ConfigKey is the key used in json config files to specify this precompile config.
const ConfigKey = "aiMiningConfig"

// ContractAddress is the address of the AI Mining precompile (0x0300)
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000000")

// AIMiningPrecompile is the singleton instance
var AIMiningPrecompile = &AIMiningContract{}

// Module is the precompile module
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     AIMiningPrecompile,
	Configurator: &configurator{},
}

// Method selectors (first 4 bytes of keccak256 of function signature)
const (
	SelectorVerifyMLDSA     uint32 = 0x01000000 // verifyMLDSA(bytes,bytes,bytes)
	SelectorCalculateReward uint32 = 0x02000000 // calculateReward(bytes,uint64)
	SelectorVerifyTEE       uint32 = 0x03000000 // verifyTEE(bytes,bytes)
	SelectorIsSpent         uint32 = 0x04000000 // isSpent(bytes32)
	SelectorMarkSpent       uint32 = 0x05000000 // markSpent(bytes32)
	SelectorComputeWorkId   uint32 = 0x06000000 // computeWorkId(bytes32,bytes32,uint64)
)

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

func (*configurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	// No state initialization required
	return nil
}

// Config implements the precompileconfig.Config interface
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade,omitempty"`
}

func (c *Config) Key() string {
	return ConfigKey
}

func (c *Config) Timestamp() *uint64 {
	return c.Upgrade.Timestamp()
}

func (c *Config) IsDisabled() bool {
	return c.Upgrade.Disable
}

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}

// AIMiningContract implements the AI Mining precompile
type AIMiningContract struct{}

// Run executes the precompile
func (c *AIMiningContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < 4 {
		return nil, suppliedGas, fmt.Errorf("input too short")
	}

	selector := binary.BigEndian.Uint32(input[:4])
	data := input[4:]

	switch selector {
	case SelectorVerifyMLDSA:
		return c.runVerifyMLDSA(accessibleState, data, suppliedGas, readOnly)
	case SelectorCalculateReward:
		return c.runCalculateReward(accessibleState, data, suppliedGas)
	case SelectorVerifyTEE:
		return c.runVerifyTEE(accessibleState, data, suppliedGas)
	case SelectorIsSpent:
		return c.runIsSpent(accessibleState, data, suppliedGas)
	case SelectorMarkSpent:
		return c.runMarkSpent(accessibleState, data, suppliedGas, readOnly)
	case SelectorComputeWorkId:
		return c.runComputeWorkId(data, suppliedGas)
	default:
		return nil, suppliedGas, fmt.Errorf("unknown method selector: %x", selector)
	}
}

func (c *AIMiningContract) runVerifyMLDSA(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if suppliedGas < GasVerifyMLDSA {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Parse input: pubkey (32 bytes length prefix), message, signature
	if len(input) < 96 {
		return nil, suppliedGas - GasVerifyMLDSA, fmt.Errorf("input too short")
	}

	pubkeyLen := binary.BigEndian.Uint32(input[0:4])
	if uint32(len(input)) < 4+pubkeyLen+4 {
		return nil, suppliedGas - GasVerifyMLDSA, fmt.Errorf("invalid pubkey length")
	}
	pubkey := input[4 : 4+pubkeyLen]

	offset := 4 + pubkeyLen
	msgLen := binary.BigEndian.Uint32(input[offset : offset+4])
	if uint32(len(input)) < offset+4+msgLen+4 {
		return nil, suppliedGas - GasVerifyMLDSA, fmt.Errorf("invalid message length")
	}
	message := input[offset+4 : offset+4+msgLen]

	offset = offset + 4 + msgLen
	sigLen := binary.BigEndian.Uint32(input[offset : offset+4])
	if uint32(len(input)) < offset+4+sigLen {
		return nil, suppliedGas - GasVerifyMLDSA, fmt.Errorf("invalid signature length")
	}
	signature := input[offset+4 : offset+4+sigLen]

	valid, err := VerifyMLDSA(pubkey, message, signature)
	if err != nil {
		return nil, suppliedGas - GasVerifyMLDSA, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, suppliedGas - GasVerifyMLDSA, nil
}

func (c *AIMiningContract) runCalculateReward(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasCalculateReward {
		return nil, 0, fmt.Errorf("out of gas")
	}

	if len(input) < 86 { // WorkProofMinSize + 8 bytes for chainId
		return nil, suppliedGas - GasCalculateReward, fmt.Errorf("input too short")
	}

	workProof := input[:len(input)-8]
	chainId := binary.BigEndian.Uint64(input[len(input)-8:])

	reward, err := CalculateReward(workProof, chainId)
	if err != nil {
		return nil, suppliedGas - GasCalculateReward, err
	}

	result := make([]byte, 32)
	reward.FillBytes(result)
	return result, suppliedGas - GasCalculateReward, nil
}

func (c *AIMiningContract) runVerifyTEE(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasVerifyTEE {
		return nil, 0, fmt.Errorf("out of gas")
	}

	if len(input) < 8 {
		return nil, suppliedGas - GasVerifyTEE, fmt.Errorf("input too short")
	}

	receiptLen := binary.BigEndian.Uint32(input[0:4])
	if uint32(len(input)) < 4+receiptLen+4 {
		return nil, suppliedGas - GasVerifyTEE, fmt.Errorf("invalid receipt length")
	}
	receipt := input[4 : 4+receiptLen]

	offset := 4 + receiptLen
	sigLen := binary.BigEndian.Uint32(input[offset : offset+4])
	if uint32(len(input)) < offset+4+sigLen {
		return nil, suppliedGas - GasVerifyTEE, fmt.Errorf("invalid signature length")
	}
	signature := input[offset+4 : offset+4+sigLen]

	valid, err := VerifyTEE(receipt, signature)
	if err != nil {
		return nil, suppliedGas - GasVerifyTEE, err
	}

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, suppliedGas - GasVerifyTEE, nil
}

func (c *AIMiningContract) runIsSpent(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasIsSpent {
		return nil, 0, fmt.Errorf("out of gas")
	}

	if len(input) < 32 {
		return nil, suppliedGas - GasIsSpent, fmt.Errorf("input too short")
	}

	var workId [32]byte
	copy(workId[:], input[:32])

	stateDB := accessibleState.GetStateDB()
	spent := IsSpent(&stateDBAdapter{stateDB, ContractAddress}, workId)

	result := make([]byte, 32)
	if spent {
		result[31] = 1
	}
	return result, suppliedGas - GasIsSpent, nil
}

func (c *AIMiningContract) runMarkSpent(
	accessibleState contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasMarkSpent {
		return nil, 0, fmt.Errorf("out of gas")
	}

	if len(input) < 32 {
		return nil, suppliedGas - GasMarkSpent, fmt.Errorf("input too short")
	}

	var workId [32]byte
	copy(workId[:], input[:32])

	stateDB := accessibleState.GetStateDB()
	err := MarkSpent(&stateDBAdapter{stateDB, ContractAddress}, workId)
	if err != nil {
		return nil, suppliedGas - GasMarkSpent, err
	}

	result := make([]byte, 32)
	result[31] = 1
	return result, suppliedGas - GasMarkSpent, nil
}

func (c *AIMiningContract) runComputeWorkId(
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasComputeWorkId {
		return nil, 0, fmt.Errorf("out of gas")
	}

	if len(input) < 72 { // 32 + 32 + 8
		return nil, suppliedGas - GasComputeWorkId, fmt.Errorf("input too short")
	}

	var deviceId, nonce [32]byte
	copy(deviceId[:], input[:32])
	copy(nonce[:], input[32:64])
	chainId := binary.BigEndian.Uint64(input[64:72])

	workId := ComputeWorkId(deviceId, nonce, chainId)
	return workId[:], suppliedGas - GasComputeWorkId, nil
}

// stateDBAdapter adapts contract.StateDB to ai.StateDB
type stateDBAdapter struct {
	stateDB contract.StateDB
	addr    common.Address
}

func (a *stateDBAdapter) GetState(addr [20]byte, key [32]byte) [32]byte {
	return [32]byte(a.stateDB.GetState(common.Address(addr), common.Hash(key)))
}

func (a *stateDBAdapter) SetState(addr [20]byte, key [32]byte, value [32]byte) {
	a.stateDB.SetState(common.Address(addr), common.Hash(key), common.Hash(value))
}

// RequiredGas returns the gas required for the precompile input
func (c *AIMiningContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasCalculateReward
	}

	selector := binary.BigEndian.Uint32(input[:4])
	switch selector {
	case SelectorVerifyMLDSA:
		return GasVerifyMLDSA
	case SelectorCalculateReward:
		return GasCalculateReward
	case SelectorVerifyTEE:
		return GasVerifyTEE
	case SelectorIsSpent:
		return GasIsSpent
	case SelectorMarkSpent:
		return GasMarkSpent
	case SelectorComputeWorkId:
		return GasComputeWorkId
	default:
		return GasCalculateReward
	}
}

// GetChainId returns the chain ID from the accessible state
func GetChainId(state contract.AccessibleState) uint64 {
	// Chain ID is typically available from block context or chain config
	// For now, return a default value - actual implementation would
	// depend on how ChainConfig exposes chain ID
	return 96369 // Default to C-Chain mainnet
}
