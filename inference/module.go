// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// module.go — the AI-inference EVM precompile (0x0303), shared by the Lux/Zoo/Hanzo
// EVMs. It runs a deterministic int8 transformer (inference.go) entirely in pure Go on
// the consensus path — every validator computes byte-identical logits/tokens with no GPU
// required. The lux-private GPU kernels are a KAT-proven byte-equal accelerator; the
// canonical result is always this Go reference, so consensus can never fork on hardware.
//
// MVP scope: the model is the built-in frozen reference (fixtureModel). On-chain model
// provisioning (a model registry keyed by weight-commitment hash) is the next step; the
// ABI is selector-based so it extends cleanly.

package inference

import (
	"encoding/binary"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*InferenceContract)(nil)

// ConfigKey is the json key for this precompile's upgrade config.
const ConfigKey = "aiInferenceConfig"

// ContractAddress — AI Mining reserved range is 0x0300…0000 .. 0x0300…00FF (the
// significant byte is 0x03 at the front; the slot is the LAST byte). 0x0300…0000 is
// AI_MINING; AI_INFERENCE takes slot 0x03 → 0x0300…0003.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000003")

// InferencePrecompile is the singleton.
var InferencePrecompile = &InferenceContract{}

// Module registers the precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     InferencePrecompile,
	Configurator: &configurator{},
}

// Method selectors (first 4 bytes).
const (
	// generate(uint32 nNew, uint32[] promptTokens) -> uint32[] (prompt+generated)
	SelectorGenerate uint32 = 0x01000000
)

// Gas costs. Inference is heavy and deterministic; gas is a pure function of the
// requested new-token count (the built-in model's dims are fixed in the MVP).
const (
	GasBaseInference uint64 = 100_000
	GasPerNewToken   uint64 = 50_000
	MaxNewTokens     uint32 = 64
	MaxSeqLen        int    = 256
)

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
	return nil // no state initialization
}

// Config is the upgrade config for the precompile.
type Config struct {
	Upgrade precompileconfig.Upgrade `json:"upgrade"`
}

func (c *Config) Key() string         { return ConfigKey }
func (c *Config) Timestamp() *uint64  { return c.Upgrade.Timestamp() }
func (c *Config) IsDisabled() bool    { return c.Upgrade.Disable }
func (c *Config) Verify(precompileconfig.ChainConfig) error { return nil }

func (c *Config) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*Config)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

// InferenceContract implements the AI-inference precompile.
type InferenceContract struct{}

// RequiredGas is a deterministic function of the input (selector + requested nNew).
func (c *InferenceContract) RequiredGas(input []byte) uint64 {
	if len(input) < 8 {
		return GasBaseInference
	}
	nNew := binary.BigEndian.Uint32(input[4:8])
	if nNew > MaxNewTokens {
		nNew = MaxNewTokens
	}
	return GasBaseInference + uint64(nNew)*GasPerNewToken
}

// Run executes the precompile (pure compute; no state access).
func (c *InferenceContract) Run(
	_ contract.AccessibleState,
	_ common.Address,
	_ common.Address,
	input []byte,
	suppliedGas uint64,
	_ bool,
) (ret []byte, remainingGas uint64, err error) {
	gas := c.RequiredGas(input)
	if suppliedGas < gas {
		return nil, 0, fmt.Errorf("out of gas: need %d have %d", gas, suppliedGas)
	}
	remainingGas = suppliedGas - gas

	if len(input) < 4 {
		return nil, remainingGas, fmt.Errorf("input too short")
	}
	selector := binary.BigEndian.Uint32(input[:4])
	if selector != SelectorGenerate {
		return nil, remainingGas, fmt.Errorf("unknown selector %#x", selector)
	}
	if len(input) < 12 { // selector(4) + nNew(4) + >=1 token(4)
		return nil, remainingGas, fmt.Errorf("input too short for generate")
	}
	nNew := binary.BigEndian.Uint32(input[4:8])
	body := input[8:]
	if len(body)%4 != 0 {
		return nil, remainingGas, fmt.Errorf("prompt not a multiple of 4 bytes")
	}
	promptLen := len(body) / 4
	if promptLen < 1 {
		return nil, remainingGas, fmt.Errorf("empty prompt")
	}
	if nNew > MaxNewTokens {
		return nil, remainingGas, fmt.Errorf("nNew %d exceeds max %d", nNew, MaxNewTokens)
	}
	if promptLen+int(nNew) > MaxSeqLen {
		return nil, remainingGas, fmt.Errorf("sequence %d exceeds max %d", promptLen+int(nNew), MaxSeqLen)
	}

	model := fixtureModel() // MVP: built-in reference model
	prompt := make([]int32, promptLen)
	for i := 0; i < promptLen; i++ {
		tok := binary.BigEndian.Uint32(body[i*4 : i*4+4])
		if tok >= model.Cfg.Vocab {
			return nil, remainingGas, fmt.Errorf("token %d out of vocab %d", tok, model.Cfg.Vocab)
		}
		prompt[i] = int32(tok)
	}

	out := model.Generate(prompt, nNew)
	ret = make([]byte, len(out)*4)
	for i, t := range out {
		binary.BigEndian.PutUint32(ret[i*4:i*4+4], uint32(t))
	}
	return ret, remainingGas, nil
}
