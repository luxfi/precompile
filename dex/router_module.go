// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*routerConfigurator)(nil)
var _ contract.StatefulPrecompiledContract = (*RouterContract)(nil)

// RouterConfigKey is the key used in json config files for the router precompile.
const RouterConfigKey = "routerConfig"

// RouterPrecompile is the singleton router instance.
var RouterPrecompile = &RouterContract{
	router: NewLXRouter(DEXPrecompile.poolManager),
}

// RouterModule is the precompile module (LXRouter at LP-9012).
var RouterModule = modules.Module{
	ConfigKey:    RouterConfigKey,
	Address:      lxRouterAddr,
	Contract:     RouterPrecompile,
	Configurator: &routerConfigurator{},
}

func init() {
	if err := modules.RegisterModule(RouterModule); err != nil {
		panic(err)
	}
}

// routerConfigurator implements contract.Configurator for the router.
type routerConfigurator struct{}

func (*routerConfigurator) MakeConfig() precompileconfig.Config {
	return new(RouterConfig)
}

func (*routerConfigurator) Configure(
	chainConfig precompileconfig.ChainConfig,
	cfg precompileconfig.Config,
	state contract.StateDB,
	blockContext contract.ConfigurationBlockContext,
) error {
	config, ok := cfg.(*RouterConfig)
	if !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &RouterConfig{}, cfg, cfg)
	}

	// Configure V3/V2 contract addresses if provided
	if config.V3QuoterAddress != (common.Address{}) {
		v3QuoterAddr = config.V3QuoterAddress
	}
	if config.V3FactoryAddress != (common.Address{}) {
		v3FactoryAddr = config.V3FactoryAddress
	}
	if config.V2RouterAddress != (common.Address{}) {
		v2RouterAddr = config.V2RouterAddress
	}
	if config.V2FactoryAddress != (common.Address{}) {
		v2FactoryAddr = config.V2FactoryAddress
	}

	return nil
}

// RouterConfig implements precompileconfig.Config for the router.
type RouterConfig struct {
	precompileconfig.Upgrade
	V3QuoterAddress  common.Address `json:"v3QuoterAddress,omitempty"`
	V3FactoryAddress common.Address `json:"v3FactoryAddress,omitempty"`
	V2RouterAddress  common.Address `json:"v2RouterAddress,omitempty"`
	V2FactoryAddress common.Address `json:"v2FactoryAddress,omitempty"`
}

func (c *RouterConfig) Key() string {
	return RouterConfigKey
}

func (c *RouterConfig) Timestamp() *uint64 {
	return c.Upgrade.Timestamp()
}

func (c *RouterConfig) IsDisabled() bool {
	return c.Upgrade.Disable
}

func (c *RouterConfig) Equal(cfg precompileconfig.Config) bool {
	other, ok := cfg.(*RouterConfig)
	if !ok {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade) &&
		c.V3QuoterAddress == other.V3QuoterAddress &&
		c.V3FactoryAddress == other.V3FactoryAddress &&
		c.V2RouterAddress == other.V2RouterAddress &&
		c.V2FactoryAddress == other.V2FactoryAddress
}

func (c *RouterConfig) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}

// RouterContract implements the LXRouter precompile at 0x9012.
type RouterContract struct {
	router *LXRouter
}

// Run executes the router precompile.
func (c *RouterContract) Run(
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
	case SelectorExactInputSingle:
		return c.runExactInputSingle(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorExactInput:
		return c.runExactInput(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorExactOutputSingle:
		return c.runExactOutputSingle(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorExactOutput:
		return c.runExactOutput(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorQuoteExactInputSingle:
		return c.runQuoteExactInputSingle(accessibleState, data, suppliedGas)
	case SelectorQuoteExactInput:
		return c.runQuoteExactInput(accessibleState, data, suppliedGas)
	case SelectorGetBestRoute:
		return c.runGetBestRoute(accessibleState, data, suppliedGas)
	default:
		return nil, suppliedGas, fmt.Errorf("unknown router method selector: %x", selector)
	}
}

func (c *RouterContract) runExactInputSingle(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}
	if suppliedGas < GasSingleSwap {
		return nil, 0, fmt.Errorf("out of gas")
	}

	params, err := DecodeExactInputSingleParams(input)
	if err != nil {
		return nil, suppliedGas - GasSingleSwap, err
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	amountOut, venue, err := c.router.ExactInputSingle(stateAdapter, caller, params)
	if err != nil {
		return nil, suppliedGas - GasSingleSwap, err
	}

	return EncodeSwapResult(amountOut, venue), suppliedGas - GasSingleSwap, nil
}

func (c *RouterContract) runExactInput(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	params, err := DecodeExactInputParams(input)
	if err != nil {
		return nil, suppliedGas, err
	}

	numHops := len(params.Path) - 1
	gasCost := GasMultiHopBase + uint64(numHops)*GasMultiHopPerHop
	if suppliedGas < gasCost {
		return nil, 0, fmt.Errorf("out of gas")
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	amountOut, err := c.router.ExactInput(stateAdapter, caller, params)
	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	result := make([]byte, 32)
	copy(result, common.LeftPadBytes(amountOut.Bytes(), 32))
	return result, suppliedGas - gasCost, nil
}

func (c *RouterContract) runExactOutputSingle(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	// Exact output routing: find minimum input for desired output.
	// For now, return not-implemented until V4 exact-output math is complete.
	return nil, suppliedGas, fmt.Errorf("exactOutputSingle not yet implemented")
}

func (c *RouterContract) runExactOutput(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	return nil, suppliedGas, fmt.Errorf("exactOutput not yet implemented")
}

func (c *RouterContract) runQuoteExactInputSingle(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasQuote {
		return nil, 0, fmt.Errorf("out of gas")
	}

	tokenIn, tokenOut, amountIn, fee, err := DecodeQuoteParams(input)
	if err != nil {
		return nil, suppliedGas - GasQuote, err
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	results, err := c.router.QuoteExactInputSingle(stateAdapter, tokenIn, tokenOut, amountIn, fee)
	if err != nil {
		return nil, suppliedGas - GasQuote, err
	}

	return EncodeQuoteResults(results), suppliedGas - GasQuote, nil
}

func (c *RouterContract) runQuoteExactInput(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	// Multi-hop quote: simulate ExactInput without state changes
	if suppliedGas < GasQuote {
		return nil, 0, fmt.Errorf("out of gas")
	}

	params, err := DecodeExactInputParams(input)
	if err != nil {
		return nil, suppliedGas - GasQuote, err
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}

	// Simulate multi-hop
	currentAmount := new(big.Int).Set(params.AmountIn)
	for i := 0; i < len(params.Path)-1; i++ {
		tokenIn := params.Path[i]
		tokenOut := params.Path[i+1]

		// Get best quote for this hop
		best, err := c.router.GetBestRoute(stateAdapter, tokenIn, tokenOut, currentAmount)
		if err != nil {
			return nil, suppliedGas - GasQuote, fmt.Errorf("quote hop %d failed: %w", i, err)
		}
		currentAmount = best.AmountOut
	}

	result := make([]byte, 32)
	copy(result, common.LeftPadBytes(currentAmount.Bytes(), 32))
	return result, suppliedGas - GasQuote, nil
}

func (c *RouterContract) runGetBestRoute(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasRouteLookup {
		return nil, 0, fmt.Errorf("out of gas")
	}

	tokenIn, tokenOut, amountIn, _, err := DecodeQuoteParams(input)
	if err != nil {
		return nil, suppliedGas - GasRouteLookup, err
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	best, err := c.router.GetBestRoute(stateAdapter, tokenIn, tokenOut, amountIn)
	if err != nil {
		return nil, suppliedGas - GasRouteLookup, err
	}

	return EncodeQuoteResults([]QuoteResult{*best}), suppliedGas - GasRouteLookup, nil
}
