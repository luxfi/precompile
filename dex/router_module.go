// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// ErrPrecompileMoved is the revert returned by the DEPRECATED 0x9012 (LP-9012) router's
// VALUE-moving selectors (exactInput* / exactOutput*). The LP-901x legacy series was a
// SECOND matcher money path: the router routed swaps through the engine's SYNCHRONOUS
// in-block matcher (poolManager.Swap), which forks consensus (each validator observes
// independently-timed fills => divergent StateRoot). There is now exactly ONE money path —
// 0x9999 receipt-settlement, which credits C only by consuming a D-committed atomic object.
// A caller hitting a moved selector must migrate to 0x9999; the read-only quote/route VIEWS
// on 0x9012 remain (they move no value). The revert reason begins with the stable token
// PRECOMPILE_MOVED so tooling can detect and redirect. Gated at the SAME existing canonical
// activation (1766708400): settle-only 0x9999 + moved 0x9012 are the Dec-25-2025 behavior.
var ErrPrecompileMoved = errors.New("PRECOMPILE_MOVED: 0x9012 value ops removed — a swap settles only via 0x9999 (consume a D-committed atomic object)")

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
	cur := contract.Read(input)
	selector, err := cur.Uint32()
	if err != nil {
		return nil, suppliedGas, fmt.Errorf("input too short")
	}

	if accessibleState.GetBlockContext() == nil {
		return nil, suppliedGas, fmt.Errorf("block context unavailable")
	}

	data := cur.Rest()

	switch selector {
	// DEPRECATED value-moving selectors — the LP-9012 router was a SECOND matcher money
	// path (it routed swaps through the engine's synchronous in-block matcher, which forks
	// consensus). They now REVERT PRECOMPILE_MOVED: there is exactly ONE money path, 0x9999
	// receipt-settlement (a swap settles only by consuming a D-committed atomic object).
	// The revert is charged NO gas — it is a "this entrypoint is gone" boundary, not work.
	case SelectorExactInputSingle, SelectorExactInput, SelectorExactOutputSingle, SelectorExactOutput:
		return nil, suppliedGas, ErrPrecompileMoved

	// Read-only quote/route VIEWS remain — advisory pricing over pool state; they move no
	// value, so they are safe to keep on the deprecated router address.
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

// The RouterContract value-execution handlers (runExactInputSingle / runExactInput /
// runExactOutputSingle / runExactOutput) were REMOVED: 0x9012's value selectors now revert
// PRECOMPILE_MOVED at the dispatch (see Run), so these dispatch handlers had no caller. They
// routed swaps through the engine's synchronous in-block matcher (LXRouter.Exact* ->
// poolManager.Swap), which forks consensus — the second money path the decomplect eliminates.
// The underlying LXRouter.Exact* + poolManager.Swap engine remains for now (legacy-engine unit
// tests exercise it directly; it is UNREACHABLE via any dispatched precompile selector) and is
// staged for a follow-up removal. Only the read-only quote/route views survive on 0x9012.

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

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
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
	// Multi-hop quote: simulate ExactInput without state changes.
	// Gas scales with the number of hops to prevent abuse via long paths.
	params, err := DecodeExactInputParams(input)
	if err != nil {
		if suppliedGas < GasQuoteBase {
			return nil, 0, fmt.Errorf("out of gas")
		}
		return nil, suppliedGas - GasQuoteBase, err
	}

	numHops := len(params.Path) - 1
	if len(params.PathKeys) > 0 {
		numHops = len(params.PathKeys)
	}
	if numHops < 1 {
		numHops = 1
	}
	if numHops > MaxPathLength {
		return nil, suppliedGas, fmt.Errorf("path too long: %d hops exceeds maximum of %d", numHops, MaxPathLength)
	}

	gasCost := GasQuoteBase + uint64(numHops)*GasQuotePerHop
	if suppliedGas < gasCost {
		return nil, 0, fmt.Errorf("out of gas")
	}

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}

	// V4 path format: quote each hop using the explicit pool key
	if len(params.PathKeys) > 0 {
		currentAmount := new(big.Int).Set(params.AmountIn)
		currencyIn := params.CurrencyIn
		for i, pk := range params.PathKeys {
			v4Amount, _, _, err := c.router.quoteV4(stateAdapter, currencyIn, pk.IntermediateCurrency, currentAmount, pk.Fee)
			if err != nil {
				return nil, suppliedGas - gasCost, fmt.Errorf("quote hop %d failed: %w", i, err)
			}
			currentAmount = v4Amount
			currencyIn = pk.IntermediateCurrency
		}
		result := make([]byte, 32)
		copy(result, common.LeftPadBytes(currentAmount.Bytes(), 32))
		return result, suppliedGas - gasCost, nil
	}

	// Simple path format: best-venue per hop
	currentAmount := new(big.Int).Set(params.AmountIn)
	for i := 0; i < len(params.Path)-1; i++ {
		tokenIn := params.Path[i]
		tokenOut := params.Path[i+1]

		best, err := c.router.GetBestRoute(stateAdapter, tokenIn, tokenOut, currentAmount)
		if err != nil {
			return nil, suppliedGas - gasCost, fmt.Errorf("quote hop %d failed: %w", i, err)
		}
		currentAmount = best.AmountOut
	}

	result := make([]byte, 32)
	copy(result, common.LeftPadBytes(currentAmount.Bytes(), 32))
	return result, suppliedGas - gasCost, nil
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

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	best, err := c.router.GetBestRoute(stateAdapter, tokenIn, tokenOut, amountIn)
	if err != nil {
		return nil, suppliedGas - GasRouteLookup, err
	}

	return EncodeQuoteResults([]QuoteResult{*best}), suppliedGas - GasRouteLookup, nil
}
