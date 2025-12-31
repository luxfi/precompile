// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*DEXContract)(nil)

// ConfigKey is the key used in json config files to specify this precompile config.
const ConfigKey = "dexConfig"

// Contract addresses
var (
	ContractPoolManagerAddress = common.HexToAddress("0x0400000000000000000000000000000000000000")
	ContractSwapRouterAddress  = common.HexToAddress("0x0401000000000000000000000000000000000000")
	ContractHooksAddress       = common.HexToAddress("0x0402000000000000000000000000000000000000")
	ContractFlashLoanAddress   = common.HexToAddress("0x0403000000000000000000000000000000000000")
	ContractLendingAddress     = common.HexToAddress("0x0410000000000000000000000000000000000000")
	ContractLiquidAddress      = common.HexToAddress("0x0430000000000000000000000000000000000000")
	ContractTeleportAddress    = common.HexToAddress("0x0440000000000000000000000000000000000000")
)

// DEXPrecompile is the singleton instance
var DEXPrecompile = &DEXContract{
	poolManager: NewPoolManager(),
}

// Module is the precompile module (PoolManager at 0x0400)
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractPoolManagerAddress,
	Contract:     DEXPrecompile,
	Configurator: &configurator{},
}

// Method selectors for PoolManager
const (
	SelectorInitialize     uint32 = 0x01000000 // initialize(PoolKey,uint160)
	SelectorSwap           uint32 = 0x02000000 // swap(PoolKey,SwapParams,bytes)
	SelectorModifyLiquidity uint32 = 0x03000000 // modifyLiquidity(PoolKey,ModifyLiqParams,bytes)
	SelectorDonate         uint32 = 0x04000000 // donate(PoolKey,uint256,uint256)
	SelectorTake           uint32 = 0x05000000 // take(Currency,address,uint256)
	SelectorSettle         uint32 = 0x06000000 // settle()
	SelectorLock           uint32 = 0x07000000 // lock(bytes)
	SelectorGetPool        uint32 = 0x08000000 // getPool(PoolKey)
	SelectorGetPosition    uint32 = 0x09000000 // getPosition(PoolKey,address,int24,int24,bytes32)
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
	config, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &Config{}, cfg, cfg)
	}

	// Set protocol fee controller if specified
	if config.ProtocolFeeController != (common.Address{}) {
		DEXPrecompile.poolManager.protocolFeeController = config.ProtocolFeeController
	}

	return nil
}

// Config implements the precompileconfig.Config interface
type Config struct {
	Upgrade               precompileconfig.Upgrade `json:"upgrade,omitempty"`
	ProtocolFeeController common.Address           `json:"protocolFeeController,omitempty"`
	MaxPools              uint64                   `json:"maxPools,omitempty"`
	EnableFlashLoans      bool                     `json:"enableFlashLoans,omitempty"`
	EnableHooks           bool                     `json:"enableHooks,omitempty"`
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
	return c.Upgrade.Equal(&other.Upgrade) &&
		c.ProtocolFeeController == other.ProtocolFeeController &&
		c.MaxPools == other.MaxPools &&
		c.EnableFlashLoans == other.EnableFlashLoans &&
		c.EnableHooks == other.EnableHooks
}

func (c *Config) Verify(chainConfig precompileconfig.ChainConfig) error {
	return nil
}

// DEXContract implements the DEX precompile
type DEXContract struct {
	poolManager *PoolManager
}

// Run executes the precompile
func (c *DEXContract) Run(
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
	case SelectorInitialize:
		return c.runInitialize(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSwap:
		return c.runSwap(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorModifyLiquidity:
		return c.runModifyLiquidity(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorDonate:
		return c.runDonate(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorTake:
		return c.runTake(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSettle:
		return c.runSettle(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorLock:
		return c.runLock(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorGetPool:
		return c.runGetPool(accessibleState, data, suppliedGas)
	case SelectorGetPosition:
		return c.runGetPosition(accessibleState, data, suppliedGas)
	default:
		return nil, suppliedGas, fmt.Errorf("unknown method selector: %x", selector)
	}
}

func (c *DEXContract) runInitialize(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasPoolCreate {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Parse PoolKey and sqrtPriceX96 from input
	// Expected format: PoolKey (128 bytes) + sqrtPriceX96 (32 bytes) + hookData
	if len(input) < 160 {
		return nil, suppliedGas - GasPoolCreate, fmt.Errorf("input too short")
	}

	key, err := DecodePoolKey(input[:128])
	if err != nil {
		return nil, suppliedGas - GasPoolCreate, err
	}

	sqrtPriceX96 := new(big.Int).SetBytes(input[128:160])
	hookData := input[160:]

	// Initialize pool
	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	tick, err := c.poolManager.Initialize(stateAdapter, key, sqrtPriceX96, hookData)
	if err != nil {
		return nil, suppliedGas - GasPoolCreate, err
	}

	// Return tick as int24 (3 bytes, padded to 32)
	result := make([]byte, 32)
	tickBytes := int24ToBytes(tick)
	copy(result[29:], tickBytes)
	return result, suppliedGas - GasPoolCreate, nil
}

func (c *DEXContract) runSwap(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasSwap {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Parse PoolKey and SwapParams from input
	key, params, hookData, err := DecodeSwapInput(input)
	if err != nil {
		return nil, suppliedGas - GasSwap, err
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	delta, err := c.poolManager.Swap(stateAdapter, key, params, hookData)
	if err != nil {
		return nil, suppliedGas - GasSwap, err
	}

	// Return BalanceDelta as two int256 values
	result := make([]byte, 64)
	copy(result[0:32], delta.Amount0.Bytes())
	copy(result[32:64], delta.Amount1.Bytes())
	return result, suppliedGas - GasSwap, nil
}

func (c *DEXContract) runModifyLiquidity(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasAddLiquidity {
		return nil, 0, fmt.Errorf("out of gas")
	}

	key, params, hookData, err := DecodeModifyLiquidityInput(input)
	if err != nil {
		return nil, suppliedGas - GasAddLiquidity, err
	}

	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	delta, feeDelta, err := c.poolManager.ModifyLiquidity(stateAdapter, key, params, hookData)
	if err != nil {
		return nil, suppliedGas - GasAddLiquidity, err
	}

	// Return BalanceDelta and FeeDelta
	result := make([]byte, 128)
	copy(result[0:32], delta.Amount0.Bytes())
	copy(result[32:64], delta.Amount1.Bytes())
	copy(result[64:96], feeDelta.Amount0.Bytes())
	copy(result[96:128], feeDelta.Amount1.Bytes())
	return result, suppliedGas - GasAddLiquidity, nil
}

func (c *DEXContract) runDonate(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasBalanceUpdate {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Donate is not yet implemented
	return nil, suppliedGas - GasBalanceUpdate, fmt.Errorf("donate not implemented")
}

func (c *DEXContract) runTake(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasBalanceUpdate {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Take is handled as part of flash accounting
	return nil, suppliedGas - GasBalanceUpdate, fmt.Errorf("take must be called within lock callback")
}

func (c *DEXContract) runSettle(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	if suppliedGas < GasSettlement {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Settle is handled as part of flash accounting
	return nil, suppliedGas - GasSettlement, fmt.Errorf("settle must be called within lock callback")
}

func (c *DEXContract) runLock(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}

	// Lock initiates flash accounting session
	// The callback data contains the operations to execute
	if suppliedGas < GasFlashLoan {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Lock implementation would normally call back to the caller contract
	// For precompile, we return success and expect nested calls
	return nil, suppliedGas - GasFlashLoan, nil
}

func (c *DEXContract) runGetPool(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasPoolLookup {
		return nil, 0, fmt.Errorf("out of gas")
	}

	key, err := DecodePoolKey(input)
	if err != nil {
		return nil, suppliedGas - GasPoolLookup, err
	}

	poolId := key.ID()
	pool, exists := c.poolManager.pools[poolId]
	if !exists {
		return nil, suppliedGas - GasPoolLookup, fmt.Errorf("pool not found")
	}

	// Encode pool state
	result := EncodePoolState(pool)
	return result, suppliedGas - GasPoolLookup, nil
}

func (c *DEXContract) runGetPosition(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasPoolLookup {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// Parse position key from input
	// Position not found returns zeroes
	result := make([]byte, 96) // liquidity (32) + feeGrowthInside0 (32) + feeGrowthInside1 (32)
	return result, suppliedGas - GasPoolLookup, nil
}

// RequiredGas returns the gas required for the precompile input
func (c *DEXContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasSwap
	}

	selector := binary.BigEndian.Uint32(input[:4])
	switch selector {
	case SelectorInitialize:
		return GasPoolCreate
	case SelectorSwap:
		return GasSwap
	case SelectorModifyLiquidity:
		return GasAddLiquidity
	case SelectorDonate:
		return GasBalanceUpdate
	case SelectorTake:
		return GasBalanceUpdate
	case SelectorSettle:
		return GasSettlement
	case SelectorLock:
		return GasFlashLoan
	case SelectorGetPool, SelectorGetPosition:
		return GasPoolLookup
	default:
		return GasSwap
	}
}

// poolStateAdapter adapts contract.StateDB to dex.StateDB
type poolStateAdapter struct {
	stateDB contract.StateDB
}

func (a *poolStateAdapter) GetState(addr common.Address, key common.Hash) common.Hash {
	return a.stateDB.GetState(addr, key)
}

func (a *poolStateAdapter) SetState(addr common.Address, key common.Hash, value common.Hash) {
	a.stateDB.SetState(addr, key, value)
}

func (a *poolStateAdapter) GetBalance(addr common.Address) *uint256.Int {
	return a.stateDB.GetBalance(addr)
}

func (a *poolStateAdapter) AddBalance(addr common.Address, amount *uint256.Int) {
	// Not directly available, would need tracing reason
}

func (a *poolStateAdapter) SubBalance(addr common.Address, amount *uint256.Int) {
	// Not directly available, would need tracing reason
}

func (a *poolStateAdapter) Exist(addr common.Address) bool {
	return a.stateDB.Exist(addr)
}

func (a *poolStateAdapter) CreateAccount(addr common.Address) {
	a.stateDB.CreateAccount(addr)
}

func (a *poolStateAdapter) GetBlockNumber() uint64 {
	return 0 // Would need block context
}

// Helper functions for encoding/decoding

func int24ToBytes(v int24) []byte {
	b := make([]byte, 3)
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
	return b
}

// DecodePoolKey decodes a PoolKey from input bytes
func DecodePoolKey(input []byte) (PoolKey, error) {
	if len(input) < 128 {
		return PoolKey{}, fmt.Errorf("input too short for PoolKey")
	}

	key := PoolKey{}
	key.Currency0 = Currency{Address: common.BytesToAddress(input[12:32])}
	key.Currency1 = Currency{Address: common.BytesToAddress(input[44:64])}
	key.Fee = uint24(binary.BigEndian.Uint32(append([]byte{0}, input[64:67]...)))
	key.TickSpacing = int24(binary.BigEndian.Uint32(append([]byte{0}, input[67:70]...)))
	key.Hooks = common.BytesToAddress(input[76:96])

	return key, nil
}

// DecodeSwapInput decodes swap input
func DecodeSwapInput(input []byte) (PoolKey, SwapParams, []byte, error) {
	if len(input) < 160 {
		return PoolKey{}, SwapParams{}, nil, fmt.Errorf("input too short for swap")
	}

	key, err := DecodePoolKey(input[:128])
	if err != nil {
		return PoolKey{}, SwapParams{}, nil, err
	}

	params := SwapParams{
		ZeroForOne:        input[128] == 1,
		AmountSpecified:   new(big.Int).SetBytes(input[129:161]),
		SqrtPriceLimitX96: new(big.Int).SetBytes(input[161:193]),
	}

	hookData := input[193:]
	return key, params, hookData, nil
}

// DecodeModifyLiquidityInput decodes modifyLiquidity input
func DecodeModifyLiquidityInput(input []byte) (PoolKey, ModifyLiquidityParams, []byte, error) {
	if len(input) < 192 {
		return PoolKey{}, ModifyLiquidityParams{}, nil, fmt.Errorf("input too short for modifyLiquidity")
	}

	key, err := DecodePoolKey(input[:128])
	if err != nil {
		return PoolKey{}, ModifyLiquidityParams{}, nil, err
	}

	params := ModifyLiquidityParams{
		TickLower:      int24(binary.BigEndian.Uint32(append([]byte{0}, input[128:131]...))),
		TickUpper:      int24(binary.BigEndian.Uint32(append([]byte{0}, input[131:134]...))),
		LiquidityDelta: new(big.Int).SetBytes(input[134:166]),
	}

	hookData := input[192:]
	return key, params, hookData, nil
}

// EncodePoolState encodes pool state for return
func EncodePoolState(pool *Pool) []byte {
	result := make([]byte, 160)
	copy(result[0:32], pool.SqrtPriceX96.Bytes())
	binary.BigEndian.PutUint32(result[32:36], uint32(pool.Tick))
	copy(result[64:96], pool.Liquidity.Bytes())
	copy(result[96:128], pool.FeeGrowth0X128.Bytes())
	copy(result[128:160], pool.FeeGrowth1X128.Bytes())
	return result
}

