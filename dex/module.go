// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)
var _ contract.StatefulPrecompiledContract = (*DEXContract)(nil)

// ConfigKey is the key used in json config files to specify this precompile config.
const ConfigKey = "dexConfig"

// Parsed addresses for LX precompiles (derived from string constants in types.go)
// See types.go for canonical LP-aligned address strings
var (
	// Core AMM (LP-9010 series - Uniswap v4 style)
	lxPoolAddr   = common.HexToAddress(LXPoolAddress)   // LP-9010 LXPool (v4 PoolManager)
	lxOracleAddr = common.HexToAddress(LXOracleAddress) // LP-9011 LXOracle
	lxRouterAddr = common.HexToAddress(LXRouterAddress) // LP-9012 LXRouter
	lxHooksAddr  = common.HexToAddress(LXHooksAddress)  // LP-9013 LXHooks
	lxFlashAddr  = common.HexToAddress(LXFlashAddress)  // LP-9014 LXFlash

	// Trading & DeFi Extensions
	lxBookAddr   = common.HexToAddress(LXBookAddress)   // LP-9020 LXBook (CLOB matcher)
	lxVaultAddr  = common.HexToAddress(LXVaultAddress)  // LP-9030 LXVault
	lxFeedAddr   = common.HexToAddress(LXFeedAddress)   // LP-9040 LXFeed
	lxLendAddr   = common.HexToAddress(LXLendAddress)   // LP-9050 LXLend (lending pool)
	lxLiquidAddr = common.HexToAddress(LXLiquidAddress) // LP-9060 LXLiquid (self-repaying loans)
)

// DEXPrecompile is the singleton instance
var DEXPrecompile = &DEXContract{
	poolManager: NewPoolManager(),
}

// Module is the precompile module (LXPool at LP-9010)
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      lxPoolAddr,
	Contract:     DEXPrecompile,
	Configurator: &configurator{},
}

// Method selectors for PoolManager
const (
	SelectorInitialize      uint32 = 0x01000000 // initialize(PoolKey,uint160)
	SelectorSwap            uint32 = 0x02000000 // swap(PoolKey,SwapParams,bytes)
	SelectorModifyLiquidity uint32 = 0x03000000 // modifyLiquidity(PoolKey,ModifyLiqParams,bytes)
	SelectorTake            uint32 = 0x05000000 // take(Currency,address,uint256)
	SelectorSettle          uint32 = 0x06000000 // settle()
	SelectorLock            uint32 = 0x07000000 // lock(bytes)
	SelectorGetPool         uint32 = 0x08000000 // getPool(PoolKey)
	SelectorGetPosition     uint32 = 0x09000000 // getPosition(PoolKey,address,int24,int24,bytes32)
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
	precompileconfig.Upgrade                // Embedded for flat JSON structure
	ProtocolFeeController    common.Address `json:"protocolFeeController,omitempty"`
	MaxPools                 uint64         `json:"maxPools,omitempty"`
	EnableFlashLoans         bool           `json:"enableFlashLoans,omitempty"`
	EnableHooks              bool           `json:"enableHooks,omitempty"`
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

	delta, err := c.poolManager.Swap(stateAdapter, caller, key, params, hookData)
	if err != nil {
		return nil, suppliedGas - GasSwap, err
	}

	// Auto-settle: transfer tokens based on the delta
	if err := c.poolManager.autoSettle(stateAdapter, caller, key, delta); err != nil {
		return nil, suppliedGas - GasSwap, err
	}

	// Return BalanceDelta as two int256 values (two's complement for negatives)
	result := make([]byte, 64)
	copy(result[0:32], bigIntTo32Bytes(delta.Amount0))
	copy(result[32:64], bigIntTo32Bytes(delta.Amount1))
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

	delta, feeDelta, err := c.poolManager.ModifyLiquidity(stateAdapter, caller, key, params, hookData)
	if err != nil {
		return nil, suppliedGas - GasAddLiquidity, err
	}

	// Auto-settle: transfer tokens based on the delta
	if err := c.poolManager.autoSettle(stateAdapter, caller, key, delta); err != nil {
		return nil, suppliedGas - GasAddLiquidity, err
	}

	// Return BalanceDelta and FeeDelta (two's complement for negatives)
	result := make([]byte, 128)
	copy(result[0:32], bigIntTo32Bytes(delta.Amount0))
	copy(result[32:64], bigIntTo32Bytes(delta.Amount1))
	copy(result[64:96], bigIntTo32Bytes(feeDelta.Amount0))
	copy(result[96:128], bigIntTo32Bytes(feeDelta.Amount1))
	return result, suppliedGas - GasAddLiquidity, nil
}

func (c *DEXContract) runTake(
	_ contract.AccessibleState,
	_ common.Address,
	_ []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	return nil, suppliedGas, fmt.Errorf("take not supported: blockchain provides atomic settlement")
}

func (c *DEXContract) runSettle(
	_ contract.AccessibleState,
	_ common.Address,
	_ []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	return nil, suppliedGas, fmt.Errorf("settle not supported: blockchain provides atomic settlement")
}

func (c *DEXContract) runLock(
	_ contract.AccessibleState,
	_ common.Address,
	_ []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	return nil, suppliedGas, fmt.Errorf("lock not supported: blockchain provides atomic settlement")
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
	stateAdapter := &poolStateAdapter{state.GetStateDB()}
	pool := c.poolManager.getPool(stateAdapter, poolId)
	if !pool.IsInitialized() {
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
	a.stateDB.AddBalance(addr, amount, tracing.BalanceChangeUnspecified)
}

func (a *poolStateAdapter) SubBalance(addr common.Address, amount *uint256.Int) {
	a.stateDB.SubBalance(addr, amount, tracing.BalanceChangeUnspecified)
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

func (a *poolStateAdapter) AddLog(log *ethtypes.Log) {
	a.stateDB.AddLog(log)
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
	// F12: TickSpacing is int24 -- sign-extend from 3 bytes
	key.TickSpacing = decodeInt24(input[67:70])
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

	// F4: AmountSpecified is a signed int256 (two's complement).
	// If the high bit is set, the value is negative.
	amountSpecified := decodeSigned256(input[129:161])

	params := SwapParams{
		ZeroForOne:        input[128] == 1,
		AmountSpecified:   amountSpecified,
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

	// F12: TickLower and TickUpper are signed int24 values. Sign-extend from 3 bytes.
	// F4: LiquidityDelta is a signed int256 (two's complement).
	params := ModifyLiquidityParams{
		TickLower:      decodeInt24(input[128:131]),
		TickUpper:      decodeInt24(input[131:134]),
		LiquidityDelta: decodeSigned256(input[134:166]),
	}

	hookData := input[192:]
	return key, params, hookData, nil
}

// EncodePoolState encodes pool state for return
func EncodePoolState(pool *Pool) []byte {
	result := make([]byte, 160)
	copy(result[0:32], bigIntTo32Bytes(pool.SqrtPriceX96))
	binary.BigEndian.PutUint32(result[32:36], uint32(pool.Tick))
	copy(result[64:96], bigIntTo32Bytes(pool.Liquidity))
	copy(result[96:128], bigIntTo32Bytes(pool.FeeGrowth0X128))
	copy(result[128:160], bigIntTo32Bytes(pool.FeeGrowth1X128))
	return result
}

// bigIntTo32Bytes encodes a big.Int as a 32-byte ABI word.
// Positive values are zero-padded. Negative values use two's complement (2^256 + v).
// This prevents FillBytes from panicking on negative values and ensures correct
// ABI encoding for signed integer return values.
func bigIntTo32Bytes(v *big.Int) []byte {
	result := make([]byte, 32)
	if v == nil || v.Sign() == 0 {
		return result
	}
	if v.Sign() > 0 {
		v.FillBytes(result)
	} else {
		// Two's complement: 2^256 + v
		tc := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), v)
		tc.FillBytes(result)
	}
	return result
}

// decodeSigned256 decodes a 32-byte big-endian two's complement int256.
// If the high bit is set, the value is negative: value = raw - 2^256.
func decodeSigned256(b []byte) *big.Int {
	val := new(big.Int).SetBytes(b)
	if len(b) > 0 && b[0]&0x80 != 0 {
		val.Sub(val, new(big.Int).Lsh(big.NewInt(1), 256))
	}
	return val
}

// decodeInt24 decodes a 3-byte big-endian signed int24 value with sign extension.
// Values >= 2^23 (sign bit set) are negative: value = raw - 2^24.
func decodeInt24(b []byte) int24 {
	if len(b) < 3 {
		return 0
	}
	val := int32(b[0])<<16 | int32(b[1])<<8 | int32(b[2])
	if val >= 1<<23 { // sign bit set
		val -= 1 << 24
	}
	return int24(val)
}
