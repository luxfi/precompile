// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
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
	lxBookAddr   = common.HexToAddress(LXBookAddress)    // LP-9020 LXBook (CLOB matcher)
	lxVaultAddr  = common.HexToAddress(LXVaultAddress)   // LP-9030 LXVault
	lxPriceAddr  = common.HexToAddress(LXPriceAddress)   // LP-9040 LXPrice
	lxLendAddr   = common.HexToAddress(LXLendAddress)    // LP-9050 LXLend (lending pool)
	lxLiquidAddr = common.HexToAddress(LXRepayerAddress) // LP-9060 LXLiquid (self-repaying loans)
)

// DEXPrecompile is the singleton instance.
//
// Backend strategy (decomplected — values, not places):
//
//   - The precompile lives at ONE address (LP-9010) across every Lux-derived
//     EVM (Lux C-Chain, Hanzo, Zoo, SPC, and white-label deployments such as
//     downstream EVM). The ABI is identical for every chain.
//
//   - The math/matching backend is parameterized. The default is the INERT
//     engine (engine_inert.go): it performs no matching and reverts every call
//     with ErrDEXBackendNotConfigured. V4 = CLOB, so the matcher lives ONLY on
//     the d-chain, reached over ZAP — never embedded in the precompile. The
//     venue makes 0x9010 live by calling SetBackend(NewZAPEngine(endpoint))
//     from the EVM plugin main when dex-zap-endpoint is set; chains that do not
//     enable it run an inert precompile that cleanly reverts.
//
//   - Brand identity is a value the backend carries (Engine.Brand()). User-
//     facing error strings produced by the precompile MUST come from the
//     backend, never hard-coded here. This keeps a tenant surface free of
//     the word "Lux" while still letting the OSS package be called "Lux DEX"
//     on Lux-network deployments.
var DEXPrecompile = newDEXContract(newInertEngine())

// SetBackend swaps the DEX engine backing the singleton precompile.
//
// MUST be called from package main of the EVM plugin BEFORE the VM starts
// initializing precompiles (i.e. before any genesis Configure() call). Calling
// it after ANY pool-manager state has accumulated returns an error — backend
// swaps must not race with live state. The guard covers every per-pool map
// the precompile maintains (pools, poolStates, positions) so a future map
// added without updating the guard doesn't silently re-open the race.
//
// Logs the backend brand to stderr on success so operators see in the boot
// log which engine is wired (e.g. "Hanzo DEX" vs upstream OSS). RED V1.
//
// Threading: not safe for concurrent use. The host binary is the single caller
// during process startup.
func SetBackend(e Engine) error {
	if e == nil {
		return fmt.Errorf("dex: backend engine must not be nil")
	}
	pm := DEXPrecompile.poolManager
	if len(pm.pools) != 0 || len(pm.poolStates) != 0 || len(pm.positions) != 0 {
		return fmt.Errorf("dex: cannot swap backend after pool initialization")
	}
	pm.engine = e
	// Surface the installed brand on the boot log. Stderr is the right sink
	// for a process-lifecycle event that operators need to see even when
	// structured logging hasn't been wired yet.
	fmt.Fprintf(os.Stderr, "dex: precompile backend installed brand=%q\n", e.Brand())
	return nil
}

// Backend returns the active engine. Useful for diagnostics and tests; do not
// use this to mutate engine state from outside the package.
func Backend() Engine {
	return DEXPrecompile.poolManager.engine
}

// newDEXContract constructs the singleton with a non-nil engine. Separated
// from the var declaration so the construction path is testable and so
// reviewers can see the engine MUST be non-nil at init.
func newDEXContract(e Engine) *DEXContract {
	if e == nil {
		// Bug in caller — panic at init time, not at first swap.
		panic("dex: DEXContract requires a non-nil engine")
	}
	return &DEXContract{
		poolManager: NewPoolManager(e),
	}
}

// Module is the precompile module (LXPool at LP-9010)
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      lxPoolAddr,
	Contract:     DEXPrecompile,
	Configurator: &configurator{},
}

// Method selectors: keccak256 of V4 function signatures (first 4 bytes).
// Verified against IPoolManager.sol at init time.
var (
	SelectorInitialize      uint32 = 0x6276CBBE // initialize((address,address,uint24,int24,address),uint160)
	SelectorSwap            uint32 = 0xF3CD914C // swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)
	SelectorModifyLiquidity uint32 = 0x5A6BCFDA // modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)
	SelectorDonate          uint32 = 0x234266D7 // donate((address,address,uint24,int24,address),uint256,uint256,bytes)
	SelectorUnlock          uint32 = 0x48C89491 // unlock(bytes)
	SelectorSettle          uint32 = 0x11DA60B4 // settle()
	SelectorSettleFor       uint32 = 0x3DD45ADB // settleFor(address)
	SelectorSync            uint32 = 0xA5841194 // sync(address)
	SelectorTake            uint32 = 0x0B0D9C09 // take(address,address,uint256)
	SelectorClear           uint32 = 0x80F0B44C // clear(address,uint256)
	SelectorMint            uint32 = 0x156E29F6 // mint(address,uint256,uint256)
	SelectorBurn            uint32 = 0xF5298ACA // burn(address,uint256,uint256)
	SelectorUpdateDynFee    uint32 = 0x52759651 // updateDynamicLPFee((address,address,uint24,int24,address),uint24)
	SelectorExtsload        uint32 = 0x1E2EAEAF // extsload(bytes32)
	SelectorExtsloadArray   uint32 = 0xDBD035FF // extsload(bytes32[])

	// CLOB custody selectors — the EVM ingress for funds in/out of the D-Chain
	// ledger ("the money lives in the order book"). deposit LOCKS the asset in the
	// 0x9010 vault (native LUX via msg.value) and MINTS the D-Chain available
	// balance; withdraw BURNS the D-Chain balance and RELEASES the vault. The CLOB
	// settles ONLY inside the D-Chain; these never fund a trade from 0x9010.
	SelectorDeposit   uint32 = 0x47E7EF24 // deposit(address,uint256)  — asset, amount (msg.value==amount for native)
	SelectorWithdraw  uint32 = 0xF3FEF3A3 // withdraw(address,uint256) — asset, want
	SelectorBalanceOf uint32 = 0xF7888AEC // balanceOf(address,address) — account, asset (read-only available)

	// Admin pause/freeze selectors — computed in init() via keccak4.
	SelectorPauseDEX   uint32
	SelectorResumeDEX  uint32
	SelectorPausePool  uint32
	SelectorResumePool uint32
	SelectorFreezePool uint32
)

// keccak4 computes the first 4 bytes of keccak256(sig) as a uint32 selector.
func keccak4(sig string) uint32 {
	hash := crypto.Keccak256([]byte(sig))
	return binary.BigEndian.Uint32(hash[:4])
}

type configurator struct{}

func init() {
	// Verify hardcoded selectors match keccak256 computation at startup.
	verifySelector := func(name string, got uint32, sig string) {
		want := keccak4(sig)
		if got != want {
			panic(fmt.Sprintf("dex: selector mismatch for %s: got 0x%08X, want 0x%08X", name, got, want))
		}
	}
	verifySelector("initialize", SelectorInitialize, "initialize((address,address,uint24,int24,address),uint160)")
	verifySelector("swap", SelectorSwap, "swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)")
	verifySelector("modifyLiquidity", SelectorModifyLiquidity, "modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)")
	verifySelector("donate", SelectorDonate, "donate((address,address,uint24,int24,address),uint256,uint256,bytes)")
	verifySelector("unlock", SelectorUnlock, "unlock(bytes)")
	verifySelector("settle", SelectorSettle, "settle()")
	verifySelector("take", SelectorTake, "take(address,address,uint256)")
	verifySelector("deposit", SelectorDeposit, "deposit(address,uint256)")
	verifySelector("withdraw", SelectorWithdraw, "withdraw(address,uint256)")
	verifySelector("balanceOf", SelectorBalanceOf, "balanceOf(address,address)")

	// Compute admin selectors at init time (not compile-time constants).
	SelectorPauseDEX = keccak4("pauseDEX()")
	SelectorResumeDEX = keccak4("resumeDEX()")
	SelectorPausePool = keccak4("pausePool(bytes32)")
	SelectorResumePool = keccak4("resumePool(bytes32)")
	SelectorFreezePool = keccak4("freezePool(bytes32)")

	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

// compromisedDevControllers lists Ethereum addresses whose private keys are
// publicly distributed (Foundry/Anvil deterministic test accounts, Hardhat
// default mnemonic, etc.). Configuring any of these as the DEX protocol fee
// controller would let any caller pause / freeze the chain-wide AMM, so
// activation is refused. Stored as the lowercase hex representation produced
// by common.Address.Hex()-stripped-and-lowered for cheap membership testing.
//
// Sources:
//   - Foundry/Anvil default mnemonic "test test test test test test test test
//     test test test junk" (anvil --accounts 10) → accounts #0..#9.
//   - Hardhat default mnemonic produces an overlapping set (same root).
//
// New entries should be appended whenever a new well-known development
// mnemonic is identified.
var compromisedDevControllers = map[common.Address]struct{}{
	common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"): {}, // anvil #0
	common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"): {}, // anvil #1
	common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"): {}, // anvil #2
	common.HexToAddress("0x90F79bf6EB2c4f870365E785982E1f101E93b906"): {}, // anvil #3
	common.HexToAddress("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"): {}, // anvil #4
	common.HexToAddress("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"): {}, // anvil #5
	common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9"): {}, // anvil #6
	common.HexToAddress("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"): {}, // anvil #7
	common.HexToAddress("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"): {}, // anvil #8
	common.HexToAddress("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"): {}, // anvil #9
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

	// Protocol fee controller is required. NO DEFAULT. A missing or zero
	// controller would leave PauseDEX / ResumeDEX / FreezePool open to any
	// caller; the operator MUST populate this explicitly in upgrade.json
	// (typically a multisig or governance contract). Refusing activation
	// surfaces the misconfiguration on the activation block rather than
	// silently shipping an open-admin DEX.
	if config.ProtocolFeeController == (common.Address{}) {
		return ErrDEXNoProtocolFeeController
	}
	// Refuse known-compromised dev keys whose private keys are public
	// knowledge (Foundry/Anvil, Hardhat default mnemonic). This catches the
	// "I'll fix the placeholder before mainnet" footgun.
	if _, bad := compromisedDevControllers[config.ProtocolFeeController]; bad {
		return fmt.Errorf("%w: %s", ErrDEXCompromisedController, config.ProtocolFeeController.Hex())
	}
	DEXPrecompile.poolManager.protocolFeeController = config.ProtocolFeeController

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

	if accessibleState.GetBlockContext() == nil {
		return nil, suppliedGas, fmt.Errorf("block context unavailable")
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
	case SelectorDeposit:
		return c.runDeposit(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorWithdraw:
		return c.runWithdraw(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorBalanceOf:
		return c.runBalanceOf(accessibleState, data, suppliedGas)
	case SelectorDonate:
		return c.runDonate(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorUnlock:
		return c.runUnlock(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorTake:
		return c.runTake(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSettle, SelectorSettleFor:
		return c.runSettle(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorSync:
		return c.runSync(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorExtsload:
		return c.runExtsload(accessibleState, data, suppliedGas)
	case SelectorExtsloadArray:
		return c.runExtsloadArray(accessibleState, data, suppliedGas)
	case SelectorPauseDEX:
		return c.runPauseDEX(accessibleState, caller, suppliedGas, readOnly)
	case SelectorResumeDEX:
		return c.runResumeDEX(accessibleState, caller, suppliedGas, readOnly)
	case SelectorPausePool:
		return c.runPausePool(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorResumePool:
		return c.runResumePool(accessibleState, caller, data, suppliedGas, readOnly)
	case SelectorFreezePool:
		return c.runFreezePool(accessibleState, caller, data, suppliedGas, readOnly)
	default:
		return nil, suppliedGas, fmt.Errorf("unknown method selector: 0x%08x", selector)
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

	// V4 ABI: PoolKey (5 slots = 160 bytes) + sqrtPriceX96 (32 bytes)
	if len(input) < 192 {
		return nil, suppliedGas - GasPoolCreate, fmt.Errorf("input too short for initialize")
	}

	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return nil, suppliedGas - GasPoolCreate, err
	}

	sqrtPriceX96 := new(big.Int).SetBytes(input[160:192])
	var hookData []byte
	if len(input) > 192 {
		hookData = decodeABIBytes(input, 192)
	}

	// Initialize pool
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	tick, err := c.poolManager.Initialize(stateAdapter, key, sqrtPriceX96, hookData)
	if err != nil {
		return nil, suppliedGas - GasPoolCreate, err
	}

	// Return tick as int24, sign-extended to int256 (32 bytes, two's complement).
	// V4 ABI returns int24 as a full int256: negative values have 0xFF in high bytes.
	result := bigIntTo32Bytes(big.NewInt(int64(tick)))
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

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}

	delta, err := c.poolManager.Swap(stateAdapter, caller, key, params, hookData)
	if err != nil {
		return nil, suppliedGas - GasSwap, err
	}

	// NO C-CHAIN SETTLEMENT. A marketable order settles ENTIRELY inside the D-Chain
	// ledger (the taker's locked spend moves to the maker, the maker's locked asset
	// moves to the taker — dchain.settleFills, value-conserving by construction).
	// The taker's funds were DEPOSITED into the D-Chain (deposit selector ->
	// clob_deposit -> available) before this swap; the swap locked + spent them in
	// the book. 0x9010 is a pure ingress adapter — it holds NO reserve, is NEVER a
	// counterparty, and does NOT move value here. The returned BalanceDelta is the
	// fills' net for the V4 ABI's caller, NOT an instruction to settle on C-Chain.
	// (The former settleNativeLegs did a caller<->0x9010 native transfer = an
	// AMM-style C-Chain reserve settlement; it left native LUX sitting in 0x9010
	// "backing resting asks" — the exact reserve hazard the CLOB model forbids.)

	// V4: Return BalanceDelta as single int256 (amount0 in upper 128 bits, amount1 in lower 128 bits)
	result := PackBalanceDelta(delta.Amount0, delta.Amount1)
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

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}

	delta, feeDelta, err := c.poolManager.ModifyLiquidity(stateAdapter, caller, key, params, hookData)
	if err != nil {
		return nil, suppliedGas - GasAddLiquidity, err
	}

	// NO C-CHAIN SETTLEMENT. Placing a resting order LOCKS the maker's already-
	// DEPOSITED D-Chain balance (available -> locked, inside the book); cancelling
	// UNLOCKS it. The maker's funds never touch C-Chain here and 0x9010 holds no
	// reserve backing the order — the resting order's funds live in the D-Chain
	// ledger's locked[maker][asset], not in 0x9010. (Was settleNativeLegs, which
	// moved native LUX caller<->0x9010 to "back" the resting ask = a reserve.)

	// V4: Return two packed BalanceDeltas (callerDelta + feesAccrued), each 32 bytes
	result := make([]byte, 64)
	copy(result[0:32], PackBalanceDelta(delta.Amount0, delta.Amount1))
	copy(result[32:64], PackBalanceDelta(feeDelta.Amount0, feeDelta.Amount1))
	return result, suppliedGas - GasAddLiquidity, nil
}

// runDeposit is the EVM ingress for funds-IN: deposit(address asset, uint256
// amount). For native LUX (asset == address(0)) the caller MUST send msg.value ==
// amount; the EVM has already moved that value into the 0x9010 vault before this
// precompile runs, so the deposit LOCKS it there and MINTS the caller's available
// D-Chain balance. 0x9010 is a passive vault, never a trade counterparty.
//
// ABI: input = asset[32] (address, right-aligned) || amount[32] (uint256).
// Returns the deposited amount as uint256 (the credited available balance delta).
func (c *DEXContract) runDeposit(
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
	if len(input) < 64 {
		return nil, suppliedGas - GasSettlement, fmt.Errorf("deposit: input too short")
	}
	asset := Currency{Address: common.BytesToAddress(input[12:32])}
	amount := new(big.Int).SetBytes(input[32:64])

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	if err := c.poolManager.Deposit(stateAdapter, caller, asset, amount); err != nil {
		return nil, suppliedGas - GasSettlement, err
	}

	out := make([]byte, 32)
	amount.FillBytes(out)
	return out, suppliedGas - GasSettlement, nil
}

// runWithdraw is the EVM ingress for funds-OUT: withdraw(address asset, uint256
// want). It BURNS up to `want` of the caller's available D-Chain balance (the
// ledger clamps to availability) and RELEASES exactly the realized amount from the
// 0x9010 vault back to the caller. Conserving: the vault never pays more than the
// ledger burned. Returns the realized amount as uint256.
func (c *DEXContract) runWithdraw(
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
	if len(input) < 64 {
		return nil, suppliedGas - GasSettlement, fmt.Errorf("withdraw: input too short")
	}
	asset := Currency{Address: common.BytesToAddress(input[12:32])}
	want := new(big.Int).SetBytes(input[32:64])

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	realized, err := c.poolManager.Withdraw(stateAdapter, caller, asset, want)
	if err != nil {
		return nil, suppliedGas - GasSettlement, err
	}

	out := make([]byte, 32)
	realized.FillBytes(out)
	return out, suppliedGas - GasSettlement, nil
}

// runBalanceOf is a read-only observation of an account's AVAILABLE D-Chain
// balance for an asset: balanceOf(address account, address asset). It forwards to
// the custody backend's Withdraw with want=0? No — a read must not mutate. It
// queries the D-Chain via the backend's read path. Returns the available balance
// as uint256. (The locked balance is queryable on the venue's clob_balance; this
// EVM view returns available, the spendable claim.)
func (c *DEXContract) runBalanceOf(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasPoolLookup {
		return nil, 0, fmt.Errorf("out of gas")
	}
	if len(input) < 64 {
		return nil, suppliedGas - GasPoolLookup, fmt.Errorf("balanceOf: input too short")
	}
	account := common.BytesToAddress(input[12:32])
	asset := Currency{Address: common.BytesToAddress(input[44:64])}

	avail, err := c.poolManager.BalanceOf(account, asset)
	if err != nil {
		return nil, suppliedGas - GasPoolLookup, err
	}
	out := make([]byte, 32)
	avail.FillBytes(out)
	return out, suppliedGas - GasPoolLookup, nil
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

func (c *DEXContract) runUnlock(
	_ contract.AccessibleState,
	_ common.Address,
	_ []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	// V4 unlock is used for flash accounting. In a precompile context the blockchain
	// provides atomic settlement, so unlock is a no-op that returns empty bytes.
	return []byte{}, suppliedGas, nil
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

	gasCost := GasSwap // donate uses similar gas to swap
	if suppliedGas < gasCost {
		return nil, 0, fmt.Errorf("out of gas")
	}

	// V4 ABI: PoolKey (160) + amount0 (32) + amount1 (32) + hookData
	if len(input) < 224 {
		return nil, suppliedGas - gasCost, fmt.Errorf("input too short for V4 donate")
	}

	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	amount0 := new(big.Int).SetBytes(input[160:192])
	amount1 := new(big.Int).SetBytes(input[192:224])

	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}

	var hookData []byte
	if len(input) > 224 {
		// Offset word for hookData (bytes arg) is at position 224 in the args buffer.
		// The value at that position is the absolute offset from byte 0 of args.
		hookData = decodeABIBytes(input, 224)
	}
	delta, err := c.poolManager.Donate(stateAdapter, caller, key, amount0, amount1, hookData)
	if err != nil {
		return nil, suppliedGas - gasCost, err
	}

	result := PackBalanceDelta(delta.Amount0, delta.Amount1)
	return result, suppliedGas - gasCost, nil
}

func (c *DEXContract) runSync(
	_ contract.AccessibleState,
	_ common.Address,
	_ []byte,
	suppliedGas uint64,
	_ bool,
) ([]byte, uint64, error) {
	// V4 sync checkpoints ERC20 balances for flash accounting.
	// Precompile uses direct state access, so sync is a no-op.
	return []byte{}, suppliedGas, nil
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
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
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

// runExtsload reads a single bytes32 storage slot from the pool manager address.
// V4 ABI: extsload(bytes32) returns (bytes32)
// Input: 32 bytes (the storage slot key)
// Output: 32 bytes (the storage value)
func (c *DEXContract) runExtsload(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	if suppliedGas < GasPoolLookup {
		return nil, 0, fmt.Errorf("out of gas")
	}

	if len(input) < 32 {
		return nil, suppliedGas - GasPoolLookup, fmt.Errorf("input too short for extsload: need 32 bytes, got %d", len(input))
	}

	slot := common.BytesToHash(input[0:32])
	value := state.GetStateDB().GetState(lxPoolAddr, slot)

	return value.Bytes(), suppliedGas - GasPoolLookup, nil
}

// runExtsloadArray reads multiple bytes32 storage slots from the pool manager address.
// V4 ABI: extsload(bytes32[]) returns (bytes32[])
// Input: ABI-encoded bytes32 array (offset word + length + slot0 + slot1 + ...)
// Output: ABI-encoded bytes32 array with the same number of values
//
// Gas: the precompile uses the canonical RequiredGas formula
// (extsloadArrayGas) as the single source of truth. Parse-time validation
// failures still charge the base fee — the dispatcher already deducted it,
// and the caller paid for the bounded work done before the error.
func (c *DEXContract) runExtsloadArray(
	state contract.AccessibleState,
	input []byte,
	suppliedGas uint64,
) ([]byte, uint64, error) {
	// Canonical gas: same formula RequiredGas advertises, computed once.
	totalGas := extsloadArrayGas(input)
	if suppliedGas < totalGas {
		return nil, 0, fmt.Errorf("out of gas")
	}
	remaining := suppliedGas - totalGas

	// ABI-encoded dynamic array: first 32 bytes = offset to array data
	if len(input) < 64 {
		return nil, remaining, fmt.Errorf("input too short for extsload array")
	}

	inputLen := uint64(len(input))
	offsetBig := new(big.Int).SetBytes(input[0:32])
	if offsetBig.BitLen() > 63 {
		return nil, remaining, fmt.Errorf("extsload array: offset overflow")
	}
	offset := offsetBig.Uint64()
	if offset > inputLen || inputLen-offset < 32 {
		return nil, remaining, fmt.Errorf("extsload array: offset out of bounds")
	}

	countBig := new(big.Int).SetBytes(input[offset : offset+32])
	if countBig.BitLen() > 63 {
		return nil, remaining, fmt.Errorf("extsload array: count overflow")
	}
	count := countBig.Uint64()
	const maxExtsloadSlots = 256
	if count > maxExtsloadSlots {
		return nil, remaining, fmt.Errorf("extsload array: count %d exceeds max %d", count, maxExtsloadSlots)
	}
	dataStart := offset + 32

	if count > 0 && (dataStart > inputLen || inputLen-dataStart < count*32) {
		return nil, remaining, fmt.Errorf("extsload array: data out of bounds")
	}

	// Build ABI-encoded return: offset (32) + count (32) + values (count * 32)
	result := make([]byte, 64+count*32)
	// Offset to array data = 32
	result[31] = 0x20
	// Array length
	copy(result[32:64], input[offset:offset+32])

	stateDB := state.GetStateDB()
	for i := range count {
		slotStart := dataStart + i*32
		slot := common.BytesToHash(input[slotStart : slotStart+32])
		value := stateDB.GetState(lxPoolAddr, slot)
		copy(result[64+i*32:64+(i+1)*32], value.Bytes())
	}

	return result, remaining, nil
}

// --- Admin: Pause / Resume / Freeze handlers ---

func (c *DEXContract) runPauseDEX(
	state contract.AccessibleState,
	caller common.Address,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}
	if suppliedGas < GasAdmin {
		return nil, 0, fmt.Errorf("out of gas")
	}
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	if err := c.poolManager.PauseDEX(stateAdapter, caller); err != nil {
		return nil, suppliedGas - GasAdmin, err
	}
	return nil, suppliedGas - GasAdmin, nil
}

func (c *DEXContract) runResumeDEX(
	state contract.AccessibleState,
	caller common.Address,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}
	if suppliedGas < GasAdmin {
		return nil, 0, fmt.Errorf("out of gas")
	}
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	if err := c.poolManager.ResumeDEX(stateAdapter, caller); err != nil {
		return nil, suppliedGas - GasAdmin, err
	}
	return nil, suppliedGas - GasAdmin, nil
}

func (c *DEXContract) runPausePool(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}
	if suppliedGas < GasAdmin {
		return nil, 0, fmt.Errorf("out of gas")
	}
	if len(input) < 32 {
		return nil, suppliedGas - GasAdmin, fmt.Errorf("input too short for pool ID")
	}
	var poolId [32]byte
	copy(poolId[:], input[:32])
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	if err := c.poolManager.PausePool(stateAdapter, caller, poolId); err != nil {
		return nil, suppliedGas - GasAdmin, err
	}
	return nil, suppliedGas - GasAdmin, nil
}

func (c *DEXContract) runResumePool(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}
	if suppliedGas < GasAdmin {
		return nil, 0, fmt.Errorf("out of gas")
	}
	if len(input) < 32 {
		return nil, suppliedGas - GasAdmin, fmt.Errorf("input too short for pool ID")
	}
	var poolId [32]byte
	copy(poolId[:], input[:32])
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	if err := c.poolManager.ResumePool(stateAdapter, caller, poolId); err != nil {
		return nil, suppliedGas - GasAdmin, err
	}
	return nil, suppliedGas - GasAdmin, nil
}

func (c *DEXContract) runFreezePool(
	state contract.AccessibleState,
	caller common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) ([]byte, uint64, error) {
	if readOnly {
		return nil, suppliedGas, fmt.Errorf("cannot write in read-only mode")
	}
	if suppliedGas < GasAdmin {
		return nil, 0, fmt.Errorf("out of gas")
	}
	if len(input) < 32 {
		return nil, suppliedGas - GasAdmin, fmt.Errorf("input too short for pool ID")
	}
	var poolId [32]byte
	copy(poolId[:], input[:32])
	stateAdapter := &poolStateAdapter{stateDB: state.GetStateDB(), blockNumber: state.GetBlockContext().Number().Uint64()}
	if err := c.poolManager.FreezePool(stateAdapter, caller, poolId); err != nil {
		return nil, suppliedGas - GasAdmin, err
	}
	return nil, suppliedGas - GasAdmin, nil
}

// RequiredGas returns the gas required for the precompile input.
//
// This is the canonical gas source for the DEX precompile — every run handler
// charges this exact value rather than re-deriving it inline. Putting the
// gas formula in one place means a tariff change only edits one switch.
//
// For dynamic-sized selectors (extsload(bytes32[])) the value is derived
// from the input: base cost + per-slot cost, capped at the maximum array
// length the loader will accept. Selectors with no input data fall back to
// their fixed tariff.
//
// RED V4 closes the divergence between this function and the previous inline
// charge in runExtsloadArray: now there is one source of truth.
func (c *DEXContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasSwap
	}

	selector := binary.BigEndian.Uint32(input[:4])
	switch selector {
	case SelectorInitialize:
		return GasPoolCreate
	case SelectorSwap, SelectorDonate:
		return GasSwap
	case SelectorModifyLiquidity:
		return GasAddLiquidity
	case SelectorDeposit, SelectorWithdraw:
		return GasSettlement
	case SelectorBalanceOf:
		return GasPoolLookup
	case SelectorTake:
		return GasBalanceUpdate
	case SelectorSettle, SelectorSettleFor:
		return GasSettlement
	case SelectorUnlock:
		return GasFlashLoan
	case SelectorSync:
		return GasPoolLookup
	case SelectorExtsload:
		return GasPoolLookup
	case SelectorExtsloadArray:
		return extsloadArrayGas(input[4:])
	case SelectorPauseDEX, SelectorResumeDEX, SelectorPausePool, SelectorResumePool, SelectorFreezePool:
		return GasAdmin
	default:
		return GasSwap
	}
}

// extsloadArrayGas computes the canonical gas charge for an extsload(bytes32[])
// call: GasPoolLookup base + GasPoolLookup per slot. Returns the base alone
// for malformed inputs — the Run path will surface the parse error and the
// caller pays the base fee for the dispatch.
//
// Inputs that would overflow uint64 are clamped to the maximum supported
// slot count (maxExtsloadSlots = 256). The Run path enforces the same cap,
// so the gas formula and the read budget agree.
func extsloadArrayGas(data []byte) uint64 {
	if len(data) < 64 {
		return GasPoolLookup
	}
	offsetBig := new(big.Int).SetBytes(data[0:32])
	if offsetBig.BitLen() > 63 {
		return GasPoolLookup
	}
	offset := offsetBig.Uint64()
	dataLen := uint64(len(data))
	if offset > dataLen || dataLen-offset < 32 {
		return GasPoolLookup
	}
	countBig := new(big.Int).SetBytes(data[offset : offset+32])
	if countBig.BitLen() > 63 {
		return GasPoolLookup
	}
	count := countBig.Uint64()
	const maxExtsloadSlots = 256
	if count > maxExtsloadSlots {
		count = maxExtsloadSlots
	}
	return GasPoolLookup + GasPoolLookup*count
}

// poolStateAdapter adapts contract.StateDB to dex.StateDB.
// blockNumber must be set from the execution context (AccessibleState.GetBlockContext().Number())
// since contract.StateDB does not expose block number.
type poolStateAdapter struct {
	stateDB     contract.StateDB
	blockNumber uint64
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
	return a.blockNumber
}

func (a *poolStateAdapter) AddLog(log *ethtypes.Log) {
	a.stateDB.AddLog(log)
}

// TxHash exposes the executing transaction hash (txIdentified seam) so the
// PoolManager can bind a marketable order to its EVM tx for replay-idempotency
// (RED H1). Sourced from the underlying geth StateDB.
func (a *poolStateAdapter) TxHash() common.Hash {
	return a.stateDB.TxHash()
}

// Helper functions for encoding/decoding

func int24ToBytes(v int24) []byte {
	b := make([]byte, 3)
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
	return b
}

// DecodePoolKey decodes a V4 ABI-encoded PoolKey from input bytes.
// V4 PoolKey is 5 slots x 32 bytes = 160 bytes:
//
//	[0:32]    currency0 (address, left-padded)
//	[32:64]   currency1 (address, left-padded)
//	[64:96]   fee (uint24, left-padded)
//	[96:128]  tickSpacing (int24, sign-extended to 32 bytes)
//	[128:160] hooks (address, left-padded)
func DecodePoolKey(input []byte) (PoolKey, error) {
	if len(input) < 160 {
		return PoolKey{}, fmt.Errorf("input too short for V4 PoolKey: need 160 bytes, got %d", len(input))
	}

	key := PoolKey{}
	key.Currency0 = Currency{Address: common.BytesToAddress(input[12:32])}
	key.Currency1 = Currency{Address: common.BytesToAddress(input[44:64])}
	key.Fee = uint24(new(big.Int).SetBytes(input[64:96]).Uint64())
	// int24 sign extension from 32-byte ABI slot
	tickVal := new(big.Int).SetBytes(input[96:128])
	if input[96]&0x80 != 0 {
		tickVal.Sub(tickVal, new(big.Int).Lsh(big.NewInt(1), 256))
	}
	key.TickSpacing = int32(tickVal.Int64())
	key.Hooks = common.BytesToAddress(input[140:160])

	return key, nil
}

// DecodeSwapInput decodes V4 ABI-encoded swap input.
// Layout after 4-byte selector:
//
//	[0:160]   PoolKey (5 slots)
//	[160:192] zeroForOne (bool, 32 bytes)
//	[192:224] amountSpecified (int256)
//	[224:256] sqrtPriceLimitX96 (uint160, 32 bytes)
//	[256:]    hookData (ABI-encoded bytes: offset + length + data)
func DecodeSwapInput(input []byte) (PoolKey, SwapParams, []byte, error) {
	if len(input) < 256 {
		return PoolKey{}, SwapParams{}, nil, fmt.Errorf("input too short for V4 swap: need 256 bytes, got %d", len(input))
	}

	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return PoolKey{}, SwapParams{}, nil, err
	}

	// V4: zeroForOne is a full 32-byte bool slot
	zeroForOne := input[191] == 1

	// V4: amountSpecified is signed int256.
	// Negative = exact input, Positive = exact output.
	amountSpecified := decodeSigned256(input[192:224])

	params := SwapParams{
		ZeroForOne:        zeroForOne,
		AmountSpecified:   amountSpecified,
		SqrtPriceLimitX96: new(big.Int).SetBytes(input[224:256]),
	}

	var hookData []byte
	if len(input) > 256 {
		// Offset word for hookData (bytes arg) is at position 256 in the args buffer.
		// The value at that position is the absolute offset from byte 0 of args.
		hookData = decodeABIBytes(input, 256)
	}
	return key, params, hookData, nil
}

// DecodeModifyLiquidityInput decodes V4 ABI-encoded modifyLiquidity input.
// Layout after 4-byte selector:
//
//	[0:160]   PoolKey (5 slots)
//	[160:192] tickLower (int24, sign-extended to 32 bytes)
//	[192:224] tickUpper (int24, sign-extended to 32 bytes)
//	[224:256] liquidityDelta (int256)
//	[256:288] salt (bytes32)
//	[288:]    hookData (ABI-encoded bytes)
func DecodeModifyLiquidityInput(input []byte) (PoolKey, ModifyLiquidityParams, []byte, error) {
	if len(input) < 288 {
		return PoolKey{}, ModifyLiquidityParams{}, nil, fmt.Errorf("input too short for V4 modifyLiquidity: need 288 bytes, got %d", len(input))
	}

	key, err := DecodePoolKey(input[:160])
	if err != nil {
		return PoolKey{}, ModifyLiquidityParams{}, nil, err
	}

	// tickLower: int24 sign-extended to 32 bytes
	tickLowerVal := decodeSigned256(input[160:192])
	// tickUpper: int24 sign-extended to 32 bytes
	tickUpperVal := decodeSigned256(input[192:224])

	params := ModifyLiquidityParams{
		TickLower:      int32(tickLowerVal.Int64()),
		TickUpper:      int32(tickUpperVal.Int64()),
		LiquidityDelta: decodeSigned256(input[224:256]),
	}
	copy(params.Salt[:], input[256:288])

	var hookData []byte
	if len(input) > 288 {
		// Offset word for hookData (bytes arg) is at position 288 in the args buffer.
		hookData = decodeABIBytes(input, 288)
	}
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

// PackBalanceDelta packs amount0 and amount1 into V4 BalanceDelta format.
// V4 BalanceDelta is a single int256: amount0 in upper 128 bits, amount1 in lower 128 bits.
// This matches: toBalanceDelta(int128 _amount0, int128 _amount1) in BalanceDelta.sol
func PackBalanceDelta(amount0, amount1 *big.Int) []byte {
	result := make([]byte, 32)
	a0 := bigIntTo16Bytes(amount0) // signed int128
	a1 := bigIntTo16Bytes(amount1) // signed int128
	copy(result[0:16], a0)
	copy(result[16:32], a1)
	return result
}

// UnpackBalanceDelta unpacks a V4 BalanceDelta (single int256) into amount0 and amount1.
// amount0 = arithmetic right shift 128 bits, amount1 = sign-extend lower 128 bits.
func UnpackBalanceDelta(data []byte) (amount0, amount1 *big.Int) {
	if len(data) < 32 {
		return big.NewInt(0), big.NewInt(0)
	}
	// amount0: upper 128 bits (bytes 0-15), signed
	a0 := new(big.Int).SetBytes(data[0:16])
	if data[0]&0x80 != 0 {
		a0.Sub(a0, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	// amount1: lower 128 bits (bytes 16-31), signed
	a1 := new(big.Int).SetBytes(data[16:32])
	if data[16]&0x80 != 0 {
		a1.Sub(a1, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return a0, a1
}

// bigIntTo16Bytes encodes a big.Int as a 16-byte signed int128 (two's complement).
func bigIntTo16Bytes(v *big.Int) []byte {
	result := make([]byte, 16)
	if v == nil || v.Sign() == 0 {
		return result
	}
	if v.Sign() > 0 {
		b := v.Bytes()
		if len(b) > 16 {
			b = b[len(b)-16:]
		}
		copy(result[16-len(b):], b)
	} else {
		// Two's complement: 2^128 + v
		tc := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), v)
		b := tc.Bytes()
		if len(b) > 16 {
			b = b[len(b)-16:]
		}
		copy(result[16-len(b):], b)
	}
	return result
}

// decodeABIBytes decodes ABI-encoded dynamic bytes from a V4 calldata buffer.
//
// V4 ABI encoding uses ABSOLUTE offsets from byte 0 of the args buffer (after
// the 4-byte selector). The offset word at position offsetPos contains the
// absolute byte position where the length-prefixed data begins.
//
// Layout at absolute offset: [length (32 bytes)] [data (length bytes)]
//
// Parameters:
//   - args: the full args buffer (input after 4-byte selector)
//   - offsetPos: byte position within args where the 32-byte offset word lives
//
// Returns nil if the input is too short or malformed.
func decodeABIBytes(args []byte, offsetPos uint64) []byte {
	argsLen := uint64(len(args))
	if offsetPos+32 > argsLen {
		return nil
	}
	// Read the absolute offset value from the offset word.
	// Reject if the big.Int exceeds uint64 (truncation attack).
	absOffsetBig := new(big.Int).SetBytes(args[offsetPos : offsetPos+32])
	if absOffsetBig.BitLen() > 63 {
		return nil // value exceeds int64 max — impossible valid offset
	}
	absOffset := absOffsetBig.Uint64()
	// Offset must point forward (past the offset word) to prevent data confusion.
	if absOffset < offsetPos+32 {
		return nil
	}
	// Check absOffset+32 without overflow.
	if absOffset > argsLen || argsLen-absOffset < 32 {
		return nil
	}
	// At absOffset: 32 bytes length, then data.
	lengthBig := new(big.Int).SetBytes(args[absOffset : absOffset+32])
	if lengthBig.BitLen() > 63 {
		return nil
	}
	length := lengthBig.Uint64()
	dataStart := absOffset + 32
	// Check dataStart+length without overflow.
	if length == 0 {
		return nil
	}
	if dataStart > argsLen || argsLen-dataStart < length {
		return nil
	}
	return args[dataStart : dataStart+length]
}

// EncodePoolKeyABI encodes a PoolKey into V4 ABI format (5 slots x 32 bytes = 160 bytes).
func EncodePoolKeyABI(key PoolKey) []byte {
	data := make([]byte, 160)
	copy(data[12:32], key.Currency0.Address.Bytes())
	copy(data[44:64], key.Currency1.Address.Bytes())
	// fee as uint24 in last 3 bytes of slot
	data[93] = byte(key.Fee >> 16)
	data[94] = byte(key.Fee >> 8)
	data[95] = byte(key.Fee)
	// tickSpacing as int24 sign-extended to 32 bytes
	if key.TickSpacing < 0 {
		for i := 96; i < 125; i++ {
			data[i] = 0xff
		}
	}
	data[125] = byte(key.TickSpacing >> 16)
	data[126] = byte(key.TickSpacing >> 8)
	data[127] = byte(key.TickSpacing)
	copy(data[140:160], key.Hooks.Bytes())
	return data
}
