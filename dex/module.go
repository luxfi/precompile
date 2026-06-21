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
)

// DEXPrecompile is retained ONLY as the in-process holder of the shared *PoolManager
// (pool/vault state lives at LP-9010's storage address — see pool_manager.go). The
// read-only periphery (LP-9012 router, LP-9997 stateview) and the LP-9999 market
// registry compose DEXPrecompile.poolManager. 0x9010 is NO LONGER a dispatchable
// precompile — it is not registered, has no Run, and reverts/forwards nothing. 0x9999
// is the SOLE canonical DEX precompile.

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
// The model (decomplected — one concern, one name):
//
//   - The precompile lives at ONE address (LP-9010) across every Lux-derived
//     EVM (Lux C-Chain, Hanzo, Zoo, SPC, and white-label deployments such as
//     downstream EVM). The ABI is identical for every chain.
//
//   - 0x9010 is an ON-RAMP to the node-LOCAL D-Chain (dexvm), NOT a matcher and
//     NOT a backend selector. The matcher is the dexvm the validators run; D is
//     a normal Lux chain validated by an authorized subset (the --dex-validator
//     opt-in + NFT authz, decided at the chain-create/validate level in the node
//     chain manager — never as a precompile-side "mode"). 0x9010 SUBMITS DEX
//     operations to that local D-Chain or VERIFIES committed D receipts.
//
//   - The DEFAULT client is dchainUnavailable (dchain_client.go): it performs no
//     matching and reverts every call with ErrDChainUnavailable. A node that
//     serves the LP-9010 path makes it live by resolving its LOCAL D-Chain over
//     loopback via InstallDChainClient from the EVM plugin; a node that is not
//     running its local dexvm cleanly reverts (the on-ramp is closed) — it never
//     fabricates a fill nor masks the absent chain as a missing pool.
//
//   - Brand identity is a value the client carries (Engine.Brand()). User-facing
//     error strings produced by the precompile MUST come from the client, never
//     hard-coded here, so a tenant surface stays free of the word "Lux" while the
//     OSS package is still "Lux DEX" on Lux-network deployments.
var DEXPrecompile = newDEXContract(newDChainUnavailable())

// InstallDChainClient resolves the singleton precompile against the node-LOCAL
// D-Chain (dexvm) client.
//
// THIS IS NOT A BACKEND SWAP. There is exactly ONE valid target: the co-located
// D-Chain this node runs, reached over loopback (the dexvm is RPC-served; the
// precompile is a leaf library that must not reach up into the node chain
// manager). The EVM plugin calls this exactly once at boot when this node serves
// the DEX path and its local D-Chain endpoint is configured. A node without its
// local D-Chain leaves the default dchainUnavailable client in place.
//
// MUST be called BEFORE the VM starts initializing precompiles (before any
// genesis Configure()). Calling it after ANY pool-manager state has accumulated
// returns an error — the resolution must not race with live state. The guard
// covers every per-pool map the precompile maintains (pools, poolStates,
// positions) so a future map added without updating the guard does not silently
// re-open the race.
//
// Logs the client brand to stderr on success so operators see in the boot log
// that the local D-Chain on-ramp is open. Threading: not safe for concurrent
// use. The host binary is the single caller during process startup.
func InstallDChainClient(e Engine) error {
	if e == nil {
		return fmt.Errorf("dex: local D-Chain client must not be nil")
	}
	pm := DEXPrecompile.poolManager
	if len(pm.pools) != 0 || len(pm.poolStates) != 0 || len(pm.positions) != 0 {
		return fmt.Errorf("dex: cannot install local D-Chain client after pool initialization")
	}
	pm.engine = e
	// Surface the open on-ramp on the boot log. Stderr is the right sink for a
	// process-lifecycle event operators need even before structured logging.
	fmt.Fprintf(os.Stderr, "dex: LP-9010 on-ramp open to local D-Chain client brand=%q\n", e.Brand())
	return nil
}

// newDEXContract constructs the singleton with a non-nil local D-Chain client.
// Separated from the var declaration so the construction path is testable and so
// reviewers can see the client MUST be non-nil at init.
func newDEXContract(e Engine) *DEXContract {
	if e == nil {
		// Bug in caller — panic at init time, not at first resolution.
		panic("dex: DEXContract requires a non-nil local D-Chain client")
	}
	return &DEXContract{
		poolManager: NewPoolManager(e),
	}
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

	// Compute admin selectors at init time (not compile-time constants). These
	// selectors are consumed by the LP-9999 settlement dispatch (settle_module.go).
	SelectorPauseDEX = keccak4("pauseDEX()")
	SelectorResumeDEX = keccak4("resumeDEX()")
	SelectorPausePool = keccak4("pausePool(bytes32)")
	SelectorResumePool = keccak4("resumePool(bytes32)")
	SelectorFreezePool = keccak4("freezePool(bytes32)")
}

// DEXContract is the in-process holder of the shared *PoolManager. It is NOT a
// registered precompile and has no Run dispatch — 0x9010 is removed as a callable
// surface. It exists solely so the read-only periphery (router/stateview) and the
// LP-9999 market registry can compose poolManager, which keys pool/vault state at
// LP-9010's storage address (pool_manager.go).
type DEXContract struct {
	poolManager *PoolManager
}

// Run executes the precompile
// poolStateAdapter adapts contract.StateDB to dex.StateDB.
// blockNumber must be set from the execution context (AccessibleState.GetBlockContext().Number())
// since contract.StateDB does not expose block number.
//
// accessibleState is retained so the adapter can reach the EVM execution
// environment (GetPrecompileEnv) for the ERC-20 custody legs, which must sub-call
// the token contract (transferFrom / transfer / balanceOf). See module_erc20.go
// for the erc20Vault binding and the optional-Call seam.
type poolStateAdapter struct {
	stateDB         contract.StateDB
	blockNumber     uint64
	accessibleState contract.AccessibleState
}

// newPoolStateAdapter builds the dex.StateDB adapter from the precompile execution
// context. The single construction point so every selector handler wires the same
// state, block number, and EVM environment (the ERC-20 vault seam needs the env).
func newPoolStateAdapter(state contract.AccessibleState) *poolStateAdapter {
	return &poolStateAdapter{
		stateDB:         state.GetStateDB(),
		blockNumber:     state.GetBlockContext().Number().Uint64(),
		accessibleState: state,
	}
}

// underlyingStateDB exposes the wrapped contract.StateDB so the settle path can
// prefer a StateDB that DIRECTLY implements erc20Vault (the authoritative ledger)
// over the adapter's EVM sub-call bridge. Used by stateDBERC20.
func (a *poolStateAdapter) underlyingStateDB() contract.StateDB { return a.stateDB }

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
//
// NOTE: this is the lenient packer (legacy callers). Each leg is masked to its low
// 16 bytes if it exceeds int128. The consensus money path (SettleSwap) must instead
// REJECT out-of-range deltas via FitsSignedInt128 before packing — toBalanceDelta
// reverts on int128 overflow in V4 and must never silently wrap/sign-flip a value.
func PackBalanceDelta(amount0, amount1 *big.Int) []byte {
	result := make([]byte, 32)
	a0 := bigIntTo16Bytes(amount0) // signed int128
	a1 := bigIntTo16Bytes(amount1) // signed int128
	copy(result[0:16], a0)
	copy(result[16:32], a1)
	return result
}

// minInt128 = -(2^127); maxInt128 = 2^127 - 1. Computed once (package-level) so the
// range guard allocates nothing on the hot path.
var (
	maxInt128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	minInt128 = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
)

// FitsSignedInt128 reports whether v is representable as a signed int128
// (-2^127 <= v <= 2^127-1), i.e. it can be packed into one BalanceDelta leg WITHOUT
// truncation or sign-flip. A nil value fits (it encodes as zero).
func FitsSignedInt128(v *big.Int) bool {
	if v == nil {
		return true
	}
	return v.Cmp(maxInt128) <= 0 && v.Cmp(minInt128) >= 0
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
