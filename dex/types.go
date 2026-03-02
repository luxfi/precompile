// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dex implements Uniswap v4-style DEX precompiles for Lux EVMs.
// This provides native singleton DEX functionality with flash accounting,
// hooks, and native token support for HFT across all Lux chains.
package dex

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Precompile addresses for LX components
// LP-aligned format: 0x0000000000000000000000000000000000LPNUM
// See LP-9015 for canonical specification
const (
	// Core AMM (LP-901x)
	LXAMMAddress    = "0x0000000000000000000000000000000000009010" // LP-9010 LXAMM (singleton AMM core)
	LXOracleAddress = "0x0000000000000000000000000000000000009011" // LP-9011 LXOracle (external price aggregation)
	LXRouterAddress = "0x0000000000000000000000000000000000009012" // LP-9012 LXRouter (swap routing)
	LXHooksAddress  = "0x0000000000000000000000000000000000009013" // LP-9013 LXHooks (hook system)

	// Orderbook (LP-902x)
	LXBookAddress = "0x0000000000000000000000000000000000009020" // LP-9020 LXBook (orderbook engine)

	// Custody (LP-903x)
	LXVaultAddress = "0x0000000000000000000000000000000000009030" // LP-9030 LXVault (custody + margin)

	// Pricing (LP-904x)
	LXPriceAddress = "0x0000000000000000000000000000000000009040" // LP-9040 LXPrice (derived/computed pricing)

	// Lending (LP-905x–906x)
	LXLendAddress      = "0x0000000000000000000000000000000000009050" // LP-9050 LXLend (lending pool)
	LXAutoRepayAddress = "0x0000000000000000000000000000000000009060" // LP-9060 LXAutoRepay (self-repaying loans)

	// Liquidation + Transmutation (LP-907x–908x)
	LXLiquidatorAddress  = "0x0000000000000000000000000000000000009070" // LP-9070 LXLiquidator (liquidation engine)
	LXTransmuterAddress  = "0x0000000000000000000000000000000000009080" // LP-9080 LXTransmuter (debt → collateral conversion)

	// Settlement (LP-909x)
	// LXFillAttestAddress is defined in fill_attestation.go               // LP-9090 LXFillAttest (broker fill attestation + fraud proofs)

	// Aliases for backward compatibility
	LXPoolAddress     = LXAMMAddress
	LXFlashAddress    = "0x0000000000000000000000000000000000009014" // LP-9014 (flash loans — part of LXAMM)
	LXFeedAddress     = LXPriceAddress
	LXLiquidAddress   = LXAutoRepayAddress
	LiquidatorAddress = LXLiquidatorAddress
	LiquidFXAddress   = LXTransmuterAddress

	// Bridge Precompiles (LP-6xxx)
	TeleportAddress = "0x0000000000000000000000000000000000006010" // LP-6010 Teleport (cross-chain)

	// Deprecated: Old addresses kept for migration reference only
	// These will be removed in a future release
	// PoolManagerAddress = "0x0400" // DEPRECATED: Use LXPoolAddress
	// SwapRouterAddress  = "0x0401" // DEPRECATED: Use LXRouterAddress
	// HooksAddress       = "0x0402" // DEPRECATED: Use LXHooksAddress
	// FlashLoanAddress   = "0x0403" // DEPRECATED: Use LXFlashAddress
)

// Gas costs optimized for HFT operations
const (
	// Core DEX operations
	GasPoolCreate     uint64 = 50_000 // Create new pool
	GasSwap           uint64 = 50_000 // Single swap
	GasAddLiquidity   uint64 = 20_000 // Add liquidity
	GasRemoveLiq      uint64 = 20_000 // Remove liquidity
	GasFlashLoan      uint64 = 5_000  // Flash loan base
	GasHookCall       uint64 = 3_000  // Hook invocation
	GasBalanceUpdate  uint64 = 500    // Balance delta update
	GasSettlement     uint64 = 8_000  // Final settlement
	GasPoolLookup     uint64 = 100    // Pool state lookup
	GasNativeTransfer uint64 = 2_100  // Native LUX transfer
	GasAdmin          uint64 = 2_100  // Admin operations (pause/freeze)

	// Lending operations
	GasSupply    uint64 = 15_000 // Supply collateral
	GasBorrow    uint64 = 20_000 // Borrow against collateral
	GasRepay     uint64 = 15_000 // Repay debt
	GasWithdraw  uint64 = 15_000 // Withdraw collateral
	GasLiquidate uint64 = 50_000 // Liquidate position

	// Perpetual operations
	GasOpenPosition  uint64 = 25_000 // Open perp position
	GasClosePosition uint64 = 25_000 // Close perp position
	GasModifyMargin  uint64 = 10_000 // Add/remove margin
	GasSettleFunding uint64 = 10_000 // Settle funding rate

	// Liquid operations (self-repaying loans)
	GasDeposit   uint64 = 20_000 // Deposit yield-bearing collateral
	GasMint      uint64 = 25_000 // Mint liquid tokens (L*)
	GasBurn      uint64 = 20_000 // Burn liquid tokens
	GasRepayDebt uint64 = 15_000 // Manual debt repayment
	GasHarvest   uint64 = 30_000 // Harvest yield and repay debt
	GasTransmute uint64 = 25_000 // Convert liquid token to underlying

	// Teleport operations
	GasTeleportInit     uint64 = 50_000 // Initiate cross-chain transfer
	GasTeleportComplete uint64 = 40_000 // Complete cross-chain transfer
)

// Pool fee tiers (basis points)
const (
	Fee001 uint24 = 100    // 0.01% - stablecoins
	Fee005 uint24 = 500    // 0.05% - stable pairs
	Fee030 uint24 = 3000   // 0.30% - standard
	Fee100 uint24 = 10000  // 1.00% - exotic pairs
	FeeMax uint24 = 100000 // 10% max fee
)

// Tick spacing for different fee tiers
const (
	TickSpacing001 int24 = 1
	TickSpacing005 int24 = 10
	TickSpacing030 int24 = 60
	TickSpacing100 int24 = 200
)

// Hook flags (bitmap for hook capabilities).
// V4: flags are encoded in the TRAILING (least significant) bits of the hook address.
// Bit positions match Uniswap V4 Hooks.sol exactly.
type HookFlags uint16

const (
	HookAfterRemoveLiquidityReturnsDelta HookFlags = 1 << 0
	HookAfterAddLiquidityReturnsDelta    HookFlags = 1 << 1
	HookAfterSwapReturnsDelta            HookFlags = 1 << 2
	HookBeforeSwapReturnsDelta           HookFlags = 1 << 3
	HookAfterDonate                      HookFlags = 1 << 4
	HookBeforeDonate                     HookFlags = 1 << 5
	HookAfterSwap                        HookFlags = 1 << 6
	HookBeforeSwap                       HookFlags = 1 << 7
	HookAfterRemoveLiquidity             HookFlags = 1 << 8
	HookBeforeRemoveLiquidity            HookFlags = 1 << 9
	HookAfterAddLiquidity                HookFlags = 1 << 10
	HookBeforeAddLiquidity               HookFlags = 1 << 11
	HookAfterInitialize                  HookFlags = 1 << 12
	HookBeforeInitialize                 HookFlags = 1 << 13

	HookAllMask HookFlags = (1 << 14) - 1
)

// Currency represents a token (native or ERC20)
// Address(0) represents native LUX
type Currency struct {
	Address common.Address
}

// NativeCurrency represents native LUX (no wrapping needed)
var NativeCurrency = Currency{Address: common.Address{}}

// IsNative returns true if this currency is native LUX
func (c Currency) IsNative() bool {
	return c.Address == common.Address{}
}

// ToBytes serializes currency for storage
func (c Currency) ToBytes() []byte {
	return c.Address.Bytes()
}

// CurrencyFromBytes deserializes currency from storage
func CurrencyFromBytes(data []byte) Currency {
	return Currency{Address: common.BytesToAddress(data)}
}

// PoolKey uniquely identifies a pool
// Sorted by currency address (currency0 < currency1)
type PoolKey struct {
	Currency0   Currency       // Lower address token
	Currency1   Currency       // Higher address token
	Fee         uint24         // Fee in basis points
	TickSpacing int24          // Tick spacing for concentrated liquidity
	Hooks       common.Address // Hook contract address (zero = no hooks)
}

// ID computes the unique pool identifier.
// V4: keccak256(abi.encode(poolKey)) where poolKey is 5 ABI slots (160 bytes).
func (pk PoolKey) ID() [32]byte {
	data := EncodePoolKeyABI(pk)
	var id [32]byte
	copy(id[:], crypto.Keccak256(data))
	return id
}

// ToBytes serializes pool key for storage
func (pk PoolKey) ToBytes() []byte {
	data := make([]byte, 20+20+3+3+20) // 66 bytes
	copy(data[0:20], pk.Currency0.ToBytes())
	copy(data[20:40], pk.Currency1.ToBytes())
	binary.BigEndian.PutUint32(data[40:44], uint32(pk.Fee))
	// Shift to use only 3 bytes
	copy(data[40:43], data[41:44])
	binary.BigEndian.PutUint32(data[43:47], uint32(pk.TickSpacing))
	copy(data[43:46], data[44:47])
	copy(data[46:66], pk.Hooks.Bytes())
	return data[:66]
}

// PoolKeyFromBytes deserializes pool key from storage
func PoolKeyFromBytes(data []byte) (PoolKey, error) {
	if len(data) < 66 {
		return PoolKey{}, errors.New("invalid pool key data length")
	}
	pk := PoolKey{}
	pk.Currency0 = CurrencyFromBytes(data[0:20])
	pk.Currency1 = CurrencyFromBytes(data[20:40])

	var feeBytes [4]byte
	copy(feeBytes[1:], data[40:43])
	pk.Fee = uint24(binary.BigEndian.Uint32(feeBytes[:]))

	var tickBytes [4]byte
	copy(tickBytes[1:], data[43:46])
	pk.TickSpacing = int24(binary.BigEndian.Uint32(tickBytes[:]))

	pk.Hooks = common.BytesToAddress(data[46:66])
	return pk, nil
}

// BalanceDelta represents the net token changes during a transaction
// Uses signed 128-bit integers for amount0 and amount1
// Positive = owed to the pool, Negative = owed to the user
type BalanceDelta struct {
	Amount0 *big.Int // Currency0 delta (positive = user owes pool)
	Amount1 *big.Int // Currency1 delta (positive = user owes pool)
}

// NewBalanceDelta creates a new balance delta
func NewBalanceDelta(amount0, amount1 *big.Int) BalanceDelta {
	return BalanceDelta{
		Amount0: new(big.Int).Set(amount0),
		Amount1: new(big.Int).Set(amount1),
	}
}

// ZeroBalanceDelta returns a zero balance delta
func ZeroBalanceDelta() BalanceDelta {
	return BalanceDelta{
		Amount0: big.NewInt(0),
		Amount1: big.NewInt(0),
	}
}

// Add combines two balance deltas
func (bd BalanceDelta) Add(other BalanceDelta) BalanceDelta {
	return BalanceDelta{
		Amount0: new(big.Int).Add(bd.Amount0, other.Amount0),
		Amount1: new(big.Int).Add(bd.Amount1, other.Amount1),
	}
}

// Sub subtracts another balance delta
func (bd BalanceDelta) Sub(other BalanceDelta) BalanceDelta {
	return BalanceDelta{
		Amount0: new(big.Int).Sub(bd.Amount0, other.Amount0),
		Amount1: new(big.Int).Sub(bd.Amount1, other.Amount1),
	}
}

// Negate inverts the balance delta signs
func (bd BalanceDelta) Negate() BalanceDelta {
	return BalanceDelta{
		Amount0: new(big.Int).Neg(bd.Amount0),
		Amount1: new(big.Int).Neg(bd.Amount1),
	}
}

// IsZero returns true if both amounts are zero
func (bd BalanceDelta) IsZero() bool {
	return bd.Amount0.Sign() == 0 && bd.Amount1.Sign() == 0
}

// Pool represents the state of a liquidity pool
type Pool struct {
	SqrtPriceX96   *big.Int // sqrt(price) * 2^96 (Q64.96)
	Tick           int24    // Current tick
	Liquidity      *big.Int // Total liquidity (L)
	FeeGrowth0X128 *big.Int // Fee growth for currency0 (Q128.128)
	FeeGrowth1X128 *big.Int // Fee growth for currency1 (Q128.128)
	ProtocolFees0  *big.Int // Accumulated protocol fees currency0
	ProtocolFees1  *big.Int // Accumulated protocol fees currency1
}

// IsInitialized returns true if the pool has been initialized
func (p *Pool) IsInitialized() bool {
	return p.SqrtPriceX96 != nil && p.SqrtPriceX96.Sign() > 0
}

// NewPool creates a new uninitialized pool
func NewPool() *Pool {
	return &Pool{
		SqrtPriceX96:   big.NewInt(0),
		Tick:           0,
		Liquidity:      big.NewInt(0),
		FeeGrowth0X128: big.NewInt(0),
		FeeGrowth1X128: big.NewInt(0),
		ProtocolFees0:  big.NewInt(0),
		ProtocolFees1:  big.NewInt(0),
	}
}

// Position represents a liquidity position
type Position struct {
	Owner                    common.Address
	TickLower                int24
	TickUpper                int24
	Liquidity                *big.Int
	FeeGrowthInside0LastX128 *big.Int
	FeeGrowthInside1LastX128 *big.Int
	TokensOwed0              *big.Int
	TokensOwed1              *big.Int
}

// PositionKey computes the unique position identifier.
// V4: keccak256(abi.encodePacked(owner, tickLower, tickUpper, salt))
// encodePacked: 20 bytes (address) + 3 bytes (int24) + 3 bytes (int24) + 32 bytes (bytes32) = 58 bytes.
func PositionKey(owner common.Address, tickLower, tickUpper int24, salt [32]byte) [32]byte {
	data := make([]byte, 58) // 20 + 3 + 3 + 32
	copy(data[0:20], owner.Bytes())
	// tickLower as int24 (3 bytes, big-endian)
	data[20] = byte(tickLower >> 16)
	data[21] = byte(tickLower >> 8)
	data[22] = byte(tickLower)
	// tickUpper as int24 (3 bytes, big-endian)
	data[23] = byte(tickUpper >> 16)
	data[24] = byte(tickUpper >> 8)
	data[25] = byte(tickUpper)
	copy(data[26:58], salt[:])
	var key [32]byte
	copy(key[:], crypto.Keccak256(data))
	return key
}

// SwapParams contains parameters for a swap.
// V4 convention: amountSpecified < 0 means exact input, > 0 means exact output.
type SwapParams struct {
	ZeroForOne        bool     // true = swap currency0 for currency1
	AmountSpecified   *big.Int // Negative = exact input, Positive = exact output (V4 convention)
	SqrtPriceLimitX96 *big.Int // Price limit (sqrt(price) * 2^96)
}

// ModifyLiquidityParams contains parameters for adding/removing liquidity
type ModifyLiquidityParams struct {
	TickLower      int24
	TickUpper      int24
	LiquidityDelta *big.Int // Positive = add, Negative = remove
	Salt           [32]byte // Position salt for uniqueness
}

// FlashParams contains parameters for flash loans
type FlashParams struct {
	Amount0   *big.Int       // Amount of currency0 to borrow
	Amount1   *big.Int       // Amount of currency1 to borrow
	Recipient common.Address // Recipient of borrowed tokens
	Data      []byte         // Callback data
}

// Errors - Core DEX
var (
	ErrPoolNotInitialized     = errors.New("pool not initialized")
	ErrPoolAlreadyInitialized = errors.New("pool already initialized")
	ErrPoolExists             = errors.New("pool already exists")
	ErrPoolNotFound           = errors.New("pool not found")
	ErrInvalidTickRange       = errors.New("invalid tick range")
	ErrInsufficientLiquidity  = errors.New("insufficient liquidity")
	ErrPriceLimitReached      = errors.New("price limit reached")
	ErrInvalidFee             = errors.New("invalid fee")
	ErrCurrencyNotSorted      = errors.New("currencies not sorted")
	ErrUnauthorized           = errors.New("unauthorized")
	ErrInvalidHookResponse    = errors.New("invalid hook response")
	ErrSettlementFailed       = errors.New("settlement failed")
	ErrInvalidSqrtPrice       = errors.New("invalid sqrt price")
	ErrTickOutOfRange         = errors.New("tick out of range")
	ErrNoLiquidity            = errors.New("no liquidity in pool")
)

// Errors - Pause/Freeze Controls (ATS regulatory compliance)
var (
	ErrDEXPaused          = errors.New("DEX: paused")
	ErrPoolPaused         = errors.New("pool: paused")
	ErrPoolFrozen         = errors.New("pool: frozen")
	ErrPoolNotPaused      = errors.New("pool: not paused")
	ErrDEXNotPaused       = errors.New("DEX: not paused")
	ErrFreezeIrreversible = errors.New("pool: freeze is irreversible without governance")
	ErrAlreadyPaused      = errors.New("already paused")
	ErrAlreadyFrozen      = errors.New("already frozen")
)

// Errors - Lending
var (
	ErrInsufficientCollateral   = errors.New("insufficient collateral")
	ErrHealthFactorTooLow       = errors.New("health factor below minimum")
	ErrBorrowCapExceeded        = errors.New("borrow cap exceeded")
	ErrReserveNotActive         = errors.New("reserve not active")
	ErrPositionNotLiquidatable  = errors.New("position not liquidatable")
	ErrReserveAlreadyExists     = errors.New("reserve already exists")
	ErrInvalidCollateralFactor  = errors.New("invalid collateral factor")
	ErrReserveNotFound          = errors.New("reserve not found")
	ErrReserveFrozen            = errors.New("reserve is frozen")
	ErrInvalidAmount            = errors.New("invalid amount")
	ErrSupplyCapExceeded        = errors.New("supply cap exceeded")
	ErrInsufficientBalance      = errors.New("insufficient balance")
	ErrBorrowDisabled           = errors.New("borrow disabled for this reserve")
	ErrPositionHealthy          = errors.New("position is healthy, cannot liquidate")
	ErrLiquidationTooSmall      = errors.New("liquidation amount too small")
	ErrFlashLiquidationDisabled = errors.New("flash liquidation disabled")
	ErrInvalidParameter         = errors.New("invalid parameter")
)

// Errors - Perpetuals
var (
	ErrMaxLeverageExceeded  = errors.New("max leverage exceeded (1111x)")
	ErrInsufficientMargin   = errors.New("insufficient margin")
	ErrPositionNotFound     = errors.New("position not found")
	ErrInvalidPositionSize  = errors.New("invalid position size")
	ErrMarkPriceUnavailable = errors.New("mark price unavailable")
	ErrBankruptPosition     = errors.New("position is bankrupt")
)

// Errors - Liquid (self-repaying loans)
var (
	ErrMaxLTVExceeded           = errors.New("max LTV exceeded (90%)")
	ErrInvalidYieldToken        = errors.New("invalid yield-bearing token")
	ErrDebtCeiling              = errors.New("debt ceiling reached")
	ErrNoDebtToRepay            = errors.New("no debt to repay")
	ErrTransmuterEmpty          = errors.New("transmuter has no underlying")
	ErrLiquidTokenNotRegistered = errors.New("liquid token not registered")
)

// Errors - Teleport
var (
	ErrInvalidChainID       = errors.New("invalid chain ID")
	ErrTeleportNotFinalized = errors.New("teleport not finalized")
	ErrDuplicateTeleportID  = errors.New("duplicate teleport ID")
	ErrInvalidWarpSignature = errors.New("invalid warp signature")
)

// Constants for math
var (
	Q96  = new(big.Int).Lsh(big.NewInt(1), 96)
	Q128 = new(big.Int).Lsh(big.NewInt(1), 128)

	MinTick int24 = -887272
	MaxTick int24 = 887272

	MinSqrtRatio    = new(big.Int).SetUint64(4295128739)
	MaxSqrtRatio, _ = new(big.Int).SetString("1461446703485210103287273052203988822378723970342", 10)
)

// uint24 type alias for fees
type uint24 = uint32

// int24 type alias for ticks
type int24 = int32

// =========================================================================
// Lending Types
// =========================================================================

// LendingReserve represents a lending market for a single asset
type LendingReserve struct {
	Asset            Currency // The asset
	TotalSupply      *big.Int // Total supplied (in underlying)
	TotalBorrow      *big.Int // Total borrowed
	SupplyIndex      *big.Int // Cumulative supply interest index (Q128)
	BorrowIndex      *big.Int // Cumulative borrow interest index (Q128)
	LastUpdateBlock  uint64   // Last block interest was accrued
	CollateralFactor *big.Int // Max borrow % (18 decimals, 0.8e18 = 80%)
	LiquidationBonus *big.Int // Liquidator bonus (18 decimals, 0.05e18 = 5%)
	BorrowCap        *big.Int // Maximum borrowable amount
	ReserveFactor    *big.Int // Protocol fee on interest (18 decimals)
	IsActive         bool     // Whether reserve accepts deposits
}

// LendingPosition represents a user's lending position
type LendingPosition struct {
	Owner           common.Address
	Asset           common.Address
	SupplyShares    *big.Int // User's share of supply pool
	BorrowAmount    *big.Int // Current borrow amount with interest
	BorrowIndex     *big.Int // Index when borrow was last updated
	LastUpdateBlock uint64   // Block when position was last updated
}

// =========================================================================
// Perpetual Types
// =========================================================================

// MaxLeverage is the maximum allowed leverage (1111x)
const MaxLeverage uint32 = 1111

// PerpMarket represents a perpetual futures market
type PerpMarket struct {
	BaseAsset         Currency // The underlying asset (e.g., ETH)
	QuoteAsset        Currency // The quote asset (e.g., USD)
	MarkPrice         *big.Int // Current mark price (Q96)
	IndexPrice        *big.Int // Oracle index price (Q96)
	OpenInterestLong  *big.Int // Total long open interest
	OpenInterestShort *big.Int // Total short open interest
	FundingRate       *big.Int // Current funding rate (signed, per 8h)
	LastFundingTime   int64    // Unix timestamp of last funding
	MaxLeverage       uint32   // Maximum leverage (default 1111x)
	MaintenanceMargin *big.Int // Maintenance margin ratio (18 decimals)
	InsuranceFund     *big.Int // Market's insurance fund balance
}

// PerpPosition represents a user's perpetual position
type PerpPosition struct {
	Owner            common.Address
	Market           [32]byte // Market ID
	Size             *big.Int // Position size (positive=long, negative=short)
	EntryPrice       *big.Int // Average entry price (Q96)
	Margin           *big.Int // Deposited margin
	LastFundingIndex *big.Int // Funding index at last update
	IsIsolated       bool     // Isolated vs cross margin
}

// FundingState tracks funding rate calculation state
type FundingState struct {
	CumulativeFunding *big.Int // Cumulative funding per unit size
	LastUpdateTime    int64    // Last funding settlement time
	PremiumEMA        *big.Int // Exponential moving average of premium
	TWAPWindow        uint64   // TWAP window in seconds (default 8h)
}

// =========================================================================
// Liquid Types (self-repaying loans with 90% LTV)
// =========================================================================

// Liquid protocol parameters
const (
	// MaxLTV is 90% - allows 90% of collateral to be minted as debt
	MaxLTV = 9000 // 90.00% in basis points

	// MinLTV is the minimum LTV to maintain position
	MinLTV = 100 // 1.00% in basis points

	// LTVPrecision for basis point calculations
	LTVPrecision = 10000
)

// LiquidToken represents a liquid asset (e.g., LUSD, LETH, LBTC)
type LiquidToken struct {
	Address         common.Address // Liquid token address
	UnderlyingAsset Currency       // The underlying asset it tracks
	TotalMinted     *big.Int       // Total liquid tokens minted
	DebtCeiling     *big.Int       // Maximum mintable
	MintFee         uint24         // Fee on minting (basis points)
	BurnFee         uint24         // Fee on burning (basis points)
}

// YieldToken represents an approved yield-bearing collateral token
// (e.g., LP tokens from DEX pools, yield vault shares)
type YieldToken struct {
	Address         common.Address // Yield token address
	UnderlyingAsset Currency       // The underlying asset
	YieldPerBlock   *big.Int       // Expected yield per block (for estimation)
	IsActive        bool           // Whether deposits are accepted
	TotalDeposited  *big.Int       // Total deposited in Liquid
}

// LiquidAccount represents a user's self-repaying loan position
type LiquidAccount struct {
	Owner            common.Address
	YieldToken       common.Address // The yield-bearing collateral token
	Collateral       *big.Int       // Amount of yield token deposited
	Debt             *big.Int       // Amount of liquid token debt owed
	LastHarvestBlock uint64         // Last block yield was harvested
	AccruedYield     *big.Int       // Unharvested yield (auto-repays debt)
}

// LiquidFXState manages the conversion of L* tokens back to underlying
type LiquidFXState struct {
	LiquidToken     common.Address // The liquid token (e.g., LUSD)
	UnderlyingAsset Currency       // The underlying (e.g., USDC)
	ExchangeBuffer  *big.Int       // Underlying available for exchange
	TotalStaked     *big.Int       // Total liquid tokens staked for transmutation
	ExchangeRate    *big.Int       // Current exchange rate (Q96)
}

// =========================================================================
// Teleport Types
// =========================================================================

// Supported chains for Teleport
const (
	ChainLux   uint32 = 96369  // Lux mainnet
	ChainHanzo uint32 = 36963  // Hanzo chain
	ChainZoo   uint32 = 200200 // Zoo chain
	ChainETH   uint32 = 1      // Ethereum mainnet
	ChainArb   uint32 = 42161  // Arbitrum One
	ChainOP    uint32 = 10     // Optimism
	ChainBase  uint32 = 8453   // Base
	ChainPoly  uint32 = 137    // Polygon
	ChainBSC   uint32 = 56     // BNB Chain
	ChainAvax  uint32 = 43114  // Avalanche C-Chain
)

// TeleportRequest represents a cross-chain transfer request
type TeleportRequest struct {
	TeleportID  [32]byte       // Unique identifier
	SourceChain uint32         // Source chain ID
	DestChain   uint32         // Destination chain ID
	Sender      common.Address // Sender on source chain
	Recipient   common.Address // Recipient on dest chain
	Token       common.Address // Token being teleported
	Amount      *big.Int       // Amount to teleport
	Timestamp   int64          // Request timestamp
	Status      TeleportStatus // Current status
}

// TeleportStatus represents the state of a teleport
type TeleportStatus uint8

const (
	TeleportPending   TeleportStatus = iota
	TeleportBurned                   // Burned on source chain
	TeleportValidated                // Validated by MPC/Warp
	TeleportMinted                   // Minted on destination chain
	TeleportFailed                   // Failed (can be retried)
)

// WarpMessage represents a cross-chain message via Lux Warp
type WarpMessage struct {
	SourceChainID [32]byte // Source chain ID (Lux format)
	Payload       []byte   // Message payload
	Signatures    []byte   // BLS aggregate signature
	BitSet        []byte   // Validator bitset
}

// OmnichainRoute represents a multi-hop cross-chain swap route
type OmnichainRoute struct {
	Hops          []RouteHop // Sequence of hops
	TotalEstimate *big.Int   // Estimated output amount
	TotalGas      uint64     // Estimated total gas
}

// RouteHop represents a single hop in a cross-chain route
type RouteHop struct {
	ChainID      uint32         // Chain for this hop
	PoolID       [32]byte       // Pool to use on this chain
	TokenIn      common.Address // Input token
	TokenOut     common.Address // Output token
	AmountIn     *big.Int       // Amount in
	MinAmountOut *big.Int       // Minimum output
}
