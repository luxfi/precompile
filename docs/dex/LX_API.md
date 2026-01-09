# LX Precompile API Specification

> **Generated from:** `~/work/lux/precompile/solidity/dex/ILX*.sol`
> **Last Updated:** 2026-01-05

## Address Registry (LP-Aligned)

| Precompile | LP Number | Address | Interface |
|------------|-----------|---------|-----------|
| LXPool     | LP-9010   | `0x0000000000000000000000000000000000009010` | `ILXPool.sol` |
| LXOracle   | LP-9011   | `0x0000000000000000000000000000000000009011` | `ILXOracle.sol` |
| LXBook     | LP-9020   | `0x0000000000000000000000000000000000009020` | `ILXBook.sol` |
| LXVault    | LP-9030   | `0x0000000000000000000000000000000000009030` | `ILXVault.sol` |
| LXFeed     | LP-9040   | `0x0000000000000000000000000000000000009040` | `ILXFeed.sol` |

---

## Shared Types (`Types.sol`)

### Custom Types

```solidity
type Currency is address;        // address(0) = native LUX
type BalanceDelta is int256;     // Positive = user owes pool
type HookPermissions is uint16;  // Bitmap of hook capabilities
```

### PoolKey

```solidity
struct PoolKey {
    Currency currency0;      // Lower address token (sorted)
    Currency currency1;      // Higher address token (sorted)
    uint24 fee;              // Fee in basis points (3000 = 0.30%)
    int24 tickSpacing;       // Tick spacing for concentrated liquidity
    address hooks;           // Hook contract (address(0) = no hooks)
}
```

### SwapParams

```solidity
struct SwapParams {
    bool zeroForOne;           // Direction: true = currency0 → currency1
    int256 amountSpecified;    // Positive = exact input, Negative = exact output
    uint160 sqrtPriceLimitX96; // Price limit (0 = no limit)
}
```

### ModifyLiquidityParams

```solidity
struct ModifyLiquidityParams {
    int24 tickLower;           // Lower tick bound
    int24 tickUpper;           // Upper tick bound
    int128 liquidityDelta;     // Positive = add, Negative = remove
    bytes32 salt;              // Salt for position key uniqueness
}
```

### Fee Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `FEE_001` | 100 | 0.01% (stablecoins) |
| `FEE_005` | 500 | 0.05% (stable pairs) |
| `FEE_030` | 3000 | 0.30% (standard) |
| `FEE_100` | 10000 | 1.00% (exotic) |
| `FEE_MAX` | 100000 | 10% maximum |

---

## ILXPool (LP-9010) — Singleton AMM

Uniswap v4-compatible singleton pool manager with flash accounting.

### Errors

| Error | Description |
|-------|-------------|
| `Unauthorized()` | Caller not authorized |
| `Reentrant()` | Reentrancy detected |
| `PoolAlreadyInitialized()` | Pool already exists |
| `PoolNotInitialized()` | Pool doesn't exist |
| `CurrencyNotSorted()` | Currencies not in order |
| `InvalidFee()` | Fee out of bounds |
| `InvalidSqrtPrice()` | Invalid sqrt price |
| `TickOutOfRange()` | Tick outside bounds |
| `InvalidTickRange()` | tickLower >= tickUpper |
| `NonZeroDelta()` | Balance delta not settled |
| `NoLiquidity()` | No liquidity in range |

### Functions

#### Pool Management

```solidity
function initialize(
    PoolKey calldata key,
    uint160 sqrtPriceX96,
    bytes calldata hookData
) external returns (int24 tick);
```
Initialize a new pool. Returns the initial tick.

```solidity
function getPool(
    PoolKey calldata key
) external view returns (uint160 sqrtPriceX96, int24 tick, uint128 liquidity);
```
Get pool state.

#### Flash Accounting

```solidity
function lock(bytes calldata data) external returns (bytes memory result);
```
Acquire callback context for flash accounting. All operations within track balance changes. Deltas must net to zero.

```solidity
function settle(Currency currency, int256 amount) external;
```
Settle a currency delta. Positive = pay pool, Negative = receive.

```solidity
function take(Currency currency, address to, uint256 amount) external;
```
Take tokens owed to recipient.

```solidity
function sync(Currency currency) external;
```
Sync reserves after external transfer.

#### Core Operations

```solidity
function swap(
    PoolKey calldata key,
    SwapParams calldata params,
    bytes calldata hookData
) external returns (BalanceDelta delta);
```
Execute a swap. Returns balance delta.

```solidity
function modifyLiquidity(
    PoolKey calldata key,
    ModifyLiquidityParams calldata params,
    bytes calldata hookData
) external returns (BalanceDelta delta0, BalanceDelta delta1);
```
Add or remove liquidity.

```solidity
function donate(
    PoolKey calldata key,
    uint256 amount0,
    uint256 amount1,
    bytes calldata hookData
) external;
```
Donate tokens to pool (protocol revenue).

#### Flash Loans

```solidity
function flash(
    address borrower,
    Currency currency,
    uint256 amount,
    bytes calldata data
) external;
```
Flash loan callback.

#### Protocol Fees

```solidity
function setProtocolFee(PoolKey calldata key, uint8 newProtocolFee) external;
```
Set protocol fee (basis points).

```solidity
function collectProtocol(
    PoolKey calldata key,
    address recipient
) external returns (uint256 amount0, uint256 amount1);
```
Collect accumulated protocol fees.

### Events

```solidity
event PoolInitialized(bytes32 indexed poolId, PoolKey key, uint160 sqrtPriceX96, int24 tick);
event Swap(bytes32 indexed poolId, address indexed sender, int256 amount0, int256 amount1, uint160 sqrtPriceX96, int24 tick);
event ModifyLiquidity(bytes32 indexed poolId, address indexed sender, int24 tickLower, int24 tickUpper, int128 liquidityDelta, int256 amount0, int256 amount1);
event Donate(bytes32 indexed poolId, address indexed sender, uint256 amount0, uint256 amount1);
```

---

## ILXBook (LP-9020) — CLOB Matching Engine

Hyperliquid-style CLOB with execute() endpoint.

### Custom Types

```solidity
type MarketId is uint32;   // Market identifier
type OrderId is uint64;    // Exchange order ID
type ClOrdId is uint128;   // Client order ID
```

### Enums

#### Side
| Value | Name | Description |
|-------|------|-------------|
| 0 | `BUY` | Buy order |
| 1 | `SELL` | Sell order |

#### OrderType (append-only)
| Value | Name | Description |
|-------|------|-------------|
| 0 | `LIMIT` | Standard limit order |
| 1 | `MARKET` | Market order (IOC) |
| 2 | `STOP_LIMIT` | Stop-limit on mark price |
| 3 | `STOP_MARKET` | Stop-market on mark price |
| 4 | `TAKE_PROFIT_LIMIT` | TP limit on mark price |
| 5 | `TAKE_PROFIT_MARKET` | TP market on mark price |
| 6 | `TRAILING_STOP` | Trailing stop |
| 7 | `TWAP` | Time-weighted average |
| 8 | `ICEBERG` | Iceberg (partial display) |

#### TimeInForce (append-only)
| Value | Name | Description |
|-------|------|-------------|
| 0 | `GTC` | Good-til-cancelled |
| 1 | `IOC` | Immediate-or-cancel |
| 2 | `FOK` | Fill-or-kill |
| 3 | `GTD` | Good-til-date |
| 4 | `ALO` | Add-liquidity-only (post-only) |

#### OrderStatus
| Value | Name | Description |
|-------|------|-------------|
| 0 | `NEW` | Accepted, not on book |
| 1 | `OPEN` | On book |
| 2 | `FILLED` | Completely filled |
| 3 | `CANCELLED` | Cancelled |
| 4 | `REJECTED` | Rejected |
| 5 | `EXPIRED` | Expired (GTD) |
| 6 | `TRIGGERED` | Stop/TP triggered |

### Structs

#### OrderRequest
```solidity
struct OrderRequest {
    MarketId marketId;        // Market to trade
    Side side;                // BUY or SELL
    OrderType orderType;      // Order type
    uint128 pxX18;            // Limit price (X18), 0 for market
    uint128 szX18;            // Size in base (X18)
    TimeInForce tif;          // Time-in-force
    bool reduceOnly;          // Only reduce position
    ClOrdId clOrdId;          // Client order ID
    uint64 expireTime;        // GTD expiration, 0 = no expiry
    uint128 triggerPxX18;     // Stop/TP trigger price
    uint128 trailingDeltaX18; // Trailing stop delta
}
```

#### Order
```solidity
struct Order {
    OrderId orderId;
    address owner;
    MarketId marketId;
    Side side;
    OrderType orderType;
    uint128 pxX18;
    uint128 origSzX18;
    uint128 remainingSzX18;
    uint128 filledSzX18;
    TimeInForce tif;
    OrderStatus status;
    uint64 timestamp;
    ClOrdId clOrdId;
    bool reduceOnly;
}
```

#### CancelRequest
```solidity
struct CancelRequest {
    OrderId orderId;    // By exchange ID
    ClOrdId clOrdId;    // OR by client ID (if orderId=0)
    MarketId marketId;  // Required if using clOrdId
}
```

#### AmendRequest
```solidity
struct AmendRequest {
    OrderId orderId;
    uint128 newPxX18;   // 0 = keep current
    uint128 newSzX18;   // 0 = keep current
}
```

#### ExecReport
```solidity
struct ExecReport {
    OrderId orderId;
    ClOrdId clOrdId;
    MarketId marketId;
    Side side;
    uint128 pxX18;        // Execution price
    uint128 szX18;        // Execution size
    uint128 feeX18;       // Fee charged
    uint64 timestamp;
    uint64 tradeId;
    bool isMaker;
    OrderStatus newStatus;
}
```

#### MarketSpec
```solidity
struct MarketSpec {
    MarketId marketId;
    string symbol;              // e.g., "BTC-PERP"
    address baseAsset;
    address quoteAsset;
    uint128 tickSizeX18;        // Min price increment
    uint128 lotSizeX18;         // Min size increment
    uint128 minOrderSzX18;
    uint128 maxOrderSzX18;
    uint16 makerFeeBps;         // Can be negative (rebate)
    uint16 takerFeeBps;
    bool active;
    bool perpMarket;            // true = perp, false = spot
}
```

### Errors

| Error | Description |
|-------|-------------|
| `InvalidMarket()` | Market doesn't exist |
| `InvalidPrice()` | Price out of bounds |
| `InvalidSize()` | Size too small/large |
| `InvalidOrderType()` | Order type not supported |
| `InvalidTIF()` | TIF not supported |
| `DuplicateClOrdId()` | Client order ID reused |
| `OrderNotFound()` | Order doesn't exist |
| `NotOrderOwner()` | Caller doesn't own order |
| `RiskCheckFailed()` | Pre-trade risk failed |
| `PostOnlyFailed()` | Post-only would take |
| `ReduceOnlyFailed()` | Would increase position |
| `SelfTrade()` | Would self-trade |
| `MarketClosed()` | Market not accepting orders |
| `RateLimited()` | Too many requests |

### Functions

#### Core Trading

```solidity
function placeOrder(OrderRequest calldata req) external returns (OrderId orderId);
function placeOrders(OrderRequest[] calldata reqs) external returns (OrderId[] memory orderIds);
function cancelOrder(CancelRequest calldata req) external returns (bool success);
function cancelOrders(CancelRequest[] calldata reqs) external returns (bool[] memory results);
function cancelAllOrders(MarketId marketId) external returns (uint32 cancelled);
function amendOrder(AmendRequest calldata req) external returns (OrderId newOrderId);
```

#### Hyperliquid-Style Execute

```solidity
function execute(string calldata action, bytes calldata data) external returns (bytes memory result);
function executeBatch(string[] calldata actions, bytes[] calldata datas) external returns (bytes[] memory results);
```

Action types: `"order"`, `"cancel"`, `"cancelByClOrdId"`, `"cancelAll"`, `"amend"`

#### Order Queries

```solidity
function getOrder(OrderId orderId) external view returns (Order memory order);
function getOrderByClOrdId(address owner, MarketId marketId, ClOrdId clOrdId) external view returns (Order memory order);
function getOpenOrders(address owner, MarketId marketId) external view returns (Order[] memory orders);
function orderCount(address owner) external view returns (uint32 count);
```

#### Market Data

```solidity
function getBBO(MarketId marketId) external view returns (uint128 bidPxX18, uint128 bidSzX18, uint128 askPxX18, uint128 askSzX18);
function getDepth(MarketId marketId, uint8 levels) external view returns (uint128[] memory bidPrices, uint128[] memory bidSizes, uint128[] memory askPrices, uint128[] memory askSizes);
function lastTrade(MarketId marketId) external view returns (uint128 pxX18, uint64 timestamp);
function getMarketSpec(MarketId marketId) external view returns (MarketSpec memory spec);
function getActiveMarkets() external view returns (MarketId[] memory marketIds);
```

### Events

```solidity
event OrderAccepted(OrderId indexed orderId, address indexed owner, MarketId indexed marketId, ClOrdId clOrdId);
event OrderRejected(address indexed owner, MarketId indexed marketId, ClOrdId clOrdId, string reason);
event OrderFilled(OrderId indexed orderId, uint128 pxX18, uint128 szX18, bool isMaker);
event OrderCancelled(OrderId indexed orderId, address indexed owner, uint128 remainingSzX18);
event OrderExpired(OrderId indexed orderId, address indexed owner);
event OrderTriggered(OrderId indexed orderId, uint128 triggerPxX18);
event Trade(MarketId indexed marketId, uint64 indexed tradeId, OrderId makerOrderId, OrderId takerOrderId, uint128 pxX18, uint128 szX18, bool takerIsBuy);
```

---

## ILXBookHFT — Packed ABI Extension

Optimized encoding for colo participants.

```solidity
function placeOrdersPacked(bytes calldata packed) external returns (uint64[] memory orderIds);
function cancelOrdersPacked(bytes calldata packed) external returns (bytes memory results);
function amendOrdersPacked(bytes calldata packed) external returns (uint64[] memory newOrderIds);
```

Packed encoding:
- Order: 64 bytes (marketId:4 + side:1 + type:1 + tif:1 + flags:1 + px:16 + sz:16 + clOrdId:16 + triggerPx:8)
- Cancel: 8 bytes (orderId:8)
- Amend: 32 bytes (orderId:8 + newPx:16 + newSz:8)

---

## ILXVault (LP-9030) — Clearinghouse

Custody, margin, positions, liquidations.

### Custom Types

```solidity
type MarketId is uint32;
```

### Enums

#### MarginMode
| Value | Name | Description |
|-------|------|-------------|
| 0 | `ISOLATED` | Per-position margin |
| 1 | `CROSS` | Shared margin (default) |
| 2 | `PORTFOLIO` | Cross-asset netting |

#### Side
| Value | Name |
|-------|------|
| 0 | `LONG` |
| 1 | `SHORT` |

### Structs

#### Fill (from LXBook)
```solidity
struct Fill {
    MarketId marketId;
    address maker;
    address taker;
    bool takerIsBuy;
    uint128 pxX18;
    uint128 szX18;
    uint128 makerFeeX18;   // Negative = rebate
    uint128 takerFeeX18;
    uint8 flags;           // FILL_FLAG_* constants
}
```

#### ApplyResult
```solidity
struct ApplyResult {
    uint128 appliedFills;
    uint128 appliedSzX18;
    uint8 status;   // 0=rejected, 1=ok, 2=partial
}
```

#### AccountState
```solidity
struct AccountState {
    int256 equityX18;
    uint256 totalCollateralX18;
    int256 unrealizedPnlX18;
    uint256 maintenanceReqX18;
    uint256 initialReqX18;
    MarginMode mode;
    bool isLiquidatable;
}
```

#### Position
```solidity
struct Position {
    MarketId marketId;
    Side side;
    uint128 sizeX18;
    uint128 avgEntryPxX18;
    int128 unrealizedPnlX18;
    uint128 marginX18;        // Isolated mode
    int128 fundingAccrued;
}
```

#### MarketConfig
```solidity
struct MarketConfig {
    MarketId marketId;
    uint128 maxLeverageX18;          // e.g., 50e18 = 50x
    uint128 maintenanceMarginX18;    // e.g., 0.03e18 = 3%
    uint128 initialMarginX18;        // e.g., 0.05e18 = 5%
    uint128 liquidationFeeX18;       // e.g., 0.025e18 = 2.5%
    uint128 maxPositionSzX18;
    uint128 maxOIX18;
    bool active;
}
```

### Fill Flags

| Constant | Value | Description |
|----------|-------|-------------|
| `FILL_FLAG_LIQUIDATION` | 0x01 | Fill is liquidation |
| `FILL_FLAG_REDUCE_ONLY` | 0x02 | Reduce-only fill |
| `FILL_FLAG_ADL` | 0x04 | Auto-deleverage |
| `FILL_FLAG_MARKET` | 0x08 | Market order |
| `FILL_FLAG_POST_ONLY_FAIL` | 0x10 | Post-only violation |

### Errors

| Error | Description |
|-------|-------------|
| `NotBook()` | Caller not LXBook |
| `NotOracle()` | Caller not oracle |
| `RiskRejected()` | Risk check failed |
| `InvalidFill()` | Fill parameters invalid |
| `InsufficientMargin()` | Not enough margin |
| `InsufficientBalance()` | Not enough balance |
| `MarketNotActive()` | Market paused |
| `PositionNotFound()` | No position |
| `NotLiquidatable()` | Above maintenance |
| `MaxOIExceeded()` | Max OI exceeded |
| `WithdrawalLocked()` | Cooldown active |

### Functions

#### Settlement (LXBook only)

```solidity
function applyFills(Fill[] calldata fills) external returns (ApplyResult memory result);
function preCheckFills(Fill[] calldata fills) external view returns (bool valid, string memory reason);
```

#### Custody

```solidity
function deposit(Currency currency, uint256 amount) external payable;
function withdraw(Currency currency, uint256 amount, address to) external;
function balanceOf(address user, Currency currency) external view returns (uint256 balance);
function totalCollateralValue(address user) external view returns (uint256 valueX18);
```

#### Margin Account

```solidity
function getAccountState(address user) external view returns (AccountState memory state);
function accountEquityX18(address user) external view returns (int256 equityX18);
function maintenanceMarginReqX18(address user) external view returns (uint256 reqX18);
function initialMarginReqX18(address user) external view returns (uint256 reqX18);
function marginRatioX18(address user) external view returns (uint256 ratioX18);
function setMarginMode(MarginMode mode) external;
```

#### Positions

```solidity
function getPosition(address user, MarketId marketId) external view returns (Position memory position);
function getAllPositions(address user) external view returns (Position[] memory positions);
function addMargin(MarketId marketId, uint256 amount) external;
function removeMargin(MarketId marketId, uint256 amount) external;
```

#### Liquidation

```solidity
function isLiquidatable(address user) external view returns (bool liquidatable);
function liquidate(address user, MarketId marketId, uint128 maxSzX18) external returns (uint128 liqSzX18);
function runADL(MarketId marketId, uint32 maxAccounts) external;
function insuranceFundBalance() external view returns (uint256 balance);
```

#### Funding

```solidity
function accrueFunding(MarketId marketId) external;
function fundingRateX18(MarketId marketId) external view returns (int256 rateX18);
function nextFundingTime(MarketId marketId) external view returns (uint256 timestamp);
```

#### Configuration

```solidity
function getMarketConfig(MarketId marketId) external view returns (MarketConfig memory config);
function openInterest(MarketId marketId) external view returns (uint128 longOIX18, uint128 shortOIX18);
```

### Events

```solidity
event Deposit(address indexed user, Currency indexed currency, uint256 amount);
event Withdraw(address indexed user, Currency indexed currency, uint256 amount);
event FillApplied(MarketId indexed marketId, address indexed maker, address indexed taker, uint128 pxX18, uint128 szX18, bool takerIsBuy);
event PositionOpened(address indexed user, MarketId indexed marketId, Side side, uint128 szX18, uint128 pxX18);
event PositionClosed(address indexed user, MarketId indexed marketId, int256 realizedPnlX18);
event PositionModified(address indexed user, MarketId indexed marketId, uint128 newSzX18, uint128 avgPxX18);
event Liquidation(address indexed user, MarketId indexed marketId, address indexed liquidator, uint128 szX18);
event ADLExecuted(MarketId indexed marketId, address indexed winner, address indexed loser, uint128 szX18);
event FundingAccrued(MarketId indexed marketId, int256 fundingRateX18, uint256 timestamp);
```

---

## ILXOracle (LP-9011) — Multi-Source Oracle

Robust index construction with outlier filtering.

### Custom Types

```solidity
type AssetId is uint32;
```

### Enums

#### PriceSource
| Value | Name | Description |
|-------|------|-------------|
| 0 | `CEX_BINANCE` | Binance spot |
| 1 | `CEX_COINBASE` | Coinbase Pro |
| 2 | `CEX_OKX` | OKX |
| 3 | `CEX_BYBIT` | Bybit |
| 4 | `DEX_UNISWAP` | Uniswap TWAP |
| 5 | `DEX_LXPOOL` | LXPool (LP-9010) |
| 6 | `CHAINLINK` | Chainlink |
| 7 | `PYTH` | Pyth network |
| 8 | `CUSTOM` | Custom oracle |

#### AggMethod
| Value | Name | Description |
|-------|------|-------------|
| 0 | `MEDIAN` | Median of valid sources |
| 1 | `TWAP` | Time-weighted average |
| 2 | `VWAP` | Volume-weighted average |
| 3 | `TRIMMED_MEAN` | Mean after outlier removal |
| 4 | `WEIGHTED_MEDIAN` | Weighted by confidence |

### Structs

#### PriceData
```solidity
struct PriceData {
    uint128 priceX18;
    uint64 timestamp;
    uint32 confidence;    // 0-10000 = 0-100%
    PriceSource source;
    bool isValid;
}
```

#### OracleConfig
```solidity
struct OracleConfig {
    AssetId assetId;
    string symbol;
    PriceSource[] sources;
    AggMethod aggMethod;
    uint32 minSources;
    uint32 maxStalenessSeconds;
    uint128 maxDeviationBps;
    bool active;
}
```

#### RobustIndexParams
```solidity
struct RobustIndexParams {
    uint32 windowSeconds;          // e.g., 900 = 15 min
    uint32 minSamples;
    uint128 outlierThresholdBps;   // e.g., 100 = 1%
    bool trimOutliers;
}
```

### Errors

| Error | Description |
|-------|-------------|
| `AssetNotFound()` | Asset not configured |
| `InsufficientSources()` | Not enough valid sources |
| `StalePrice()` | All prices too old |
| `SourceDeviationTooHigh()` | Sources diverge too much |
| `InvalidConfig()` | Invalid configuration |
| `Unauthorized()` | Caller not authorized |

### Functions

#### Price Queries

```solidity
function getPrice(AssetId assetId) external view returns (uint128 priceX18, uint64 timestamp);
function getPriceData(AssetId assetId) external view returns (PriceData memory data);
function getPrices(AssetId[] calldata assetIds) external view returns (uint128[] memory prices, uint64[] memory timestamps);
function getSourcePrice(AssetId assetId, PriceSource source) external view returns (uint128 priceX18, uint64 timestamp);
function getAllSourcePrices(AssetId assetId) external view returns (PriceData[] memory data);
```

#### Index Price

```solidity
function indexPrice(AssetId assetId) external view returns (uint128 indexPriceX18);
function indexPriceDetailed(AssetId assetId) external view returns (uint128 indexPriceX18, uint32 sourcesUsed, uint32 outliersTrimmed);
```

#### TWAP

```solidity
function getTWAP(AssetId assetId, uint32 windowSeconds) external view returns (uint128 twapX18);
```

#### Configuration

```solidity
function getConfig(AssetId assetId) external view returns (OracleConfig memory config);
function getRobustParams(AssetId assetId) external view returns (RobustIndexParams memory params);
function getAssetId(string calldata symbol) external view returns (AssetId assetId);
```

### Events

```solidity
event PriceUpdated(AssetId indexed assetId, uint128 priceX18, uint64 timestamp, uint32 numSources);
event SourcePriceReceived(AssetId indexed assetId, PriceSource indexed source, uint128 priceX18);
event OracleConfigured(AssetId indexed assetId, string symbol);
event PriceDeviation(AssetId indexed assetId, uint128 lowX18, uint128 highX18, uint128 deviationBps);
```

---

## ILXFeed (LP-9040) — Computed Price Feeds

Mark price, funding rate, liquidation triggers.

### Custom Types

```solidity
type MarketId is uint32;
```

### Enums

#### PriceType
| Value | Name | Description |
|-------|------|-------------|
| 0 | `INDEX` | Robust index from LXOracle |
| 1 | `MARK` | Index + premium |
| 2 | `LAST` | Last trade from LXBook |
| 3 | `MID` | Order book mid |
| 4 | `ORACLE` | Raw oracle price |

### Structs

#### MarketPrices
```solidity
struct MarketPrices {
    uint128 indexPriceX18;
    uint128 markPriceX18;
    uint128 lastPriceX18;
    uint128 midPriceX18;
    int128 premiumX18;        // mark - index
    int128 fundingRateX18;    // Per hour
    uint64 timestamp;
}
```

#### FundingParams
```solidity
struct FundingParams {
    int128 premiumX18;
    int128 fundingRateX18;
    int128 cappedRateX18;
    uint64 nextFundingTime;
    uint32 fundingIntervalSecs;   // e.g., 28800 = 8 hours
}
```

#### MarkPriceConfig
```solidity
struct MarkPriceConfig {
    uint32 ewmaWindowSeconds;     // e.g., 300 = 5 min
    uint128 maxPremiumBps;        // e.g., 500 = 5%
    uint128 dampingFactor;        // X18
    bool useMidPrice;
}
```

### Errors

| Error | Description |
|-------|-------------|
| `MarketNotFound()` | Market doesn't exist |
| `StalePrice()` | Prices too old |
| `InvalidPriceType()` | Invalid type |

### Functions

#### Core Prices

```solidity
function indexPrice(MarketId marketId) external view returns (uint128 priceX18);
function markPrice(MarketId marketId) external view returns (uint128 priceX18);
function lastPrice(MarketId marketId) external view returns (uint128 priceX18);
function midPrice(MarketId marketId) external view returns (uint128 priceX18);
function getPrice(MarketId marketId, PriceType priceType) external view returns (uint128 priceX18);
function getAllPrices(MarketId marketId) external view returns (MarketPrices memory prices);
function getMultipleMarketPrices(MarketId[] calldata marketIds) external view returns (MarketPrices[] memory prices);
```

#### Funding Rate

```solidity
function fundingRate(MarketId marketId) external view returns (int128 rateX18);
function getFundingParams(MarketId marketId) external view returns (FundingParams memory params);
function predictedFundingRate(MarketId marketId) external view returns (int128 predictedRateX18);
```

#### Trigger Prices

```solidity
function checkTrigger(MarketId marketId, uint128 triggerPxX18, bool isAbove, PriceType priceType) external view returns (bool triggered);
function liquidationPrice(address account, MarketId marketId) external view returns (uint128 liqPriceX18);
```

#### Premium/Basis

```solidity
function premium(MarketId marketId) external view returns (int128 premiumX18);
function basis(MarketId marketId) external view returns (int128 basisBps);
function premiumEWMA(MarketId marketId) external view returns (int128 ewmaX18);
```

#### Configuration

```solidity
function getMarkPriceConfig(MarketId marketId) external view returns (MarkPriceConfig memory config);
function fundingInterval(MarketId marketId) external view returns (uint32 intervalSecs);
function maxFundingRate(MarketId marketId) external view returns (uint128 maxRateX18);
```

### Events

```solidity
event MarkPriceUpdated(MarketId indexed marketId, uint128 markPriceX18, int128 premiumX18);
event FundingRateUpdated(MarketId indexed marketId, int128 fundingRateX18, uint64 timestamp);
event PriceTriggered(MarketId indexed marketId, PriceType priceType, uint128 triggerPriceX18);
```

---

## Price Trigger Rules

### Stop Orders
- Trigger on **MARK** price by default
- Long position: triggers when `mark <= trigger`
- Short position: triggers when `mark >= trigger`

### Take-Profit Orders
- Trigger on **MARK** price by default
- Long position: triggers when `mark >= trigger`
- Short position: triggers when `mark <= trigger`

### Liquidation
- Always uses **MARK** price
- Triggered when `marginRatio < 1.0`

### Funding
- Calculated from premium (`MARK - INDEX`)
- Capped at max funding rate
- Applied every funding interval (default: 8 hours)

### ADL (Auto-Deleverage)
- Triggered when insurance fund insufficient
- Uses **MARK** price for position valuation
