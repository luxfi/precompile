# LX Architecture

LX is a native EVM DEX combining Uniswap v4-style AMM with Hyperliquid-class CLOB in a unified, permissionless protocol.

## Overview

```
+------------------+     +------------------+     +------------------+
|   Protocol Layer |     |   Gateway Layer  |     | Operations Layer |
|   (Canonical)    |     |   (Low Latency)  |     |   (HFT/Colo)     |
+------------------+     +------------------+     +------------------+
| LXPool (LP-9010) |<--->| JSON-RPC API     |<--->| Colo Connectivity|
| LXBook (LP-9020) |     | FIX Protocol     |     | Session Mgmt     |
| LXVault(LP-9030) |     | WebSocket Streams|     | Risk Controls    |
| LXOracle/Feed    |     | REST Endpoints   |     | Pre-trade Checks |
+------------------+     +------------------+     +------------------+
```

## Layer A: Protocol Layer (Canonical)

All settlement and state changes happen on-chain via EVM precompiles.

### Address Registry (LP-9xxx)

| Component | LP | Address | Description |
|-----------|-----|----------------------------------------------|-------------|
| LXPool | LP-9010 | `0x0000000000000000000000000000000000009010` | v4 PoolManager-compatible AMM |
| LXOracle | LP-9011 | `0x0000000000000000000000000000000000009011` | Multi-source price aggregation |
| LXRouter | LP-9012 | `0x0000000000000000000000000000000000009012` | Optimized swap routing |
| LXHooks | LP-9013 | `0x0000000000000000000000000000000000009013` | Hook contract registry |
| LXFlash | LP-9014 | `0x0000000000000000000000000000000000009014` | Flash loan facility |
| LXBook | LP-9020 | `0x0000000000000000000000000000000000009020` | CLOB matching engine |
| LXVault | LP-9030 | `0x0000000000000000000000000000000000009030` | Clearinghouse (margin/positions) |
| LXFeed | LP-9040 | `0x0000000000000000000000000000000000009040` | Computed prices (mark/index) |
| LXLend | LP-9050 | `0x0000000000000000000000000000000000009050` | Lending pool (Aave-style) |
| LXLiquid | LP-9060 | `0x0000000000000000000000000000000000009060` | Self-repaying loans |
| Liquidator | LP-9070 | `0x0000000000000000000000000000000000009070` | Liquidation engine |
| LiquidFX | LP-9080 | `0x0000000000000000000000000000000000009080` | Transmuter |

### Settlement Flow

```
User Order → LXBook (match) → LXVault.applyFills() → State Update
                ↓
         LXFeed.markPrice() ← LXOracle.indexPrice()
                ↓
         Margin/Risk Checks
```

**Pattern 1 (Recommended)**: LXBook calls LXVault
- `LXBook.placeOrder()` matches and produces `Fill[]`
- LXBook atomically calls `LXVault.applyFills(Fill[])`
- LXVault validates risk and updates positions

### Core Interfaces

- **ILXPool.sol** (LP-9010): Uniswap v4-compatible PoolManager
- **ILXBook.sol** (LP-9020): CLOB with execute() endpoint
- **ILXVault.sol** (LP-9030): Clearinghouse for margin and positions
- **ILXOracle.sol** (LP-9011): Multi-source price aggregation
- **ILXFeed.sol** (LP-9040): Mark price, funding rate computation

---

## Layer B: Gateway Layer (Low Latency)

Off-chain interfaces for order entry and market data streaming.

### JSON-RPC API

```
POST /rpc
{
  "jsonrpc": "2.0",
  "method": "lx_placeOrder",
  "params": { /* OrderRequest */ },
  "id": 1
}
```

| Method | Description |
|--------|-------------|
| `lx_placeOrder` | Submit new order |
| `lx_cancelOrder` | Cancel order by ID |
| `lx_cancelAll` | Cancel all orders |
| `lx_amendOrder` | Modify existing order |
| `lx_getOpenOrders` | List open orders |
| `lx_getPositions` | Get account positions |
| `lx_getAccountState` | Full account state |
| `lx_getBBO` | Best bid/offer |
| `lx_getDepth` | Order book depth |

### WebSocket Streams

```
ws://api.lux.exchange/ws

// Subscribe to market data
{"op": "subscribe", "channel": "trades", "market": "BTC-PERP"}
{"op": "subscribe", "channel": "orderbook", "market": "BTC-PERP", "depth": 20}
{"op": "subscribe", "channel": "ticker", "market": "BTC-PERP"}

// Subscribe to account updates
{"op": "subscribe", "channel": "orders", "account": "0x..."}
{"op": "subscribe", "channel": "fills", "account": "0x..."}
{"op": "subscribe", "channel": "positions", "account": "0x..."}
```

### FIX Protocol (4.4)

| MsgType | Name | Description |
|---------|------|-------------|
| D | NewOrderSingle | Place new order |
| F | OrderCancelRequest | Cancel order |
| G | OrderCancelReplaceRequest | Amend order |
| 8 | ExecutionReport | Fill/status notification |
| H | OrderStatusRequest | Query order status |
| AF | OrderMassStatusRequest | Query all orders |

**FIX Tag Mapping to OrderRequest**:

| FIX Tag | Field | OrderRequest Field |
|---------|-------|-------------------|
| 1 | Account | (derived from session) |
| 11 | ClOrdId | clOrdId |
| 38 | OrderQty | szX18 |
| 40 | OrdType | orderType |
| 44 | Price | pxX18 |
| 54 | Side | side |
| 55 | Symbol | marketId |
| 59 | TimeInForce | tif |
| 99 | StopPx | triggerPxX18 |
| 18 | ExecInst | reduceOnly flag |

---

## Layer C: Operations Layer (HFT/Colo)

### Colocation

- **Location**: Same rack as validator nodes
- **Latency**: <100μs to matching engine
- **Connectivity**: Direct fiber, dedicated NICs
- **Sessions**: Authenticated FIX sessions per account

### Risk Controls

| Control | Description |
|---------|-------------|
| Pre-trade margin | Orders validated against available margin |
| Position limits | Per-market and per-account limits |
| Rate limits | Orders/second per session |
| Kill switch | Emergency session termination |
| Self-trade prevention | STP modes: cancel-newest, cancel-oldest |

### Permissionless vs Enrolled

| Feature | Permissionless | Enrolled (Colo) |
|---------|---------------|-----------------|
| Order placement | Yes | Yes |
| FIX access | No | Yes |
| Colo connectivity | No | Yes |
| HFT packed ABI | Yes | Yes |
| Market making | Yes | Yes (rebates) |
| KYC required | No | Optional |

**HFT Packed ABI** (ILXBookHFT.sol):
- 64-byte packed order encoding
- Batch operations in single call
- Minimal decoding overhead
- Same semantics as standard ABI

---

## Trading Semantics

### Order Types

| Type | Trigger | Execution |
|------|---------|-----------|
| LIMIT | Immediate | Resting on book until filled/cancelled |
| MARKET | Immediate | IOC execution at best available |
| STOP_LIMIT | Mark price crosses trigger | Becomes LIMIT order |
| STOP_MARKET | Mark price crosses trigger | Becomes MARKET order |
| TAKE_PROFIT_LIMIT | Mark price crosses trigger | Becomes LIMIT order |
| TAKE_PROFIT_MARKET | Mark price crosses trigger | Becomes MARKET order |
| TRAILING_STOP | Dynamic trigger tracks price | Becomes MARKET on trigger |
| TWAP | Time intervals | Splits into child orders |
| ICEBERG | Display qty exhausted | Refreshes visible quantity |

### Time-in-Force

| TIF | Behavior |
|-----|----------|
| GTC | Good-til-cancelled (default) |
| IOC | Immediate-or-cancel (partial fills OK) |
| FOK | Fill-or-kill (full fill or reject) |
| GTD | Good-til-date (expires at timestamp) |
| ALO | Add-liquidity-only (post-only, maker-only) |

### Trigger Price Rules

- **STOP orders**: Trigger on MARK price
  - Long position stop: triggers when mark ≤ trigger
  - Short position stop: triggers when mark ≥ trigger
- **TAKE_PROFIT orders**: Trigger on MARK price
  - Long TP: triggers when mark ≥ trigger
  - Short TP: triggers when mark ≤ trigger

---

## Margin & Risk

### Margin Modes

| Mode | Description |
|------|-------------|
| ISOLATED | Each position has separate margin |
| CROSS | All positions share account margin |
| PORTFOLIO | Cross-asset margin with netting |

### Margin Calculations

```
Initial Margin = Σ(position_notional × initial_margin_rate)
Maintenance Margin = Σ(position_notional × maintenance_margin_rate)

Account Equity = Total Collateral + Unrealized PnL
Margin Ratio = Account Equity / Maintenance Margin

Liquidatable when Margin Ratio < 1.0
```

### Margin Tiers (Example: BTC-PERP)

| Position Size | Max Leverage | Initial Margin | Maintenance |
|---------------|--------------|----------------|-------------|
| 0 - 100 BTC | 50x | 2.0% | 1.0% |
| 100 - 500 BTC | 25x | 4.0% | 2.0% |
| 500 - 1000 BTC | 10x | 10.0% | 5.0% |
| >1000 BTC | 5x | 20.0% | 10.0% |

---

## Liquidation Flow

```
1. Account falls below maintenance margin
   ↓
2. Liquidation order placed at bankruptcy price
   ↓
3. Matched against order book
   ↓
4. Liquidation fee to insurance fund
   ↓
5. If shortfall: insurance fund covers
   ↓
6. If insurance insufficient: ADL triggered
```

### Auto-Deleverage (ADL)

When insurance fund cannot cover losses:
1. Rank profitable traders by PnL + leverage score
2. Force-close positions against most profitable counterparties
3. ADL fills use mark price (no slippage)
4. Affected traders notified via ADL event

### Insurance Fund

- Funded by liquidation penalties
- Covers socialized losses before ADL
- Separate fund per market
- Transparent balance via `LXVault.insuranceFundBalance()`

---

## Funding Rate

Perpetual contracts use funding to anchor perp price to index.

### Calculation

```
Premium = (Mark Price - Index Price) / Index Price
Funding Rate = clamp(Premium × Interest Rate, -maxRate, +maxRate)

// Applied every 8 hours
Funding Payment = Position Size × Funding Rate
```

### Rules

- **Positive rate**: Longs pay shorts (perp > index)
- **Negative rate**: Shorts pay longs (perp < index)
- **Interval**: Every 8 hours (configurable per market)
- **Cap**: ±0.05% per interval (configurable)

---

## Oracle Architecture

### Robust Index Construction

Following Hyperliquid methodology:
1. Collect prices from multiple CEX/DEX sources
2. Remove outliers (>1% deviation from median)
3. Compute TWAP over 15-minute window
4. Require minimum 3 valid sources

### Mark Price

```
Mark = Index + EWMA(Premium)

// Premium smoothed with 5-minute EWMA
// Capped at ±5% deviation from index
```

### Price Sources

| Source | Weight | Latency |
|--------|--------|---------|
| Binance | 25% | <100ms |
| Coinbase | 25% | <100ms |
| OKX | 20% | <100ms |
| Bybit | 15% | <100ms |
| LXPool | 15% | Native |

---

## Canonical Schemas

### OrderRequest (Solidity)

```solidity
struct OrderRequest {
    MarketId marketId;      // uint32
    Side side;              // enum: BUY=0, SELL=1
    OrderType orderType;    // enum: 0-8
    uint128 pxX18;          // Limit price (18 decimals)
    uint128 szX18;          // Size (18 decimals)
    TimeInForce tif;        // enum: 0-4
    bool reduceOnly;        // Reduce-only flag
    ClOrdId clOrdId;        // uint128 client order ID
    uint64 expireTime;      // GTD expiration (0 = no expiry)
    uint128 triggerPxX18;   // Stop/TP trigger price
    uint128 trailingDeltaX18; // Trailing stop delta
}
```

### Fill (Settlement)

```solidity
struct Fill {
    MarketId marketId;      // uint32
    address maker;          // Maker address
    address taker;          // Taker address
    bool takerIsBuy;        // Taker direction
    uint128 pxX18;          // Execution price
    uint128 szX18;          // Execution size
    uint128 makerFeeX18;    // Maker fee (can be negative)
    uint128 takerFeeX18;    // Taker fee
    uint8 flags;            // LIQUIDATION=0x01, REDUCE_ONLY=0x02, ADL=0x04
}
```

### JSON Schema

```json
{
  "OrderRequest": {
    "marketId": "uint32",
    "side": "BUY | SELL",
    "orderType": "LIMIT | MARKET | STOP_LIMIT | ...",
    "price": "string (decimal, 18 places)",
    "size": "string (decimal, 18 places)",
    "timeInForce": "GTC | IOC | FOK | GTD | ALO",
    "reduceOnly": "boolean",
    "clOrdId": "string (uint128 as hex or decimal)",
    "expireTime": "uint64 (unix timestamp, 0 = none)",
    "triggerPrice": "string (decimal, optional)",
    "trailingDelta": "string (decimal, optional)"
  }
}
```

---

## Enum Stability Policy

**APPEND-ONLY**: Existing enum values MUST NOT be reordered or removed.

```solidity
// CORRECT: Append new values
enum OrderType {
    LIMIT,      // 0 - never change
    MARKET,     // 1 - never change
    // ... existing values ...
    NEW_TYPE    // N - append at end
}

// WRONG: Never reorder or remove
enum OrderType {
    MARKET,     // DON'T move MARKET to 0
    LIMIT,      // DON'T move LIMIT to 1
}
```

---

## Performance

### Matching Engine (M1 Max benchmarks)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Swap (AMM) | 2.26μs | 443K ops/sec |
| Place Order | 1.5μs | 667K ops/sec |
| Cancel Order | 0.8μs | 1.25M ops/sec |
| Match + Settle | 3.2μs | 312K ops/sec |

### Gateway Latency

| Path | Latency |
|------|---------|
| JSON-RPC → Chain | <1ms |
| FIX → Chain | <500μs |
| Colo → Chain | <100μs |

---

## Files Reference

```
precompile/solidity/dex/
├── IPoolManager.sol    # LP-9010 LXPool (v4 PoolManager)
├── ILXBook.sol         # LP-9020 CLOB matching engine
├── ILXVault.sol        # LP-9030 Clearinghouse
├── ILXOracle.sol       # LP-9011 Price aggregation
├── ILXFeed.sol         # LP-9040 Mark/funding prices
├── IHooks.sol          # LP-9013 Hook interface
├── Types.sol           # Shared types
├── IERC20Minimal.sol   # ERC20 interface
└── LX.md            # This document
```

---

*Last Updated: 2026-01-05*
*Version: 1.0.0*
