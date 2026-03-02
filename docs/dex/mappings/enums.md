# LXDEX Enum Definitions

**APPEND-ONLY POLICY**: Existing enum values MUST NOT be reordered or removed. New values may only be appended at the end.

## Side

| Value | Name | Description |
|-------|------|-------------|
| 0 | BUY | Buy order (go long) |
| 1 | SELL | Sell order (go short) |

## OrderType

| Value | Name | FIX OrdType | Description |
|-------|------|-------------|-------------|
| 0 | LIMIT | 2 | Standard limit order |
| 1 | MARKET | 1 | Market order (IOC execution) |
| 2 | STOP_LIMIT | 4 | Stop-limit (triggers on mark) |
| 3 | STOP_MARKET | 3 | Stop-market (triggers on mark) |
| 4 | TAKE_PROFIT_LIMIT | K | Take-profit limit |
| 5 | TAKE_PROFIT_MARKET | J | Take-profit market |
| 6 | TRAILING_STOP | P | Trailing stop (dynamic trigger) |
| 7 | TWAP | - | Time-weighted average price |
| 8 | ICEBERG | - | Iceberg (partial display) |

## TimeInForce

| Value | Name | FIX TIF | Description |
|-------|------|---------|-------------|
| 0 | GTC | 1 | Good-til-cancelled (default) |
| 1 | IOC | 3 | Immediate-or-cancel |
| 2 | FOK | 4 | Fill-or-kill |
| 3 | GTD | 6 | Good-til-date |
| 4 | ALO | B | Add-liquidity-only (post-only) |

## OrderStatus

| Value | Name | FIX OrdStatus | Description |
|-------|------|---------------|-------------|
| 0 | NEW | 0 | Order accepted, not yet on book |
| 1 | OPEN | 1 | Order on book, partially/unfilled |
| 2 | FILLED | 2 | Completely filled |
| 3 | CANCELLED | 4 | Cancelled by user |
| 4 | REJECTED | 8 | Rejected (risk, validation) |
| 5 | EXPIRED | C | Expired (GTD) |
| 6 | TRIGGERED | - | Stop/TP triggered |

## MarginMode

| Value | Name | Description |
|-------|------|-------------|
| 0 | ISOLATED | Each position has separate margin |
| 1 | CROSS | All positions share account margin |
| 2 | PORTFOLIO | Cross-asset margin with netting |

## PositionSide

| Value | Name | Description |
|-------|------|-------------|
| 0 | LONG | Long position (bought) |
| 1 | SHORT | Short position (sold) |

## PriceSource (LXOracle)

| Value | Name | Description |
|-------|------|-------------|
| 0 | CEX_BINANCE | Binance spot price |
| 1 | CEX_COINBASE | Coinbase Pro price |
| 2 | CEX_OKX | OKX price |
| 3 | CEX_BYBIT | Bybit price |
| 4 | DEX_UNISWAP | Uniswap TWAP |
| 5 | DEX_LXPOOL | LXPool (native) |
| 6 | CHAINLINK | Chainlink oracle |
| 7 | PYTH | Pyth network |
| 8 | CUSTOM | Custom oracle |

## AggMethod (LXOracle)

| Value | Name | Description |
|-------|------|-------------|
| 0 | MEDIAN | Median of all valid sources |
| 1 | TWAP | Time-weighted average |
| 2 | VWAP | Volume-weighted average |
| 3 | TRIMMED_MEAN | Mean after removing outliers |
| 4 | WEIGHTED_MEDIAN | Weighted median by confidence |

## PriceType (LXFeed)

| Value | Name | Description |
|-------|------|-------------|
| 0 | INDEX | Robust index price from LXOracle |
| 1 | MARK | Mark price (index + premium) |
| 2 | LAST | Last trade price from LXBook |
| 3 | MID | Mid price from order book |
| 4 | ORACLE | Raw oracle price |

## Fill Flags (bitmask)

| Bit | Value | Name | Description |
|-----|-------|------|-------------|
| 0 | 0x01 | LIQUIDATION | Fill is from liquidation |
| 1 | 0x02 | REDUCE_ONLY | Fill is reduce-only |
| 2 | 0x04 | ADL | Fill is from auto-deleverage |
| 3 | 0x08 | MARKET | Fill is from market order |
| 4 | 0x10 | POST_ONLY_FAIL | Post-only violation |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-05 | Initial enum definitions |

---

## Stability Guarantees

1. **Numeric values are immutable**: Once assigned, a numeric value will never change meaning
2. **Names may be aliased**: Old names may be aliased but never removed
3. **New values append only**: New enum values are always added at the end
4. **Deprecation**: Values may be deprecated but will remain valid indefinitely

### Example: Adding New Order Type

```solidity
// CORRECT: Append at end
enum OrderType {
    LIMIT,              // 0 - immutable
    MARKET,             // 1 - immutable
    STOP_LIMIT,         // 2 - immutable
    STOP_MARKET,        // 3 - immutable
    TAKE_PROFIT_LIMIT,  // 4 - immutable
    TAKE_PROFIT_MARKET, // 5 - immutable
    TRAILING_STOP,      // 6 - immutable
    TWAP,               // 7 - immutable
    ICEBERG,            // 8 - immutable
    NEW_ORDER_TYPE      // 9 - NEW: append only
}

// WRONG: Never reorder
enum OrderType {
    NEW_ORDER_TYPE,     // DON'T insert at position 0
    LIMIT,              // Values would shift
    // ...
}
```

---

*Last Updated: 2026-01-05*
