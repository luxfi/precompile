# FIX Protocol Mapping for LXDEX

FIX 4.4 protocol mapping to canonical LXDEX OrderRequest and ExecReport structures.

## NewOrderSingle (MsgType=D) → OrderRequest

| FIX Tag | FIX Name | Type | OrderRequest Field | Notes |
|---------|----------|------|-------------------|-------|
| 1 | Account | String | (session) | Derived from FIX session |
| 11 | ClOrdId | String | `clOrdId` | Client order ID (unique per account) |
| 21 | HandlInst | Char | - | Always "1" (automated) |
| 38 | OrderQty | Qty | `szX18` | Convert to X18 (multiply by 1e18) |
| 40 | OrdType | Char | `orderType` | See OrdType mapping below |
| 44 | Price | Price | `pxX18` | Convert to X18 |
| 54 | Side | Char | `side` | "1"=BUY, "2"=SELL |
| 55 | Symbol | String | `marketId` | Market symbol → MarketId lookup |
| 59 | TimeInForce | Char | `tif` | See TimeInForce mapping |
| 60 | TransactTime | UTCTimestamp | - | Ignored (use server time) |
| 99 | StopPx | Price | `triggerPxX18` | For Stop/TP orders |
| 18 | ExecInst | MultipleChar | `reduceOnly` | "r"=reduce-only |
| 126 | ExpireTime | UTCTimestamp | `expireTime` | For GTD orders |
| 7928 | TrailingDelta | Price | `trailingDeltaX18` | Custom tag for trailing stop |

### OrdType Mapping (Tag 40)

| FIX Value | FIX Name | OrderRequest.orderType |
|-----------|----------|----------------------|
| 1 | Market | MARKET (1) |
| 2 | Limit | LIMIT (0) |
| 3 | Stop | STOP_MARKET (3) |
| 4 | StopLimit | STOP_LIMIT (2) |
| J | MarketIfTouched | TAKE_PROFIT_MARKET (5) |
| K | LimitIfTouched | TAKE_PROFIT_LIMIT (4) |
| P | Pegged | TRAILING_STOP (6) |

### TimeInForce Mapping (Tag 59)

| FIX Value | FIX Name | OrderRequest.tif |
|-----------|----------|-----------------|
| 0 | Day | GTC (0) - treated as GTC |
| 1 | GoodTillCancel | GTC (0) |
| 3 | ImmediateOrCancel | IOC (1) |
| 4 | FillOrKill | FOK (2) |
| 6 | GoodTillDate | GTD (3) |
| B | GoodTillCrossing | ALO (4) - post-only |

### Side Mapping (Tag 54)

| FIX Value | FIX Name | OrderRequest.side |
|-----------|----------|------------------|
| 1 | Buy | BUY (0) |
| 2 | Sell | SELL (1) |

### ExecInst Flags (Tag 18)

| FIX Value | Meaning | OrderRequest Field |
|-----------|---------|-------------------|
| r | ReduceOnly | `reduceOnly = true` |
| 6 | ParticipateDoNotInitiate | `tif = ALO` (post-only) |

---

## ExecutionReport (MsgType=8) ← ExecReport

| FIX Tag | FIX Name | Type | ExecReport Field | Notes |
|---------|----------|------|-----------------|-------|
| 6 | AvgPx | Price | (calculated) | Average fill price |
| 11 | ClOrdId | String | `clOrdId` | Client order ID |
| 14 | CumQty | Qty | (calculated) | Cumulative filled |
| 17 | ExecID | String | `tradeId` | Unique execution ID |
| 31 | LastPx | Price | `pxX18` | Last fill price (X18→decimal) |
| 32 | LastQty | Qty | `szX18` | Last fill size (X18→decimal) |
| 37 | OrderID | String | `orderId` | Exchange order ID |
| 38 | OrderQty | Qty | - | Original order quantity |
| 39 | OrdStatus | Char | `newStatus` | See OrdStatus mapping |
| 44 | Price | Price | - | Limit price |
| 54 | Side | Char | `side` | "1"=BUY, "2"=SELL |
| 55 | Symbol | String | `marketId` | Market symbol |
| 60 | TransactTime | UTCTimestamp | `timestamp` | Execution time |
| 150 | ExecType | Char | - | See ExecType mapping |
| 151 | LeavesQty | Qty | (calculated) | Remaining quantity |
| 12 | Commission | Amt | `feeX18` | Fee amount |
| 13 | CommType | Char | - | "3" (absolute) |
| 851 | LastLiquidityInd | Int | `isMaker` | 1=added, 2=removed |

### OrdStatus Mapping (Tag 39)

| FIX Value | FIX Name | ExecReport.newStatus |
|-----------|----------|---------------------|
| 0 | New | NEW (0) |
| 1 | PartiallyFilled | OPEN (1) |
| 2 | Filled | FILLED (2) |
| 4 | Canceled | CANCELLED (3) |
| 8 | Rejected | REJECTED (4) |
| C | Expired | EXPIRED (5) |
| A | PendingNew | NEW (0) |
| 6 | PendingCancel | OPEN (1) |

### ExecType Mapping (Tag 150)

| FIX Value | FIX Name | Meaning |
|-----------|----------|---------|
| 0 | New | Order accepted |
| F | Trade | Fill occurred |
| 4 | Canceled | Order canceled |
| 8 | Rejected | Order rejected |
| C | Expired | Order expired |
| D | Restated | Order amended |

### LastLiquidityInd Mapping (Tag 851)

| FIX Value | Meaning | ExecReport.isMaker |
|-----------|---------|-------------------|
| 1 | AddedLiquidity | `true` (maker) |
| 2 | RemovedLiquidity | `false` (taker) |

---

## OrderCancelRequest (MsgType=F) → CancelRequest

| FIX Tag | FIX Name | Type | CancelRequest Field |
|---------|----------|------|---------------------|
| 11 | ClOrdId | String | `clOrdId` |
| 37 | OrderID | String | `orderId` |
| 41 | OrigClOrdId | String | `clOrdId` (original) |
| 55 | Symbol | String | `marketId` |

---

## OrderCancelReplaceRequest (MsgType=G) → AmendRequest

| FIX Tag | FIX Name | Type | AmendRequest Field |
|---------|----------|------|-------------------|
| 11 | ClOrdId | String | (new client ID) |
| 37 | OrderID | String | `orderId` |
| 38 | OrderQty | Qty | `newSzX18` |
| 41 | OrigClOrdId | String | (original client ID) |
| 44 | Price | Price | `newPxX18` |

---

## Session Messages

### Logon (MsgType=A)

| Tag | Name | Required |
|-----|------|----------|
| 98 | EncryptMethod | 0 (none) |
| 108 | HeartBtInt | 30 |
| 553 | Username | API key |
| 554 | Password | API secret signature |

### Heartbeat (MsgType=0)

| Tag | Name | Required |
|-----|------|----------|
| 112 | TestReqID | If responding to TestRequest |

### TestRequest (MsgType=1)

| Tag | Name | Required |
|-----|------|----------|
| 112 | TestReqID | Yes |

---

## Drop Copy (MsgType=AQ, AR)

Drop copy feed provides real-time execution reports without order entry capability.

### TradeCaptureReport (MsgType=AE)

| Tag | Name | Type | Description |
|-----|------|------|-------------|
| 571 | TradeReportID | String | Unique trade ID |
| 487 | TradeReportTransType | Int | 0=New |
| 55 | Symbol | String | Market symbol |
| 32 | LastQty | Qty | Trade size |
| 31 | LastPx | Price | Trade price |
| 75 | TradeDate | LocalMktDate | Trade date |
| 60 | TransactTime | UTCTimestamp | Trade time |

---

## Example Messages

### NewOrderSingle (Limit Buy)

```
8=FIX.4.4|9=148|35=D|49=CLIENT|56=LXDEX|34=2|52=20260105-12:00:00.000|
11=order123|21=1|38=1.5|40=2|44=50000.00|54=1|55=BTC-PERP|59=1|10=XXX|
```

### ExecutionReport (Fill)

```
8=FIX.4.4|9=200|35=8|49=LXDEX|56=CLIENT|34=3|52=20260105-12:00:00.001|
37=ex123456|11=order123|17=trade789|150=F|39=2|55=BTC-PERP|54=1|
38=1.5|44=50000.00|32=1.5|31=50000.00|14=1.5|151=0|6=50000.00|
12=0.00075|13=3|851=2|60=20260105-12:00:00.001|10=XXX|
```

---

## Notes

1. **Price Precision**: All prices converted to/from X18 (18 decimal places)
2. **Quantity Precision**: All quantities converted to/from X18
3. **Timestamps**: FIX uses UTCTimestamp format; convert to Unix timestamp for on-chain
4. **ClOrdId Uniqueness**: Must be unique per account, per day
5. **Session Persistence**: FIX sessions maintain sequence numbers across reconnects

---

*Last Updated: 2026-01-05*
