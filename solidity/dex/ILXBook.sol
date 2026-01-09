// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILXVault} from "./ILXVault.sol";

/// @title ILXBook (LP-9020)
/// @notice Central Limit Order Book (CLOB) matching engine for LX
/// @dev Precompile address: LP-9020 (0x0000000000000000000000000000000000009020)
/// @dev Matches orders and atomically settles via LXVault.applyFills()
/// @dev Hyperliquid-style execute() endpoint for HFT
interface ILXBook {
    // =========================================================================
    // Custom Types
    // =========================================================================

    /// @notice Market identifier (matches ILXVault.MarketId)
    type MarketId is uint32;

    /// @notice Order identifier (globally unique)
    type OrderId is uint64;

    /// @notice Client order ID (unique per user)
    type ClOrdId is uint128;

    /// @notice Order side
    enum Side {
        BUY,
        SELL
    }

    /// @notice Order type
    /// @dev Append-only policy: NEVER reorder existing values
    enum OrderType {
        LIMIT,              // 0: Standard limit order
        MARKET,             // 1: Market order (immediate-or-cancel)
        STOP_LIMIT,         // 2: Stop-limit (trigger on mark price)
        STOP_MARKET,        // 3: Stop-market (trigger on mark price)
        TAKE_PROFIT_LIMIT,  // 4: Take-profit limit (trigger on mark price)
        TAKE_PROFIT_MARKET, // 5: Take-profit market
        TRAILING_STOP,      // 6: Trailing stop (dynamic trigger)
        TWAP,               // 7: Time-weighted average price
        ICEBERG             // 8: Iceberg (partial display)
    }

    /// @notice Time-in-force
    /// @dev Append-only policy: NEVER reorder existing values
    enum TimeInForce {
        GTC,    // 0: Good-til-cancelled (default)
        IOC,    // 1: Immediate-or-cancel
        FOK,    // 2: Fill-or-kill
        GTD,    // 3: Good-til-date
        ALO     // 4: Add-liquidity-only (post-only, maker-only)
    }

    /// @notice Order status
    enum OrderStatus {
        NEW,            // Order accepted, not yet on book
        OPEN,           // Order on book, partially or unfilled
        FILLED,         // Completely filled
        CANCELLED,      // Cancelled by user
        REJECTED,       // Rejected (risk, validation, etc.)
        EXPIRED,        // Expired (GTD)
        TRIGGERED       // Stop/TP triggered, converted to limit/market
    }

    // =========================================================================
    // Structs - Order Entry
    // =========================================================================

    /// @notice Canonical order request structure
    /// @dev This is the SINGLE source of truth for order schema
    /// @dev FIX and JSON-RPC map directly to this struct
    struct OrderRequest {
        MarketId marketId;      // Market to trade
        Side side;              // BUY or SELL
        OrderType orderType;    // Order type
        uint128 pxX18;          // Limit price (X18), 0 for market orders
        uint128 szX18;          // Size in base asset (X18)
        TimeInForce tif;        // Time-in-force
        bool reduceOnly;        // Only reduce position, don't open/increase
        ClOrdId clOrdId;        // Client order ID (for idempotency)
        uint64 expireTime;      // Expiration timestamp (GTD only), 0 = no expiry
        uint128 triggerPxX18;   // Trigger price for stop/TP orders (X18)
        uint128 trailingDeltaX18; // Trailing delta for trailing stop (X18)
    }

    /// @notice Order on the book
    struct Order {
        OrderId orderId;        // Exchange-assigned order ID
        address owner;          // Order owner
        MarketId marketId;      // Market ID
        Side side;              // BUY or SELL
        OrderType orderType;    // Order type
        uint128 pxX18;          // Limit price (X18)
        uint128 origSzX18;      // Original size (X18)
        uint128 remainingSzX18; // Remaining size (X18)
        uint128 filledSzX18;    // Filled size (X18)
        TimeInForce tif;        // Time-in-force
        OrderStatus status;     // Current status
        uint64 timestamp;       // Order creation time
        ClOrdId clOrdId;        // Client order ID
        bool reduceOnly;        // Reduce-only flag
    }

    /// @notice Cancel request
    struct CancelRequest {
        OrderId orderId;        // Order to cancel (by exchange ID)
        ClOrdId clOrdId;        // OR by client order ID (if orderId is 0)
        MarketId marketId;      // Market (required if using clOrdId)
    }

    /// @notice Cancel-replace (amend) request
    struct AmendRequest {
        OrderId orderId;        // Order to amend
        uint128 newPxX18;       // New price (0 = keep current)
        uint128 newSzX18;       // New size (0 = keep current)
    }

    /// @notice Execution report (fill notification)
    struct ExecReport {
        OrderId orderId;        // Order ID
        ClOrdId clOrdId;        // Client order ID
        MarketId marketId;      // Market ID
        Side side;              // Order side
        uint128 pxX18;          // Execution price
        uint128 szX18;          // Execution size
        uint128 feeX18;         // Fee charged
        uint64 timestamp;       // Execution timestamp
        uint64 tradeId;         // Unique trade ID
        bool isMaker;           // True if maker, false if taker
        OrderStatus newStatus;  // New order status after fill
    }

    // =========================================================================
    // Errors
    // =========================================================================

    error InvalidMarket();              // Market doesn't exist or inactive
    error InvalidPrice();               // Price out of bounds or tick alignment
    error InvalidSize();                // Size too small or too large
    error InvalidOrderType();           // Order type not supported for market
    error InvalidTIF();                 // TIF not supported for order type
    error DuplicateClOrdId();           // Client order ID already used
    error OrderNotFound();              // Order doesn't exist
    error NotOrderOwner();              // Caller doesn't own order
    error RiskCheckFailed();            // Pre-trade risk check failed
    error PostOnlyFailed();             // Post-only order would take
    error ReduceOnlyFailed();           // Reduce-only would increase position
    error SelfTrade();                  // Would self-trade
    error MarketClosed();               // Market not accepting orders
    error RateLimited();                // Too many requests

    // =========================================================================
    // Events
    // =========================================================================

    event OrderAccepted(OrderId indexed orderId, address indexed owner, MarketId indexed marketId, ClOrdId clOrdId);
    event OrderRejected(address indexed owner, MarketId indexed marketId, ClOrdId clOrdId, string reason);
    event OrderFilled(OrderId indexed orderId, uint128 pxX18, uint128 szX18, bool isMaker);
    event OrderCancelled(OrderId indexed orderId, address indexed owner, uint128 remainingSzX18);
    event OrderExpired(OrderId indexed orderId, address indexed owner);
    event OrderTriggered(OrderId indexed orderId, uint128 triggerPxX18);
    event Trade(
        MarketId indexed marketId,
        uint64 indexed tradeId,
        OrderId makerOrderId,
        OrderId takerOrderId,
        uint128 pxX18,
        uint128 szX18,
        bool takerIsBuy
    );

    // =========================================================================
    // Core Trading Interface
    // =========================================================================

    /// @notice Submit a new order
    /// @param req Order request
    /// @return orderId Assigned order ID
    function placeOrder(OrderRequest calldata req) external returns (OrderId orderId);

    /// @notice Submit multiple orders atomically
    /// @param reqs Array of order requests
    /// @return orderIds Array of assigned order IDs
    function placeOrders(OrderRequest[] calldata reqs) external returns (OrderId[] memory orderIds);

    /// @notice Cancel an order
    /// @param req Cancel request
    /// @return success True if cancelled
    function cancelOrder(CancelRequest calldata req) external returns (bool success);

    /// @notice Cancel multiple orders atomically
    /// @param reqs Array of cancel requests
    /// @return results Array of success/failure
    function cancelOrders(CancelRequest[] calldata reqs) external returns (bool[] memory results);

    /// @notice Cancel all orders for caller in a market
    /// @param marketId Market to cancel in (0 = all markets)
    /// @return cancelled Number of orders cancelled
    function cancelAllOrders(MarketId marketId) external returns (uint32 cancelled);

    /// @notice Amend an existing order (cancel-replace)
    /// @param req Amend request
    /// @return newOrderId New order ID (may be same as original)
    function amendOrder(AmendRequest calldata req) external returns (OrderId newOrderId);

    // =========================================================================
    // Hyperliquid-Style Execute Endpoint
    // =========================================================================

    /// @notice Single entry point for all trading operations
    /// @dev Hyperliquid-compatible execute() pattern
    /// @dev Action types: "order", "cancel", "cancelByClOrdId", "cancelAll", "amend"
    /// @param action Action type string
    /// @param data ABI-encoded action data
    /// @return result ABI-encoded result
    function execute(string calldata action, bytes calldata data) external returns (bytes memory result);

    /// @notice Batch execute multiple actions atomically
    /// @param actions Array of action types
    /// @param datas Array of action data
    /// @return results Array of results
    function executeBatch(string[] calldata actions, bytes[] calldata datas) external returns (bytes[] memory results);

    // =========================================================================
    // Order Query Interface
    // =========================================================================

    /// @notice Get order by ID
    /// @param orderId Order ID
    /// @return order Order details
    function getOrder(OrderId orderId) external view returns (Order memory order);

    /// @notice Get order by client order ID
    /// @param owner Order owner
    /// @param marketId Market ID
    /// @param clOrdId Client order ID
    /// @return order Order details
    function getOrderByClOrdId(address owner, MarketId marketId, ClOrdId clOrdId) external view returns (Order memory order);

    /// @notice Get all open orders for a user in a market
    /// @param owner Order owner
    /// @param marketId Market ID (0 = all markets)
    /// @return orders Array of open orders
    function getOpenOrders(address owner, MarketId marketId) external view returns (Order[] memory orders);

    /// @notice Get order count for user
    /// @param owner Order owner
    /// @return count Number of open orders
    function orderCount(address owner) external view returns (uint32 count);

    // =========================================================================
    // Market Data Interface
    // =========================================================================

    /// @notice Get best bid/ask for a market
    /// @param marketId Market ID
    /// @return bidPxX18 Best bid price
    /// @return bidSzX18 Size at best bid
    /// @return askPxX18 Best ask price
    /// @return askSzX18 Size at best ask
    function getBBO(MarketId marketId) external view returns (
        uint128 bidPxX18,
        uint128 bidSzX18,
        uint128 askPxX18,
        uint128 askSzX18
    );

    /// @notice Get order book depth
    /// @param marketId Market ID
    /// @param levels Number of levels to return
    /// @return bidPrices Bid prices (descending)
    /// @return bidSizes Sizes at each bid
    /// @return askPrices Ask prices (ascending)
    /// @return askSizes Sizes at each ask
    function getDepth(MarketId marketId, uint8 levels) external view returns (
        uint128[] memory bidPrices,
        uint128[] memory bidSizes,
        uint128[] memory askPrices,
        uint128[] memory askSizes
    );

    /// @notice Get last trade price
    /// @param marketId Market ID
    /// @return pxX18 Last trade price
    /// @return timestamp Last trade timestamp
    function lastTrade(MarketId marketId) external view returns (uint128 pxX18, uint64 timestamp);

    // =========================================================================
    // Market Configuration
    // =========================================================================

    /// @notice Market specification
    struct MarketSpec {
        MarketId marketId;          // Market ID
        string symbol;              // Trading symbol (e.g., "BTC-PERP")
        address baseAsset;          // Base asset address
        address quoteAsset;         // Quote asset address
        uint128 tickSizeX18;        // Minimum price increment
        uint128 lotSizeX18;         // Minimum size increment
        uint128 minOrderSzX18;      // Minimum order size
        uint128 maxOrderSzX18;      // Maximum order size
        uint16 makerFeeBps;         // Maker fee (basis points, can be negative)
        uint16 takerFeeBps;         // Taker fee (basis points)
        bool active;                // Market is active
        bool perpMarket;            // True = perpetual, false = spot
    }

    /// @notice Get market specification
    /// @param marketId Market ID
    /// @return spec Market specification
    function getMarketSpec(MarketId marketId) external view returns (MarketSpec memory spec);

    /// @notice Get all active markets
    /// @return marketIds Array of active market IDs
    function getActiveMarkets() external view returns (MarketId[] memory marketIds);
}

// =========================================================================
// HFT Packed ABI Extension (ILXBookHFT)
// =========================================================================

/// @title ILXBookHFT
/// @notice High-frequency trading packed ABI for colo participants
/// @dev Optimized encoding for minimal calldata and decoding overhead
/// @dev Same semantics as ILXBook, just more efficient encoding
interface ILXBookHFT {
    /// @notice Place orders with packed encoding
    /// @dev Each order is 64 bytes: marketId(4) + side(1) + type(1) + tif(1) + flags(1) + 
    ///      px(16) + sz(16) + clOrdId(16) + triggerPx(8)
    /// @param packed Packed order data
    /// @return orderIds Assigned order IDs
    function placeOrdersPacked(bytes calldata packed) external returns (uint64[] memory orderIds);

    /// @notice Cancel orders with packed encoding
    /// @dev Each cancel is 8 bytes: orderId(8)
    /// @param packed Packed cancel data
    /// @return results Success flags
    function cancelOrdersPacked(bytes calldata packed) external returns (bytes memory results);

    /// @notice Cancel-replace with packed encoding
    /// @dev Each amend is 32 bytes: orderId(8) + newPx(16) + newSz(8)
    /// @param packed Packed amend data
    /// @return newOrderIds New order IDs
    function amendOrdersPacked(bytes calldata packed) external returns (uint64[] memory newOrderIds);
}
