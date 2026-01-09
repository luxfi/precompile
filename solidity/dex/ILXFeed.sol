// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILXOracle} from "./ILXOracle.sol";

/// @title ILXFeed (LP-9040)
/// @notice Computed price feeds for LX - mark price, funding rate, liquidation triggers
/// @dev Precompile address: LP-9040 (0x0000000000000000000000000000000000009040)
/// @dev Computes derived prices from oracle data and order book state
/// @dev Mark price is used for: PnL, margin, liquidation triggers, TP/SL triggers
interface ILXFeed {
    // =========================================================================
    // Custom Types
    // =========================================================================

    /// @notice Market identifier (matches ILXVault.MarketId)
    type MarketId is uint32;

    /// @notice Price type selector
    enum PriceType {
        INDEX,      // Robust index price from LXOracle
        MARK,       // Mark price (index + premium)
        LAST,       // Last trade price from LXBook
        MID,        // Mid price from order book
        ORACLE      // Raw oracle price
    }

    // =========================================================================
    // Structs
    // =========================================================================

    /// @notice Complete price snapshot for a market
    struct MarketPrices {
        uint128 indexPriceX18;      // Robust index price
        uint128 markPriceX18;       // Mark price (index + premium adjustment)
        uint128 lastPriceX18;       // Last trade price
        uint128 midPriceX18;        // Order book mid price
        int128 premiumX18;          // Premium/discount to index (mark - index)
        int128 fundingRateX18;      // Current funding rate (X18 per hour)
        uint64 timestamp;           // Price timestamp
    }

    /// @notice Funding rate calculation parameters
    struct FundingParams {
        int128 premiumX18;          // Current premium
        int128 fundingRateX18;      // Calculated funding rate
        int128 cappedRateX18;       // Capped funding rate (after limits)
        uint64 nextFundingTime;     // Next funding settlement time
        uint32 fundingIntervalSecs; // Funding interval (e.g., 28800 = 8 hours)
    }

    /// @notice Mark price calculation config
    struct MarkPriceConfig {
        uint32 ewmaWindowSeconds;   // EWMA window for premium (e.g., 300 = 5 min)
        uint128 maxPremiumBps;      // Max premium deviation from index (e.g., 500 = 5%)
        uint128 dampingFactor;      // Premium damping factor (X18)
        bool useMidPrice;           // Include mid price in calculation
    }

    // =========================================================================
    // Errors
    // =========================================================================

    error MarketNotFound();         // Market doesn't exist
    error StalePrice();             // Prices too old
    error InvalidPriceType();       // Invalid price type requested

    // =========================================================================
    // Events
    // =========================================================================

    event MarkPriceUpdated(MarketId indexed marketId, uint128 markPriceX18, int128 premiumX18);
    event FundingRateUpdated(MarketId indexed marketId, int128 fundingRateX18, uint64 timestamp);
    event PriceTriggered(MarketId indexed marketId, PriceType priceType, uint128 triggerPriceX18);

    // =========================================================================
    // Core Price Interface
    // =========================================================================

    /// @notice Get index price for a market
    /// @dev Delegates to LXOracle with robust index construction
    /// @param marketId Market identifier
    /// @return priceX18 Index price (X18)
    function indexPrice(MarketId marketId) external view returns (uint128 priceX18);

    /// @notice Get mark price for a market
    /// @dev Mark = Index + Premium adjustment (EWMA smoothed)
    /// @dev This is the price used for PnL, margin, and liquidation
    /// @param marketId Market identifier
    /// @return priceX18 Mark price (X18)
    function markPrice(MarketId marketId) external view returns (uint128 priceX18);

    /// @notice Get last trade price for a market
    /// @dev From LXBook last matched trade
    /// @param marketId Market identifier
    /// @return priceX18 Last trade price (X18)
    function lastPrice(MarketId marketId) external view returns (uint128 priceX18);

    /// @notice Get mid price from order book
    /// @dev (Best bid + Best ask) / 2
    /// @param marketId Market identifier
    /// @return priceX18 Mid price (X18)
    function midPrice(MarketId marketId) external view returns (uint128 priceX18);

    /// @notice Get specific price type
    /// @param marketId Market identifier
    /// @param priceType Type of price to retrieve
    /// @return priceX18 Requested price (X18)
    function getPrice(MarketId marketId, PriceType priceType) external view returns (uint128 priceX18);

    /// @notice Get all prices for a market
    /// @param marketId Market identifier
    /// @return prices Complete price snapshot
    function getAllPrices(MarketId marketId) external view returns (MarketPrices memory prices);

    /// @notice Get prices for multiple markets
    /// @param marketIds Array of market IDs
    /// @return prices Array of price snapshots
    function getMultipleMarketPrices(MarketId[] calldata marketIds) external view returns (
        MarketPrices[] memory prices
    );

    // =========================================================================
    // Funding Rate Interface
    // =========================================================================

    /// @notice Get current funding rate for a market
    /// @dev Positive = longs pay shorts, Negative = shorts pay longs
    /// @param marketId Market identifier
    /// @return rateX18 Funding rate per hour (X18)
    function fundingRate(MarketId marketId) external view returns (int128 rateX18);

    /// @notice Get detailed funding parameters
    /// @param marketId Market identifier
    /// @return params Funding calculation parameters
    function getFundingParams(MarketId marketId) external view returns (FundingParams memory params);

    /// @notice Get predicted funding for next interval
    /// @param marketId Market identifier
    /// @return predictedRateX18 Predicted funding rate
    function predictedFundingRate(MarketId marketId) external view returns (int128 predictedRateX18);

    // =========================================================================
    // Trigger Price Interface (for Stop/TP orders)
    // =========================================================================

    /// @notice Check if a trigger price has been hit
    /// @dev Used by LXBook to trigger stop/TP orders
    /// @param marketId Market identifier
    /// @param triggerPxX18 Trigger price to check
    /// @param isAbove True if trigger is >= price, false if <=
    /// @param priceType Which price to use for trigger check
    /// @return triggered True if price condition met
    function checkTrigger(
        MarketId marketId,
        uint128 triggerPxX18,
        bool isAbove,
        PriceType priceType
    ) external view returns (bool triggered);

    /// @notice Get the price that would trigger liquidation for an account
    /// @dev Calculates liquidation price based on position and margin
    /// @param account Account address
    /// @param marketId Market identifier
    /// @return liqPriceX18 Liquidation price (0 if no position)
    function liquidationPrice(address account, MarketId marketId) external view returns (uint128 liqPriceX18);

    // =========================================================================
    // Premium/Basis Interface
    // =========================================================================

    /// @notice Get current premium (mark - index)
    /// @param marketId Market identifier
    /// @return premiumX18 Premium in absolute terms (X18)
    function premium(MarketId marketId) external view returns (int128 premiumX18);

    /// @notice Get current basis (premium as percentage of index)
    /// @param marketId Market identifier
    /// @return basisBps Basis in basis points (e.g., 50 = 0.5%)
    function basis(MarketId marketId) external view returns (int128 basisBps);

    /// @notice Get premium EWMA (smoothed premium)
    /// @param marketId Market identifier
    /// @return ewmaX18 EWMA of premium (X18)
    function premiumEWMA(MarketId marketId) external view returns (int128 ewmaX18);

    // =========================================================================
    // Configuration Interface
    // =========================================================================

    /// @notice Get mark price configuration
    /// @param marketId Market identifier
    /// @return config Mark price configuration
    function getMarkPriceConfig(MarketId marketId) external view returns (MarkPriceConfig memory config);

    /// @notice Get funding interval for a market
    /// @param marketId Market identifier
    /// @return intervalSecs Funding interval in seconds
    function fundingInterval(MarketId marketId) external view returns (uint32 intervalSecs);

    /// @notice Get max funding rate cap
    /// @param marketId Market identifier
    /// @return maxRateX18 Max funding rate per interval (X18)
    function maxFundingRate(MarketId marketId) external view returns (uint128 maxRateX18);
}

// =========================================================================
// Price Trigger Rules (Documentation)
// =========================================================================

// STOP_LIMIT / STOP_MARKET orders:
//   - Trigger on MARK price by default
//   - Long position: triggers when mark <= trigger price
//   - Short position: triggers when mark >= trigger price
//
// TAKE_PROFIT_LIMIT / TAKE_PROFIT_MARKET orders:
//   - Trigger on MARK price by default
//   - Long position: triggers when mark >= trigger price
//   - Short position: triggers when mark <= trigger price
//
// LIQUIDATION:
//   - Always uses MARK price
//   - Triggered when margin ratio < 1.0 (maintenance margin)
//
// FUNDING:
//   - Calculated from premium (MARK - INDEX)
//   - Capped at max funding rate
//   - Applied every funding interval (default: 8 hours)
//
// ADL (Auto-Deleverage):
//   - Triggered when insurance fund insufficient after liquidation
//   - Uses MARK price for position valuation
