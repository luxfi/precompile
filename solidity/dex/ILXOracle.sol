// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ILXOracle (LP-9011)
/// @notice Multi-source price aggregation oracle for LX
/// @dev Precompile address: LP-9011 (0x0000000000000000000000000000000000009011)
/// @dev Aggregates prices from multiple sources with robust index construction
/// @dev Used by LXVault for liquidation triggers and LXFeed for mark price calculation
interface ILXOracle {
    // =========================================================================
    // Custom Types
    // =========================================================================

    /// @notice Asset identifier
    type AssetId is uint32;

    /// @notice Price source identifier
    enum PriceSource {
        CEX_BINANCE,        // Binance spot
        CEX_COINBASE,       // Coinbase Pro
        CEX_OKX,            // OKX
        CEX_BYBIT,          // Bybit
        DEX_UNISWAP,        // Uniswap TWAP
        DEX_LXPOOL,         // LXPool (LP-9010)
        CHAINLINK,          // Chainlink oracle
        PYTH,               // Pyth network
        CUSTOM              // Custom oracle
    }

    /// @notice Price with metadata
    struct PriceData {
        uint128 priceX18;       // Price in USD (X18)
        uint64 timestamp;       // Price timestamp
        uint32 confidence;      // Confidence score (0-10000 = 0-100%)
        PriceSource source;     // Price source
        bool isValid;           // Price passes validity checks
    }

    /// @notice Aggregation method for multi-source prices
    enum AggMethod {
        MEDIAN,             // Median of all valid sources
        TWAP,               // Time-weighted average
        VWAP,               // Volume-weighted average
        TRIMMED_MEAN,       // Mean after removing outliers
        WEIGHTED_MEDIAN     // Weighted median by confidence
    }

    // =========================================================================
    // Structs
    // =========================================================================

    /// @notice Oracle configuration for an asset
    struct OracleConfig {
        AssetId assetId;            // Asset identifier
        string symbol;              // Asset symbol (e.g., "BTC")
        PriceSource[] sources;      // Enabled price sources
        AggMethod aggMethod;        // Aggregation method
        uint32 minSources;          // Minimum sources required
        uint32 maxStalenessSeconds; // Max age for valid price
        uint128 maxDeviationBps;    // Max deviation between sources (bps)
        bool active;                // Oracle is active
    }

    /// @notice Robust index construction parameters
    /// @dev Based on Hyperliquid's robust index methodology
    struct RobustIndexParams {
        uint32 windowSeconds;       // TWAP window (e.g., 900 = 15 min)
        uint32 minSamples;          // Minimum samples in window
        uint128 outlierThresholdBps;// Outlier threshold (e.g., 100 = 1%)
        bool trimOutliers;          // Remove outliers before aggregation
    }

    // =========================================================================
    // Errors
    // =========================================================================

    error AssetNotFound();          // Asset not configured
    error InsufficientSources();    // Not enough valid sources
    error StalePrice();             // All prices too old
    error SourceDeviationTooHigh(); // Source prices diverge too much
    error InvalidConfig();          // Invalid oracle configuration
    error Unauthorized();           // Caller not authorized

    // =========================================================================
    // Events
    // =========================================================================

    event PriceUpdated(AssetId indexed assetId, uint128 priceX18, uint64 timestamp, uint32 numSources);
    event SourcePriceReceived(AssetId indexed assetId, PriceSource indexed source, uint128 priceX18);
    event OracleConfigured(AssetId indexed assetId, string symbol);
    event PriceDeviation(AssetId indexed assetId, uint128 lowX18, uint128 highX18, uint128 deviationBps);

    // =========================================================================
    // Price Query Interface
    // =========================================================================

    /// @notice Get latest aggregated price for an asset
    /// @param assetId Asset identifier
    /// @return priceX18 Aggregated price (X18)
    /// @return timestamp Price timestamp
    function getPrice(AssetId assetId) external view returns (uint128 priceX18, uint64 timestamp);

    /// @notice Get price with full metadata
    /// @param assetId Asset identifier
    /// @return data Price data with metadata
    function getPriceData(AssetId assetId) external view returns (PriceData memory data);

    /// @notice Get prices for multiple assets
    /// @param assetIds Array of asset IDs
    /// @return prices Array of prices (X18)
    /// @return timestamps Array of timestamps
    function getPrices(AssetId[] calldata assetIds) external view returns (
        uint128[] memory prices,
        uint64[] memory timestamps
    );

    /// @notice Get price from a specific source
    /// @param assetId Asset identifier
    /// @param source Price source
    /// @return priceX18 Price from source (X18)
    /// @return timestamp Source timestamp
    function getSourcePrice(AssetId assetId, PriceSource source) external view returns (
        uint128 priceX18,
        uint64 timestamp
    );

    /// @notice Get all source prices for an asset
    /// @param assetId Asset identifier
    /// @return data Array of price data from all sources
    function getAllSourcePrices(AssetId assetId) external view returns (PriceData[] memory data);

    // =========================================================================
    // Index Price Interface (for perp markets)
    // =========================================================================

    /// @notice Get robust index price for a perp market
    /// @dev Uses robust index construction with outlier filtering
    /// @param assetId Asset identifier
    /// @return indexPriceX18 Robust index price (X18)
    function indexPrice(AssetId assetId) external view returns (uint128 indexPriceX18);

    /// @notice Get index price with calculation details
    /// @param assetId Asset identifier
    /// @return indexPriceX18 Robust index price (X18)
    /// @return sourcesUsed Number of sources used
    /// @return outliersTrimmed Number of outliers removed
    function indexPriceDetailed(AssetId assetId) external view returns (
        uint128 indexPriceX18,
        uint32 sourcesUsed,
        uint32 outliersTrimmed
    );

    // =========================================================================
    // TWAP Interface
    // =========================================================================

    /// @notice Get TWAP for an asset
    /// @param assetId Asset identifier
    /// @param windowSeconds TWAP window in seconds
    /// @return twapX18 Time-weighted average price (X18)
    function getTWAP(AssetId assetId, uint32 windowSeconds) external view returns (uint128 twapX18);

    // =========================================================================
    // Configuration Interface
    // =========================================================================

    /// @notice Get oracle configuration for an asset
    /// @param assetId Asset identifier
    /// @return config Oracle configuration
    function getConfig(AssetId assetId) external view returns (OracleConfig memory config);

    /// @notice Get robust index parameters
    /// @param assetId Asset identifier
    /// @return params Robust index parameters
    function getRobustParams(AssetId assetId) external view returns (RobustIndexParams memory params);

    /// @notice Get asset ID by symbol
    /// @param symbol Asset symbol (e.g., "BTC")
    /// @return assetId Asset identifier
    function getAssetId(string calldata symbol) external view returns (AssetId assetId);
}
