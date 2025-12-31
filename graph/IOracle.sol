// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries Inc. All rights reserved.

pragma solidity ^0.8.24;

import "./IGraphQL.sol";

/**
 * @title IOracle
 * @notice Unified Oracle interface for AMM and price feed queries
 * @dev Uses G-Chain GraphQL precompile at 0x0500
 *
 * This provides a clean interface for:
 * - Token price feeds (USD, ETH, LUX denominated)
 * - Pool data (liquidity, fees, volume)
 * - Swap quotes and routing
 * - LP position values
 */
interface IOracle {
    // =========================================================================
    // Price Feed Queries
    // =========================================================================

    /**
     * @notice Get ETH price in USD (18 decimals)
     */
    function getETHPrice() external view returns (uint256 priceUSD);

    /**
     * @notice Get LUX price in USD (18 decimals)
     */
    function getLUXPrice() external view returns (uint256 priceUSD);

    /**
     * @notice Get token price in USD (18 decimals)
     * @param token Token address
     */
    function getTokenPrice(address token) external view returns (uint256 priceUSD);

    /**
     * @notice Get token price in ETH (18 decimals)
     * @param token Token address
     */
    function getTokenPriceETH(address token) external view returns (uint256 priceETH);

    /**
     * @notice Get TWAP price for a pool over specified hours
     * @param pool Pool address
     * @param hours Number of hours for TWAP calculation
     */
    function getTWAP(address pool, uint256 hours) external view returns (
        uint256 token0Price,
        uint256 token1Price
    );

    /**
     * @notice Get all major token prices at once
     * @return tokens Array of token addresses
     * @return prices Array of USD prices (18 decimals)
     */
    function getAllPrices() external view returns (
        address[] memory tokens,
        uint256[] memory prices
    );

    // =========================================================================
    // Pool Queries
    // =========================================================================

    /**
     * @notice Get pool by token pair
     * @param token0 First token address
     * @param token1 Second token address
     * @param fee Fee tier (100, 500, 3000, 10000)
     */
    function getPool(
        address token0,
        address token1,
        uint24 fee
    ) external view returns (
        address pool,
        uint128 liquidity,
        uint160 sqrtPriceX96,
        int24 tick
    );

    /**
     * @notice Get pool liquidity depth
     * @param pool Pool address
     */
    function getPoolLiquidity(address pool) external view returns (
        uint128 liquidity,
        uint256 tvlToken0,
        uint256 tvlToken1,
        uint256 tvlUSD
    );

    /**
     * @notice Get pool volume and fees
     * @param pool Pool address
     */
    function getPoolStats(address pool) external view returns (
        uint256 volume24hUSD,
        uint256 fees24hUSD,
        uint256 txCount24h,
        uint256 apr
    );

    /**
     * @notice Get pool fee growth for LP calculations
     * @param pool Pool address
     */
    function getPoolFeeGrowth(address pool) external view returns (
        uint256 feeGrowthGlobal0X128,
        uint256 feeGrowthGlobal1X128
    );

    // =========================================================================
    // Swap Queries
    // =========================================================================

    /**
     * @notice Get swap quote (exact input)
     * @param tokenIn Input token
     * @param tokenOut Output token
     * @param amountIn Input amount
     */
    function quoteExactInput(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external view returns (
        uint256 amountOut,
        uint256 priceImpact,
        uint256 gasEstimate
    );

    /**
     * @notice Get swap quote (exact output)
     * @param tokenIn Input token
     * @param tokenOut Output token
     * @param amountOut Desired output amount
     */
    function quoteExactOutput(
        address tokenIn,
        address tokenOut,
        uint256 amountOut
    ) external view returns (
        uint256 amountIn,
        uint256 priceImpact,
        uint256 gasEstimate
    );

    /**
     * @notice Get best swap route
     * @param tokenIn Input token
     * @param tokenOut Output token
     * @param amountIn Input amount
     */
    function getBestRoute(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external view returns (
        address[] memory path,
        uint24[] memory fees,
        uint256 expectedOutput
    );

    // =========================================================================
    // Position Queries
    // =========================================================================

    /**
     * @notice Get all positions for an owner
     * @param owner Position owner
     */
    function getPositions(address owner) external view returns (
        uint256[] memory tokenIds,
        address[] memory pools,
        uint128[] memory liquidities,
        uint256[] memory valuesUSD
    );

    /**
     * @notice Get position details by token ID
     * @param tokenId NFT position token ID
     */
    function getPosition(uint256 tokenId) external view returns (
        address pool,
        int24 tickLower,
        int24 tickUpper,
        uint128 liquidity,
        uint256 amount0,
        uint256 amount1,
        uint256 fees0,
        uint256 fees1,
        bool inRange
    );

    /**
     * @notice Get uncollected fees for a position
     * @param tokenId NFT position token ID
     */
    function getPositionFees(uint256 tokenId) external view returns (
        uint256 fees0,
        uint256 fees1,
        uint256 feesUSD
    );

    // =========================================================================
    // Events
    // =========================================================================

    event PriceUpdated(address indexed token, uint256 priceUSD, uint256 timestamp);
    event PoolStatsUpdated(address indexed pool, uint256 tvlUSD, uint256 volume24hUSD);
}

/**
 * @title LuxOracle
 * @notice Implementation of IOracle using G-Chain GraphQL precompile
 */
library LuxOracle {
    address constant GRAPHQL = address(0x0500);

    // Query IDs from graph/oracle.go
    uint16 constant QUERY_ETH_PRICE = 0x1001;
    uint16 constant QUERY_LUX_PRICE = 0x1002;
    uint16 constant QUERY_TOKEN_PRICE = 0x1004;
    uint16 constant QUERY_TWAP = 0x1010;
    uint16 constant QUERY_SPOT_PRICE = 0x1011;
    uint16 constant QUERY_ALL_PRICES = 0x1020;

    uint16 constant QUERY_POOL_BY_TOKENS = 0x2001;
    uint16 constant QUERY_POOL_LIQUIDITY = 0x2002;
    uint16 constant QUERY_POOL_FEES = 0x2003;
    uint16 constant QUERY_POOL_VOLUME = 0x2004;
    uint16 constant QUERY_MY_POSITIONS = 0x2010;
    uint16 constant QUERY_POSITION_VALUE = 0x2011;
    uint16 constant QUERY_QUOTE = 0x2020;

    /**
     * @notice Get ETH price in USD
     */
    function getETHPrice() internal returns (uint256) {
        bytes[] memory args = new bytes[](0);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_ETH_PRICE, args);
        return _parsePrice(result);
    }

    /**
     * @notice Get LUX price in USD
     */
    function getLUXPrice() internal returns (uint256) {
        bytes[] memory args = new bytes[](0);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_LUX_PRICE, args);
        return _parsePrice(result);
    }

    /**
     * @notice Get any token price in USD
     */
    function getTokenPrice(address token) internal returns (uint256) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(token);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_TOKEN_PRICE, args);
        return _parsePrice(result);
    }

    /**
     * @notice Get pool spot price
     */
    function getSpotPrice(address pool) internal returns (uint256 token0Price, uint256 token1Price) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(pool);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_SPOT_PRICE, args);
        return _parsePoolPrices(result);
    }

    /**
     * @notice Get pool liquidity info
     */
    function getPoolLiquidity(address pool) internal returns (
        uint128 liquidity,
        uint256 tvlToken0,
        uint256 tvlToken1,
        uint256 tvlUSD
    ) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(pool);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_POOL_LIQUIDITY, args);
        return _parsePoolLiquidity(result);
    }

    /**
     * @notice Get swap quote
     */
    function getQuote(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) internal returns (uint256 amountOut, uint256 priceImpact) {
        bytes[] memory args = new bytes[](3);
        args[0] = abi.encodePacked(tokenIn);
        args[1] = abi.encodePacked(tokenOut);
        args[2] = abi.encode(amountIn);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_QUOTE, args);
        return _parseQuote(result);
    }

    /**
     * @notice Get user positions
     */
    function getPositions(address owner) internal returns (
        uint256[] memory tokenIds,
        uint256[] memory liquidities
    ) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(owner);
        bytes memory result = IGraphQL(GRAPHQL).queryPredefined(QUERY_MY_POSITIONS, args);
        return _parsePositions(result);
    }

    // =========================================================================
    // Internal Parsing Functions
    // =========================================================================

    function _parsePrice(bytes memory data) internal pure returns (uint256) {
        // Simple JSON parsing - in production use proper decoder
        // Returns price with 18 decimals
        if (data.length == 0) return 0;

        // Mock implementation - real one would parse JSON
        // For now, decode as uint256 if it's ABI encoded
        if (data.length >= 32) {
            return abi.decode(data, (uint256));
        }
        return 0;
    }

    function _parsePoolPrices(bytes memory data) internal pure returns (uint256, uint256) {
        if (data.length < 64) return (0, 0);
        (uint256 p0, uint256 p1) = abi.decode(data, (uint256, uint256));
        return (p0, p1);
    }

    function _parsePoolLiquidity(bytes memory data) internal pure returns (
        uint128, uint256, uint256, uint256
    ) {
        if (data.length < 128) return (0, 0, 0, 0);
        return abi.decode(data, (uint128, uint256, uint256, uint256));
    }

    function _parseQuote(bytes memory data) internal pure returns (uint256, uint256) {
        if (data.length < 64) return (0, 0);
        return abi.decode(data, (uint256, uint256));
    }

    function _parsePositions(bytes memory data) internal pure returns (
        uint256[] memory,
        uint256[] memory
    ) {
        if (data.length == 0) {
            return (new uint256[](0), new uint256[](0));
        }
        return abi.decode(data, (uint256[], uint256[]));
    }
}

/**
 * @title OracleConsumer
 * @notice Example contract showing how to use LuxOracle
 */
abstract contract OracleConsumer {
    using LuxOracle for *;

    /**
     * @notice Get value of a token amount in USD
     */
    function getValueUSD(address token, uint256 amount) public returns (uint256) {
        uint256 price = LuxOracle.getTokenPrice(token);
        return (amount * price) / 1e18;
    }

    /**
     * @notice Get expected output for a swap
     */
    function getExpectedOutput(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) public returns (uint256 amountOut) {
        (amountOut, ) = LuxOracle.getQuote(tokenIn, tokenOut, amountIn);
    }

    /**
     * @notice Check if price impact is acceptable
     */
    function checkPriceImpact(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 maxImpactBps
    ) public returns (bool acceptable) {
        (, uint256 impact) = LuxOracle.getQuote(tokenIn, tokenOut, amountIn);
        return impact <= maxImpactBps;
    }
}
