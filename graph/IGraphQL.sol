// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries Inc. All rights reserved.

pragma solidity ^0.8.24;

/**
 * @title IGraphQL
 * @notice Native GraphQL query interface for G-Chain unified query layer
 * @dev Precompile address: 0x0500
 *
 * This precompile enables any EVM contract to execute GraphQL queries against
 * the unified G-Chain query layer. It provides:
 * - Cross-chain data aggregation (query multiple chains at once)
 * - DEX data (pools, pairs, tokens, swaps, positions)
 * - Account and balance information
 * - Pre-defined query templates for gas efficiency
 */
interface IGraphQL {
    // =========================================================================
    // Query Methods
    // =========================================================================

    /**
     * @notice Execute a GraphQL query
     * @param query The GraphQL query string
     * @param variables JSON-encoded query variables
     * @return data The query result as JSON bytes
     */
    function query(
        string calldata query,
        bytes calldata variables
    ) external returns (bytes memory data);

    /**
     * @notice Execute a GraphQL query with operation name
     * @param query The GraphQL query string
     * @param variables JSON-encoded query variables
     * @param operationName The operation name
     * @return data The query result as JSON bytes
     */
    function queryNamed(
        string calldata query,
        bytes calldata variables,
        string calldata operationName
    ) external returns (bytes memory data);

    /**
     * @notice Execute a cross-chain GraphQL query
     * @param query The GraphQL query string
     * @param variables JSON-encoded query variables
     * @param targetChains Array of chain IDs to query (empty = all chains)
     * @return data The query result as JSON bytes
     */
    function queryCrossChain(
        string calldata query,
        bytes calldata variables,
        uint64[] calldata targetChains
    ) external returns (bytes memory data);

    /**
     * @notice Execute a pre-defined query template (lower gas)
     * @param queryId The pre-defined query ID
     * @param args Query arguments
     * @return data The query result as JSON bytes
     */
    function queryPredefined(
        uint16 queryId,
        bytes[] calldata args
    ) external returns (bytes memory data);

    // =========================================================================
    // View Methods
    // =========================================================================

    /**
     * @notice Get query statistics
     * @return totalQueries Total number of queries executed
     * @return cacheHits Number of cache hits
     * @return cacheMisses Number of cache misses
     * @return totalGasUsed Total gas consumed by queries
     */
    function getStats() external view returns (
        uint64 totalQueries,
        uint64 cacheHits,
        uint64 cacheMisses,
        uint64 totalGasUsed
    );

    /**
     * @notice Get supported chain IDs
     * @return chainIds Array of supported chain IDs
     */
    function getSupportedChains() external view returns (uint64[] memory chainIds);

    // =========================================================================
    // Pre-defined Query IDs
    // =========================================================================

    // Chain queries (0x00xx)
    uint16 constant QUERY_CHAIN_INFO = 0x0001;
    uint16 constant QUERY_BLOCK_BY_HASH = 0x0002;
    uint16 constant QUERY_BLOCK_BY_NUMBER = 0x0003;

    // Account queries (0x01xx)
    uint16 constant QUERY_BALANCE = 0x0101;
    uint16 constant QUERY_ACCOUNT_INFO = 0x0102;

    // DEX Factory queries (0x02xx)
    uint16 constant QUERY_FACTORY = 0x0201;
    uint16 constant QUERY_BUNDLE = 0x0202;

    // Token queries (0x03xx)
    uint16 constant QUERY_TOKEN = 0x0301;
    uint16 constant QUERY_TOKENS = 0x0302;
    uint16 constant QUERY_TOKEN_PRICE = 0x0303;

    // Pool queries (0x04xx)
    uint16 constant QUERY_POOL = 0x0401;
    uint16 constant QUERY_POOLS = 0x0402;
    uint16 constant QUERY_POOL_TICKS = 0x0403;
    uint16 constant QUERY_POOL_DAY_DATA = 0x0404;

    // Pair queries v2 (0x05xx)
    uint16 constant QUERY_PAIR = 0x0501;
    uint16 constant QUERY_PAIRS = 0x0502;
    uint16 constant QUERY_PAIR_DAY_DATA = 0x0503;

    // Position queries (0x06xx)
    uint16 constant QUERY_POSITION = 0x0601;
    uint16 constant QUERY_POSITIONS = 0x0602;
    uint16 constant QUERY_POSITIONS_BY_OWNER = 0x0603;

    // Swap queries (0x07xx)
    uint16 constant QUERY_SWAPS = 0x0701;
    uint16 constant QUERY_SWAPS_BY_POOL = 0x0702;
    uint16 constant QUERY_SWAPS_BY_TOKEN = 0x0703;

    // Cross-chain queries (0x0Fxx)
    uint16 constant QUERY_ALL_CHAINS_TVL = 0x0F01;
    uint16 constant QUERY_ALL_CHAINS_VOLUME = 0x0F02;

    // =========================================================================
    // Chain IDs
    // =========================================================================

    uint64 constant CHAIN_LUX_MAINNET = 96369;
    uint64 constant CHAIN_LUX_TESTNET = 96368;
    uint64 constant CHAIN_ZOO_MAINNET = 200200;
    uint64 constant CHAIN_ZOO_TESTNET = 200201;
    uint64 constant CHAIN_SPC_MAINNET = 36911;
    uint64 constant CHAIN_SPC_TESTNET = 36910;
    uint64 constant CHAIN_HANZO_MAINNET = 36963;
    uint64 constant CHAIN_HANZO_TESTNET = 36962;

    // =========================================================================
    // Events
    // =========================================================================

    event QueryExecuted(
        address indexed caller,
        bytes32 indexed queryHash,
        uint64 gasUsed,
        bool fromCache
    );

    event QueryError(
        address indexed caller,
        bytes32 indexed queryHash,
        string error
    );
}

/**
 * @title GraphQL
 * @notice Library for interacting with the GraphQL precompile
 */
library GraphQL {
    address constant PRECOMPILE = address(0x0500);

    /**
     * @notice Get ETH/LUX price from bundle
     * @return ethPriceUSD ETH price in USD (18 decimals)
     * @return luxPriceUSD LUX price in USD (18 decimals)
     */
    function getPriceBundle() internal returns (uint256 ethPriceUSD, uint256 luxPriceUSD) {
        bytes[] memory args = new bytes[](0);
        bytes memory result = IGraphQL(PRECOMPILE).queryPredefined(
            IGraphQL.QUERY_BUNDLE,
            args
        );
        // Parse JSON result (simplified - real implementation would use proper parsing)
        // For now, return mock values
        ethPriceUSD = 2000e18;
        luxPriceUSD = 10e18;
    }

    /**
     * @notice Get token info by address
     * @param tokenAddress The token address
     * @return symbol Token symbol
     * @return decimals Token decimals
     * @return volumeUSD 24h volume in USD
     * @return tvlUSD Total value locked in USD
     */
    function getToken(address tokenAddress) internal returns (
        string memory symbol,
        uint8 decimals,
        uint256 volumeUSD,
        uint256 tvlUSD
    ) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(tokenAddress);

        bytes memory result = IGraphQL(PRECOMPILE).queryPredefined(
            IGraphQL.QUERY_TOKEN,
            args
        );
        // Parse JSON result
        // Return mock values for now
        symbol = "TOKEN";
        decimals = 18;
        volumeUSD = 1000000e18;
        tvlUSD = 5000000e18;
    }

    /**
     * @notice Get pool info by address
     * @param poolAddress The pool address
     * @return token0 Token0 address
     * @return token1 Token1 address
     * @return fee Pool fee tier
     * @return liquidity Current liquidity
     * @return sqrtPriceX96 Current sqrt price
     */
    function getPool(address poolAddress) internal returns (
        address token0,
        address token1,
        uint24 fee,
        uint128 liquidity,
        uint160 sqrtPriceX96
    ) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(poolAddress);

        bytes memory result = IGraphQL(PRECOMPILE).queryPredefined(
            IGraphQL.QUERY_POOL,
            args
        );
        // Parse JSON result
        // Return mock values for now
    }

    /**
     * @notice Get all positions for an owner
     * @param owner The position owner address
     * @return positionIds Array of position token IDs
     */
    function getPositionsByOwner(address owner) internal returns (uint256[] memory positionIds) {
        bytes[] memory args = new bytes[](1);
        args[0] = abi.encodePacked(owner);

        bytes memory result = IGraphQL(PRECOMPILE).queryPredefined(
            IGraphQL.QUERY_POSITIONS_BY_OWNER,
            args
        );
        // Parse JSON result
        // Return mock values for now
        positionIds = new uint256[](0);
    }

    /**
     * @notice Get TVL across all chains
     * @return chainIds Array of chain IDs
     * @return tvls Array of TVL values in USD (18 decimals)
     */
    function getAllChainsTVL() internal returns (
        uint64[] memory chainIds,
        uint256[] memory tvls
    ) {
        bytes[] memory args = new bytes[](0);

        bytes memory result = IGraphQL(PRECOMPILE).queryPredefined(
            IGraphQL.QUERY_ALL_CHAINS_TVL,
            args
        );
        // Parse JSON result
        // Return mock values for now
        chainIds = new uint64[](4);
        chainIds[0] = IGraphQL.CHAIN_LUX_MAINNET;
        chainIds[1] = IGraphQL.CHAIN_ZOO_MAINNET;
        chainIds[2] = IGraphQL.CHAIN_SPC_MAINNET;
        chainIds[3] = IGraphQL.CHAIN_HANZO_MAINNET;

        tvls = new uint256[](4);
        tvls[0] = 100_000_000e18;  // $100M
        tvls[1] = 50_000_000e18;   // $50M
        tvls[2] = 25_000_000e18;   // $25M
        tvls[3] = 10_000_000e18;   // $10M
    }
}
