// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IStableSwap - Curve-style StableSwap AMM Precompile
/// @notice Native EVM precompile for constant-sum AMM invariant computation
/// @dev Precompile address: 0x0400000000000000000000000000000000000060
/// @dev Implements: An^n * sum(x_i) + D = A * D^(n+1) / (n^n * prod(x_i))
/// @dev 10x gas savings vs Solidity StableSwap math
interface IStableSwap {
    error InvalidInput();
    error InvalidTokenIndex();
    error ZeroLiquidity();
    error ConvergenceFailure();

    /// @notice Calculate swap output amount
    /// @param i Index of input token
    /// @param j Index of output token
    /// @param dx Amount of input token
    /// @param balances Current pool balances
    /// @param amp Amplification coefficient
    /// @return dy Amount of output token
    function getDy(
        uint32 i,
        uint32 j,
        uint256 dx,
        uint256[] calldata balances,
        uint256 amp
    ) external pure returns (uint256 dy);

    /// @notice Calculate LP tokens minted for a deposit
    /// @param amounts Amounts of each token to deposit
    /// @param balances Current pool balances
    /// @param amp Amplification coefficient
    /// @param totalSupply Current LP token total supply
    /// @return mintAmount LP tokens to mint
    function addLiquidity(
        uint256[] calldata amounts,
        uint256[] calldata balances,
        uint256 amp,
        uint256 totalSupply
    ) external pure returns (uint256 mintAmount);

    /// @notice Calculate underlying amounts for LP token burn
    /// @param lpAmount LP tokens to burn
    /// @param balances Current pool balances
    /// @param totalSupply Current LP token total supply
    /// @return amounts Underlying token amounts returned
    function removeLiquidity(
        uint256 lpAmount,
        uint256[] calldata balances,
        uint256 totalSupply
    ) external pure returns (uint256[] memory amounts);

    /// @notice Calculate the StableSwap invariant D
    /// @param balances Pool token balances
    /// @param amp Amplification coefficient
    /// @return d The invariant value
    function getD(
        uint256[] calldata balances,
        uint256 amp
    ) external pure returns (uint256 d);
}
