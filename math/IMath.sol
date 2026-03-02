// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IMath - Fixed-Point Math Precompile
/// @notice Native EVM precompile for high-precision arithmetic operations
/// @dev Precompile address: 0x0400000000000000000000000000000000000050
/// @dev Saves ~2000 gas per MulDiv vs Solidity (no overflow checks in Go native)
interface IMath {
    error InvalidInput();
    error DivisionByZero();
    error OutOfGas();

    /// @notice Compute (a * b) / denominator without intermediate overflow
    /// @param a First multiplicand (uint256)
    /// @param b Second multiplicand (uint256)
    /// @param denominator Divisor (uint256, must be non-zero)
    /// @return result Floor division result
    function mulDiv(uint256 a, uint256 b, uint256 denominator) external pure returns (uint256 result);

    /// @notice Compute ceil((a * b) / denominator) without intermediate overflow
    /// @param a First multiplicand (uint256)
    /// @param b Second multiplicand (uint256)
    /// @param denominator Divisor (uint256, must be non-zero)
    /// @return result Ceiling division result
    function mulDivRoundUp(uint256 a, uint256 b, uint256 denominator) external pure returns (uint256 result);

    /// @notice Compute floor(sqrt(x)) using Newton's method
    /// @param x Input value (uint256)
    /// @return result Integer square root
    function sqrt(uint256 x) external pure returns (uint256 result);

    /// @notice Compute floor(log2(x))
    /// @param x Input value (uint256, must be > 0)
    /// @return result Integer logarithm base 2
    function log2(uint256 x) external pure returns (uint256 result);

    /// @notice Compute e^x in Q128.128 fixed-point format
    /// @param x Exponent in Q128.128 format
    /// @return result e^x in Q128.128 format
    function exp(uint256 x) external pure returns (uint256 result);

    /// @notice Compute base^exponent mod 2^256
    /// @param base Base value (uint256)
    /// @param exponent Exponent value (uint256)
    /// @return result base^exponent mod 2^256
    function pow(uint256 base, uint256 exponent) external pure returns (uint256 result);
}
