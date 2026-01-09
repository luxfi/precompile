// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Currency} from "./Types.sol";

/// @title ILXVault (LP-9030)
/// @notice Clearinghouse interface for LX - custody, margin, positions, liquidations
/// @dev Precompile address: LP-9030 (0x0000000000000000000000000000000000009030)
/// @dev This is the ONLY contract that mutates user balances and positions
/// @dev LXBook calls applyFills() to settle trades atomically
interface ILXVault {
    // =========================================================================
    // Custom Types
    // =========================================================================

    /// @notice Market identifier (perp markets, spot pairs, etc.)
    type MarketId is uint32;

    /// @notice Account margin mode
    enum MarginMode {
        ISOLATED,       // Each position has isolated margin
        CROSS,          // All positions share margin (default)
        PORTFOLIO       // Portfolio margin with cross-asset netting
    }

    /// @notice Position side
    enum Side {
        LONG,
        SHORT
    }

    // =========================================================================
    // Structs - Settlement
    // =========================================================================

    /// @notice Fill from LXBook to be applied to accounts
    /// @dev All amounts are X18 (18 decimal fixed point)
    struct Fill {
        MarketId marketId;      // Market this fill belongs to
        address maker;          // Maker address
        address taker;          // Taker address
        bool takerIsBuy;        // True if taker is buying (going long)
        uint128 pxX18;          // Execution price (X18)
        uint128 szX18;          // Size in base asset (X18)
        uint128 makerFeeX18;    // Maker fee (negative = rebate)
        uint128 takerFeeX18;    // Taker fee
        uint8 flags;            // Bit flags: 0x01=liquidation, 0x02=reduce-only, 0x04=ADL
    }

    /// @notice Result of applying fills
    struct ApplyResult {
        uint128 appliedFills;   // Number of fills successfully applied
        uint128 appliedSzX18;   // Total size applied
        uint8 status;           // 0=rejected, 1=ok, 2=partial
    }

    // =========================================================================
    // Structs - Account State
    // =========================================================================

    /// @notice User's margin account state
    struct AccountState {
        int256 equityX18;           // Total equity (collateral + unrealized PnL)
        uint256 totalCollateralX18; // Total collateral value
        int256 unrealizedPnlX18;    // Unrealized PnL across all positions
        uint256 maintenanceReqX18;  // Maintenance margin requirement
        uint256 initialReqX18;      // Initial margin requirement
        MarginMode mode;            // Current margin mode
        bool isLiquidatable;        // True if below maintenance margin
    }

    /// @notice Position in a specific market
    struct Position {
        MarketId marketId;      // Market ID
        Side side;              // LONG or SHORT
        uint128 sizeX18;        // Position size (X18)
        uint128 avgEntryPxX18;  // Average entry price (X18)
        int128 unrealizedPnlX18;// Current unrealized PnL (X18)
        uint128 marginX18;      // Margin allocated (isolated mode)
        int128 fundingAccrued;  // Accumulated funding (X18)
    }

    /// @notice Market configuration for risk parameters
    struct MarketConfig {
        MarketId marketId;          // Market ID
        uint128 maxLeverageX18;     // Max leverage (e.g., 50e18 = 50x)
        uint128 maintenanceMarginX18; // Maintenance margin ratio (e.g., 0.03e18 = 3%)
        uint128 initialMarginX18;   // Initial margin ratio (e.g., 0.05e18 = 5%)
        uint128 liquidationFeeX18;  // Liquidation penalty (e.g., 0.025e18 = 2.5%)
        uint128 maxPositionSzX18;   // Max position size per account
        uint128 maxOIX18;           // Max open interest for market
        bool active;                // Market is active
    }

    // =========================================================================
    // Errors
    // =========================================================================

    error NotBook();                    // Caller is not LXBook
    error NotOracle();                  // Caller is not LXOracle/LXFeed
    error RiskRejected();               // Risk check failed
    error InvalidFill();                // Fill parameters invalid
    error InsufficientMargin();         // Not enough margin
    error InsufficientBalance();        // Not enough balance
    error MarketNotActive();            // Market is paused or disabled
    error PositionNotFound();           // No position exists
    error NotLiquidatable();            // Account above maintenance margin
    error MaxOIExceeded();              // Would exceed max open interest
    error WithdrawalLocked();           // Withdrawal cooldown active

    // =========================================================================
    // Events
    // =========================================================================

    event Deposit(address indexed user, Currency indexed currency, uint256 amount);
    event Withdraw(address indexed user, Currency indexed currency, uint256 amount);
    event FillApplied(
        MarketId indexed marketId,
        address indexed maker,
        address indexed taker,
        uint128 pxX18,
        uint128 szX18,
        bool takerIsBuy
    );
    event PositionOpened(address indexed user, MarketId indexed marketId, Side side, uint128 szX18, uint128 pxX18);
    event PositionClosed(address indexed user, MarketId indexed marketId, int256 realizedPnlX18);
    event PositionModified(address indexed user, MarketId indexed marketId, uint128 newSzX18, uint128 avgPxX18);
    event Liquidation(address indexed user, MarketId indexed marketId, address indexed liquidator, uint128 szX18);
    event ADLExecuted(MarketId indexed marketId, address indexed winner, address indexed loser, uint128 szX18);
    event FundingAccrued(MarketId indexed marketId, int256 fundingRateX18, uint256 timestamp);

    // =========================================================================
    // Settlement Interface (called by LXBook only)
    // =========================================================================

    /// @notice Apply a batch of fills atomically from LXBook
    /// @dev ONLY callable by LXBook (LP-9020)
    /// @dev Validates risk, updates positions, applies fees
    /// @param fills Array of fills to apply
    /// @return result Summary of applied fills
    function applyFills(Fill[] calldata fills) external returns (ApplyResult memory result);

    /// @notice Pre-check if fills would be accepted (for order validation)
    /// @dev Does NOT modify state - used for pre-trade risk checks
    /// @param fills Array of fills to validate
    /// @return valid True if all fills would be accepted
    /// @return reason Rejection reason if not valid
    function preCheckFills(Fill[] calldata fills) external view returns (bool valid, string memory reason);

    // =========================================================================
    // Custody Interface (Spot Balances)
    // =========================================================================

    /// @notice Deposit collateral into vault
    /// @param currency Token to deposit (address(0) for native LUX)
    /// @param amount Amount to deposit
    function deposit(Currency currency, uint256 amount) external payable;

    /// @notice Withdraw collateral from vault
    /// @dev Subject to margin requirements and withdrawal cooldown
    /// @param currency Token to withdraw
    /// @param amount Amount to withdraw
    /// @param to Recipient address
    function withdraw(Currency currency, uint256 amount, address to) external;

    /// @notice Get user's balance of a specific currency
    /// @param user Account to query
    /// @param currency Token address
    /// @return balance Available balance (not locked in margin)
    function balanceOf(address user, Currency currency) external view returns (uint256 balance);

    /// @notice Get user's total collateral value in USD
    /// @param user Account to query
    /// @return valueX18 Total collateral value (X18)
    function totalCollateralValue(address user) external view returns (uint256 valueX18);

    // =========================================================================
    // Margin Account Interface
    // =========================================================================

    /// @notice Get full account state
    /// @param user Account to query
    /// @return state Complete account state
    function getAccountState(address user) external view returns (AccountState memory state);

    /// @notice Get account equity (collateral + unrealized PnL)
    /// @param user Account to query
    /// @return equityX18 Account equity (X18, can be negative)
    function accountEquityX18(address user) external view returns (int256 equityX18);

    /// @notice Get maintenance margin requirement
    /// @param user Account to query
    /// @return reqX18 Maintenance margin requirement (X18)
    function maintenanceMarginReqX18(address user) external view returns (uint256 reqX18);

    /// @notice Get initial margin requirement
    /// @param user Account to query
    /// @return reqX18 Initial margin requirement (X18)
    function initialMarginReqX18(address user) external view returns (uint256 reqX18);

    /// @notice Get margin ratio (equity / maintenance requirement)
    /// @param user Account to query
    /// @return ratioX18 Margin ratio (X18), <1.0 = liquidatable
    function marginRatioX18(address user) external view returns (uint256 ratioX18);

    /// @notice Set margin mode for account
    /// @param mode New margin mode
    function setMarginMode(MarginMode mode) external;

    // =========================================================================
    // Position Interface
    // =========================================================================

    /// @notice Get user's position in a market
    /// @param user Account to query
    /// @param marketId Market ID
    /// @return position Position details (zero if no position)
    function getPosition(address user, MarketId marketId) external view returns (Position memory position);

    /// @notice Get all positions for a user
    /// @param user Account to query
    /// @return positions Array of all positions
    function getAllPositions(address user) external view returns (Position[] memory positions);

    /// @notice Add margin to isolated position
    /// @param marketId Market ID
    /// @param amount Additional margin amount
    function addMargin(MarketId marketId, uint256 amount) external;

    /// @notice Remove margin from isolated position (if excess)
    /// @param marketId Market ID
    /// @param amount Margin to remove
    function removeMargin(MarketId marketId, uint256 amount) external;

    // =========================================================================
    // Liquidation Interface
    // =========================================================================

    /// @notice Check if account is liquidatable
    /// @param user Account to check
    /// @return liquidatable True if below maintenance margin
    function isLiquidatable(address user) external view returns (bool liquidatable);

    /// @notice Liquidate an undercollateralized position
    /// @dev Anyone can call - liquidator receives bonus
    /// @param user Account to liquidate
    /// @param marketId Market to liquidate
    /// @param maxSzX18 Maximum size to liquidate
    /// @return liqSzX18 Actual size liquidated
    function liquidate(address user, MarketId marketId, uint128 maxSzX18) external returns (uint128 liqSzX18);

    /// @notice Run Auto-Deleveraging for a market
    /// @dev Called when insurance fund insufficient - socializes losses
    /// @param marketId Market to ADL
    /// @param maxAccounts Maximum accounts to process
    function runADL(MarketId marketId, uint32 maxAccounts) external;

    /// @notice Get insurance fund balance
    /// @return balance Insurance fund balance (X18)
    function insuranceFundBalance() external view returns (uint256 balance);

    // =========================================================================
    // Funding Interface
    // =========================================================================

    /// @notice Accrue funding for a market
    /// @dev Called periodically (e.g., every 8 hours)
    /// @param marketId Market to accrue funding for
    function accrueFunding(MarketId marketId) external;

    /// @notice Get current funding rate for a market
    /// @param marketId Market ID
    /// @return rateX18 Funding rate (X18, positive = longs pay shorts)
    function fundingRateX18(MarketId marketId) external view returns (int256 rateX18);

    /// @notice Get next funding time
    /// @param marketId Market ID
    /// @return timestamp Next funding timestamp
    function nextFundingTime(MarketId marketId) external view returns (uint256 timestamp);

    // =========================================================================
    // Market Configuration
    // =========================================================================

    /// @notice Get market configuration
    /// @param marketId Market ID
    /// @return config Market configuration
    function getMarketConfig(MarketId marketId) external view returns (MarketConfig memory config);

    /// @notice Get current open interest for a market
    /// @param marketId Market ID
    /// @return longOIX18 Long open interest
    /// @return shortOIX18 Short open interest
    function openInterest(MarketId marketId) external view returns (uint128 longOIX18, uint128 shortOIX18);
}

// =========================================================================
// Fill Flags (for Fill.flags field)
// =========================================================================

/// @notice Fill is a liquidation fill
uint8 constant FILL_FLAG_LIQUIDATION = 0x01;

/// @notice Fill is reduce-only (cannot increase position)
uint8 constant FILL_FLAG_REDUCE_ONLY = 0x02;

/// @notice Fill is from ADL (auto-deleverage)
uint8 constant FILL_FLAG_ADL = 0x04;

/// @notice Fill is from a market order
uint8 constant FILL_FLAG_MARKET = 0x08;

/// @notice Fill is post-only violation (should reject)
uint8 constant FILL_FLAG_POST_ONLY_FAIL = 0x10;
