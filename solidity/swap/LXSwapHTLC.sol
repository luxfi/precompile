// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20Minimal} from "../dex/IERC20Minimal.sol";

/// @title LXSwapHTLC — the EVM counterparty leg of a Lux cross-chain atomic swap.
/// @notice This is the off-Lux mirror of the on-Lux HTLC precompile LP-90A0
///         (`swap/swap.go`). The two legs are bound ONLY by a shared SHA-256
///         hashlock `h`: a single 32-byte preimage `s` with `sha256(s)==h`
///         claims both, so revealing it on one chain to take the funds exposes
///         it for the counterparty to take the other. Deploy this on any EVM
///         chain that is NOT Lux (Ethereum, an L2, …); on Lux itself the
///         precompile is the canonical leg.
///
/// @dev Semantics are deliberately identical to the precompile:
///        - hashlock is SHA-256 (Bitcoin OP_SHA256 / EVM 0x02), NOT keccak, so
///          one preimage spans an EVM leg, the Lux precompile leg, and a BTC
///          P2WSH leg;
///        - funds locked under `h` move ONLY to the `recipient` fixed at lock
///          time (on preimage) or back to the `refund` address fixed at lock
///          time (after `timeout`) — claim and refund windows are disjoint;
///        - there is NO owner, NO pause, NO mint, NO upgrade, NO set-balance:
///          non-custody is STRUCTURAL. Every wei paid out was locked by its
///          owner; the per-asset `reserve` ledger is backed by observed inbound
///          deltas (native `msg.value`, or an exact ERC-20 `transferFrom`
///          delta that rejects fee-on-transfer tokens), so for every asset
///          `selfBalance(asset) >= reserve[asset]` always holds;
///        - state changes happen BEFORE the external pay-out (effects-before-
///          interaction) under a non-reentrant guard.
///
///      Both legs custody the chain-native asset (`asset == address(0)`)
///      symmetrically: here the amount is delivered as `msg.value`; on the
///      precompile the EVM moves the value into the precompile address before Run
///      and the lock measures it as an observed balance delta (the native analog
///      of the ERC-20 transferFrom delta). Native and ERC-20 behave identically on
///      both sides — no leg mints.
contract LXSwapHTLC {
    // --- types ---------------------------------------------------------------

    enum Status {
        None, // 0 — no swap at this id
        Locked, // 1 — funds escrowed, awaiting claim or refund
        Claimed, // 2 — preimage revealed, paid to recipient
        Refunded // 3 — timed out, returned to refund address
    }

    struct Swap {
        Status status;
        bytes32 hashlock; // SHA-256 lock; one preimage unlocks every leg
        address recipient; // fixed payee on a valid preimage
        address refund; // fixed payee after timeout
        address asset; // address(0) == chain-native, else ERC-20
        uint256 amount; // exact escrowed amount (observed, not requested)
        uint64 timeout; // unix seconds; claim iff now < timeout, refund iff >=
        bytes32 preimage; // the revealed secret, once claimed
    }

    // --- bounds (mirror swap.go) --------------------------------------------

    /// @notice Per-lock dust floor: a lock below this is rejected so claim/refund
    ///         gas can never exceed the output (fee-griefing guard).
    uint256 public constant MIN_AMOUNT = 1;
    /// @notice Lower bound on `timeout - block.timestamp`: a real counterparty
    ///         must have time to act.
    uint64 public constant MIN_TIMEOUT = 10 minutes;
    /// @notice Upper bound on `timeout - block.timestamp`: capital is never
    ///         locked unboundedly.
    uint64 public constant MAX_TIMEOUT = 30 days;
    /// @notice The fixed preimage size, for Bitcoin-witness compatibility.
    uint256 public constant PREIMAGE_LEN = 32;

    // --- state ---------------------------------------------------------------

    /// @notice swapId => swap. swapId binds every term plus the locker and a
    ///         monotonic per-locker nonce, so identical terms locked twice yield
    ///         distinct ids and cross-locker collisions are impossible.
    mapping(bytes32 => Swap) private _swaps;

    /// @notice hashlock => revealed preimage (the cross-leg secret relay; the
    ///         counterparty's watchtower reads this to claim the other leg).
    mapping(bytes32 => bytes32) private _preimageOf;

    /// @notice asset => escrowed reserve. Invariant: for every asset,
    ///         `selfBalance(asset) >= reserve[asset]`.
    mapping(address => uint256) public reserve;

    /// @notice locker => monotonic lock counter, for swapId uniqueness.
    mapping(address => uint256) public nonceOf;

    /// @dev Non-reentrant guard (1 = idle, 2 = entered).
    uint256 private _guard = 1;

    // --- events --------------------------------------------------------------

    event Locked(
        bytes32 indexed swapId,
        bytes32 indexed hashlock,
        address indexed recipient,
        address refund,
        address asset,
        uint256 amount,
        uint64 timeout
    );
    /// @dev `preimage` is emitted in the clear: revealing it is the whole point —
    ///      it relays the secret to the counterparty leg.
    event Claimed(bytes32 indexed swapId, bytes32 indexed hashlock, bytes32 preimage, address recipient, uint256 amount);
    event Refunded(bytes32 indexed swapId, address indexed refund, uint256 amount);

    // --- errors --------------------------------------------------------------

    error Reentrant();
    error ZeroHashlock();
    error ZeroRecipient();
    error ZeroRefund();
    error DustAmount();
    error TimeoutOutOfBounds();
    error SwapExists();
    error NativeValueMismatch(); // msg.value != amount for a native lock, or != 0 for an ERC-20 lock
    error DeltaMismatch(); // observed ERC-20 inbound delta != amount (fee-on-transfer)
    error TransferFromFailed();
    error TransferFailed();
    error NotLocked();
    error Expired(); // claim after timeout
    error NotExpired(); // refund before timeout
    error BadPreimage(); // sha256(preimage) != hashlock

    modifier nonReentrant() {
        if (_guard != 1) revert Reentrant();
        _guard = 2;
        _;
        _guard = 1;
    }

    // --- lock ----------------------------------------------------------------

    /// @notice Escrow `amount` of `asset` under `hashlock`, payable to `recipient`
    ///         on preimage before `timeout`, refundable to `refund` after.
    /// @dev For a native lock pass `asset == address(0)` and `msg.value == amount`.
    ///      For an ERC-20 lock pass `msg.value == 0`; the caller must have
    ///      approved this contract for `amount`, and the OBSERVED inbound delta
    ///      must equal `amount` exactly (fee-on-transfer tokens are rejected).
    /// @return swapId the unique identifier of the new swap.
    function lock(
        bytes32 hashlock,
        address recipient,
        address refundTo,
        address asset,
        uint256 amount,
        uint64 timeout
    ) external payable nonReentrant returns (bytes32 swapId) {
        if (hashlock == bytes32(0)) revert ZeroHashlock();
        if (recipient == address(0)) revert ZeroRecipient();
        if (refundTo == address(0)) revert ZeroRefund();
        if (amount < MIN_AMOUNT) revert DustAmount();
        if (timeout < block.timestamp + MIN_TIMEOUT || timeout > block.timestamp + MAX_TIMEOUT) {
            revert TimeoutOutOfBounds();
        }

        uint256 nonce = nonceOf[msg.sender];
        swapId = keccak256(abi.encode(hashlock, recipient, refundTo, asset, amount, timeout, msg.sender, nonce));
        if (_swaps[swapId].status != Status.None) revert SwapExists();

        // Move funds IN and require the observed delta to equal `amount` exactly.
        if (asset == address(0)) {
            if (msg.value != amount) revert NativeValueMismatch();
        } else {
            if (msg.value != 0) revert NativeValueMismatch();
            uint256 before = IERC20Minimal(asset).balanceOf(address(this));
            _safeTransferFrom(asset, msg.sender, amount);
            uint256 delta = IERC20Minimal(asset).balanceOf(address(this)) - before;
            if (delta != amount) revert DeltaMismatch();
        }

        _swaps[swapId] = Swap({
            status: Status.Locked,
            hashlock: hashlock,
            recipient: recipient,
            refund: refundTo,
            asset: asset,
            amount: amount,
            timeout: timeout,
            preimage: bytes32(0)
        });
        reserve[asset] += amount;
        nonceOf[msg.sender] = nonce + 1;

        emit Locked(swapId, hashlock, recipient, refundTo, asset, amount, timeout);
    }

    // --- claim ---------------------------------------------------------------

    /// @notice Reveal `preimage` to pay the locked funds to the swap's fixed
    ///         recipient. Anyone may submit (a watchtower, the recipient); the
    ///         payee is the STORED recipient, not the caller.
    function claim(bytes32 swapId, bytes32 preimage) external nonReentrant returns (bool) {
        Swap storage s = _swaps[swapId];
        if (s.status != Status.Locked) revert NotLocked();
        if (block.timestamp >= s.timeout) revert Expired();
        if (sha256(abi.encodePacked(preimage)) != s.hashlock) revert BadPreimage();

        // EFFECTS before INTERACTION.
        address asset = s.asset;
        address recipient = s.recipient;
        uint256 amount = s.amount;
        bytes32 hashlock = s.hashlock;

        s.status = Status.Claimed;
        s.preimage = preimage;
        _preimageOf[hashlock] = preimage;
        reserve[asset] -= amount;

        emit Claimed(swapId, hashlock, preimage, recipient, amount);

        _payOut(asset, recipient, amount);
        return true;
    }

    // --- refund --------------------------------------------------------------

    /// @notice After `timeout`, return the locked funds to the swap's fixed
    ///         refund address. Anyone may submit; the payee is the STORED refund
    ///         address, not the caller.
    function refund(bytes32 swapId) external nonReentrant returns (bool) {
        Swap storage s = _swaps[swapId];
        if (s.status != Status.Locked) revert NotLocked();
        if (block.timestamp < s.timeout) revert NotExpired();

        // EFFECTS before INTERACTION.
        address asset = s.asset;
        address refundTo = s.refund;
        uint256 amount = s.amount;

        s.status = Status.Refunded;
        reserve[asset] -= amount;

        emit Refunded(swapId, refundTo, amount);

        _payOut(asset, refundTo, amount);
        return true;
    }

    // --- views ---------------------------------------------------------------

    /// @notice The full swap tuple (zeroed if unknown).
    function getSwap(bytes32 swapId) external view returns (Swap memory) {
        return _swaps[swapId];
    }

    /// @notice The revealed preimage for a hashlock, or bytes32(0) if none has
    ///         been claimed (the cross-leg secret relay).
    function getPreimage(bytes32 hashlock) external view returns (bytes32) {
        return _preimageOf[hashlock];
    }

    // --- internal ------------------------------------------------------------

    /// @dev Pay `amount` of `asset` to `to`: native via `call`, ERC-20 via a
    ///      return-checked `transfer`. On failure the whole frame reverts,
    ///      including every effect above (so the swap is never half-settled).
    function _payOut(address asset, address to, uint256 amount) private {
        if (asset == address(0)) {
            (bool ok, ) = payable(to).call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            _safeTransfer(asset, to, amount);
        }
    }

    /// @dev `transferFrom(from, this, amount)` tolerant of non-standard tokens
    ///      that return no data; reverts on an explicit `false`.
    function _safeTransferFrom(address asset, address from, uint256 amount) private {
        (bool ok, bytes memory data) = asset.call(
            abi.encodeWithSelector(IERC20Minimal.transferFrom.selector, from, address(this), amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFromFailed();
    }

    /// @dev `transfer(to, amount)` tolerant of non-standard tokens; reverts on `false`.
    function _safeTransfer(address asset, address to, uint256 amount) private {
        (bool ok, bytes memory data) = asset.call(
            abi.encodeWithSelector(IERC20Minimal.transfer.selector, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}
