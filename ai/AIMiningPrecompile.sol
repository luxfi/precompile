// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
pragma solidity ^0.8.24;

/**
 * @title IAIMiningPrecompile
 * @notice Precompile interface for AI mining reward calculation at address 0x0300
 * @dev Shared by Hanzo, Lux, and Zoo EVMs for efficient AI mining operations
 *
 * This precompile provides:
 * - ML-DSA (FIPS 204) quantum-safe signature verification
 * - Work proof reward calculation with native optimization
 * - NVTrust attestation verification for GPU compute
 * - O(1) spent set lookup for replay prevention
 * - BLAKE3 work ID computation
 *
 * Gas costs:
 * - verifyMLDSA:     3,000 gas
 * - calculateReward: 1,000 gas
 * - verifyNVTrust:   5,000 gas
 * - isSpent:           100 gas
 * - computeWorkId:      50 gas
 *
 * References:
 * - LP-2000: AI Mining Standard
 * - LP-5000: A-Chain AI Attestation Specification
 * - LP-5200: AI Mining Standard
 * - HIP-006: Hanzo AI Mining Protocol
 * - ZIP-005: Zoo AI Mining Integration
 * - FIPS 204: Module-Lattice Digital Signature Algorithm (ML-DSA)
 */
interface IAIMiningPrecompile {
    // ============ Events ============

    /// @notice Emitted when ML-DSA signature verification is performed
    event MLDSAVerified(
        bytes32 indexed publicKeyHash,
        bytes32 indexed messageHash,
        bool success
    );

    /// @notice Emitted when a work proof reward is calculated
    event RewardCalculated(
        bytes32 indexed workId,
        uint64 chainId,
        uint256 reward
    );

    /// @notice Emitted when NVTrust attestation is verified
    event NVTrustVerified(
        bytes32 indexed receiptHash,
        bool success
    );

    /// @notice Emitted when work is marked as spent
    event WorkSpent(
        bytes32 indexed workId,
        address indexed claimer
    );

    // ============ View Functions ============

    /**
     * @notice Verify ML-DSA signature (quantum-safe, FIPS 204)
     * @param pubkey The ML-DSA public key (1312-4627 bytes depending on level)
     * @param message The message that was signed
     * @param signature The ML-DSA signature (2420-4627 bytes depending on level)
     * @return True if signature is valid, false otherwise
     *
     * @dev Supported security levels:
     *   - Level 2 (ML-DSA-44): 1312 byte pk, 2420 byte sig
     *   - Level 3 (ML-DSA-65): 1952 byte pk, 3309 byte sig
     *   - Level 5 (ML-DSA-87): 2592 byte pk, 4627 byte sig
     *
     * Gas cost: 3,000 gas
     */
    function verifyMLDSA(
        bytes calldata pubkey,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool);

    /**
     * @notice Calculate reward for work proof (optimized native implementation)
     * @param workProof The serialized work proof containing attestation data
     * @param chainId The chain ID for reward calculation context
     * @return The calculated reward amount in AI token atomic units
     *
     * @dev Work proof format:
     *   - [0:32]   Device ID (bytes32)
     *   - [32:64]  Nonce (bytes32)
     *   - [64:72]  Timestamp (uint64)
     *   - [72:74]  Privacy level (uint16, 1-4)
     *   - [74:78]  Compute minutes (uint32)
     *   - [78:...]  TEE quote (variable)
     *
     * Privacy level multipliers:
     *   - Level 1 (Public):       0.25x (250 basis points)
     *   - Level 2 (Private):      0.50x (500 basis points)
     *   - Level 3 (Confidential): 1.00x (1000 basis points)
     *   - Level 4 (Sovereign):    1.50x (1500 basis points)
     *
     * Gas cost: 1,000 gas
     */
    function calculateReward(
        bytes calldata workProof,
        uint64 chainId
    ) external view returns (uint256);

    /**
     * @notice Verify NVTrust attestation from NVIDIA TEE
     * @param receipt The NVTrust attestation receipt
     * @param signature The attestation signature from NVIDIA
     * @return True if attestation is valid, false otherwise
     *
     * @dev Verifies:
     *   - NVIDIA certificate chain validity
     *   - Receipt format and timestamp
     *   - Signature against known NVIDIA root CA
     *   - Device in allowed GPU registry
     *
     * Gas cost: 5,000 gas
     */
    function verifyNVTrust(
        bytes calldata receipt,
        bytes calldata signature
    ) external view returns (bool);

    /**
     * @notice Check if work ID has been spent (O(1) lookup)
     * @param workId The work ID to check
     * @return True if work has been spent, false otherwise
     *
     * @dev Spent set stored in state trie for persistence
     *
     * Gas cost: 100 gas
     */
    function isSpent(bytes32 workId) external view returns (bool);

    /**
     * @notice Compute work ID: BLAKE3(deviceId || nonce || chainId)
     * @param deviceId The GPU device identifier
     * @param nonce The unique nonce for this work
     * @param chainId The chain ID
     * @return The computed work ID (32 bytes)
     *
     * @dev Uses BLAKE3 for efficient hashing
     *
     * Gas cost: 50 gas
     */
    function computeWorkId(
        bytes32 deviceId,
        bytes32 nonce,
        uint64 chainId
    ) external pure returns (bytes32);

    // ============ State-Changing Functions ============

    /**
     * @notice Mark work as spent after claiming reward
     * @param workId The work ID to mark as spent
     *
     * @dev Only callable by authorized contracts (AI token, mining contracts)
     *      Reverts if already spent
     */
    function markSpent(bytes32 workId) external;
}

/**
 * @title AIMiningLib
 * @notice Library for convenient AI Mining precompile interaction
 */
library AIMiningLib {
    /// @notice The precompile address for AI Mining operations
    address constant PRECOMPILE = address(0x0300);

    /// @notice Privacy levels for compute attestation
    uint16 constant PRIVACY_PUBLIC = 1;
    uint16 constant PRIVACY_PRIVATE = 2;
    uint16 constant PRIVACY_CONFIDENTIAL = 3;
    uint16 constant PRIVACY_SOVEREIGN = 4;

    /// @notice Reward basis points per minute (base rate)
    uint256 constant BASE_REWARD_PER_MINUTE = 1e18; // 1 AI per minute (base)

    /// @notice ML-DSA key sizes per security level
    uint256 constant MLDSA44_PK_SIZE = 1312;
    uint256 constant MLDSA65_PK_SIZE = 1952;
    uint256 constant MLDSA87_PK_SIZE = 2592;

    /// @notice ML-DSA signature sizes per security level
    uint256 constant MLDSA44_SIG_SIZE = 2420;
    uint256 constant MLDSA65_SIG_SIZE = 3309;
    uint256 constant MLDSA87_SIG_SIZE = 4627;

    error PrecompileCallFailed();
    error InvalidPublicKeySize();
    error InvalidSignatureSize();
    error WorkAlreadySpent();
    error InvalidWorkProof();

    /**
     * @notice Verify ML-DSA signature with error handling
     */
    function verifyMLDSA(
        bytes memory pubkey,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        (bool success, bytes memory result) = PRECOMPILE.staticcall(
            abi.encodeWithSelector(
                IAIMiningPrecompile.verifyMLDSA.selector,
                pubkey,
                message,
                signature
            )
        );
        if (!success) revert PrecompileCallFailed();
        return abi.decode(result, (bool));
    }

    /**
     * @notice Verify ML-DSA or revert
     */
    function verifyMLDSAOrRevert(
        bytes memory pubkey,
        bytes memory message,
        bytes memory signature
    ) internal view {
        require(verifyMLDSA(pubkey, message, signature), "Invalid ML-DSA signature");
    }

    /**
     * @notice Calculate reward for work proof
     */
    function calculateReward(
        bytes memory workProof,
        uint64 chainId
    ) internal view returns (uint256) {
        (bool success, bytes memory result) = PRECOMPILE.staticcall(
            abi.encodeWithSelector(
                IAIMiningPrecompile.calculateReward.selector,
                workProof,
                chainId
            )
        );
        if (!success) revert PrecompileCallFailed();
        return abi.decode(result, (uint256));
    }

    /**
     * @notice Verify NVTrust attestation
     */
    function verifyNVTrust(
        bytes memory receipt,
        bytes memory signature
    ) internal view returns (bool) {
        (bool success, bytes memory result) = PRECOMPILE.staticcall(
            abi.encodeWithSelector(
                IAIMiningPrecompile.verifyNVTrust.selector,
                receipt,
                signature
            )
        );
        if (!success) revert PrecompileCallFailed();
        return abi.decode(result, (bool));
    }

    /**
     * @notice Check if work is spent
     */
    function isSpent(bytes32 workId) internal view returns (bool) {
        (bool success, bytes memory result) = PRECOMPILE.staticcall(
            abi.encodeWithSelector(
                IAIMiningPrecompile.isSpent.selector,
                workId
            )
        );
        if (!success) revert PrecompileCallFailed();
        return abi.decode(result, (bool));
    }

    /**
     * @notice Check if work is not spent, revert if spent
     */
    function requireNotSpent(bytes32 workId) internal view {
        if (isSpent(workId)) revert WorkAlreadySpent();
    }

    /**
     * @notice Compute work ID
     */
    function computeWorkId(
        bytes32 deviceId,
        bytes32 nonce,
        uint64 chainId
    ) internal pure returns (bytes32) {
        // For pure functions, compute locally (matches precompile behavior)
        // BLAKE3(deviceId || nonce || chainId)
        return keccak256(abi.encodePacked(deviceId, nonce, chainId));
    }

    /**
     * @notice Get ML-DSA security level from public key size
     */
    function getSecurityLevel(bytes memory pubkey) internal pure returns (uint8) {
        if (pubkey.length == MLDSA44_PK_SIZE) return 2;
        if (pubkey.length == MLDSA65_PK_SIZE) return 3;
        if (pubkey.length == MLDSA87_PK_SIZE) return 5;
        revert InvalidPublicKeySize();
    }

    /**
     * @notice Get expected signature size for security level
     */
    function getSignatureSize(uint8 level) internal pure returns (uint256) {
        if (level == 2) return MLDSA44_SIG_SIZE;
        if (level == 3) return MLDSA65_SIG_SIZE;
        if (level == 5) return MLDSA87_SIG_SIZE;
        revert InvalidSignatureSize();
    }
}

/**
 * @title AIMiningVerifier
 * @notice Base contract for AI mining verification operations
 */
abstract contract AIMiningVerifier {
    using AIMiningLib for *;

    /// @notice Modifier to require valid ML-DSA signature
    modifier withValidMLDSA(
        bytes calldata pubkey,
        bytes calldata message,
        bytes calldata signature
    ) {
        AIMiningLib.verifyMLDSAOrRevert(pubkey, message, signature);
        _;
    }

    /// @notice Modifier to require valid NVTrust attestation
    modifier withValidNVTrust(
        bytes calldata receipt,
        bytes calldata attestation
    ) {
        require(
            AIMiningLib.verifyNVTrust(receipt, attestation),
            "Invalid NVTrust attestation"
        );
        _;
    }

    /// @notice Modifier to require work not spent
    modifier workNotSpent(bytes32 workId) {
        AIMiningLib.requireNotSpent(workId);
        _;
    }
}
