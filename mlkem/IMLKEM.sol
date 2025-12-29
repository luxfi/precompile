// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

pragma solidity ^0.8.20;

/**
 * @title IMLKEM
 * @notice Interface for the ML-KEM (FIPS 203) key encapsulation precompile
 * @dev Precompile address: 0x0200000000000000000000000000000000000007
 *
 * ML-KEM provides post-quantum secure key encapsulation for establishing
 * shared secrets between parties. This precompile supports three security levels:
 * - ML-KEM-512: 128-bit security (NIST Level 1)
 * - ML-KEM-768: 192-bit security (NIST Level 3)
 * - ML-KEM-1024: 256-bit security (NIST Level 5)
 *
 * See LP-4318 for full specification.
 */
interface IMLKEM {
    /// @notice ML-KEM mode for 128-bit security (NIST Level 1)
    uint8 constant MODE_MLKEM_512 = 0x00;

    /// @notice ML-KEM mode for 192-bit security (NIST Level 3)
    uint8 constant MODE_MLKEM_768 = 0x01;

    /// @notice ML-KEM mode for 256-bit security (NIST Level 5)
    uint8 constant MODE_MLKEM_1024 = 0x02;

    /// @notice Key sizes for ML-KEM-512
    uint256 constant MLKEM_512_PUBLIC_KEY_SIZE = 800;
    uint256 constant MLKEM_512_PRIVATE_KEY_SIZE = 1632;
    uint256 constant MLKEM_512_CIPHERTEXT_SIZE = 768;

    /// @notice Key sizes for ML-KEM-768
    uint256 constant MLKEM_768_PUBLIC_KEY_SIZE = 1184;
    uint256 constant MLKEM_768_PRIVATE_KEY_SIZE = 2400;
    uint256 constant MLKEM_768_CIPHERTEXT_SIZE = 1088;

    /// @notice Key sizes for ML-KEM-1024
    uint256 constant MLKEM_1024_PUBLIC_KEY_SIZE = 1568;
    uint256 constant MLKEM_1024_PRIVATE_KEY_SIZE = 3168;
    uint256 constant MLKEM_1024_CIPHERTEXT_SIZE = 1568;

    /// @notice Shared secret size (same for all modes)
    uint256 constant SHARED_SECRET_SIZE = 32;

    /**
     * @notice Encapsulate a shared secret using a public key
     * @param mode The ML-KEM mode (0=512, 1=768, 2=1024)
     * @param publicKey The recipient's public key
     * @return ciphertext The encapsulated ciphertext to send to recipient
     * @return sharedSecret The 32-byte shared secret
     */
    function encapsulate(
        uint8 mode,
        bytes calldata publicKey
    ) external view returns (
        bytes memory ciphertext,
        bytes32 sharedSecret
    );

    /**
     * @notice Decapsulate a ciphertext to recover the shared secret
     * @param mode The ML-KEM mode (0=512, 1=768, 2=1024)
     * @param privateKey The recipient's private key
     * @param ciphertext The encapsulated ciphertext from sender
     * @return sharedSecret The 32-byte shared secret
     */
    function decapsulate(
        uint8 mode,
        bytes calldata privateKey,
        bytes calldata ciphertext
    ) external view returns (bytes32 sharedSecret);
}

/**
 * @title MLKEMCaller
 * @notice Helper library for calling the ML-KEM precompile
 */
library MLKEMCaller {
    address constant MLKEM_PRECOMPILE = 0x0200000000000000000000000000000000000007;

    uint8 constant OP_ENCAPSULATE = 0x01;
    uint8 constant OP_DECAPSULATE = 0x02;

    error MLKEMCallFailed();
    error InvalidResultLength();

    /**
     * @notice Encapsulate using ML-KEM-768 (recommended)
     */
    function encapsulate768(bytes memory publicKey) internal view returns (bytes memory ciphertext, bytes32 sharedSecret) {
        return encapsulate(IMLKEM.MODE_MLKEM_768, publicKey);
    }

    /**
     * @notice Decapsulate using ML-KEM-768 (recommended)
     */
    function decapsulate768(bytes memory privateKey, bytes memory ciphertext) internal view returns (bytes32 sharedSecret) {
        return decapsulate(IMLKEM.MODE_MLKEM_768, privateKey, ciphertext);
    }

    /**
     * @notice Encapsulate with specified mode
     */
    function encapsulate(uint8 mode, bytes memory publicKey) internal view returns (bytes memory ciphertext, bytes32 sharedSecret) {
        bytes memory input = abi.encodePacked(OP_ENCAPSULATE, mode, publicKey);

        (bool success, bytes memory result) = MLKEM_PRECOMPILE.staticcall(input);
        if (!success) revert MLKEMCallFailed();

        // Result is ciphertext || sharedSecret(32 bytes)
        if (result.length < 32) revert InvalidResultLength();

        uint256 ctLen = result.length - 32;
        ciphertext = new bytes(ctLen);
        for (uint256 i = 0; i < ctLen; i++) {
            ciphertext[i] = result[i];
        }

        assembly {
            sharedSecret := mload(add(add(result, 32), ctLen))
        }
    }

    /**
     * @notice Decapsulate with specified mode
     */
    function decapsulate(uint8 mode, bytes memory privateKey, bytes memory ciphertext) internal view returns (bytes32 sharedSecret) {
        bytes memory input = abi.encodePacked(OP_DECAPSULATE, mode, privateKey, ciphertext);

        (bool success, bytes memory result) = MLKEM_PRECOMPILE.staticcall(input);
        if (!success) revert MLKEMCallFailed();

        if (result.length != 32) revert InvalidResultLength();

        assembly {
            sharedSecret := mload(add(result, 32))
        }
    }
}
