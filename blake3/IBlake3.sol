// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

pragma solidity ^0.8.24;

/**
 * @title IBlake3
 * @notice Interface for Blake3 hash precompile at 0x0504
 * @dev Blake3 is a fast cryptographic hash function that:
 *      - Is 6-17x faster than SHA-3 and SHA-256
 *      - Supports arbitrary-length output (XOF)
 *      - Is suitable for Merkle tree and KDF use cases
 *
 * Gas costs:
 *   - hash256: 100 + 3 per 32-byte word
 *   - hash512: 150 + 3 per 32-byte word
 *   - hashXOF: 200 + 3 per input word + 5 per output word
 *   - hashWithDomain: 150 + 3 per 32-byte word
 *   - merkleRoot: 500 + 100 per leaf
 *   - deriveKey: 300 + 3 per 32-byte word
 */
interface IBlake3 {
    /**
     * @notice Compute 32-byte Blake3 hash
     * @param data Input data to hash
     * @return digest 32-byte hash output
     */
    function hash256(bytes calldata data) external view returns (bytes32 digest);

    /**
     * @notice Compute 64-byte Blake3 hash
     * @param data Input data to hash
     * @return digest 64-byte hash output
     */
    function hash512(bytes calldata data) external view returns (bytes memory digest);

    /**
     * @notice Compute arbitrary-length Blake3 hash using XOF mode
     * @param data Input data to hash
     * @param outputLength Desired output length (max 1024 bytes)
     * @return digest Variable-length hash output
     */
    function hashXOF(bytes calldata data, uint32 outputLength) external view returns (bytes memory digest);

    /**
     * @notice Compute domain-separated Blake3 hash
     * @param domain Domain separator string
     * @param data Input data to hash
     * @return digest 32-byte hash output
     */
    function hashWithDomain(string calldata domain, bytes calldata data) external view returns (bytes32 digest);

    /**
     * @notice Compute Merkle tree root from leaf hashes
     * @param leaves Array of 32-byte leaf hashes
     * @return root Merkle tree root hash
     */
    function merkleRoot(bytes32[] calldata leaves) external view returns (bytes32 root);

    /**
     * @notice Derive a key using Blake3 KDF
     * @param context Context string for domain separation
     * @param keyMaterial 32-byte key material
     * @return derivedKey 32-byte derived key
     */
    function deriveKey(string calldata context, bytes32 keyMaterial) external view returns (bytes32 derivedKey);
}

/**
 * @title Blake3Lib
 * @notice Library for calling Blake3 precompile with proper encoding
 * @dev Address: 0x0000000000000000000000000000000000000504
 */
library Blake3Lib {
    address internal constant BLAKE3_ADDRESS = 0x0000000000000000000000000000000000000504;

    // Operation selectors
    uint8 internal constant OP_HASH256 = 0x01;
    uint8 internal constant OP_HASH512 = 0x02;
    uint8 internal constant OP_HASH_XOF = 0x03;
    uint8 internal constant OP_HASH_WITH_DOMAIN = 0x04;
    uint8 internal constant OP_MERKLE_ROOT = 0x10;
    uint8 internal constant OP_DERIVE_KEY = 0x20;

    error Blake3CallFailed();
    error InvalidOutputLength();

    /**
     * @notice Compute 32-byte Blake3 hash
     * @param data Input data to hash
     * @return digest 32-byte hash
     */
    function hash256(bytes memory data) internal view returns (bytes32 digest) {
        bytes memory input = abi.encodePacked(OP_HASH256, data);
        (bool success, bytes memory result) = BLAKE3_ADDRESS.staticcall(input);
        if (!success || result.length != 32) revert Blake3CallFailed();
        return bytes32(result);
    }

    /**
     * @notice Compute 64-byte Blake3 hash
     * @param data Input data to hash
     * @return digest 64-byte hash
     */
    function hash512(bytes memory data) internal view returns (bytes memory digest) {
        bytes memory input = abi.encodePacked(OP_HASH512, data);
        (bool success, bytes memory result) = BLAKE3_ADDRESS.staticcall(input);
        if (!success || result.length != 64) revert Blake3CallFailed();
        return result;
    }

    /**
     * @notice Compute arbitrary-length Blake3 hash
     * @param data Input data to hash
     * @param outputLength Desired output length (1-1024 bytes)
     * @return digest Variable-length hash
     */
    function hashXOF(bytes memory data, uint32 outputLength) internal view returns (bytes memory digest) {
        if (outputLength == 0 || outputLength > 1024) revert InvalidOutputLength();
        bytes memory input = abi.encodePacked(OP_HASH_XOF, outputLength, data);
        (bool success, bytes memory result) = BLAKE3_ADDRESS.staticcall(input);
        if (!success || result.length != outputLength) revert Blake3CallFailed();
        return result;
    }

    /**
     * @notice Compute domain-separated Blake3 hash
     * @param domain Domain separator (max 255 bytes)
     * @param data Input data to hash
     * @return digest 32-byte hash
     */
    function hashWithDomain(string memory domain, bytes memory data) internal view returns (bytes32 digest) {
        bytes memory domainBytes = bytes(domain);
        require(domainBytes.length <= 255, "Domain too long");
        bytes memory input = abi.encodePacked(OP_HASH_WITH_DOMAIN, uint8(domainBytes.length), domainBytes, data);
        (bool success, bytes memory result) = BLAKE3_ADDRESS.staticcall(input);
        if (!success || result.length != 32) revert Blake3CallFailed();
        return bytes32(result);
    }

    /**
     * @notice Compute Merkle tree root from leaf hashes
     * @param leaves Array of 32-byte leaf hashes (max 1024)
     * @return root Merkle tree root
     */
    function merkleRoot(bytes32[] memory leaves) internal view returns (bytes32 root) {
        require(leaves.length <= 1024, "Too many leaves");
        bytes memory input = abi.encodePacked(OP_MERKLE_ROOT, uint32(leaves.length));
        for (uint256 i = 0; i < leaves.length; i++) {
            input = abi.encodePacked(input, leaves[i]);
        }
        (bool success, bytes memory result) = BLAKE3_ADDRESS.staticcall(input);
        if (!success || result.length != 32) revert Blake3CallFailed();
        return bytes32(result);
    }

    /**
     * @notice Derive a key using Blake3 KDF
     * @param context Context string for domain separation (max 255 bytes)
     * @param keyMaterial 32-byte key material
     * @return derivedKey 32-byte derived key
     */
    function deriveKey(string memory context, bytes32 keyMaterial) internal view returns (bytes32 derivedKey) {
        bytes memory contextBytes = bytes(context);
        require(contextBytes.length <= 255, "Context too long");
        bytes memory input = abi.encodePacked(OP_DERIVE_KEY, uint8(contextBytes.length), contextBytes, keyMaterial);
        (bool success, bytes memory result) = BLAKE3_ADDRESS.staticcall(input);
        if (!success || result.length != 32) revert Blake3CallFailed();
        return bytes32(result);
    }

    /**
     * @notice Verify a Merkle proof
     * @param leaf The leaf hash to verify
     * @param proof Array of sibling hashes from leaf to root
     * @param index Index of the leaf in the tree
     * @param root Expected Merkle root
     * @return valid True if proof is valid
     */
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] memory proof,
        uint256 index,
        bytes32 root
    ) internal view returns (bool valid) {
        bytes32 computedHash = leaf;
        
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            
            bytes32[] memory pair = new bytes32[](2);
            if (index % 2 == 0) {
                pair[0] = computedHash;
                pair[1] = proofElement;
            } else {
                pair[0] = proofElement;
                pair[1] = computedHash;
            }
            
            computedHash = merkleRoot(pair);
            index = index / 2;
        }
        
        return computedHash == root;
    }
}

/**
 * @title Blake3Consumer
 * @notice Example contract demonstrating Blake3 precompile usage
 */
abstract contract Blake3Consumer {
    using Blake3Lib for bytes;
    using Blake3Lib for bytes32[];
    using Blake3Lib for string;

    /**
     * @notice Hash data using Blake3
     * @param data Data to hash
     * @return 32-byte hash
     */
    function _blake3Hash(bytes memory data) internal view returns (bytes32) {
        return Blake3Lib.hash256(data);
    }

    /**
     * @notice Compute commitment hash with domain separation
     * @param domain Domain identifier
     * @param data Data to commit
     * @return commitment Domain-separated commitment hash
     */
    function _computeCommitment(string memory domain, bytes memory data) internal view returns (bytes32) {
        return Blake3Lib.hashWithDomain(domain, data);
    }

    /**
     * @notice Build Merkle tree and get root
     * @param items Items to include in tree
     * @return root Merkle tree root
     */
    function _buildMerkleRoot(bytes32[] memory items) internal view returns (bytes32) {
        return Blake3Lib.merkleRoot(items);
    }
}
