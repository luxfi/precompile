// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IFHE
 * @notice Interface for the FHE precompile at 0x0200000000000000000000000000000000000080
 * @dev Provides fully homomorphic encryption operations for Lux blockchain
 *      Powered by CKKS scheme via luxfi/lattice with threshold decryption
 */
interface IFHE {
    // ============ Encryption Types ============
    // ebool   - encrypted boolean (1 bit)
    // euint8  - encrypted 8-bit unsigned integer
    // euint16 - encrypted 16-bit unsigned integer
    // euint32 - encrypted 32-bit unsigned integer
    // euint64 - encrypted 64-bit unsigned integer
    // euint128 - encrypted 128-bit unsigned integer
    // euint256 - encrypted 256-bit unsigned integer
    // eaddress - encrypted address (160 bits)

    // ============ Encryption Operations ============
    
    /// @notice Encrypt a uint64 value
    /// @param value The plaintext value to encrypt
    /// @return handle The encrypted value handle
    function asEuint64(uint64 value) external returns (bytes32 handle);

    /// @notice Encrypt a uint128 value
    function asEuint128(uint128 value) external returns (bytes32 handle);

    /// @notice Encrypt a uint256 value
    function asEuint256(uint256 value) external returns (bytes32 handle);

    /// @notice Encrypt an address
    function asEaddress(address value) external returns (bytes32 handle);

    /// @notice Encrypt a boolean
    function asEbool(bool value) external returns (bytes32 handle);

    // ============ Arithmetic Operations ============

    /// @notice Add two encrypted values
    function add(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Subtract two encrypted values
    function sub(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Multiply two encrypted values
    function mul(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Divide two encrypted values
    function div(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Modulo of two encrypted values
    function rem(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Negate an encrypted value
    function neg(bytes32 a) external returns (bytes32 result);

    // ============ Comparison Operations ============

    /// @notice Check if a < b (encrypted)
    function lt(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Check if a <= b (encrypted)
    function le(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Check if a > b (encrypted)
    function gt(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Check if a >= b (encrypted)
    function ge(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Check if a == b (encrypted)
    function eq(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Check if a != b (encrypted)
    function ne(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Return the minimum of two encrypted values
    function min(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Return the maximum of two encrypted values
    function max(bytes32 a, bytes32 b) external returns (bytes32 result);

    // ============ Bitwise Operations ============

    /// @notice Bitwise AND of two encrypted values
    function and(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Bitwise OR of two encrypted values
    function or(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Bitwise XOR of two encrypted values
    function xor(bytes32 a, bytes32 b) external returns (bytes32 result);

    /// @notice Bitwise NOT of an encrypted value
    function not(bytes32 a) external returns (bytes32 result);

    /// @notice Shift left
    function shl(bytes32 a, bytes32 bits) external returns (bytes32 result);

    /// @notice Shift right
    function shr(bytes32 a, bytes32 bits) external returns (bytes32 result);

    /// @notice Rotate left
    function rotl(bytes32 a, bytes32 bits) external returns (bytes32 result);

    /// @notice Rotate right
    function rotr(bytes32 a, bytes32 bits) external returns (bytes32 result);

    // ============ Conditional Operations ============

    /// @notice Conditional select: if condition then ifTrue else ifFalse
    function select(bytes32 condition, bytes32 ifTrue, bytes32 ifFalse) external returns (bytes32 result);

    // ============ Randomness ============

    /// @notice Generate encrypted random value of specified type
    /// @param ctType The ciphertext type (0=bool, 4=uint64, etc.)
    function rand(uint8 ctType) external returns (bytes32 result);

    // ============ Type Casting ============

    /// @notice Cast encrypted value to different type
    function cast(bytes32 value, uint8 toType) external returns (bytes32 result);

    // ============ Require Operations ============

    /// @notice Require that encrypted boolean is true, revert otherwise
    /// @dev Triggers threshold decryption and blocks until result
    function require_(bytes32 condition) external;

    /// @notice Require with custom error message
    function require_(bytes32 condition, string calldata message) external;
}

/**
 * @title IACL
 * @notice Access Control List for encrypted values
 * @dev Located at 0x0200000000000000000000000000000000000081
 */
interface IACL {
    /// @notice Grant access to an address for an encrypted value
    function allow(bytes32 handle, address allowedAddr) external;

    /// @notice Grant access to the calling contract
    function allowThis(bytes32 handle) external;

    /// @notice Make encrypted value accessible to all (public)
    function allowForAll(bytes32 handle) external;

    /// @notice Check if an address has access to an encrypted value
    function isAllowed(bytes32 handle, address addr) external view returns (bool);

    /// @notice Revoke access from an address
    function revoke(bytes32 handle, address revokedAddr) external;

    /// @notice Revoke public access
    function revokeForAll(bytes32 handle) external;

    /// @notice Get the owner of an encrypted value
    function getOwner(bytes32 handle) external view returns (address);

    /// @notice Transfer ownership of an encrypted value
    function transferOwnership(bytes32 handle, address newOwner) external;

    // Events
    event AccessGranted(bytes32 indexed handle, address indexed owner, address indexed allowedAddr);
    event AccessRevoked(bytes32 indexed handle, address indexed owner, address indexed revokedAddr);
    event OwnershipTransferred(bytes32 indexed handle, address indexed previousOwner, address indexed newOwner);
}

/**
 * @title IFHEDecrypt
 * @notice FHE Decryption precompile for async threshold decryption via T-Chain
 * @dev Located at 0x0200000000000000000000000000000000000083
 */
interface IFHEDecrypt {
    /// @notice Request decryption of an encrypted value
    /// @param handle The encrypted value handle
    /// @param ctType The ciphertext type
    /// @return requestId The decryption request ID
    function requestDecryption(bytes32 handle, uint8 ctType) external returns (bytes32 requestId);

    /// @notice Request decryption with callback
    /// @param handle The encrypted value handle
    /// @param ctType The ciphertext type
    /// @param callback Contract to call when decryption completes
    /// @param callbackSelector Function selector to call
    function requestDecryptionWithCallback(
        bytes32 handle,
        uint8 ctType,
        address callback,
        bytes4 callbackSelector
    ) external returns (bytes32 requestId);

    /// @notice Get decryption result (poll-based)
    /// @param requestId The decryption request ID
    /// @return result The decrypted value (if ready)
    /// @return ready Whether the result is available
    function getDecryptResult(bytes32 requestId) external view returns (bytes memory result, bool ready);

    /// @notice Fulfill a decryption request (called by T-Chain relayer)
    /// @param requestId The request ID
    /// @param result The decrypted plaintext value
    function fulfillDecryption(bytes32 requestId, bytes calldata result) external;

    // Events
    event DecryptionRequested(bytes32 indexed requestId, bytes32 indexed handle, uint8 ctType, address requester);
    event DecryptionFulfilled(bytes32 indexed requestId, bytes result);
}
