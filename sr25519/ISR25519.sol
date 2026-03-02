// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISR25519 — Substrate sr25519 signature verification precompile
/// @notice Verifies sr25519 (Schnorrkel) signatures with "substrate" signing context.
/// @dev Used for Substrate → EVM account migration attestation.
///      Precompile address: 0x0A00000000000000000000000000000000000001
interface ISR25519 {
    /// @notice Verify an sr25519 signature.
    /// @param publicKey  32-byte Ristretto255 compressed public key (SS58-decoded)
    /// @param signature  64-byte Schnorrkel signature (R || s)
    /// @param message    Raw message bytes that were signed
    /// @return valid     True if the signature is valid
    function verify(
        bytes32 publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external view returns (bool valid);
}

/// @title SR25519Lib — Helper library for calling the sr25519 precompile
library SR25519Lib {
    address internal constant SR25519_PRECOMPILE = 0x0A00000000000000000000000000000000000001;

    /// @notice Low-level staticcall to the sr25519 precompile.
    /// @dev Input format: pubkey(32) || signature(64) || message(N)
    ///      Output: 32-byte word, last byte = 1 if valid, 0 if invalid.
    function verify(
        bytes32 publicKey,
        bytes memory signature,
        bytes memory message
    ) internal view returns (bool) {
        require(signature.length == 64, "SR25519: sig must be 64 bytes");
        require(message.length > 0, "SR25519: empty message");

        bytes memory input = abi.encodePacked(publicKey, signature, message);
        (bool ok, bytes memory result) = SR25519_PRECOMPILE.staticcall(input);
        if (!ok || result.length < 32) return false;
        return uint256(bytes32(result)) == 1;
    }

    /// @notice Verify or revert.
    function verifyOrRevert(
        bytes32 publicKey,
        bytes memory signature,
        bytes memory message
    ) internal view {
        require(verify(publicKey, signature, message), "SR25519: invalid signature");
    }
}

/// @title SubstrateMigration — Example migration contract using sr25519 verification
/// @dev Old Substrate account signs "migrate:<evmAddress>" to prove ownership,
///      then claims the EVM address on-chain.
contract SubstrateMigration {
    using SR25519Lib for bytes32;

    mapping(bytes32 => address) public migrations; // sr25519 pubkey → EVM address
    mapping(address => bytes32) public origins;     // EVM address → sr25519 pubkey

    event Migrated(bytes32 indexed substratePubKey, address indexed evmAddress);

    /// @notice Claim an EVM address by proving ownership of a Substrate sr25519 key.
    /// @param substratePubKey The 32-byte sr25519 public key
    /// @param signature       The 64-byte sr25519 signature over the migration message
    function migrate(bytes32 substratePubKey, bytes calldata signature) external {
        require(migrations[substratePubKey] == address(0), "already migrated");

        // The message that must be signed: "migrate:" + hex-encoded EVM address
        bytes memory message = abi.encodePacked("migrate:", msg.sender);

        substratePubKey.verifyOrRevert(signature, message);

        migrations[substratePubKey] = msg.sender;
        origins[msg.sender] = substratePubKey;

        emit Migrated(substratePubKey, msg.sender);
    }
}
