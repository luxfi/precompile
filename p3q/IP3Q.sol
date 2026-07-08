// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IP3Q — Post-Quantum Pulsar Proof
 * @notice Interface for the P3Q EVM precompile at slot 0x012205.
 * @dev Precompile address: 0x0000000000000000000000000000000000012205
 *
 * Canonical reference:
 *   - LP-218 (ZAP-Native PQ-Secured Rollups via the P3Q Precompile)
 *   - HANZO-CRYPTO-SUITE §5.2 (P3Q definition)
 *   - ROADMAP-CRYPTO-STACK §B.11
 *
 * P3Q verifies Pulsar / FIPS 204 ML-DSA threshold signatures on-chain.
 * The cryptographic verifier core IS the FIPS 204 ML-DSA.Verify
 * algorithm — Pulsar's headline Class N1 claim is that a threshold-
 * ceremony signature is byte-equal to a single-party FIPS 204
 * signature on the same message and group public key.
 *
 * Distinction from sibling precompiles:
 *   - 0x012202 ML-DSA: generic single-party FIPS 204 verifier
 *   - 0x012204 Pulsar: generic Pulsar/threshold-FIPS-204 verifier
 *     (variable-length message support)
 *   - 0x012205 P3Q:    LP-218 rollup-commit verifier
 *     (32-byte fixed messageHash, Solidity-bool return)
 *
 * Primary consumer: LP-218 Tier-3 rollups. A rollup sequencer Pulsar-
 * signs the tuple (prev_root || new_root || batch_hash); the parent
 * L1 verifies the signature via P3Q inside normal block validation.
 *
 * Wire format (raw calldata, not Solidity-ABI-encoded):
 *
 *   [ 1 byte  ] kind (0x01 Pulsar / 0x02 Corona / 0x03 Magnetar)
 *   [ 1 byte  ] mode (0x44 / 0x65 / 0x87)
 *   [ 4 bytes ] pulsarSig length (big-endian uint32)
 *   [ N bytes ] pulsarSig
 *   [ 4 bytes ] groupPubKey length (big-endian uint32)
 *   [ M bytes ] groupPubKey
 *   [ 32 bytes ] messageHash
 *
 * The leading kind byte is mandatory: the precompile dispatches on it
 * (2026-06-03 single-slot / kind-byte decomplection) and rejects any
 * calldata whose first byte is not a known kind. This mirror encoder
 * MUST prepend it — omitting it makes the precompile read the mode byte
 * (0x44/0x65/0x87) as the kind and reject on the default branch.
 *
 * Output: 32-byte EVM-ABI bool (last byte 0x01 on verifying signature,
 * 0x00 on any verification failure). The precompile never reverts on
 * cryptographic failure — the Solidity caller decides whether `false`
 * is fatal.
 *
 * Gas cost: 50,000 base + 10 per input byte.
 *   - Canonical ML-DSA-65 (1952 pk + 3309 sig + 32 hash + 10 framing):
 *     ~103,030 gas (5303 bytes * 10 + 50,000)
 *   - Block budget at 12M gas: ~117 P3Q verifies per block
 *
 * Domain separation: every P3Q verify binds the FIPS 204 context
 * string `lux-evm-precompile-p3q-v1`. Mismatched context vs signer
 * causes rejection — prevents cross-precompile replay against the
 * 0x012204 Pulsar slot.
 */
interface IP3Q {
    /**
     * @notice Verify a Pulsar threshold signature over a 32-byte hash.
     * @dev Encodes the LP-218 ABI per the wire format documented above.
     *      Solidity callers should prefer the P3QLib.verify() helper
     *      below, which packs the calldata correctly.
     * @param pulsarSig Serialized Pulsar threshold signature
     *        (byte-equal to single-party FIPS 204 ML-DSA signature).
     * @param messageHash 32-byte digest of the signed payload
     *        (typically H(prev_root || new_root || batch_hash)).
     * @param groupPubKey Pulsar group public key
     *        (byte-equal to single-party FIPS 204 ML-DSA public key).
     * @return valid True iff the signature verifies under the
     *         FIPS 204 ML-DSA.Verify(groupPubKey, messageHash,
     *         pulsarSig, "lux-evm-precompile-p3q-v1") predicate.
     */
    function verifyPulsarSig(
        bytes calldata pulsarSig,
        bytes32 messageHash,
        bytes calldata groupPubKey
    ) external view returns (bool valid);
}

/**
 * @title P3QLib
 * @notice Helper library that packs the LP-218 wire format and
 *         dispatches to the P3Q precompile via staticcall.
 *
 *         Solidity contracts should consume P3Q through this library
 *         rather than constructing the calldata themselves — the
 *         library is the canonical wire-format encoder for the
 *         precompile (mirror of Go's p3q.EncodeInput).
 */
library P3QLib {
    /// @notice Precompile address (LP-218 + HANZO-CRYPTO-SUITE §5.2).
    address constant P3Q = address(uint160(0x012205));

    /// @notice P3Q family kind (wire byte 0). Slot 0x012205 dispatches
    ///         on this byte; Pulsar (FIPS 204 ML-DSA) is the only wired
    ///         kind today (Corona / Magnetar reserved).
    uint8 constant KIND_PULSAR = 0x01;

    /// @notice ML-DSA parameter set identifiers (FIPS 204 §4 Table 1).
    uint8 constant MODE_MLDSA44 = 0x44; // NIST PQ Category 2
    uint8 constant MODE_MLDSA65 = 0x65; // NIST PQ Category 3 (default)
    uint8 constant MODE_MLDSA87 = 0x87; // NIST PQ Category 5

    /// @notice Base gas cost (LP-218 §"Honest cost comparison").
    uint256 constant BASE_GAS = 50_000;

    /// @notice Per-byte gas adder (serialization / wire-parse).
    uint256 constant PER_BYTE_GAS = 10;

    /// @notice Revert sentinel for caller-side verification failure.
    error P3QVerificationFailed();

    /// @notice Revert sentinel for unsupported mode parameter.
    error P3QUnsupportedMode(uint8 mode);

    /**
     * @notice Verify a Pulsar threshold signature; revert on failure.
     * @param mode FIPS 204 parameter set (0x44 / 0x65 / 0x87).
     * @param pulsarSig Pulsar threshold signature bytes.
     * @param groupPubKey Pulsar group public key bytes.
     * @param messageHash 32-byte digest of the signed payload.
     */
    function verifyOrRevert(
        uint8 mode,
        bytes memory pulsarSig,
        bytes memory groupPubKey,
        bytes32 messageHash
    ) internal view {
        if (mode != MODE_MLDSA44 && mode != MODE_MLDSA65 && mode != MODE_MLDSA87) {
            revert P3QUnsupportedMode(mode);
        }
        if (!verify(mode, pulsarSig, groupPubKey, messageHash)) {
            revert P3QVerificationFailed();
        }
    }

    /**
     * @notice Verify a Pulsar threshold signature; return bool.
     * @param mode FIPS 204 parameter set (0x44 / 0x65 / 0x87).
     * @param pulsarSig Pulsar threshold signature bytes.
     * @param groupPubKey Pulsar group public key bytes.
     * @param messageHash 32-byte digest of the signed payload.
     * @return valid True iff the signature verifies.
     */
    function verify(
        uint8 mode,
        bytes memory pulsarSig,
        bytes memory groupPubKey,
        bytes32 messageHash
    ) internal view returns (bool valid) {
        bytes memory input = encode(mode, pulsarSig, groupPubKey, messageHash);
        uint256 gasLimit = BASE_GAS + (input.length * PER_BYTE_GAS) + 1;
        bytes memory out = new bytes(32);
        bool ok;
        // staticcall — the precompile is stateless and pure
        // cryptographic.
        assembly {
            ok := staticcall(
                gasLimit,
                P3Q,
                add(input, 0x20),
                mload(input),
                add(out, 0x20),
                32
            )
        }
        if (!ok) {
            return false;
        }
        // The 32-byte ABI bool: last byte 0x01 == true.
        bytes32 word;
        assembly { word := mload(add(out, 0x20)) }
        return uint256(word) == 1;
    }

    /**
     * @notice Pack the LP-218 wire format. Canonical encoder; mirror
     *         of Go's p3q.EncodeInput. Any deviation between this
     *         encoder and the precompile's parser is a bug in one or
     *         the other.
     *
     *         Wire layout:
     *           [ 1 byte ] kind (KIND_PULSAR)
     *           [ 1 byte ] mode
     *           [ 4 bytes ] uint32(sigLen)  BE
     *           [ N bytes ] sig
     *           [ 4 bytes ] uint32(pkLen)   BE
     *           [ M bytes ] pk
     *           [ 32 bytes ] messageHash
     */
    function encode(
        uint8 mode,
        bytes memory pulsarSig,
        bytes memory groupPubKey,
        bytes32 messageHash
    ) internal pure returns (bytes memory out) {
        uint32 sigLen = uint32(pulsarSig.length);
        uint32 pkLen = uint32(groupPubKey.length);
        out = abi.encodePacked(
            KIND_PULSAR,
            mode,
            sigLen,
            pulsarSig,
            pkLen,
            groupPubKey,
            messageHash
        );
    }

    /**
     * @notice Estimate gas for a given input layout.
     * @param sigLen Pulsar signature length in bytes.
     * @param pkLen  Pulsar public key length in bytes.
     * @return gasEstimate Total gas cost (base + per-byte).
     */
    function estimateGas(uint256 sigLen, uint256 pkLen) internal pure returns (uint256) {
        // 1 kind + 1 mode + 4 sigLen + 4 pkLen + 32 hash framing.
        uint256 inputLen = 1 + 1 + 4 + sigLen + 4 + pkLen + 32;
        return BASE_GAS + inputLen * PER_BYTE_GAS;
    }
}
