// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZK - Zero-Knowledge Precompile Interfaces
 * @notice Comprehensive ZK proof verification and privacy operations
 * @dev Precompile addresses: 0x0900-0x0932
 * 
 * Address Map:
 *   0x0900 - Generic ZK verification
 *   0x0901 - Groth16 verifier
 *   0x0902 - PLONK verifier
 *   0x0903 - fflonk verifier
 *   0x0904 - Halo2 verifier
 *   0x0910 - KZG commitments
 *   0x0912 - Inner product arguments (IPA)
 *   0x0920 - Privacy pool operations
 *   0x0921 - Nullifier verification
 *   0x0922 - Commitment verification
 *   0x0923 - Range proof verification (Bulletproofs)
 *   0x0930 - ZK rollup batch verification
 *   0x0931 - State root verification
 *   0x0932 - Batch proof aggregation
 */

// ============================================================================
// TYPES AND ENUMS
// ============================================================================

/// @notice Proof system types
enum ProofSystem {
    Groth16,
    Plonk,
    Fflonk,
    Halo2,
    Stark
}

/// @notice Predefined circuit types
enum CircuitType {
    Transfer,      // Token transfer
    Mint,          // Token minting
    Burn,          // Token burning
    Swap,          // DEX swap
    Liquidity,     // Liquidity provision
    RollupBatch,   // Rollup batch
    Custom         // Custom circuit
}

/// @notice Commitment scheme types
enum CommitmentType {
    Pedersen,
    KZG,
    IPA,
    Hash
}

/// @notice Verification result
struct VerificationResult {
    bool valid;
    ProofSystem proofSystem;
    CircuitType circuitType;
    uint256[] publicInputs;
    uint256 gasUsed;
}

/// @notice Groth16 proof structure
struct Groth16Proof {
    uint256[2] a;     // G1 point
    uint256[2][2] b;  // G2 point
    uint256[2] c;     // G1 point
}

/// @notice PLONK proof structure (variable length)
struct PlonkProof {
    bytes proof;
    uint256[] publicInputs;
}

/// @notice Verifying key for Groth16
struct Groth16VerifyingKey {
    uint256[2] alpha;
    uint256[2][2] beta;
    uint256[2][2] gamma;
    uint256[2][2] delta;
    uint256[2][] ic;
}

/// @notice Range proof data
struct RangeProof {
    bytes commitment;
    bytes proof;
    uint32 bitLength;
}

/// @notice Rollup batch structure
struct RollupBatch {
    bytes32 batchId;
    bytes32 rollupId;
    bytes32 prevStateRoot;
    bytes32 newStateRoot;
    uint64 transactionCount;
    bytes proof;
    uint64 l1BatchNum;
    uint64 timestamp;
    address proposer;
}

// ============================================================================
// CORE INTERFACES
// ============================================================================

/**
 * @title IZKVerifier
 * @notice Main ZK verification interface at 0x0900
 */
interface IZKVerifier {
    /// @notice Register a new verifying key
    function registerVerifyingKey(
        ProofSystem proofSystem,
        CircuitType circuitType,
        bytes calldata vkData
    ) external returns (bytes32 keyId);

    /// @notice Get verifying key info
    function getVerifyingKey(bytes32 keyId) external view returns (
        ProofSystem proofSystem,
        CircuitType circuitType,
        address owner,
        uint256 createdAt
    );

    /// @notice Verify a proof using registered key
    function verify(
        bytes32 keyId,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool valid);

    /// @notice Get verification statistics
    function getStats() external view returns (
        uint256 totalVerifications,
        uint256 totalValid,
        uint256 totalFailed
    );
}

/**
 * @title IGroth16Verifier
 * @notice Groth16 proof verification at 0x0901
 * @dev Gas: ~200,000 per verification
 */
interface IGroth16Verifier {
    /// @notice Verify Groth16 proof with verifying key ID
    function verify(
        bytes32 vkId,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[] calldata publicInputs
    ) external view returns (bool);

    /// @notice Verify Groth16 proof with inline verifying key
    function verifyWithVK(
        Groth16VerifyingKey calldata vk,
        Groth16Proof calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);

    /// @notice Batch verify multiple proofs
    function batchVerify(
        bytes32[] calldata vkIds,
        Groth16Proof[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view returns (bool[] memory results);
}

/**
 * @title IPlonkVerifier
 * @notice PLONK proof verification at 0x0902
 * @dev Gas: ~250,000 per verification
 */
interface IPlonkVerifier {
    /// @notice Verify PLONK proof
    function verify(
        bytes32 vkId,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);

    /// @notice Verify PLONK proof with custom gate constraints
    function verifyCustom(
        bytes calldata verifyingKey,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

/**
 * @title IFflonkVerifier
 * @notice fflonk proof verification at 0x0903
 * @dev Optimized PLONK variant with faster verification
 */
interface IFflonkVerifier {
    /// @notice Verify fflonk proof
    function verify(
        bytes calldata verifyingKey,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

/**
 * @title IHalo2Verifier
 * @notice Halo2 proof verification at 0x0904
 * @dev Recursive proof composition support
 */
interface IHalo2Verifier {
    /// @notice Verify Halo2 proof
    function verify(
        bytes calldata verifyingKey,
        bytes calldata proof,
        bytes calldata instances
    ) external view returns (bool);

    /// @notice Verify recursively composed proof
    function verifyRecursive(
        bytes calldata outerVK,
        bytes calldata outerProof,
        bytes calldata innerInstances
    ) external view returns (bool);
}

// ============================================================================
// COMMITMENT INTERFACES
// ============================================================================

/**
 * @title IKZG
 * @notice KZG polynomial commitment operations at 0x0910
 * @dev Compatible with EIP-4844 blob commitments
 * @dev Gas: ~50,000 per point evaluation
 */
interface IKZG {
    /// @notice Verify a point evaluation proof
    /// @param commitment The polynomial commitment (48 bytes)
    /// @param z The evaluation point
    /// @param y The claimed evaluation value
    /// @param proof The KZG proof (48 bytes)
    function verifyEvaluation(
        bytes calldata commitment,
        bytes32 z,
        bytes32 y,
        bytes calldata proof
    ) external view returns (bool);

    /// @notice Verify EIP-4844 blob commitment
    function verifyBlob(
        bytes calldata blobCommitment,
        bytes calldata blobProof,
        bytes32 versionedHash
    ) external view returns (bool);

    /// @notice Batch verify multiple KZG proofs
    function batchVerify(
        bytes[] calldata commitments,
        bytes32[] calldata zs,
        bytes32[] calldata ys,
        bytes[] calldata proofs
    ) external view returns (bool);

    /// @notice Compute commitment from polynomial coefficients
    function commit(uint256[] calldata coefficients) external view returns (bytes memory);
}

/**
 * @title IIPA
 * @notice Inner Product Argument operations at 0x0912
 */
interface IIPA {
    /// @notice Verify an inner product proof
    function verifyInnerProduct(
        bytes calldata commitment,
        bytes calldata proof,
        uint256[] calldata a,
        uint256[] calldata b,
        uint256 innerProduct
    ) external view returns (bool);
}

// ============================================================================
// PRIVACY INTERFACES
// ============================================================================

/**
 * @title IPrivacyPool
 * @notice Confidential transaction pool operations at 0x0920
 */
interface IPrivacyPool {
    /// @notice Create a new confidential pool
    function createPool(
        address token,
        uint32 merkleDepth
    ) external returns (bytes32 poolId);

    /// @notice Deposit into confidential pool
    function deposit(
        bytes32 poolId,
        bytes calldata commitment,
        uint256 value
    ) external returns (bytes32 commitmentId);

    /// @notice Withdraw from confidential pool with proof
    function withdraw(
        bytes32 poolId,
        bytes calldata nullifier,
        bytes calldata recipient,
        uint256 value,
        bytes calldata proof,
        bytes32[] calldata merkleProof
    ) external returns (bool);

    /// @notice Get pool merkle root
    function getMerkleRoot(bytes32 poolId) external view returns (bytes32);

    /// @notice Get pool info
    function getPoolInfo(bytes32 poolId) external view returns (
        address token,
        bytes32 merkleRoot,
        uint32 merkleDepth,
        uint256 totalDeposits,
        bool enabled
    );
}

/**
 * @title INullifier
 * @notice Nullifier operations for double-spend prevention at 0x0921
 */
interface INullifier {
    /// @notice Check if nullifier has been spent
    function isSpent(bytes32 nullifierHash) external view returns (bool);

    /// @notice Mark nullifier as spent (only callable by privacy pool)
    function spend(bytes32 nullifierHash) external returns (bool);

    /// @notice Batch check nullifiers
    function batchIsSpent(bytes32[] calldata nullifiers) external view returns (bool[] memory);

    /// @notice Event emitted when nullifier is spent
    event NullifierSpent(bytes32 indexed nullifierHash, address indexed pool, uint256 timestamp);
}

/**
 * @title ICommitment
 * @notice Commitment verification operations at 0x0922
 */
interface ICommitment {
    /// @notice Verify commitment opening
    function verifyOpening(
        CommitmentType commitType,
        bytes calldata commitment,
        uint256 value,
        bytes calldata blinding
    ) external view returns (bool);

    /// @notice Verify commitment is in merkle tree
    function verifyInclusion(
        bytes32 root,
        bytes32 commitmentHash,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external view returns (bool);

    /// @notice Compute Pedersen commitment
    function pedersenCommit(
        uint256 value,
        uint256 blinding
    ) external view returns (bytes memory commitment);

    /// @notice Verify Pedersen commitment
    function pedersenVerify(
        bytes calldata commitment,
        uint256 value,
        uint256 blinding
    ) external view returns (bool);
}

/**
 * @title IRangeProof
 * @notice Bulletproofs-style range proof verification at 0x0923
 * @dev Gas: ~100,000 per verification
 */
interface IRangeProof {
    /// @notice Verify range proof
    /// @param commitment The value commitment
    /// @param proof The range proof
    /// @param bitLength Maximum bits in the value
    function verifyRangeProof(
        bytes calldata commitment,
        bytes calldata proof,
        uint32 bitLength
    ) external view returns (bool);

    /// @notice Generate range proof (off-chain, returns estimated gas)
    function estimateGas(uint32 bitLength) external pure returns (uint256);

    /// @notice Batch verify multiple range proofs
    function batchVerify(
        bytes[] calldata commitments,
        bytes[] calldata proofs,
        uint32[] calldata bitLengths
    ) external view returns (bool);
}

// ============================================================================
// ROLLUP INTERFACES
// ============================================================================

/**
 * @title IRollupVerifier
 * @notice ZK rollup batch verification at 0x0930
 * @dev Gas: ~500,000 per batch verification
 */
interface IRollupVerifier {
    /// @notice Register a new ZK rollup
    function registerRollup(
        bytes32 verifyingKeyId,
        ProofSystem proofSystem,
        uint64 maxTxPerBatch,
        uint64 batchInterval,
        address sequencer
    ) external returns (bytes32 rollupId);

    /// @notice Verify and submit a rollup batch
    function verifyBatch(
        bytes32 rollupId,
        RollupBatch calldata batch
    ) external returns (bool);

    /// @notice Get rollup state
    function getRollupState(bytes32 rollupId) external view returns (
        bytes32 lastBatchId,
        bytes32 lastStateRoot,
        uint64 lastL1Block,
        uint64 totalBatches,
        uint64 totalTxs
    );

    /// @notice Get rollup configuration
    function getRollupConfig(bytes32 rollupId) external view returns (
        address owner,
        ProofSystem proofSystem,
        uint64 maxTxPerBatch,
        uint64 batchInterval,
        uint64 challengeWindow,
        address sequencer,
        bool enabled
    );

    /// @notice Challenge a fraudulent batch (for optimistic rollups)
    function challenge(
        bytes32 rollupId,
        bytes32 batchId,
        bytes calldata fraudProof
    ) external returns (bool);

    /// @notice Events
    event RollupRegistered(bytes32 indexed rollupId, address indexed owner, ProofSystem proofSystem);
    event BatchVerified(bytes32 indexed rollupId, bytes32 indexed batchId, bytes32 newStateRoot);
    event BatchChallenged(bytes32 indexed rollupId, bytes32 indexed batchId, address challenger);
}

/**
 * @title IStateRoot
 * @notice State root verification at 0x0931
 */
interface IStateRoot {
    /// @notice Verify state root transition
    function verifyTransition(
        bytes32 prevStateRoot,
        bytes32 newStateRoot,
        bytes32 txRoot,
        bytes calldata proof
    ) external view returns (bool);

    /// @notice Verify account proof against state root
    function verifyAccountProof(
        bytes32 stateRoot,
        address account,
        bytes calldata proof
    ) external view returns (
        uint256 nonce,
        uint256 balance,
        bytes32 storageRoot,
        bytes32 codeHash
    );

    /// @notice Verify storage proof against storage root
    function verifyStorageProof(
        bytes32 storageRoot,
        bytes32 slot,
        bytes calldata proof
    ) external view returns (bytes32 value);
}

/**
 * @title IBatchProof
 * @notice Batch proof aggregation at 0x0932
 */
interface IBatchProof {
    /// @notice Aggregate multiple proofs into one
    function aggregate(
        bytes32[] calldata vkIds,
        bytes[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view returns (bytes memory aggregatedProof);

    /// @notice Verify aggregated proof
    function verifyAggregated(
        bytes32[] calldata vkIds,
        bytes calldata aggregatedProof,
        uint256[][] calldata publicInputs
    ) external view returns (bool);
}

// ============================================================================
// HELPER LIBRARY
// ============================================================================

/**
 * @title ZKLib
 * @notice Convenience library for ZK operations
 */
library ZKLib {
    // Precompile addresses
    address constant ZK_VERIFY = address(0x0900);
    address constant GROTH16 = address(0x0901);
    address constant PLONK = address(0x0902);
    address constant FFLONK = address(0x0903);
    address constant HALO2 = address(0x0904);
    address constant KZG = address(0x0910);
    address constant IPA = address(0x0912);
    address constant PRIVACY_POOL = address(0x0920);
    address constant NULLIFIER = address(0x0921);
    address constant COMMITMENT = address(0x0922);
    address constant RANGE_PROOF = address(0x0923);
    address constant ROLLUP_VERIFY = address(0x0930);
    address constant STATE_ROOT = address(0x0931);
    address constant BATCH_PROOF = address(0x0932);

    /// @notice Verify Groth16 proof with automatic precompile call
    function verifyGroth16(
        bytes32 vkId,
        uint256[2] memory proofA,
        uint256[2][2] memory proofB,
        uint256[2] memory proofC,
        uint256[] memory publicInputs
    ) internal view returns (bool) {
        (bool success, bytes memory result) = GROTH16.staticcall(
            abi.encodeCall(IGroth16Verifier.verify, (vkId, proofA, proofB, proofC, publicInputs))
        );
        return success && abi.decode(result, (bool));
    }

    /// @notice Verify PLONK proof with automatic precompile call
    function verifyPlonk(
        bytes32 vkId,
        bytes memory proof,
        uint256[] memory publicInputs
    ) internal view returns (bool) {
        (bool success, bytes memory result) = PLONK.staticcall(
            abi.encodeCall(IPlonkVerifier.verify, (vkId, proof, publicInputs))
        );
        return success && abi.decode(result, (bool));
    }

    /// @notice Verify KZG point evaluation
    function verifyKZG(
        bytes memory commitment,
        bytes32 z,
        bytes32 y,
        bytes memory proof
    ) internal view returns (bool) {
        (bool success, bytes memory result) = KZG.staticcall(
            abi.encodeCall(IKZG.verifyEvaluation, (commitment, z, y, proof))
        );
        return success && abi.decode(result, (bool));
    }

    /// @notice Verify range proof
    function verifyRange(
        bytes memory commitment,
        bytes memory proof,
        uint32 bitLength
    ) internal view returns (bool) {
        (bool success, bytes memory result) = RANGE_PROOF.staticcall(
            abi.encodeCall(IRangeProof.verifyRangeProof, (commitment, proof, bitLength))
        );
        return success && abi.decode(result, (bool));
    }

    /// @notice Check if nullifier is spent
    function isNullifierSpent(bytes32 nullifierHash) internal view returns (bool) {
        (bool success, bytes memory result) = NULLIFIER.staticcall(
            abi.encodeCall(INullifier.isSpent, (nullifierHash))
        );
        return success && abi.decode(result, (bool));
    }

    /// @notice Verify rollup batch
    function verifyRollupBatch(
        bytes32 rollupId,
        RollupBatch memory batch
    ) internal view returns (bool) {
        (bool success, bytes memory result) = ROLLUP_VERIFY.staticcall(
            abi.encodeCall(IRollupVerifier.verifyBatch, (rollupId, batch))
        );
        return success && abi.decode(result, (bool));
    }

    /// @notice Verify or revert with error
    function verifyOrRevert(
        bytes32 vkId,
        bytes memory proof,
        uint256[] memory publicInputs,
        ProofSystem system
    ) internal view {
        bool valid;
        if (system == ProofSystem.Groth16) {
            // Decode Groth16 proof structure
            (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = 
                abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
            valid = verifyGroth16(vkId, a, b, c, publicInputs);
        } else if (system == ProofSystem.Plonk) {
            valid = verifyPlonk(vkId, proof, publicInputs);
        } else {
            revert("Unsupported proof system");
        }
        require(valid, "Invalid ZK proof");
    }
}

// ============================================================================
// EXAMPLE CONSUMER CONTRACTS
// ============================================================================

/**
 * @title ZKConsumer
 * @notice Base contract for ZK proof consumers
 */
abstract contract ZKConsumer {
    using ZKLib for *;

    bytes32 public immutable verifyingKeyId;
    ProofSystem public immutable proofSystem;

    constructor(bytes32 _vkId, ProofSystem _system) {
        verifyingKeyId = _vkId;
        proofSystem = _system;
    }

    /// @notice Modifier to require valid proof
    modifier requiresProof(bytes calldata proof, uint256[] calldata publicInputs) {
        ZKLib.verifyOrRevert(verifyingKeyId, proof, publicInputs, proofSystem);
        _;
    }
}

/**
 * @title PrivateTransfer
 * @notice Example: Confidential token transfers with ZK proofs
 */
abstract contract PrivateTransfer is ZKConsumer {
    bytes32 public poolId;

    constructor(bytes32 _vkId, bytes32 _poolId) ZKConsumer(_vkId, ProofSystem.Groth16) {
        poolId = _poolId;
    }

    /// @notice Transfer tokens privately
    function privateTransfer(
        bytes calldata nullifier,
        bytes calldata newCommitment,
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32[] calldata merkleProof
    ) external requiresProof(proof, publicInputs) {
        // 1. Check nullifier not spent
        require(!ZKLib.isNullifierSpent(bytes32(nullifier)), "Nullifier spent");

        // 2. Mark nullifier as spent via precompile
        (bool success,) = ZKLib.NULLIFIER.call(
            abi.encodeCall(INullifier.spend, (bytes32(nullifier)))
        );
        require(success, "Failed to spend nullifier");

        // 3. Add new commitment to pool
        (success,) = ZKLib.PRIVACY_POOL.call(
            abi.encodeCall(IPrivacyPool.deposit, (poolId, newCommitment, 0))
        );
        require(success, "Failed to add commitment");
    }
}

/**
 * @title RollupSettlement
 * @notice Example: ZK rollup settlement contract
 */
abstract contract RollupSettlement {
    using ZKLib for *;

    bytes32 public rollupId;
    bytes32 public latestStateRoot;

    event BatchSettled(bytes32 indexed batchId, bytes32 newStateRoot, uint64 txCount);

    constructor(bytes32 _rollupId) {
        rollupId = _rollupId;
    }

    /// @notice Settle a verified batch
    function settleBatch(RollupBatch calldata batch) external {
        // Verify batch proof
        require(ZKLib.verifyRollupBatch(rollupId, batch), "Invalid batch proof");

        // Verify state transition
        require(batch.prevStateRoot == latestStateRoot, "Invalid prev state");

        // Update state
        latestStateRoot = batch.newStateRoot;

        emit BatchSettled(batch.batchId, batch.newStateRoot, batch.transactionCount);
    }
}
