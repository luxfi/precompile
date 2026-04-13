// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IComputeMarket - AI Compute Marketplace Precompile
/// @notice Native EVM precompile for decentralized AI compute coordination
/// @dev Precompile address: 0x0300000000000000000000000000000000000010
/// @dev Integrates with A-Chain TEE attestation for compute verification
interface IComputeMarket {
    error InvalidInput();
    error NotProvider();
    error JobNotFound();
    error JobAlreadyClaimed();

    event ProviderRegistered(bytes32 indexed providerId, address indexed owner, bytes32 gpuType);
    event JobSubmitted(bytes32 indexed jobId, address indexed submitter, bytes32 modelHash, uint256 maxPrice);
    event RewardClaimed(bytes32 indexed jobId, address indexed provider, bytes32 outputHash);
    event ComputeVerified(bytes32 indexed jobId);

    /// @notice Register as a compute provider with GPU and TEE attestation
    /// @param gpuType GPU hardware identifier (e.g., keccak256("A100-80GB"))
    /// @param teeAttestation TEE attestation data from A-Chain
    /// @return providerId Unique provider identifier
    function registerProvider(
        bytes32 gpuType,
        bytes32 teeAttestation
    ) external returns (bytes32 providerId);

    /// @notice Submit a compute job to the marketplace
    /// @param modelHash Hash of the AI model to execute
    /// @param inputHash Hash of the input data
    /// @param maxPrice Maximum price willing to pay (in wei)
    /// @return jobId Unique job identifier
    function submitJob(
        bytes32 modelHash,
        bytes32 inputHash,
        uint256 maxPrice
    ) external returns (bytes32 jobId);

    /// @notice Claim reward for completing a compute job
    /// @param jobId The job to claim
    /// @param outputHash Hash of the computation output
    /// @return success Whether the claim was accepted
    function claimReward(
        bytes32 jobId,
        bytes32 outputHash
    ) external returns (bool success);

    /// @notice Verify compute result using TEE attestation
    /// @param jobId The job to verify
    /// @param attestation TEE attestation proof (keccak256(jobId, outputHash))
    /// @return verified Whether the computation was verified
    function verifyCompute(
        bytes32 jobId,
        bytes32 attestation
    ) external returns (bool verified);

    /// @notice Get price estimate for a compute job
    /// @param modelHash Hash of the AI model
    /// @param inputSize Size of input data in bytes
    /// @return price Estimated price in wei
    function getPrice(
        bytes32 modelHash,
        uint256 inputSize
    ) external pure returns (uint256 price);
}
