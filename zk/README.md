# ZK Precompiles

Zero-Knowledge proof verification and privacy operations for Lux EVM.

## Overview

The ZK precompile suite provides comprehensive support for:

- **Proof Verification**: Groth16, PLONK, fflonk, Halo2
- **Commitment Schemes**: KZG, Pedersen, IPA
- **Privacy Operations**: Confidential pools, nullifiers, range proofs
- **Rollup Support**: ZK rollup batch verification, state roots

## Precompile Addresses

### Core ZK Verification

| Address | Precompile | Gas Cost | Description |
|---------|-----------|----------|-------------|
| `0x0900` | ZKVerifier | Variable | Generic ZK proof verification |
| `0x0901` | Groth16 | ~200,000 | Groth16 SNARK verification |
| `0x0902` | PLONK | ~250,000 | PLONK proof verification |
| `0x0903` | fflonk | ~180,000 | Optimized PLONK variant |
| `0x0904` | Halo2 | ~300,000 | Recursive proof verification |

### Commitment Schemes

| Address | Precompile | Gas Cost | Description |
|---------|-----------|----------|-------------|
| `0x0501` | Poseidon2 | ~5,000 | PQ-safe hash commitment |
| `0x0502` | Pedersen | ~10,000 | Elliptic curve commitment |
| `0x0910` | KZG | ~50,000 | Polynomial commitment (EIP-4844) |
| `0x0912` | IPA | ~30,000 | Inner product argument |

### Privacy Operations

| Address | Precompile | Gas Cost | Description |
|---------|-----------|----------|-------------|
| `0x0920` | PrivacyPool | ~100,000 | Confidential transaction pool |
| `0x0921` | Nullifier | ~5,000 | Double-spend prevention |
| `0x0922` | Commitment | ~10,000 | Commitment verification |
| `0x0923` | RangeProof | ~100,000 | Bulletproofs range verification |

### Rollup Support

| Address | Precompile | Gas Cost | Description |
|---------|-----------|----------|-------------|
| `0x0930` | RollupVerify | ~500,000 | ZK rollup batch verification |
| `0x0931` | StateRoot | ~50,000 | State root verification |
| `0x0932` | BatchProof | ~200,000 | Proof aggregation |

## Usage

### Solidity

```solidity
import "@luxfi/precompile/zk/IZK.sol";

contract MyZKApp {
    using ZKLib for *;

    bytes32 public verifyingKeyId;

    function verifyTransfer(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        return ZKLib.verifyGroth16(
            verifyingKeyId,
            proofA,
            proofB,
            proofC,
            publicInputs
        );
    }
}
```

### PLONK Verification

```solidity
contract PLONKVerifier {
    using ZKLib for *;

    function verifyPlonkProof(
        bytes32 vkId,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        return ZKLib.verifyPlonk(vkId, proof, publicInputs);
    }
}
```

### Range Proofs (Bulletproofs)

```solidity
contract ConfidentialToken {
    using ZKLib for *;

    function verifyConfidentialTransfer(
        bytes calldata senderCommitment,
        bytes calldata recipientCommitment,
        bytes calldata rangeProofSender,
        bytes calldata rangeProofRecipient
    ) external view returns (bool) {
        // Verify both amounts are in valid range (64-bit)
        require(ZKLib.verifyRange(senderCommitment, rangeProofSender, 64), "Invalid sender range");
        require(ZKLib.verifyRange(recipientCommitment, rangeProofRecipient, 64), "Invalid recipient range");
        return true;
    }
}
```

### ZK Rollup Integration

```solidity
contract L2Settlement {
    using ZKLib for *;

    bytes32 public rollupId;
    bytes32 public stateRoot;

    function settleBatch(RollupBatch calldata batch) external {
        require(ZKLib.verifyRollupBatch(rollupId, batch), "Invalid batch proof");
        require(batch.prevStateRoot == stateRoot, "State mismatch");
        stateRoot = batch.newStateRoot;
    }
}
```

## GPU Acceleration

The ZK precompiles leverage GPU acceleration via Metal shaders for Apple Silicon:

### Accelerated Operations

| Operation | CPU Time | GPU Time | Speedup |
|-----------|----------|----------|---------|
| Groth16 Verify | 12ms | 1.5ms | 8x |
| PLONK Verify | 18ms | 2ms | 9x |
| KZG Verify | 3ms | 0.4ms | 7.5x |
| MSM (256 pts) | 45ms | 3ms | 15x |
| FFT (2^16) | 120ms | 8ms | 15x |

### Metal Shader Files

```
luxcpp/crypto/src/metal/
├── bn254.metal      # BN254 curve operations (Pedersen, Groth16)
├── kzg.metal        # KZG polynomial commitments
├── blake3.metal     # Blake3 hash (Merkle trees)
├── metal_zk.h       # C++ header
└── metal_zk.mm      # Objective-C++ implementation
```

## Proof Systems

### Groth16

- **Verification**: Constant size (3 G1 + 1 G2)
- **Trusted Setup**: Required (circuit-specific)
- **Use Cases**: Token transfers, DeFi, identity

```solidity
struct Groth16Proof {
    uint256[2] a;      // G1 point
    uint256[2][2] b;   // G2 point
    uint256[2] c;      // G1 point
}
```

### PLONK

- **Verification**: Larger proofs (~1KB)
- **Trusted Setup**: Universal (one-time)
- **Use Cases**: General computation, rollups

### Halo2

- **Verification**: Recursive composition
- **Trusted Setup**: None required
- **Use Cases**: Incremental verification, IVC

## Privacy Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PRIVACY POOL ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DEPOSIT                                WITHDRAW                            │
│  ┌─────────────┐                        ┌─────────────┐                     │
│  │  Generate   │                        │ Generate    │                     │
│  │ Commitment  │                        │ Nullifier   │                     │
│  │ C = H(v,r)  │                        │ N = H(sk)   │                     │
│  └──────┬──────┘                        └──────┬──────┘                     │
│         │                                      │                             │
│         ▼                                      ▼                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                     │
│  │   Deposit   │───>│  Merkle     │<───│   ZK Proof  │                     │
│  │   Token     │    │   Tree      │    │  Verify +   │                     │
│  └─────────────┘    └──────┬──────┘    │  Withdraw   │                     │
│                            │           └─────────────┘                     │
│                            ▼                                                │
│                     ┌─────────────┐                                        │
│                     │ Commitment  │                                        │
│                     │    Pool     │                                        │
│                     └─────────────┘                                        │
│                                                                              │
│  Proof verifies:                                                            │
│    1. Commitment exists in Merkle tree                                     │
│    2. Nullifier correctly derived from secret                              │
│    3. Output commitment correctly formed                                    │
│    4. No double-spending (nullifier not in spent set)                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Rollup Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ZK ROLLUP ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  L2 SEQUENCER                          L1 VERIFIER                          │
│  ┌─────────────┐                       ┌─────────────┐                      │
│  │ Batch       │                       │ Verify      │                      │
│  │ Transactions│                       │ ZK Proof    │                      │
│  └──────┬──────┘                       └──────┬──────┘                      │
│         │                                     │                              │
│         ▼                                     ▼                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                      │
│  │  Execute    │───>│  Generate   │───>│  Update     │                      │
│  │  & Compute  │    │  ZK Proof   │    │  State Root │                      │
│  │  New State  │    │             │    │             │                      │
│  └─────────────┘    └─────────────┘    └─────────────┘                      │
│                                                                              │
│  Batch contains:                                                            │
│    - Previous state root                                                    │
│    - New state root                                                         │
│    - Transaction count                                                      │
│    - Validity proof (Groth16/PLONK/Halo2)                                   │
│    - L1 batch number                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Post-Quantum Status

| Precompile | PQ-Safe | Notes |
|------------|---------|-------|
| Groth16 | ❌ | Discrete log on BN254 |
| PLONK | ❌ | Discrete log on BN254 |
| KZG | ❌ | Pairing-based |
| Pedersen | ❌ | Elliptic curve DL |
| Poseidon2 | ✅ | Hash-based |
| Bulletproofs | ❌ | Discrete log |

For post-quantum security, use:
- **Poseidon2** (`0x0501`) for commitments
- **ML-DSA** (`0x0300`) for signatures
- **Ringtail** for threshold signatures

### Trusted Setup

| System | Setup Type | Trust Assumption |
|--------|------------|------------------|
| Groth16 | Circuit-specific | Ceremony participants |
| PLONK | Universal | Single ceremony |
| KZG | Universal | Powers of tau ceremony |
| Halo2 | None | Cryptographic assumptions |

## Integration with Lux Privacy Layer

The ZK precompiles integrate with the Z-Chain privacy layer:

1. **Shielded Transactions**: Use privacy pools for confidential transfers
2. **Private DeFi**: Range proofs for confidential AMM operations
3. **ZK Rollups**: Native L2 scaling with validity proofs
4. **Cross-Chain Privacy**: Warp messaging with ZK attestations

## Files

```
zk/
├── commitment.go       # Commitment utilities
├── commitment_test.go  # Commitment tests
├── IZK.sol            # Solidity interfaces
├── module.go          # Module registration
├── pedersen.go        # Pedersen commitments
├── poseidon.go        # Poseidon2 hash
├── README.md          # This file
├── stark.go           # STARK support
├── types.go           # Type definitions
├── verifier.go        # Main verifier
└── verifier_test.go   # Verifier tests
```

## Related Precompiles

- **Blake3** (`0x0504`): Fast hashing for Merkle trees
- **KZG4844** (`0x031D`): EIP-4844 blob commitments
- **FHE** (`0x0200`): Homomorphic encryption
- **Warp** (`0x0008`): Cross-chain messaging

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [PLONK Paper](https://eprint.iacr.org/2019/953)
- [Halo2 Book](https://zcash.github.io/halo2/)
- [EIP-4844](https://eips.ethereum.org/EIPS/eip-4844)
- [Bulletproofs](https://eprint.iacr.org/2017/1066)
