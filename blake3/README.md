# Blake3 Precompile

**Address**: `0x0000000000000000000000000000000000000504`

Blake3 hash function precompile for the Lux EVM.

## Overview

Blake3 is a cryptographic hash function that is:
- **Fast**: 6-17x faster than SHA-3 and SHA-256
- **Parallelizable**: Can utilize multiple cores
- **Versatile**: Supports XOF (extendable output), KDF, and MAC
- **Simple**: Single algorithm for all use cases

## Operations

| Operation | Selector | Gas Cost | Description |
|-----------|----------|----------|-------------|
| `hash256` | `0x01` | 100 + 3/word | Standard 32-byte hash |
| `hash512` | `0x02` | 150 + 3/word | Extended 64-byte hash |
| `hashXOF` | `0x03` | 200 + 3/in + 5/out | Arbitrary length output |
| `hashWithDomain` | `0x04` | 150 + 3/word | Domain-separated hash |
| `merkleRoot` | `0x10` | 500 + 100/leaf | Merkle tree root |
| `deriveKey` | `0x20` | 300 + 3/word | Key derivation |

## Input Formats

### hash256 (0x01)
```
[1 byte: 0x01][data...]
```
Returns: 32 bytes

### hash512 (0x02)
```
[1 byte: 0x02][data...]
```
Returns: 64 bytes

### hashXOF (0x03)
```
[1 byte: 0x03][4 bytes: output_length][data...]
```
Returns: `output_length` bytes (max 1024)

### hashWithDomain (0x04)
```
[1 byte: 0x04][1 byte: domain_length][domain bytes][data...]
```
Returns: 32 bytes

### merkleRoot (0x10)
```
[1 byte: 0x10][4 bytes: num_leaves][32 bytes: leaf_0][32 bytes: leaf_1]...
```
Returns: 32 bytes (Merkle root)

### deriveKey (0x20)
```
[1 byte: 0x20][1 byte: context_length][context bytes][32 bytes: key_material]
```
Returns: 32 bytes (derived key)

## Solidity Usage

```solidity
import {Blake3Lib} from "./IBlake3.sol";

contract MyContract {
    using Blake3Lib for bytes;
    
    function hashData(bytes memory data) external view returns (bytes32) {
        return Blake3Lib.hash256(data);
    }
    
    function buildMerkleRoot(bytes32[] memory leaves) external view returns (bytes32) {
        return Blake3Lib.merkleRoot(leaves);
    }
    
    function deriveEncryptionKey(bytes32 masterKey) external view returns (bytes32) {
        return Blake3Lib.deriveKey("MyApp.encryption.v1", masterKey);
    }
}
```

## Use Cases

### 1. Fast Hashing
Blake3 is ideal for high-throughput applications that need fast hashing:
- Content addressing
- Transaction hashing
- State root computation

### 2. Merkle Trees
Built-in Merkle tree root computation:
- Rollup state commitments
- Data availability proofs
- Batch transaction verification

### 3. Key Derivation
Domain-separated key derivation for:
- Hierarchical key generation
- Deterministic wallet derivation
- Protocol-specific key isolation

### 4. Commitments
Domain-separated hashing for:
- Commit-reveal schemes
- Privacy protocols
- Zero-knowledge commitments

## Security Considerations

1. **Not Post-Quantum**: Blake3 uses classical construction. For quantum-resistant hashing, use Poseidon2 (0x0502) or SHAKE256.

2. **Domain Separation**: Always use domain-separated hashing for different purposes to prevent cross-protocol attacks.

3. **XOF Mode**: When using XOF, ensure output length matches security requirements (256 bits = 128-bit security).

## Performance

| Operation | Input Size | Gas Cost | Time (M1 Max) |
|-----------|------------|----------|---------------|
| hash256 | 1 KB | ~200 | ~1 μs |
| hash256 | 1 MB | ~100K | ~1 ms |
| merkleRoot | 256 leaves | ~26K | ~50 μs |
| deriveKey | 32 bytes | ~300 | ~0.5 μs |

## Related Precompiles

| Address | Precompile | Use Case |
|---------|------------|----------|
| 0x0502 | Pedersen | ZK-friendly commitments |
| 0x0503 | Poseidon2 | Post-quantum ZK hashing |
| 0x0504 | Blake3 | Fast general-purpose hashing |
| 0x031D | KZG4844 | Blob commitments (EIP-4844) |

## Standards

- [Blake3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Blake3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
