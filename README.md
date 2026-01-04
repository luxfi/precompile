# Lux Precompiled Contracts

This directory contains all precompiled contracts (precompiles) for the Lux blockchain ecosystem. Precompiles are special smart contracts implemented natively in the node software for performance-critical operations that would be too expensive or slow to implement in Solidity.

## Overview

Precompiles are located at deterministic addresses starting from `0x0200000000000000000000000000000000000000`. They provide optimized implementations for cryptographic operations, cross-chain messaging, and chain configuration.

## Precompile Addresses

| Address | Name | Description | LP |
|---------|------|-------------|-----|
| `0x0200000000000000000000000000000000000001` | **DeployerAllowList** | Access control for contract deployment | LP-315 |
| `0x0200000000000000000000000000000000000002` | **TxAllowList** | Access control for transaction execution | LP-316 |
| `0x0200000000000000000000000000000000000003` | **FeeManager** | Dynamic fee configuration and management | LP-314 |
| `0x0200000000000000000000000000000000000004` | **NativeMinter** | Mint and burn native LUX tokens | LP-317 |
| `0x0200000000000000000000000000000000000005` | **RewardManager** | Validator reward distribution | LP-318 |
| `0x0200000000000000000000000000000000000006` | **ML-DSA** | Post-quantum signature verification (FIPS 204) | LP-311 |
| `0x0200000000000000000000000000000000000007` | **SLH-DSA** | Hash-based signature verification (FIPS 205) | LP-312 |
| `0x0200000000000000000000000000000000000008` | **Warp** | Cross-chain messaging and attestation | LP-313 |
| `0x0200000000000000000000000000000000000009` | **PQCrypto** | General post-quantum cryptography operations | LP-310 |
| `0x020000000000000000000000000000000000000A` | **Quasar** | Advanced consensus operations | LP-99 |
| `0x020000000000000000000000000000000000000B` | **Ringtail** | Lattice-based threshold signatures (LWE) | LP-320 |
| `0x020000000000000000000000000000000000000C` | **FROST** | Schnorr/EdDSA threshold signatures | LP-321 |
| `0x020000000000000000000000000000000000000D` | **CGGMP21** | ECDSA threshold signatures with aborts | LP-322 |
| `0x020000000000000000000000000000000000000E` | **Bridge** | Cross-chain bridge verification | LP-323 (Reserved) |

### Hashing & Commitment Precompiles

| Address | Name | Description | LP |
|---------|------|-------------|-----|
| `0x0000000000000000000000000000000000000501` | **Poseidon2** | PQ-safe hash commitment | - |
| `0x0000000000000000000000000000000000000502` | **Pedersen** | Elliptic curve commitment (BN254) | - |
| `0x0000000000000000000000000000000000000504` | **Blake3** | Fast hashing (6-17x faster than SHA-3) | - |

### Zero-Knowledge Precompiles

| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| `0x0000000000000000000000000000000000000900` | **ZKVerifier** | Generic ZK proof verification | Variable |
| `0x0000000000000000000000000000000000000901` | **Groth16** | Groth16 SNARK verification | ~200,000 |
| `0x0000000000000000000000000000000000000902` | **PLONK** | PLONK proof verification | ~250,000 |
| `0x0000000000000000000000000000000000000903` | **fflonk** | Optimized PLONK variant | ~180,000 |
| `0x0000000000000000000000000000000000000904` | **Halo2** | Recursive proof verification | ~300,000 |
| `0x0000000000000000000000000000000000000910` | **KZG** | Polynomial commitment (EIP-4844) | ~50,000 |
| `0x0000000000000000000000000000000000000912` | **IPA** | Inner product arguments | ~30,000 |
| `0x0000000000000000000000000000000000000920` | **PrivacyPool** | Confidential transaction pool | ~100,000 |
| `0x0000000000000000000000000000000000000921` | **Nullifier** | Double-spend prevention | ~5,000 |
| `0x0000000000000000000000000000000000000922` | **Commitment** | Commitment verification | ~10,000 |
| `0x0000000000000000000000000000000000000923` | **RangeProof** | Bulletproofs range verification | ~100,000 |
| `0x0000000000000000000000000000000000000930` | **RollupVerify** | ZK rollup batch verification | ~500,000 |
| `0x0000000000000000000000000000000000000931` | **StateRoot** | State root verification | ~50,000 |
| `0x0000000000000000000000000000000000000932` | **BatchProof** | Proof aggregation | ~200,000 |

## Categories

### 1. Access Control Precompiles

These precompiles manage permissions for critical blockchain operations:

#### DeployerAllowList (`0x...0001`)
- **Purpose**: Control which addresses can deploy smart contracts
- **Use Case**: Enterprise/private chains with deployment restrictions
- **Gas Cost**: Minimal (configuration reads)
- **Documentation**: [deployerallowlist/](./deployerallowlist/)

#### TxAllowList (`0x...0002`)
- **Purpose**: Control which addresses can submit transactions
- **Use Case**: Permissioned blockchains, compliance requirements
- **Gas Cost**: Minimal (configuration reads)
- **Documentation**: [txallowlist/](./txallowlist/)

### 2. Economic Precompiles

These precompiles manage blockchain economics and tokenomics:

#### FeeManager (`0x...0003`)
- **Purpose**: Configure gas fees, base fees, and EIP-1559 parameters
- **Use Case**: Dynamic fee adjustment, custom fee models
- **Gas Cost**: Varies by operation
- **Documentation**: [feemanager/](./feemanager/)
- **LP**: [LP-314](../../lps/LPs/lp-314.md)

#### NativeMinter (`0x...0004`)
- **Purpose**: Mint and burn native LUX tokens
- **Use Case**: Bridging, wrapping/unwrapping, supply management
- **Gas Cost**: Proportional to amount
- **Documentation**: [nativeminter/](./nativeminter/)

#### RewardManager (`0x...0005`)
- **Purpose**: Distribute staking and validation rewards
- **Use Case**: Validator compensation, staking yields
- **Gas Cost**: Proportional to recipient count
- **Documentation**: [rewardmanager/](./rewardmanager/)

### 3. Post-Quantum Cryptography Precompiles

These precompiles provide quantum-resistant cryptographic operations per NIST FIPS standards:

#### ML-DSA (`0x...0006`)
- **Purpose**: Verify ML-DSA-65 signatures (FIPS 204 - Dilithium)
- **Security Level**: NIST Level 3 (192-bit equivalent)
- **Key Sizes**:
  - Public Key: 1,952 bytes
  - Signature: 3,309 bytes
- **Performance**: ~108μs verification on Apple M1
- **Gas Cost**: 100,000 base + 10 gas/byte of message
- **Use Cases**:
  - Quantum-safe transaction authorization
  - Cross-chain message authentication
  - Post-quantum multisig wallets
- **Documentation**: [mldsa/](./mldsa/)
- **LP**: [LP-311](../../lps/LPs/lp-311.md)
- **Solidity Interface**: [mldsa/IMLDSA.sol](./mldsa/IMLDSA.sol)

#### SLH-DSA (`0x...0007`)
- **Purpose**: Verify SLH-DSA signatures (FIPS 205 - SPHINCS+)
- **Security Level**: NIST Level 1-5 (128-256 bit)
- **Key Sizes** (SLH-DSA-128s):
  - Public Key: 32 bytes
  - Signature: 7,856 bytes
- **Performance**: ~286μs verification on Apple M1
- **Gas Cost**: 15,000 base + 10 gas/byte of message
- **Use Cases**:
  - Hash-based quantum-safe signatures
  - Long-term signature validity (archival)
  - Conservative post-quantum security
  - Firmware update verification
- **Documentation**: [slhdsa/](./slhdsa/)
- **LP**: [LP-312](../../lps/LPs/lp-312.md)
- **Solidity Interface**: [slhdsa/ISLHDSA.sol](./slhdsa/ISLHDSA.sol)

#### PQCrypto (`0x...0009`)
- **Purpose**: General post-quantum cryptography operations
- **Operations**:
  - ML-KEM-768 key encapsulation (FIPS 203)
  - Hybrid classical+PQ operations
  - Quantum-safe key exchange
- **Documentation**: [pqcrypto/](./pqcrypto/)
- **LP**: [LP-310](../../lps/LPs/lp-310.md) *(to be created)*

### 4. Interoperability Precompiles

These precompiles enable cross-chain communication and messaging:

#### Warp (`0x...0008`)
- **Purpose**: Cross-chain message signing and verification
- **Features**:
  - BLS signature aggregation
  - Validator attestations
  - Cross-chain asset transfers
- **Performance**: ~1.5ms per BLS verification
- **Gas Cost**: Variable based on validator set size
- **Use Cases**:
  - Cross-chain token transfers
  - Multi-chain contract calls
  - Subnet synchronization
- **Documentation**: [warp/](./warp/)
- **LP**: [LP-313](../../lps/LPs/lp-313.md) *(to be created)*

### 5. Threshold Signature Precompiles

Multi-party computation and threshold signatures for custody and consensus:

#### Ringtail (`0x...000B`)
- **Purpose**: Lattice-based threshold signature verification
- **Algorithm**: LWE-based two-round threshold scheme
- **Security**: Post-quantum (Ring Learning With Errors)
- **Gas Cost**: 150,000 base + 10,000 per party
- **Use Cases**:
  - Quantum-safe threshold wallets
  - Distributed validator signing
  - Post-quantum consensus
  - Multi-party custody
- **Documentation**: [ringtail/](./ringtail/)
- **LP**: [LP-320](../../lps/LPs/lp-320.md)

#### FROST (`0x...000C`)
- **Purpose**: Schnorr/EdDSA threshold signature verification
- **Algorithm**: FROST (Flexible Round-Optimized Schnorr Threshold)
- **Standards**: IETF FROST, BIP-340/341 (Taproot)
- **Gas Cost**: 50,000 base + 5,000 per signer
- **Signature Size**: 64 bytes (compact Schnorr)
- **Use Cases**:
  - Bitcoin Taproot multisig
  - Ed25519 threshold (Solana, Cardano, TON)
  - Schnorr aggregate signatures
  - Lightweight threshold custody
- **Documentation**: [frost/](./frost/)
- **LP**: [LP-321](../../lps/LPs/lp-321.md)

#### CGGMP21 (`0x...000D`)
- **Purpose**: Modern ECDSA threshold signature verification
- **Algorithm**: CGGMP21 with identifiable aborts
- **Security**: Detects malicious parties
- **Gas Cost**: 75,000 base + 10,000 per signer
- **Signature Size**: 65 bytes (standard ECDSA)
- **Use Cases**:
  - Ethereum threshold wallets
  - Bitcoin threshold multisig
  - MPC custody solutions
  - Enterprise key management
- **Documentation**: [cggmp21/](./cggmp21/)
- **LP**: [LP-322](../../lps/LPs/lp-322.md)

### 6. Hashing Precompiles

Fast cryptographic hashing for Merkle trees and commitments:

#### Blake3 (`0x0504`)
- **Purpose**: High-performance hashing (6-17x faster than SHA-3)
- **Operations**:
  - `hash256`: Standard 256-bit hash
  - `hash512`: Extended 512-bit hash
  - `hashXOF`: Extensible output function (arbitrary length)
  - `hashWithDomain`: Domain-separated hashing
  - `merkleRoot`: Batch Merkle tree computation
  - `deriveKey`: KDF key derivation
- **Gas Cost**: 100 base + 3-5 gas/word
- **Use Cases**:
  - ZK Merkle trees
  - Content addressing
  - Key derivation
- **GPU Acceleration**: Metal shaders available
- **Documentation**: [blake3/](./blake3/)
- **Solidity Interface**: [blake3/IBlake3.sol](./blake3/IBlake3.sol)

#### Poseidon2 (`0x0501`)
- **Purpose**: ZK-friendly hash function (post-quantum safe)
- **Gas Cost**: ~5,000 per hash
- **Use Cases**: ZK circuits, commitments

#### Pedersen (`0x0502`)
- **Purpose**: Elliptic curve commitment on BN254
- **Gas Cost**: ~10,000 per commitment
- **Note**: NOT post-quantum safe (discrete log)
- **GPU Acceleration**: Metal shaders available

### 7. Zero-Knowledge Precompiles

Comprehensive ZK proof verification and privacy operations:

#### ZK Verifier (`0x0900`)
- **Purpose**: Generic ZK proof verification router
- **Features**:
  - Verifying key registration
  - Multi-proof-system support
  - Verification statistics
- **Documentation**: [zk/](./zk/)
- **Solidity Interface**: [zk/IZK.sol](./zk/IZK.sol)

#### Groth16 (`0x0901`)
- **Purpose**: Groth16 SNARK verification
- **Gas Cost**: ~200,000 per verification
- **Proof Size**: 128 bytes (2 G1 + 1 G2)
- **Trusted Setup**: Circuit-specific
- **GPU Acceleration**: BN254 pairing via Metal

#### PLONK (`0x0902`)
- **Purpose**: Universal PLONK verification
- **Gas Cost**: ~250,000 per verification
- **Proof Size**: ~1KB (variable)
- **Trusted Setup**: Universal (one-time)

#### fflonk (`0x0903`)
- **Purpose**: Optimized PLONK variant
- **Gas Cost**: ~180,000 per verification
- **Improvements**: Faster verification, smaller proofs

#### Halo2 (`0x0904`)
- **Purpose**: Recursive proof composition
- **Gas Cost**: ~300,000 per verification
- **Trusted Setup**: None required
- **Use Cases**: IVC, recursive rollups

#### KZG (`0x0910`)
- **Purpose**: Polynomial commitments (EIP-4844)
- **Gas Cost**: ~50,000 per evaluation
- **Use Cases**: Blob commitments, data availability
- **GPU Acceleration**: FFT and MSM via Metal

#### Privacy Pool (`0x0920`)
- **Purpose**: Confidential transaction pool
- **Features**: Merkle tree, deposit/withdraw
- **Gas Cost**: ~100,000 per operation

#### Nullifier (`0x0921`)
- **Purpose**: Double-spend prevention
- **Gas Cost**: ~5,000 per lookup

#### RangeProof (`0x0923`)
- **Purpose**: Bulletproofs range verification
- **Gas Cost**: ~100,000 per proof
- **Use Cases**: Confidential amounts

#### RollupVerify (`0x0930`)
- **Purpose**: ZK rollup batch verification
- **Gas Cost**: ~500,000 per batch
- **Features**:
  - Rollup registration
  - Batch verification
  - State root tracking
  - Challenge support

### 8. Consensus Precompiles

Advanced consensus and validation operations:

#### Quasar (`0x...000A`)
- **Purpose**: Advanced consensus operations for Quasar hybrid consensus
- **Features**:
  - Dual certificate verification (classical + PQ)
  - BLS signature aggregation
  - Hybrid BLS+ML-DSA verification
  - Verkle witness verification
- **Documentation**: [quasar/](./quasar/)
- **LP**: [LP-99](../../lps/LPs/lp-99.md)

## Implementation Structure

Each precompile directory contains:

```
<precompile-name>/
├── module.go          # Precompile module registration
├── contract.go        # Core precompile implementation
├── contract_test.go   # Go test suite
├── config.go          # Configuration structures (if applicable)
├── config_test.go     # Configuration tests
├── I<Name>.sol        # Solidity interface
├── contract.abi       # ABI definition (if applicable)
└── README.md          # Detailed documentation
```

## Development Guidelines

### Adding a New Precompile

1. **Choose an Address**: Select next available address in sequence
2. **Create Directory**: `mkdir -p src/precompiles/<name>`
3. **Implement Interface**: Must implement `StatefulPrecompiledContract`
4. **Write Tests**: Minimum 80% code coverage
5. **Create Solidity Interface**: Include full documentation
6. **Write LP**: Document specification in lps/LPs/
7. **Update This README**: Add to address table and category

### Required Interfaces

All precompiles must implement:

```go
type StatefulPrecompiledContract interface {
    // Address returns the precompile address
    Address() common.Address
    
    // RequiredGas calculates gas cost for input
    RequiredGas(input []byte) uint64
    
    // Run executes the precompile logic
    Run(
        accessibleState AccessibleState,
        caller common.Address,
        addr common.Address,
        input []byte,
        suppliedGas uint64,
        readOnly bool,
    ) ([]byte, uint64, error)
}
```

### Module Registration

Each precompile must provide a module for registration:

```go
type module struct {
    address  common.Address
    contract StatefulPrecompiledContract
}

func (m *module) Address() common.Address { 
    return m.address 
}

func (m *module) Contract() StatefulPrecompiledContract { 
    return m.contract 
}
```

### Gas Calculation Guidelines

Gas costs should reflect:
1. **Computational complexity**: Higher for crypto operations
2. **Memory usage**: Larger for big inputs/outputs
3. **State access**: More for state reads/writes
4. **Benchmarks**: Based on real performance measurements

Example gas formulas:
- **Simple state read**: ~2,000 gas
- **Cryptographic verification**: 50,000 - 500,000 gas
- **Per-byte processing**: 10 - 50 gas/byte
- **State writes**: ~20,000 gas per slot

## Testing Requirements

All precompiles must have:

1. **Unit Tests** (`contract_test.go`):
   - Valid input cases
   - Invalid input cases
   - Edge cases
   - Gas calculation verification

2. **Solidity Tests**:
   - Interface usage examples
   - Integration with other contracts
   - Gas benchmarks

3. **Benchmarks**:
   - Performance measurements
   - Gas cost validation
   - Comparison with pure Solidity implementation

## Security Considerations

### Input Validation
- **Always** validate input length before parsing
- Check for buffer overflows
- Validate all parameters against constraints

### Gas Limits
- Ensure gas costs prevent DoS attacks
- Test with maximum-size inputs
- Verify gas calculations don't overflow

### State Access
- Only modify state in non-read-only calls
- Validate caller permissions for privileged operations
- Ensure atomic state updates

### Cryptographic Operations
- Use constant-time implementations when possible
- Validate all cryptographic inputs
- Check signature/key sizes match expected values
- Test against known attack vectors

## Performance Benchmarks

Performance targets on Apple M1 (reference hardware):

### Signature Verification

| Operation | Target | Current |
|-----------|--------|---------|
| ML-DSA-65 Verify | < 150μs | ~108μs ✓ |
| SLH-DSA-192s Verify | < 20ms | ~15ms ✓ |
| BLS Signature Verify | < 2ms | ~1.5ms ✓ |
| FROST (3-of-5) | < 100μs | ~55μs ✓ |
| CGGMP21 (3-of-5) | < 150μs | ~80μs ✓ |

### ZK Proof Verification

| Operation | CPU | GPU (Metal) | Speedup |
|-----------|-----|-------------|---------|
| Groth16 Verify | 12ms | 1.5ms | 8x |
| PLONK Verify | 18ms | 2ms | 9x |
| KZG Point Eval | 3ms | 0.4ms | 7.5x |
| Range Proof (64-bit) | 8ms | 1ms | 8x |
| MSM (256 points) | 45ms | 3ms | 15x |
| FFT (2^16) | 120ms | 8ms | 15x |

### Hashing

| Operation | Target | Current |
|-----------|--------|---------|
| Blake3 256-bit | < 1μs/KB | ~0.3μs/KB ✓ |
| Blake3 Merkle (1K leaves) | < 100μs | ~45μs ✓ |
| Poseidon2 | < 10μs | ~5μs ✓ |

### State Operations

| Operation | Target | Current |
|-----------|--------|---------|
| State Read | < 5μs | ~2μs ✓ |
| State Write | < 10μs | ~5μs ✓ |

## Documentation Standards

Each precompile must document:

1. **Purpose and Use Cases**: Why it exists, when to use it
2. **Input/Output Format**: Exact byte layouts with examples
3. **Gas Costs**: Formula and examples
4. **Error Conditions**: All possible failure modes
5. **Security Considerations**: Potential vulnerabilities
6. **Examples**: Both Go and Solidity usage

## References

- **Lux Precompile Standards (LPS)**: [../lps/](../../lps/)
- **EVM Precompiles**: [../evm/](../../evm/)
- **Solidity Interfaces**: [./*/I*.sol](.)
- **NIST PQC Standards**: https://csrc.nist.gov/projects/post-quantum-cryptography

## License

Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
See the file [LICENSE](../../LICENSE) for licensing terms.
