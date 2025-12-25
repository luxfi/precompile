# precompiles

## Overview

This package contains precompiled contracts (precompiles) for the Lux blockchain ecosystem. Precompiles are native Go implementations of smart contracts that execute much faster than Solidity bytecode.

**Current Version**: v0.1.2

## Package Types

### Standalone Precompiles (No EVM dependency)
These precompiles work independently and can be used in any Go project:

| Package | Address | Description | Status |
|---------|---------|-------------|--------|
| `mldsa` | 0x0300...01 | ML-DSA signature verification (FIPS 204) | ✅ Working |
| `slhdsa` | 0x0300...02 | SLH-DSA hash-based signatures (FIPS 205) | ✅ Working |
| `pqcrypto` | 0x0300...03 | ML-KEM key encapsulation (FIPS 203) | ✅ Working |
| `ecies` | - | Elliptic Curve Integrated Encryption | ✅ Working |
| `hpke` | - | Hybrid Public Key Encryption | ✅ Working |
| `kzg4844` | - | KZG commitments for EIP-4844 | ✅ Working |
| `ring` | - | Ring signatures | ✅ Working |

### EVM-Integrated Precompiles (Require luxfi/evm)
These precompiles are designed to work with the full EVM and have circular imports with `luxfi/evm`. Use the versions in `luxfi/evm/precompile/contracts/` instead:

| Package | Description | Use Instead |
|---------|-------------|-------------|
| `deployerallowlist` | Contract deployment permissions | `evm/precompile/contracts/deployerallowlist` |
| `nativeminter` | Native token minting | `evm/precompile/contracts/nativeminter` |
| `txallowlist` | Transaction allow list | `evm/precompile/contracts/txallowlist` |
| `feemanager` | Fee configuration | `evm/precompile/contracts/feemanager` |
| `rewardmanager` | Reward distribution | `evm/precompile/contracts/rewardmanager` |

## Architecture

### Import Cycle Solution (v0.1.1 - v0.1.2)

The `contract/` package defines minimal interfaces to avoid import cycles with `geth/core/vm`:

```go
// contract/interfaces.go - Local interface, no geth imports
type PrecompileEnvironment interface {
    ReadOnly() bool  // Minimal interface for stateless precompiles
}

// contract/utils.go - Local error definition
var ErrOutOfGas = errors.New("out of gas")
```

This allows standalone precompiles (mldsa, slhdsa, pqcrypto) to work without importing geth.

### Integration with geth

geth v1.16.64+ includes `core/vm/lux_precompiles.go` which provides:
- `LuxPrecompiles()` - Returns map of PQ crypto precompiles
- `MergeLuxPrecompiles()` - Merges with standard Ethereum precompiles
- `PrecompiledContractsLux` - Combined precompile set for Lux chains

## Development

### Build

```bash
go build ./...
```

### Test

```bash
# Test standalone precompiles (will pass)
go test ./mldsa/... ./slhdsa/... ./pqcrypto/... ./ecies/... ./hpke/...

# Full test (some EVM-integrated tests will fail due to import cycles)
go test ./...
```

### Dependencies

- `luxfi/crypto` v1.17.26+ - Cryptographic primitives
- `luxfi/geth` - Ethereum types (common, abi)

## Version History

| Version | Changes |
|---------|---------|
| v0.1.2 | Simplified PrecompileEnvironment to `ReadOnly() bool` |
| v0.1.1 | Fixed import cycle - removed geth/core/vm dependency |
| v0.1.0 | Initial release with PQ crypto precompiles |

---

*Last Updated: 2025-12-25*
