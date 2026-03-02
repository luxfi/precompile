# secp256r1 (P-256) Signature Verification Precompile

Implementation of the secp256r1 (NIST P-256) signature verification precompile for the Lux Network EVM.

## Overview

This precompile enables efficient verification of ECDSA signatures using the NIST P-256 curve, commonly used by:

- **WebAuthn/Passkeys**: Modern password-less authentication
- **Apple Secure Enclave**: Face ID / Touch ID
- **Windows Hello**: Biometric authentication
- **Android Keystore**: Device-backed keys
- **Enterprise HSMs**: NIST-approved cryptography

## Precompile Details

| Property | Value |
|----------|-------|
| Address | `0x0000000000000000000000000000000000000100` |
| Gas Cost | 3,450 |
| Input Size | 160 bytes |
| Output Size | 32 bytes (success) or 0 bytes (failure) |

## Input Format

```
[32 bytes] message hash
[32 bytes] r (signature component)
[32 bytes] s (signature component)
[32 bytes] x (public key x-coordinate)
[32 bytes] y (public key y-coordinate)
```

## Output Format

- **Success**: 32 bytes with value `0x0000000000000000000000000000000000000000000000000000000000000001`
- **Failure**: Empty (0 bytes)

## Usage

### Solidity

```solidity
import {Secp256r1Lib, P256PublicKey} from "./ISecp256r1.sol";

contract MyContract {
    using Secp256r1Lib for bytes32;

    function verifyBiometric(
        bytes32 hash,
        bytes32 r,
        bytes32 s,
        bytes32 pubX,
        bytes32 pubY
    ) external view returns (bool) {
        return Secp256r1Lib.verify(hash, r, s, pubX, pubY);
    }
}
```

### Go

```go
import "github.com/luxfi/precompiles/secp256r1"

func verify(hash []byte, r, s, x, y *big.Int) bool {
    return secp256r1.Verify(hash, r, s, x, y)
}
```

## Gas Comparison

| Method | Gas Cost | Savings |
|--------|----------|---------|
| Solidity implementation | 200,000 - 330,000 | - |
| This precompile | 3,450 | **99%** |

## Use Cases

1. **Biometric Wallets**: Sign transactions with Face ID/Touch ID
2. **Enterprise SSO**: Integrate with corporate identity systems
3. **WebAuthn/Passkeys**: Password-less authentication for dApps
4. **Cross-Chain Identity**: Unified authentication across Lux chains

## Standards Compliance

- [EIP-7212](https://eips.ethereum.org/EIPS/eip-7212): secp256r1 Curve Support
- [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md): Rollup precompile
- [NIST FIPS 186-3](https://csrc.nist.gov/publications/detail/fips/186/3/archive/2009-06-25): Digital Signature Standard
- [LP-3651](https://github.com/luxfi/lps): Lux Network specification

## Testing

```bash
go test -v ./...
```

## Benchmarks

```bash
go test -bench=. -benchmem
```

Typical results (Apple M1 Max):

```
BenchmarkContract_Run-10    100000    10.5 µs/op    0 B/op    0 allocs/op
BenchmarkVerify-10          100000    10.3 µs/op    0 B/op    0 allocs/op
```

## Security Considerations

1. **Constant Time**: Uses Go stdlib `crypto/ecdsa` which provides constant-time operations
2. **Point Validation**: Validates that public key is on curve before verification
3. **Range Checks**: Validates r, s are in range [1, n-1]
4. **No Malleability Check**: Follows NIST specification exactly

## License

MIT License - Copyright (C) 2025, Lux Industries, Inc.
