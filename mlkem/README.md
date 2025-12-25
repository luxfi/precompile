# ML-KEM Precompile

Post-quantum key encapsulation mechanism precompile implementing FIPS 203 (ML-KEM).

## Address

`0x0200000000000000000000000000000000000007`

## Specification

See [LP-4318: ML-KEM Post-Quantum Key Encapsulation](https://lps.lux.network/docs/lp-4318-ml-kem-post-quantum-key-encapsulation/)

## Operations

### Encapsulate (0x01)

Generate a shared secret and ciphertext from a public key.

**Input:**
| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Operation (0x01) |
| 1 | 1 | Mode (0x00=512, 0x01=768, 0x02=1024) |
| 2 | varies | Public key |

**Output:**
| Offset | Size | Description |
|--------|------|-------------|
| 0 | varies | Ciphertext |
| varies | 32 | Shared secret |

### Decapsulate (0x02)

Recover the shared secret from a ciphertext using a private key.

**Input:**
| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Operation (0x02) |
| 1 | 1 | Mode (0x00=512, 0x01=768, 0x02=1024) |
| 2 | varies | Private key |
| varies | varies | Ciphertext |

**Output:**
| Offset | Size | Description |
|--------|------|-------------|
| 0 | 32 | Shared secret |

## Key Sizes

| Mode | Public Key | Private Key | Ciphertext | Shared Secret |
|------|------------|-------------|------------|---------------|
| ML-KEM-512 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 |

## Gas Costs

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| Encapsulate | 50,000 | 75,000 | 100,000 |
| Decapsulate | 60,000 | 90,000 | 120,000 |

## Security Levels

- **ML-KEM-512**: 128-bit security (NIST Level 1)
- **ML-KEM-768**: 192-bit security (NIST Level 3) - **Recommended**
- **ML-KEM-1024**: 256-bit security (NIST Level 5)

## Usage Example (Solidity)

```solidity
import {MLKEMCaller} from "./IMLKEM.sol";

contract QuantumSecureExchange {
    using MLKEMCaller for *;

    function establishSecret(bytes calldata recipientPubKey)
        external view
        returns (bytes memory ciphertext, bytes32 sharedSecret)
    {
        return MLKEMCaller.encapsulate768(recipientPubKey);
    }

    function recoverSecret(
        bytes calldata privateKey,
        bytes calldata ciphertext
    ) external view returns (bytes32 sharedSecret) {
        return MLKEMCaller.decapsulate768(privateKey, ciphertext);
    }
}
```

## References

- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
