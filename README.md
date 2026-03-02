# Lux Precompiled Contracts

Native EVM precompiles for the Lux blockchain. Each precompile is a Go package that implements `contract.StatefulPrecompiledContract` and registers via `modules.RegisterModule()` in its `init()`.

Geth provides `NewPrecompileAdapter()` to wrap these into geth-compatible precompiles. L1 chains select which precompiles to enable via `PrecompileOverrider`.

## Precompiles

### Post-Quantum Cryptography (baseline — all Lux chains)

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `mldsa` | `0x0200...0006` | ML-DSA-65 signature verify (FIPS 204) | 100k + 10/byte |
| `slhdsa` | `0x0600...0001` | SLH-DSA signature verify (FIPS 205) | 15k–250k by mode |
| `pqcrypto` | `0x9003` | ML-KEM key encapsulation + hybrid PQ ops | variable |
| `mlkem` | `0x0200...0007` | ML-KEM-768 encapsulate/decapsulate | 50k base |

### Threshold Signatures

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `frost` | `0x0800...0002` | FROST Schnorr threshold verify (secp256k1/Ed25519) | 50k + 5k/signer |
| `cggmp21` | `0x0800...0003` | CGGMP21 threshold ECDSA verify (secp256k1) | 75k + 10k/signer |
| `ringtail` | `0x0200...000B` | Ring-LWE lattice threshold verify (post-quantum) | 150k + 10k/party |

### Curves & Signatures

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `sr25519` | `0x0A00...0001` | Schnorrkel verify for Substrate→EVM migration | 9k + 3/byte |
| `ed25519` | `0x3211...0000` | Ed25519 signature verify | 3k |
| `secp256r1` | `0x0100` | P-256 ECDSA verify (WebAuthn/passkeys) | 3.5k |

### Hashing

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `blake3` | `0x0500...0004` | Blake3 hash, Merkle root, KDF, XOF | 100 + 3–5/word |
| `kzg4844` | `0xB002` | KZG polynomial commitment (EIP-4844) | 50k |

### Privacy & ZK

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `zk` | `0x0900` | ZK proof verification (Groth16, PLONK, fflonk, Halo2) | 180k–500k |
| `fhe` | — | Fully homomorphic encryption ops | variable |
| `ring` | `0x9202` | Ring signature verification | variable |
| `ecies` | `0x9201` | ECIES encryption/decryption | variable |
| `hpke` | `0x9200` | Hybrid public key encryption | variable |

### DEX

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `dex` | `0x0400...0000` | Native DEX (PoolManager, Router, Hooks, Lending) | variable |

### Infrastructure

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `ai` | `0x0300...0000` | AI mining (ML-DSA verify, TEE attestation, rewards) | variable |
| `quasar` | — | Hybrid consensus certificate verification | variable |
| `dead` | `0x0000...0000` | Dead address interceptor | minimal |
| `graph` | — | GraphQL query precompile | variable |
| `bridge` | — | Cross-chain bridge verification | variable |
| `threshold` | — | Threshold key management | variable |
| `attestation` | — | TEE/GPU attestation | variable |

### Support Packages

| Package | Purpose |
|---------|---------|
| `contract` | Core interfaces (`StatefulPrecompiledContract`, `AccessibleState`) |
| `modules` | Module registration system and reserved address ranges |
| `precompileconfig` | Config interfaces (`Upgrade`, `Timestamp`, `IsDisabled`) |
| `registry` | Address-to-LP mapping |

## Structure

Each precompile follows this pattern:

```
<name>/
├── contract.go        # Run(), RequiredGas(), Address()
├── contract_test.go   # Tests with known vectors
├── module.go          # init() → modules.RegisterModule()
└── I<Name>.sol        # Solidity interface (optional)
```

## Adding a Precompile

1. Pick an address in a [reserved range](modules/registerer.go)
2. Implement `contract.StatefulPrecompiledContract`
3. Register via `modules.RegisterModule()` in `init()`
4. Add tests (valid, invalid, gas, edge cases)
5. Wire into your L1 via `PrecompileOverrider` or geth's `LuxPrecompiles()`

## Building

```bash
go build ./...
go test ./...
go test -bench=. ./sr25519/  # benchmark a specific package
```

CGO is required for `sr25519` (sr25519-donna C library). All other packages are pure Go.

## License

Copyright (C) 2025, Lux Industries, Inc. All rights reserved.

### ZK-Friendly Curves (0x0500)

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `poseidon` | `0x0500..05` | Poseidon/Poseidon2 hash (ZK-optimized, PQ-safe) | 800 |
| `pedersen` | `0x0500..06` | Pedersen commitment (legacy, NOT PQ-safe) | 6,000 |
| `babyjubjub` | `0x0500..07` | Baby Jubjub curve (BN254 scalar field, zkEVM) | 3,000 |
| `pasta` | `0x0500..08` | Pallas + Vesta curves (Halo2 proving) | 5,000 |

### Symmetric & Key Exchange

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `aes` | `0x9210` | AES-256-GCM authenticated encryption | 5,000 |
| `chacha20` | `0x9211` | ChaCha20-Poly1305 stream cipher | 4,000 |
| `x25519` | `0x9203` | X25519 Diffie-Hellman key exchange | 10,000 |
| `xwing` | `0x0200..0C` | X-Wing hybrid KEM (X25519 + ML-KEM-768) | 50,000 |
| `curve25519` | `0x9204` | Raw Curve25519 point operations | 5,000 |

### Math (0x0450)

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `math` | `0x0450` | MulDiv, Sqrt, Log2, Exp, Pow (fixed-point) | 50 + 5/word |

Saves ~2000 gas per MulDiv vs Solidity. Used by every DeFi calculation.

### StableSwap (0x0460)

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `stableswap` | `0x0460` | Curve-style constant-sum AMM | 5,000 |

10x gas savings vs Solidity StableSwap. For pegged-asset pools (LUSD/USDC, LETH/stETH).

### Compute Market (0x0310)

| Package | Address | Description | Gas |
|---------|---------|-------------|-----|
| `compute` | `0x0310` | AI compute marketplace | 10,000-50,000 |

Integrates with A-Chain TEE attestation. Register GPU providers, submit jobs, verify compute, claim $AI rewards.
