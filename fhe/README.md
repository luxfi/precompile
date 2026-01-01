# FHE Precompile

Fully Homomorphic Encryption (FHE) precompile for Lux blockchain, enabling privacy-preserving smart contracts.

## Overview

This precompile provides FHE operations using the CKKS (Cheon-Kim-Kim-Song) scheme implemented in pure Go via `luxfi/lattice`. It supports threshold decryption through the T-Chain (67-of-100 validators via LP-333).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        C-Chain (EVM)                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Smart Contracts                         │   │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │   │
│  │   │ FHERC20.sol │  │ Auction.sol │  │ PrivateVote.sol │ │   │
│  │   └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ │   │
│  └──────────┼────────────────┼──────────────────┼──────────┘   │
│             │                │                  │               │
│  ┌──────────▼────────────────▼──────────────────▼──────────┐   │
│  │                    FHE Precompiles                       │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │   │
│  │  │ FHE (0x80)  │  │ ACL (0x81)  │  │ Gateway (0x83)  │  │   │
│  │  │ Operations  │  │ Access Ctrl │  │ Decryption      │  │   │
│  │  └──────┬──────┘  └─────────────┘  └────────┬────────┘  │   │
│  └─────────┼───────────────────────────────────┼───────────┘   │
└────────────┼───────────────────────────────────┼───────────────┘
             │ Warp Message                      │ Warp Message
             ▼                                   ▼
┌────────────────────────┐         ┌─────────────────────────────┐
│      Z-Chain (zkVM)    │         │     T-Chain (Threshold)     │
│  ┌──────────────────┐  │         │  ┌───────────────────────┐  │
│  │   FHE Processor  │  │         │  │ Threshold Decryptor   │  │
│  │   - CKKS Ops     │  │         │  │ - 67-of-100 shares    │  │
│  │   - Coprocessor  │  │         │  │ - CKKS Multiparty     │  │
│  │   - luxfi/lattice│  │         │  │ - Share Combiner      │  │
│  └──────────────────┘  │         │  └───────────────────────┘  │
└────────────────────────┘         └─────────────────────────────┘
```

## Precompile Addresses

| Precompile | Address | Purpose |
|------------|---------|---------|
| FHE | `0x0200000000000000000000000000000000000080` | Core FHE operations |
| ACL | `0x0200000000000000000000000000000000000081` | Access control |
| InputVerifier | `0x0200000000000000000000000000000000000082` | Input validation |
| FHEDecrypt | `0x0200000000000000000000000000000000000083` | Threshold decryption via T-Chain |

## Encrypted Types

| Type | Description | Solidity |
|------|-------------|----------|
| `ebool` | Encrypted boolean | `type ebool is bytes32` |
| `euint8` | Encrypted 8-bit uint | `type euint8 is bytes32` |
| `euint16` | Encrypted 16-bit uint | `type euint16 is bytes32` |
| `euint32` | Encrypted 32-bit uint | `type euint32 is bytes32` |
| `euint64` | Encrypted 64-bit uint | `type euint64 is bytes32` |
| `euint128` | Encrypted 128-bit uint | `type euint128 is bytes32` |
| `euint256` | Encrypted 256-bit uint | `type euint256 is bytes32` |
| `eaddress` | Encrypted address | `type eaddress is bytes32` |

## Operations

### Arithmetic
- `add(a, b)` - Addition
- `sub(a, b)` - Subtraction
- `mul(a, b)` - Multiplication
- `div(a, b)` - Division
- `rem(a, b)` - Remainder
- `neg(a)` - Negation

### Comparison
- `lt(a, b)` - Less than
- `le(a, b)` - Less than or equal
- `gt(a, b)` - Greater than
- `ge(a, b)` - Greater than or equal
- `eq(a, b)` - Equal
- `ne(a, b)` - Not equal
- `min(a, b)` - Minimum
- `max(a, b)` - Maximum

### Bitwise
- `and(a, b)` - Bitwise AND
- `or(a, b)` - Bitwise OR
- `xor(a, b)` - Bitwise XOR
- `not(a)` - Bitwise NOT
- `shl(a, bits)` - Shift left
- `shr(a, bits)` - Shift right

### Conditional
- `select(cond, ifTrue, ifFalse)` - Conditional select

### Randomness
- `rand(type)` - Generate encrypted random value

## Gas Costs

| Operation | Gas Cost |
|-----------|----------|
| Encryption | 50,000 |
| Add/Sub | 65,000 |
| Mul | 150,000 |
| Div/Rem | 500,000 |
| Comparison | 60,000 |
| Bitwise | 50,000 |
| Select | 100,000 |
| Random | 100,000 |
| Decrypt Request | 10,000 |

## Usage Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint64, ebool} from "lux-standard/contracts/fhe/FHE.sol";

contract PrivateBalance {
    mapping(address => euint64) private balances;
    
    function deposit(uint64 amount) external {
        euint64 encrypted = FHE.asEuint64(amount);
        balances[msg.sender] = FHE.add(balances[msg.sender], encrypted);
        FHE.allowThis(balances[msg.sender]);
    }
    
    function transfer(address to, uint64 amount) external {
        euint64 encAmount = FHE.asEuint64(amount);
        
        // Check sufficient balance (encrypted comparison)
        ebool sufficient = FHE.ge(balances[msg.sender], encAmount);
        
        // Conditional update (works on encrypted data)
        balances[msg.sender] = FHE.select(
            sufficient,
            FHE.sub(balances[msg.sender], encAmount),
            balances[msg.sender]
        );
        
        balances[to] = FHE.select(
            sufficient,
            FHE.add(balances[to], encAmount),
            balances[to]
        );
    }
}
```

## Decryption Flow

1. **Request**: Contract calls `FHE.decrypt(value)` or `Gateway.decrypt(handle, type)`
2. **Warp**: Request sent to T-Chain via Warp messaging
3. **Threshold**: 67-of-100 validators contribute decryption shares
4. **Combine**: Shares combined to recover plaintext
5. **Fulfill**: Result returned via `fulfill(requestId, result)` callback
6. **Poll/Callback**: Contract retrieves result via `reveal(requestId)` or receives callback

## Files

- `module.go` - Module registration
- `contract.go` - FHE precompile implementation
- `acl.go` - Access control implementation (in evm/precompile)
- `gateway.go` - Decryption gateway (in evm/precompile)
- `IFHE.sol` - Solidity interfaces

## Related Components

- `luxfi/lattice` - Pure Go CKKS implementation
- `node/vms/zkvm/fhe` - Z-Chain FHE processor
- `node/vms/thresholdvm` - T-Chain threshold operations
- `standard/contracts/fhe` - Solidity FHE library

## License

Copyright (C) 2019-2024, Lux Partners Limited. All rights reserved.
See the file LICENSE for licensing terms.
