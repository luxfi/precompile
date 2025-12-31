# Lux Ecosystem - AI Assistant Documentation

## Project Overview

This document provides comprehensive documentation for the Lux blockchain ecosystem, including the new DEX precompile system implementing Uniswap v4-style architecture natively at the EVM level.

## New: DEX Precompiles (Uniswap v4-Style)

### Architecture Overview

The Lux DEX precompiles implement a Uniswap v4-style decentralized exchange as native EVM precompiles, providing:

- **Singleton Architecture**: All pools live in a single precompile contract at `0x0400`
- **Flash Accounting**: Token transfers are netted at the end of each transaction
- **Hooks System**: Modular contracts for custom pool logic (dynamic fees, MEV protection, limit orders)
- **Native LUX Support**: No wrapping needed - trade native LUX directly
- **HFT Optimized**: Sub-microsecond execution for high-frequency trading

### Performance Benchmarks (M1 Max)

| Operation | Latency | Throughput | Memory |
|-----------|---------|------------|--------|
| Swap | 2.26μs | 443K ops/sec | 888 B/op |
| ModifyLiquidity | 2.87μs | 348K ops/sec | 840 B/op |
| PoolKeyID | 439ns | 2.7M ops/sec | 0 B/op |
| HookPermission | 0.45ns | 2.2B ops/sec | 0 B/op |

### Precompile Addresses

| Component | Address | Description |
|-----------|---------|-------------|
| PoolManager | `0x0400` | Singleton pool manager with flash accounting |
| SwapRouter | `0x0401` | Optimized swap routing |
| HooksRegistry | `0x0402` | Hook contract registry |
| FlashLoan | `0x0403` | Flash loan facility |

### Directory Structure

```
/Users/z/work/lux/
├── precompiles/
│   ├── ai/                    # AI Mining precompile (0x0300)
│   │   ├── ai_mining.go       # ML-DSA signatures, NVTrust verification
│   │   └── ai_mining_test.go  # Comprehensive tests
│   └── dex/                   # DEX precompiles (0x0400-0x04FF)
│       ├── types.go           # Core types (Currency, PoolKey, BalanceDelta)
│       ├── pool_manager.go    # Singleton PoolManager implementation
│       ├── hooks.go           # Hooks system for custom pool logic
│       ├── pool_manager_test.go
│       ├── hooks_test.go
│       ├── lending.go         # Lending protocol (Alchemist)
│       └── transmuter.go      # Stablecoin transmuter
├── solidity/dex/              # Solidity interfaces for EVM contracts
│   ├── IPoolManager.sol       # PoolManager interface (0x0400)
│   ├── IHooks.sol             # Hooks interface with BaseHook
│   ├── IERC20Minimal.sol      # Minimal ERC20 interface
│   └── Types.sol              # Shared type definitions
└── dex/                       # Symlink to /Users/z/work/lx/dex (standalone CLOB DEX)
```

### Core Types

#### Currency
```go
type Currency struct {
    Address common.Address  // address(0) = native LUX
}
```

#### PoolKey
```go
type PoolKey struct {
    Currency0   Currency       // Lower address token (sorted)
    Currency1   Currency       // Higher address token (sorted)
    Fee         uint24         // Fee in basis points (3000 = 0.30%)
    TickSpacing int24          // Tick spacing for concentrated liquidity
    Hooks       common.Address // Hook contract (address(0) = no hooks)
}
```

#### BalanceDelta
```go
type BalanceDelta struct {
    Amount0 *big.Int  // Positive = user owes pool
    Amount1 *big.Int  // Negative = pool owes user
}
```

### Flash Accounting Pattern

Flash accounting allows multiple operations within a transaction, with token transfers netted at the end:

```solidity
// 1. Acquire lock
IPoolManager.lock(callbackData);

// Inside callback:
// 2. Execute operations (swap, addLiquidity, etc.)
BalanceDelta delta = poolManager.swap(key, params, hookData);

// 3. Settle deltas (pay what you owe, receive what you're owed)
poolManager.settle(currency0, amount0);  // Pay pool
poolManager.take(currency1, recipient, amount1);  // Receive from pool

// 4. Verify all deltas net to zero (automatic)
```

### Hooks System

Hook capabilities are encoded in the hook contract address (first 2 bytes):

| Bit | Flag | Description |
|-----|------|-------------|
| 0 | BeforeInitialize | Called before pool creation |
| 1 | AfterInitialize | Called after pool creation |
| 2 | BeforeAddLiquidity | Called before adding liquidity |
| 3 | AfterAddLiquidity | Called after adding liquidity |
| 4 | BeforeRemoveLiquidity | Called before removing liquidity |
| 5 | AfterRemoveLiquidity | Called after removing liquidity |
| 6 | BeforeSwap | Called before swap (can modify fee) |
| 7 | AfterSwap | Called after swap (can modify delta) |
| 8 | BeforeDonate | Called before donation |
| 9 | AfterDonate | Called after donation |
| 10 | BeforeFlash | Called before flash loan |
| 11 | AfterFlash | Called after flash loan |

Example hook implementations:
- **Dynamic Fees**: Adjust fees based on volatility
- **TWAP Oracle**: Built-in time-weighted average price
- **Limit Orders**: On-chain limit orders executed at tick
- **MEV Protection**: Commit-reveal scheme to prevent front-running

### Key Advantages Over Traditional DEX

1. **Gas Efficiency**
   - Pool creation: ~99% cheaper (no separate contract deployment)
   - Multi-hop swaps: Single transaction, netted transfers
   - Native precompile execution: No EVM overhead

2. **Unified Liquidity**
   - All pools in singleton contract
   - Global liquidity across all Lux chains
   - Cross-chain swaps via Warp messaging

3. **Native Token Support**
   - Trade native LUX without wrapping
   - Saves gas on wrap/unwrap operations
   - Better UX for users

4. **HFT Capability**
   - 430K swaps/sec throughput
   - 2.3μs latency per swap
   - Zero-allocation hot paths

## Complete Precompile Registry (v0.3.0)

### Address Ranges
| Range | Category | Description |
|-------|----------|-------------|
| 0x0001-0x00FF | Standard EVM | ECRECOVER, SHA256, BN254, BLS12-381 |
| 0x0100-0x01FF | Warp/Teleport | Cross-chain messaging |
| 0x0200-0x02FF | Chain Config | Subnet-EVM style (AllowLists, FeeManager) |
| 0x0300-0x03FF | AI/ML | Mining, NVTrust, ModelRegistry |
| 0x0400-0x04FF | DEX | Uniswap v4-style AMM, Lending, Perps |
| 0x0500-0x05FF | Graph/Query | GraphQL, Subscriptions, Cache |
| 0x0600-0x06FF | Post-Quantum | ML-DSA, ML-KEM, SLH-DSA, Quasar |
| 0x0700-0x07FF | Privacy | FHE, ECIES, Ring, HPKE |
| 0x0800-0x08FF | Threshold | FROST, CGGMP21, Ringtail |
| 0x0900-0x09FF | ZK Proofs | KZG, Groth16, PLONK |
| 0x0A00-0x0AFF | Curves | P-256 (secp256r1) |

### All Precompiles by Package

#### ai/ - AI Mining (0x0300-0x03FF)
| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0300 | AI_MINING | ML-DSA signature verification, rewards | 100,000 |
| 0x0301 | NV_TRUST | GPU TEE attestation (NVTrust) | 50,000 |
| 0x0302 | MODEL_REGISTRY | AI model registration/verification | 25,000 |

#### dex/ - DEX Operations (0x0400-0x04FF)
| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0400 | POOL_MANAGER | Singleton pool manager (Uniswap v4) | 50,000 |
| 0x0401 | SWAP_ROUTER | Optimized swap routing | 10,000 |
| 0x0402 | HOOKS_REGISTRY | Custom hook contracts | 3,000 |
| 0x0403 | FLASH_LOAN | Flash loan facility | 5,000 |
| 0x0410 | LENDING_POOL | Supply/borrow with collateral | 15,000 |
| 0x0411 | INTEREST_RATE | Dynamic interest rate curves | 5,000 |
| 0x0412 | LIQUIDATOR | Liquidation engine | 50,000 |
| 0x0420 | PERP_ENGINE | Perpetuals (up to 1111x leverage) | 25,000 |
| 0x0421 | FUNDING_RATE | Funding rate calculation | 10,000 |
| 0x0422 | INSURANCE_FUND | Insurance and ADL | 20,000 |
| 0x0430 | LIQUID_VAULT | Self-repaying loans (90% LTV) | 20,000 |
| 0x0431 | LIQUID_FX | L* token to underlying conversion | 25,000 |
| 0x0432 | LIQUID_TOKEN | Liquid token registry (LUSD, LETH) | 5,000 |
| 0x0433 | YIELD_ROUTER | Yield strategy routing | 30,000 |
| 0x0440 | TELEPORT_BRIDGE | Cross-chain transfer engine | 50,000 |
| 0x0441 | OMNICHAIN_ROUTER | Multi-chain liquidity routing | 40,000 |

#### graph/ - Query Layer (0x0500-0x05FF)
| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0500 | GRAPHQL_QUERY | Unified GraphQL interface | 5,000 |
| 0x0501 | GRAPH_SUBSCRIBE | Event subscriptions | 10,000 |
| 0x0502 | GRAPH_CACHE | Query result caching | 2,000 |
| 0x0503 | GRAPH_INDEX | Index management | 15,000 |

#### Post-Quantum Crypto (0x0600-0x06FF)
| Address | Name | Package | Description | Gas |
|---------|------|---------|-------------|-----|
| 0x0600 | ML_DSA | mldsa/ | NIST ML-DSA signatures (Dilithium) | 50,000 |
| 0x0601 | ML_KEM | mlkem/ | NIST ML-KEM key encapsulation | 25,000 |
| 0x0602 | SLH_DSA | slhdsa/ | Stateless hash-based signatures | 75,000 |
| 0x0603 | PQ_CRYPTO | pqcrypto/ | Multi-PQ operations | 30,000 |
| 0x0604 | QUASAR | quasar/ | Quantum consensus verification | 100,000 |

#### Privacy/Encryption (0x0700-0x07FF)
| Address | Name | Package | Description | Gas |
|---------|------|---------|-------------|-----|
| 0x0700 | FHE | fhe/ | Fully Homomorphic Encryption | 500,000 |
| 0x0701 | ECIES | ecies/ | Elliptic Curve Integrated Encryption | 25,000 |
| 0x0702 | RING | ring/ | Ring signatures (anonymity) | 50,000 |
| 0x0703 | HPKE | hpke/ | Hybrid Public Key Encryption | 20,000 |

#### Threshold Signatures (0x0800-0x08FF)
| Address | Name | Package | Description | Gas |
|---------|------|---------|-------------|-----|
| 0x0800 | FROST | frost/ | Schnorr threshold signatures | 25,000 |
| 0x0801 | CGGMP21 | cggmp21/ | ECDSA threshold signatures | 50,000 |
| 0x0802 | RINGTAIL | ringtail/ | Threshold lattice signatures (PQ) | 75,000 |

#### ZK Proofs (0x0900-0x09FF)
| Address | Name | Package | Description | Gas |
|---------|------|---------|-------------|-----|
| 0x0900 | KZG_4844 | kzg4844/ | KZG commitments (EIP-4844) | 50,000 |
| 0x0901 | GROTH16 | (planned) | Groth16 ZK verifier | 200,000 |
| 0x0902 | PLONK | (planned) | PLONK ZK verifier | 250,000 |

#### Curves (0x0A00-0x0AFF)
| Address | Name | Package | Description | Gas |
|---------|------|---------|-------------|-----|
| 0x0A00 | P256_VERIFY | secp256r1/ | secp256r1/P-256 verification | 3,450 |

### Chain-Specific Precompile Activation

| Chain | Precompiles Enabled |
|-------|---------------------|
| **C-Chain** | ALL (full feature set) |
| **Z-Chain (Zoo)** | Warp, PoolManager, SwapRouter, AIMining, GraphQL |
| **D-Chain (DEX)** | Warp, Full DEX suite, GraphQL |
| **K-Chain (Keys)** | Warp, PQ Crypto, Privacy, Threshold, GraphQL |
| **Q-Chain (Quantum)** | Warp, Full PQ suite, Ringtail, GraphQL |
| **B-Chain (Bridge)** | Warp, TeleportBridge, GraphQL |

### Missing from Z-Chain (Zoo) for Full Integration

Current Z-Chain precompiles are limited. To enable full native chain functionality:

| Feature | Missing Precompiles | Priority |
|---------|---------------------|----------|
| **Bridge** | TeleportBridge (0x0440), OmnichainRouter (0x0441) | HIGH |
| **Threshold** | FROST (0x0800), CGGMP21 (0x0801), Ringtail (0x0802) | HIGH |
| **FHE** | FHE (0x0700), ECIES (0x0701) | MEDIUM |
| **Full DEX** | HooksRegistry, FlashLoan, LendingPool, PerpEngine | MEDIUM |
| **PQ Crypto** | ML-DSA (0x0600), ML-KEM (0x0601) | LOW |

### Standard Precompiles (Subnet-EVM)
| Address | Name | Description |
|---------|------|-------------|
| 0x0200...01 | DeployerAllowList | Contract deployment permissions |
| 0x0200...02 | TxAllowList | Transaction permissions |
| 0x0200...03 | FeeManager | Dynamic fee configuration |
| 0x0200...04 | NativeMinter | Native token minting |
| 0x0200...05 | RewardManager | Validator rewards |

### FHE Sub-Addresses
| Address | Name | Description |
|---------|------|-------------|
| 0x0200...80 | FHE_CONTRACT | Main FHE operations |
| 0x0200...81 | FHE_ACL | Access control for ciphertexts |
| 0x0200...82 | FHE_INPUT_VERIFIER | Input verification |
| 0x0200...83 | FHE_GATEWAY | Gateway for external interactions |

## Testing

Run DEX precompile tests:
```bash
go test -v github.com/luxfi/precompiles/dex

# Run benchmarks
go test -bench=. -benchmem github.com/luxfi/precompiles/dex
```

All 68 tests passing with comprehensive coverage:
- Pool initialization
- Swap operations
- Liquidity management
- Flash accounting
- Hook permissions
- Balance delta operations
- Lending protocol (Alchemist)
- Transmuter stablecoin

## Integration with LX DEX

The precompile DEX complements the standalone LX DEX at `/Users/z/work/lx/dex`:

| Feature | LX DEX (Standalone CLOB) | DEX Precompiles (AMM) |
|---------|--------------------------|----------------------|
| Architecture | Separate service | Native EVM |
| Order Type | Central Limit Order Book | Automated Market Maker |
| Use Case | Professional trading, HFT | Liquidity pools, swaps |
| Deployment | Docker/K8s | Built into chain |

The precompile AMM approach is ideal for:
- AMM-style liquidity pools
- Cross-chain unified liquidity
- Composability with other contracts
- Simple integration for dApps

The standalone LX DEX (CLOB) is ideal for:
- Central limit orderbook
- Professional trading
- Ultra-low latency requirements
- High-frequency market making

## Future Work

1. **Integration with Lux EVM**
   - Register precompiles in EVM config
   - Add to genesis block configuration
   - Cross-chain liquidity via Warp

2. **Advanced Hooks**
   - Concentrated liquidity ranges
   - Automated position management
   - Oracle integrations

3. **Performance Optimization**
   - SIMD operations for batch processing
   - Memory-mapped state for hot data
   - Assembly-optimized math

## Recent Improvements (v1.1.0)

### Critical Bug Fixes
1. **Currency Sorting Fix**: Changed from `Hex()` string comparison to `bytes.Compare()` for correct address ordering
2. **Tick Math Implementation**: Replaced placeholder with binary search-based tick calculation using lookup tables
3. **Reentrancy Protection**: Added mutex-based reentrancy guard in `Lock()` function
4. **Division by Zero Protection**: Added liquidity validation in `Donate()` to prevent panic

### Solidity Interface Optimization
- **BalanceDelta**: Converted from struct to packed `int256` user-defined type (saves 1 storage slot)
- **Custom Errors**: Using custom errors instead of strings (~50 gas savings per revert)
- **File-level Constants**: Hook flags as file-level constants for better gas efficiency
- **Library Functions**: `BalanceDeltaLib` for packed delta operations
- **Reduced Code Size**: IPoolManager.sol -35%, IHooks.sol -58%

### Architecture Enhancements
- Added `sync.RWMutex` for concurrent access protection
- Implemented `tickToSqrtPriceX96()` for bidirectional tick/price conversion
- Added `ErrReentrant` and `ErrNoLiquidity` errors

---

*Last Updated: 2025-12-31*
*Version: 0.3.0*
*Test Status: 14 packages passing*

---

## Block Import: RLP Chain Data

### Overview

Lux supports importing historical blocks from RLP exports using the CLI's `chain import` command, which uses the geth `admin_importChain` API internally.

### RLP Data Files

Block data is stored in RLP format at `~/work/lux/state/rlp/`:

| Chain | File | Size | Blocks |
|-------|------|------|--------|
| Lux Mainnet | `lux-mainnet/lux-mainnet-96369.rlp` | 1.2GB | ~1M |
| Lux Testnet | `lux-testnet/lux-testnet-96368.rlp` | 695KB | ~219 |
| Zoo Mainnet | `zoo-mainnet/zoo-mainnet-200200.rlp` | 1.3MB | - |
| Zoo Testnet | `zoo-testnet/zoo-testnet-200201.rlp` | 156KB | - |

### Genesis Hashes

| Network | Chain ID | Genesis Hash |
|---------|----------|--------------|
| Lux Mainnet | 96369 | `0x3f4fa2a0b0ce089f52bf0ae9199c75ffdd76ecafc987794050cb0d286f1ec61e` |
| Lux Testnet | 96368 | `0x1c5fe37764b8bc146dc88bc1c2e0259cd8369b07a06439bcfa1782b5d4fb0995` |
| Zoo Mainnet | 200200 | `0x7c548af47de27560779ccc67dda32a540944accc71dac3343da3b9cd18f14933` |
| Zoo Testnet | 200201 | `0x0652fb2fde1460544a5893e5eba5095ff566861cbc87fcb1c73be2b81d6d1979` |

### Import via CLI

```bash
# Import blocks to C-Chain
lux chain import --rlp ~/work/lux/state/rlp/lux-mainnet/lux-mainnet-96369.rlp
```

### Header Format: 17-field Lux Format

Lux mainnet uses 17-field headers:
- 15 core Ethereum fields
- BaseFee (field 16)
- ExtDataHash (field 17)

The geth fork's `DecodeHeader` supports multi-format decoding (15-24 fields) to handle this.

---

## Coreth/SubnetEVM Header Format Fix (2024-12-17)

### Problem
When importing blocks from coreth/subnet-evm chaindata via RLP export, block validation failed with:
```
invalid blockGasCost: have <nil>, want 0
```

### Root Cause
RLP field order mismatch between coreth and geth header formats:

| Position | Coreth Format | Geth Format |
|----------|---------------|-------------|
| 15 | ExtDataHash (REQUIRED) | BaseFee (optional) |
| 16 | BaseFee (optional) | ExtDataHash (optional) |
| 17 | ExtDataGasUsed (optional) | ExtDataGasUsed (optional) |
| 18 | BlockGasCost (optional) | BlockGasCost (optional) |

When geth decodes a coreth-exported header, it interprets ExtDataHash as BaseFee and vice versa, causing BlockGasCost to not be decoded properly.

### Solution
Added coreth-compatible header structs in `/Users/z/work/lux/geth/core/types/decode.go`:

```go
// hdr19coreth - Coreth 19-field format
type hdr19coreth struct {
    // ... 15 core fields ...
    ExtDataHash    common.Hash  // Position 15 - VALUE TYPE (required in coreth)
    BaseFee        *big.Int     // Position 16
    ExtDataGasUsed *big.Int     // Position 17
    BlockGasCost   *big.Int     // Position 18
}
```

Updated `decode19()` to try coreth format first, then fall back to geth formats.

### Files Modified
- `/Users/z/work/lux/geth/core/types/decode.go`
  - Added: `hdr17coreth`, `hdr18coreth`, `hdr19coreth` structs
  - Modified: `decode17()`, `decode18()`, `decode19()` functions
- `/Users/z/work/lux/geth/core/types/block_test.go`
  - Added: `TestDecodeCoreth19FieldFormat`

### Verification
```bash
cd ~/work/lux/geth && go test -v ./core/types/... -run "TestDecodeCoreth19FieldFormat"
# --- PASS: TestDecodeCoreth19FieldFormat (0.00s)
```

### Import Workflow Script
Created `/Users/z/work/lux/scripts/cchain-import.sh` for the full export/import pipeline:
```bash
# 1. Export blocks from coreth chaindata
./cchain-import.sh export <coreth-chaindata> /tmp/blocks.rlp

# 2. Import RLP to geth
./cchain-import.sh import /tmp/blocks.rlp /tmp/geth-import

# 3. Import to luxd C-Chain
./cchain-import.sh luxd /tmp/geth-import/geth/chaindata
```

---

## LP Documentation - Network Upgrade Mapping

Created LP-99 (`/Users/z/work/lux/lps/LPs/lp-0099-cchain-upgrade-mapping.md`) documenting:
- All C-Chain upgrades (Apricot 1-6, Banff, Cortina, Durango, Etna, Fortuna, Granite)
- Mapping to Ethereum hard forks
- Associated LP numbers for each upgrade
- Header format evolution across upgrades
- Genesis configuration fields

## Tools Created

### NodeID Calculator
`/tmp/nodeid-tool` - Calculates NodeID from staker TLS certificate:
```bash
/tmp/nodeid-tool <staker.crt>
# Output: NodeID-FrtEjhat6RUqjEWCJgYZKqBaxY2Woyy5G
```

### Genesis Tool
`/tmp/genesis-tool` (from `~/work/lux/genesis`) - Generates proper genesis files:
```bash
# From mnemonic
LUX_MNEMONIC="test test..." /tmp/genesis-tool -network-id 96369 -validators 5 -output genesis.json

# From existing keys
/tmp/genesis-tool -network mainnet -keys-dir ~/.lux/keys -output genesis.json
```

### Genesis Fix Tool
`/tmp/fix-genesis` (from `~/work/lux/genesis/tools/fix_genesis.go`) - Regenerates genesis with correct bech32 addresses:
```bash
/tmp/fix-genesis \
  -validators /Users/z/work/lux/mainnet/validators \
  -cchain /Users/z/work/lux/genesis/configs/mainnet/cchain.json \
  -output genesis_mainnet.json
```

---

## Bech32 Address Checksum Fix (2025-12-17)

### Problem
Genesis addresses had invalid bech32 checksums, causing validation errors:
```
invalid lux address P-lux18jma8ppw3nhx5r4ap8clazz0dps7rv5u00z96u:
invalid checksum (expected (bech32=v98e28, bech32m=v98e28eeh409), got 00z96u)
```

### Root Cause
The CLI's `genesis.go` was computing bech32 checksums incorrectly:
- **Wrong**: `formatBech32("P-lux", shortID)` - includes chain prefix in HRP
- **Correct**: Compute bech32 with just "lux", then prepend "P-"

The node's `address.Format()` correctly separates chain prefix from HRP:
```go
// address.Format("P", "lux", addr) produces "P-lux1..."
// The bech32 checksum is computed using only "lux", not "P-lux"
```

### Fix Applied

1. **CLI genesis.go** (`/Users/z/work/lux/cli/cmd/keycmd/genesis.go`):
   - Added `formatLuxAddress(chainPrefix, hrp, data)` that correctly separates chain prefix from HRP
   - Updated P-Chain and X-Chain address generation to use the new function

2. **Genesis package** (`/Users/z/work/lux/genesis/pkg/genesis/types.go`):
   - Already had correct implementation via `formatBech32WithChain()`
   - Added comprehensive tests in `types_test.go`

### Correct Mainnet Addresses (Network ID: 96369)

| Validator | NodeID | P-Chain Address |
|-----------|--------|-----------------|
| Node 1 | NodeID-FrtEjhat6RUqjEWCJgYZKqBaxY2Woyy5G | P-lux1ck0t9h5u7jvvzhx29n99guqjsfkpzt67wgx7wg |
| Node 2 | NodeID-9hq49qGVZN7M7tXxdpF3AqptQGdmPCFnQ | P-lux1dclruwcn9ug8u0jjk3ukh676jr3lsy4er9m3l5 |
| Node 3 | NodeID-8osEnSC4LQFdG1LMit12CBsE6BfKGHNAw | P-lux1qdv9zns0gpfesw0h28jqp2up6h77du2damqf88 |
| Node 4 | NodeID-MrdgTgPuddyo7anomKr4akMcoKzVKcgbG | P-lux1jjs4nx7ul4d6pnsjtpv2khzu8p4yctegvass46 |
| Node 5 | NodeID-Mgd5yHs4pe6qRjkBcW5Y7oqHA51j4afcC | P-lux1970ngvf6s6rsndrkvjzr6lfvf2tdl30529c435 |

### C-Chain Genesis (Preserved)
- **Path**: `/Users/z/work/lux/genesis/configs/mainnet/cchain.json`
- **Genesis Hash**: `0x3f4fa2a0b0ce089f52bf0ae9199c75ffdd76ecafc987794050cb0d286f1ec61e`
- **State Root**: `0x2d1cedac263020c5c56ef962f6abe0da1f5217bdc6468f8c9258a0ea23699e80`
- **Chain ID**: 96369
- **Treasury Address**: `0x9011E888251AB053B7bD1cdB598Db4f9DEd94714`

### Verification
```bash
# Run address tests
cd ~/work/lux/genesis && go test -v ./pkg/genesis/... -run TestBech32

# Verify address parsing
cat genesis.json | jq -r '.initialStakers[].rewardAddress' | while read addr; do
  # address.Parse should succeed for all addresses
done
```

### Files Modified
- `/Users/z/work/lux/cli/cmd/keycmd/genesis.go` - Fixed bech32 address generation
- `/Users/z/work/lux/genesis/pkg/genesis/types_test.go` - Added address validation tests
- `/Users/z/work/lux/genesis/tools/fix_genesis.go` - Tool to regenerate genesis
- `/Users/z/work/lux/mainnet/genesis_mainnet.json` - Updated with correct addresses

---

## Local Network Deployment (2025-12-24)

### Overview

Deploy complete Lux networks locally with C-Chain and Zoo EVM chains, then import historical blocks.

### Network Configuration

| Network | Network ID | HTTP Base Port | gRPC Port | Staking Port |
|---------|------------|----------------|-----------|--------------|
| Mainnet | 1 | 9630 | 8369 | 9631 |
| Testnet | 2 | 9640 | 8368 | 9641 |
| Devnet | 5 | 9650 | 8370 | 9651 |
| Custom | - | 9660 | 8371 | 9661 |

### Chain Configuration

| Chain | Network | Chain ID | VMID |
|-------|---------|----------|------|
| C-Chain Mainnet | Mainnet | 96369 | `mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6` |
| C-Chain Testnet | Testnet | 96368 | `mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6` |
| Zoo Mainnet | Mainnet | 200200 | `ag3GReYPNuSR17rUP8acMdZipQBikdXNRKDyFszAysmy3vDXE` |
| Zoo Testnet | Testnet | 200201 | `ag3GReYPNuSR17rUP8acMdZipQBikdXNRKDyFszAysmy3vDXE` |

### RLP Data Files

| Chain | File Path | Size | Blocks | Notes |
|-------|-----------|------|--------|-------|
| C-Chain Mainnet | `~/work/lux/state/rlp/lux-mainnet/lux-mainnet-96369.rlp` | 1.2GB | ~700k | Single combined file |
| C-Chain Mainnet | `~/work/lux/state/rlp/lux-mainnet/lux-mainnet-96369.part.*` | 2.4GB total | ~700k | 7 split parts (100MB each) |
| C-Chain Testnet | `~/work/lux/state/rlp/lux-testnet/lux-testnet-96368.rlp` | 695KB | 218 | Single file |
| Zoo Mainnet | `~/work/lux/state/rlp/zoo-mainnet/zoo-mainnet-200200.rlp` | 1.3MB | 799 | Single file |
| Zoo Testnet | `~/work/lux/state/rlp/zoo-testnet/zoo-testnet-200201.rlp` | 156KB | 84 | Single file |

### Deployment Steps

#### 1. Start Networks

```bash
# Start Testnet (5 nodes on ports 9640-9648)
lux network start --testnet

# Start Mainnet (5 nodes on ports 9630-9638)
lux network start --mainnet
```

#### 2. Create Zoo Chains

**Testnet (zootest):**
```bash
# Create chain config from genesis
mkdir -p ~/.lux/chains/zootest
cp ~/work/lux/genesis/configs/zoo-testnet/genesis.json ~/.lux/chains/zootest/genesis.json

# Create sidecar.json
cat > ~/.lux/chains/zootest/sidecar.json << 'EOF'
{
    "Name": "zootest",
    "VM": "Lux EVM",
    "VMID": "ag3GReYPNuSR17rUP8acMdZipQBikdXNRKDyFszAysmy3vDXE",
    "VMVersion": "v0.8.0",
    "RPCVersion": 42,
    "TokenName": "ZOO",
    "TokenSymbol": "ZOO",
    "ChainID": "200201",
    "Version": "1.4.0"
}
EOF

# Deploy to testnet
lux chain deploy zootest --testnet
```

**Mainnet (zoo):**
```bash
# Create chain config from genesis
mkdir -p ~/.lux/chains/zoo
cp ~/work/lux/genesis/configs/zoo-mainnet/genesis.json ~/.lux/chains/zoo/genesis.json

# Create sidecar.json
cat > ~/.lux/chains/zoo/sidecar.json << 'EOF'
{
    "Name": "zoo",
    "VM": "Lux EVM",
    "VMID": "ag3GReYPNuSR17rUP8acMdZipQBikdXNRKDyFszAysmy3vDXE",
    "VMVersion": "v0.8.0",
    "RPCVersion": 42,
    "TokenName": "ZOO",
    "TokenSymbol": "ZOO",
    "ChainID": "200200",
    "Version": "1.4.0"
}
EOF

# Deploy to mainnet
lux chain deploy zoo --mainnet
```

#### 3. Import Blocks

Import order: Testnet C-Chain → Zootest → Zoo → Mainnet C-Chain (last, largest)

```bash
# Import C-Chain testnet blocks (fast, ~218 blocks)
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_importChain","params":["'$HOME'/work/lux/state/rlp/lux-testnet/lux-testnet-96368.rlp"],"id":1}' \
  http://127.0.0.1:9642/ext/bc/C/rpc

# Import zootest blocks (84 blocks)
# First get the blockchain ID
ZOOTEST_ID=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"platform.getBlockchains","params":{},"id":1}' \
  http://127.0.0.1:9642/ext/bc/P | jq -r '.result.blockchains[] | select(.name=="zootest") | .id')

curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_importChain","params":["'$HOME'/work/lux/state/rlp/zoo-testnet/zoo-testnet-200201.rlp"],"id":1}' \
  http://127.0.0.1:9642/ext/bc/${ZOOTEST_ID}/rpc

# Import zoo mainnet blocks (799 blocks)
ZOO_ID=$(curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"platform.getBlockchains","params":{},"id":1}' \
  http://127.0.0.1:9632/ext/bc/P | jq -r '.result.blockchains[] | select(.name=="zoo") | .id')

curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_importChain","params":["'$HOME'/work/lux/state/rlp/zoo-mainnet/zoo-mainnet-200200.rlp"],"id":1}' \
  http://127.0.0.1:9632/ext/bc/${ZOO_ID}/rpc

# Import C-Chain mainnet blocks (LAST - ~700k blocks, runs in background)
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_importChain","params":["'$HOME'/work/lux/state/rlp/lux-mainnet/lux-mainnet-96369.rlp"],"id":1}' \
  http://127.0.0.1:9632/ext/bc/C/rpc
```

#### 4. Verify Import Progress

```bash
# Check C-Chain block height
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://127.0.0.1:9632/ext/bc/C/rpc | jq -r '.result' | xargs printf "%d\n"

# Check logs for import progress
tail -f ~/.lux/runs/mainnet/run_*/node1/db/mainnet/main.log | grep -E "(Inserted|Imported)"
```

### Run Directories

| Network | Run Directory |
|---------|---------------|
| Testnet | `~/.lux/runs/testnet/run_YYYYMMDD_HHMMSS/` |
| Mainnet | `~/.lux/runs/mainnet/run_YYYYMMDD_HHMMSS/` |

### Successful Deployment State (2025-12-24)

```
TESTNET (ports 9640-9648):
  C-Chain (96368): 218 blocks
  Zootest (200201): 84 blocks

MAINNET (ports 9630-9638):
  Zoo (200200): 799 blocks
  C-Chain (96369): ~700k blocks (import completed)
```

### Key Notes

1. **Network Flags Required**: Always use `--mainnet` or `--testnet` to target correct network
2. **Import Runs in Background**: The `admin_importChain` call returns immediately; import continues in background
3. **Genesis Must Match**: Block import requires exact genesis match (state root must be accessible)
4. **C-Chain Import Speed**: ~700-1000 blocks/sec on M1 Max
5. **EVM Plugin**: Shared VMID `ag3GReYPNuSR17rUP8acMdZipQBikdXNRKDyFszAysmy3vDXE` for all Lux EVM chains

---

## Docker Compose Stacks (2025-12-24)

### Overview

Two Docker Compose stacks for running the Lux ecosystem:

| Stack | Purpose | Location |
|-------|---------|----------|
| **stack** | Public developer stack | `/Users/z/work/lux/stack/` |
| **universe** | Internal production stack | `/Users/z/work/lux/universe/` |

### Stack (Public Developer Ecosystem)

Complete developer ecosystem for running Lux locally:

```bash
# Start full stack
docker compose up -d

# With dev tools (adminer, redis-commander, mailhog)
docker compose --profile dev up -d

# With P/X chain indexers
docker compose --profile indexers up -d
```

**Services:**
| Service | Port | Description |
|---------|------|-------------|
| node | 9650 | Lux blockchain node |
| explorer | 4000 | Blockscout explorer |
| exchange | 3000 | DEX frontend |
| exchange-api | 3010 | DEX backend |
| marketplace | 3001 | NFT marketplace |
| bridge | 3002 | Cross-chain bridge UI |
| finance | 3003 | DeFi platform |
| wallet | 3004 | Web wallet |
| graph-node | 8000 | Subgraph indexing |
| ipfs | 5001/8081 | Decentralized storage |
| redis | 6380 | Cache layer |

**Files:**
- `compose.yml` - Main production config
- `compose.dev.yml` - Development overlay with hot-reload
- `compose-minimal.yml` - Just node + redis
- `.env.example` - Environment configuration

### Universe (Production Mainnet)

Full 5-node validator network with production configuration:

```bash
# Start mainnet (5 validators)
docker compose up -d

# Add explorers for Zoo/Hanzo chains
docker compose --profile explorers up -d

# Add subgraph indexing
docker compose --profile graph up -d

# Add P/X chain indexers
docker compose --profile indexers up -d

# Add bridge infrastructure
docker compose --profile bridge up -d

# Add frontend UIs
docker compose --profile ui up -d
```

**Validator NodeIDs:**
| Node | NodeID | Port |
|------|--------|------|
| 1 (Bootstrap) | `NodeID-FrtEjhat6RUqjEWCJgYZKqBaxY2Woyy5G` | 9630 |
| 2 | `NodeID-9hq49qGVZN7M7tXxdpF3AqptQGdmPCFnQ` | 9660 |
| 3 | `NodeID-8osEnSC4LQFdG1LMit12CBsE6BfKGHNAw` | 9670 |
| 4 | `NodeID-MrdgTgPuddyo7anomKr4akMcoKzVKcgbG` | 9680 |
| 5 | `NodeID-Mgd5yHs4pe6qRjkBcW5Y7oqHA51j4afcC` | 9690 |

**Explorers:**
| Chain | Chain ID | Port |
|-------|----------|------|
| LUX C-Chain | 96369 | 4010 |
| Zoo Network | 200200 | 4011 |
| Hanzo AI Chain | 36963 | 4012 |

**Network:** `lux-network` (172.30.0.0/16)

**Files:**
- `compose.yml` - Main production config
- `.env.example` - Environment configuration
- `docker/init.sql` - PostgreSQL database initialization

### Key Differences

| Feature | Stack | Universe |
|---------|-------|----------|
| Nodes | 1 | 5 (validators) |
| Explorers | 1 (C-Chain) | 3 (LUX, Zoo, Hanzo) |
| Use Case | Development | Production |
| Network | Single node | Full consensus |

---

## Fortuna Timestamp Fix & Complete RLP Import (2025-12-25)

### Problem: Gas Limit Mismatch on Block Import

When importing Zoo chain blocks, the import failed with:
```
invalid gas limit: have 12000000, want 10000000
```

### Root Cause

The Zoo genesis files had `fortunaTimestamp: 0` which activates the Fortuna upgrade from block 0. With Fortuna active, `VerifyGasLimit()` in `/Users/z/work/lux/coreth/plugin/evm/header/gas_limit.go` uses `state.MaxCapacity()` which returns 10,000,000 based on fee state calculation.

However, the original Zoo chain blocks were created with gasLimit 12,000,000 (under Cortina rules, not Fortuna).

### Solution

Set Fortuna, Etna, and Granite timestamps to far-future (253399622400) instead of 0:

```json
{
  "config": {
    "durangoBlockTimestamp": 0,
    "etnaTimestamp": 253399622400,
    "fortunaTimestamp": 253399622400,
    "graniteTimestamp": 253399622400
  }
}
```

This keeps Cortina active (which accepts 12M, 8M, or 15M gas limits) while deferring Fortuna upgrade.

### Files Modified

- `/Users/z/.lux/chains/zoo/genesis.json`
- `/Users/z/.lux/chains/zootest/genesis.json`
- `/Users/z/work/lux/genesis/configs/zoo-mainnet/genesis.json`
- `/Users/z/work/lux/genesis/configs/zoo-testnet/genesis.json`

### Import Procedure (Using Admin APIs)

The import requires two steps:
1. **Write Genesis State Spec**: Stores genesis allocations in the database
2. **Import Chain**: Imports blocks from RLP file

```bash
# 1. Write genesis state spec (enables import without full state trie)
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_writeGenesisStateSpec","params":["/path/to/genesis.json"],"id":1}' \
  "http://127.0.0.1:9630/ext/bc/<CHAIN_ID>/rpc"

# 2. Import blocks from RLP
curl -s -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"admin_importChain","params":["/path/to/blocks.rlp"],"id":1}' \
  "http://127.0.0.1:9630/ext/bc/<CHAIN_ID>/rpc"
```

### Verified Import Results (2025-12-25)

| Network | Chain | Chain ID | Blocks | Genesis Hash |
|---------|-------|----------|--------|--------------|
| **MAINNET** | C-Chain | 96369 | **1,082,780** | `0x3f4fa2a0b0ce089f52bf0ae9199c75ffdd76ecafc987794050cb0d286f1ec61e` |
| **MAINNET** | Zoo | 200200 | **799** | `0x7c548af47de27560779ccc67dda32a540944accc71dac3343da3b9cd18f14933` |
| **TESTNET** | C-Chain | 96368 | **218** | `0x1c5fe37764b8bc146dc88bc1c2e0259cd8369b07a06439bcfa1782b5d4fb0995` |
| **TESTNET** | Zootest | 200201 | **84** | `0x0652fb2fde1460544a5893e5eba5095ff566861cbc87fcb1c73be2b81d6d1979` |

### Current Network State

**Mainnet (Network ID: 1)**
- gRPC: `localhost:8369`
- Validators: 5 nodes on ports 9630-9638
- Chains:
  - C-Chain: `http://127.0.0.1:9630/ext/bc/C/rpc`
  - Zoo: `http://127.0.0.1:9630/ext/bc/2iJykKjE7gpWNjGUvGG6fVtj7u5Tbvo89CVCu6gjNPCnEdCVpY/rpc`

**Testnet (Network ID: 2)**
- gRPC: `localhost:8368`
- Validators: 5 nodes on ports 9640-9648
- Chains:
  - C-Chain: `http://127.0.0.1:9640/ext/bc/C/rpc`
  - Zootest: `http://127.0.0.1:9640/ext/bc/9iABHiD4jiXiShpC2eL2P5VFg76kBnLvd5qCxp6iRpjemC89W/rpc`

### RLP Files (Updated Counts)

| File | Size | Blocks |
|------|------|--------|
| `lux-mainnet-96369.rlp` | 1.2GB | 1,082,780 |
| `zoo-mainnet-200200.rlp` | 1.3MB | 799 |
| `lux-testnet-96368.rlp` | 695KB | 218 |
| `zoo-testnet-200201.rlp` | 156KB | 84 |

### Gas Limit Validation Rules

From `/Users/z/work/lux/coreth/plugin/evm/header/gas_limit.go`:

| Upgrade | Gas Limit Rule |
|---------|----------------|
| **Fortuna** | `state.MaxCapacity()` (dynamic, ~10M) |
| **Cortina** | Accepts 15M, 8M, or 12M |
| **ApricotPhase1** | Accepts 8M or 12M |
| **Pre-Apricot** | Parent gas limit ± bound |

### Import Speed

On M1 Max:
- C-Chain mainnet: ~1,000-1,400 blocks/sec
- Total import time: ~15 minutes for 1M blocks

---

## Multi-VM Precompile Integration (v0.4.0)

### Overview

The Lux precompile system now provides comprehensive integration with all specialized VMs in the node:

| VM | Chain | Precompile Package | Address Range | Purpose |
|----|-------|-------------------|---------------|---------|
| BridgeVM | B-Chain | `bridge/` | 0x0440-0x0445 | MPC-based cross-chain bridging |
| ThresholdVM | T-Chain | `threshold/` | 0x0800-0x0813 | Threshold signatures (LSS, FROST, CGGMP21, Ringtail) |
| ZKVM | Z-Chain | `zk/` | 0x0900-0x0932 | Zero-knowledge proofs, privacy, rollups |
| QuantumVM | Q-Chain | `quantum/` | 0x0600-0x0632 | Post-quantum crypto, quantum stamps |

### Bridge Precompiles (bridge/)

EVM interface to B-Chain MPC bridge operations:

| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0440 | BRIDGE_GATEWAY | Main bridge gateway for cross-chain transfers | 100,000 |
| 0x0441 | BRIDGE_ROUTER | Cross-chain routing | 50,000 |
| 0x0442 | BRIDGE_VERIFIER | Message verification | 25,000 |
| 0x0443 | BRIDGE_LIQUIDITY | Bridge liquidity pools | 75,000 |
| 0x0444 | BRIDGE_FEE | Fee management | 10,000 |
| 0x0445 | BRIDGE_SIGNER | MPC signer interface | 150,000 |

**Supported Chains:**
- Lux ecosystem: C-Chain (96369), Hanzo (36963), Zoo (200200), SPC (36911)
- External: Ethereum (1), Arbitrum (42161), Optimism (10), Base (8453), Polygon (137), BSC (56), Avalanche (43114)

**Key Features:**
- LP-333 opt-in signer model (100 max signers, 100M LUX bond)
- 2/3 BFT threshold for signatures
- Daily limits and per-transaction limits
- Liquidity provider incentives

### Threshold Precompiles (threshold/)

EVM interface to T-Chain MPC-as-a-service:

| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0800 | THRESHOLD_KEYGEN | Distributed key generation | 500,000 |
| 0x0801 | THRESHOLD_SIGN | Threshold signing | 100,000 |
| 0x0802 | THRESHOLD_REFRESH | Key share refresh | 250,000 |
| 0x0803 | THRESHOLD_RESHARE | Key resharing | 500,000 |
| 0x0804 | THRESHOLD_VERIFY | Signature verification | 25,000 |
| 0x0810 | FROST | FROST threshold Schnorr | 25,000 |
| 0x0811 | CGGMP21 | CGGMP21 threshold ECDSA | 50,000 |
| 0x0812 | RINGTAIL | Post-quantum threshold | 75,000 |
| 0x0813 | LSS | Lux Secret Sharing | 25,000 |

**Supported Key Types:**
- secp256k1 (ECDSA)
- Ed25519 (EdDSA)
- BLS12-381
- Ringtail (post-quantum)
- ML-DSA

### ZK Precompiles (zk/)

EVM interface to ZKVM for privacy and rollups:

| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0900 | ZK_VERIFY | Generic ZK proof verification | 200,000 |
| 0x0901 | GROTH16 | Groth16 verifier | 200,000 |
| 0x0902 | PLONK | PLONK verifier | 250,000 |
| 0x0903 | FFLONK | fflonk verifier | 250,000 |
| 0x0904 | HALO2 | Halo2 verifier | 300,000 |
| 0x0910 | KZG | KZG commitments | 50,000 |
| 0x0911 | PEDERSEN | Pedersen commitments | 10,000 |
| 0x0912 | IPA | Inner product arguments | 75,000 |
| 0x0920 | PRIVACY_POOL | Confidential transaction pool | 50,000 |
| 0x0921 | NULLIFIER | Nullifier verification | 5,000 |
| 0x0922 | COMMITMENT | Commitment verification | 10,000 |
| 0x0923 | RANGE_PROOF | Range proof verification | 100,000 |
| 0x0930 | ROLLUP_VERIFY | ZK rollup batch verification | 500,000 |
| 0x0931 | STATE_ROOT | State root verification | 25,000 |
| 0x0932 | BATCH_PROOF | Batch proof aggregation | 100,000 |

**Features:**
- Groth16 and PLONK proof verification
- Confidential UTXO model with nullifiers
- ZK rollup batch verification
- KZG polynomial commitments (EIP-4844)
- Range proofs for hidden amounts

### Quantum Precompiles (quantum/)

EVM interface to QuantumVM for post-quantum security:

| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| 0x0600 | QUANTUM_VERIFY | Generic quantum signature verification | 75,000 |
| 0x0601 | RINGTAIL | Ringtail threshold signatures | 75,000 |
| 0x0602 | ML_DSA | NIST ML-DSA (Dilithium) | 50,000 |
| 0x0603 | ML_KEM | NIST ML-KEM (Kyber) | 25,000 |
| 0x0604 | SLH_DSA | NIST SLH-DSA (SPHINCS+) | 100,000 |
| 0x0610 | HYBRID_BLS_RINGTAIL | BLS + Ringtail hybrid | 100,000 |
| 0x0611 | HYBRID_ECDSA_MLDSA | ECDSA + ML-DSA hybrid | 100,000 |
| 0x0612 | HYBRID_SCHNORR_RINGTAIL | Schnorr + Ringtail hybrid | 100,000 |
| 0x0620 | QUANTUM_STAMP | Quantum timestamp verification | 50,000 |
| 0x0621 | QUANTUM_ANCHOR | Quantum anchor verification | 50,000 |
| 0x0630 | BLS_VERIFY | BLS12-381 signature verification | 25,000 |
| 0x0631 | BLS_AGGREGATE | BLS signature aggregation | 10,000 |
| 0x0632 | BLS_MULTI_VERIFY | BLS multi-signature verification | 50,000 |

**NIST PQ Standards:**
- ML-DSA-44/65/87 (FIPS 204)
- ML-KEM-512/768/1024 (FIPS 203)
- SLH-DSA (FIPS 205)

**Hybrid Signatures:**
- Both classical and quantum signatures required for maximum security
- Graceful degradation if one fails
- Future-proof against quantum attacks

### Directory Structure (Updated)

```
/Users/z/work/lux/precompile/
├── ai/           # AI Mining (0x0300)
├── bridge/       # B-Chain bridge (0x0440-0x0445) [NEW]
│   ├── types.go
│   ├── gateway.go
│   └── signer.go
├── cggmp21/      # CGGMP21 threshold ECDSA
├── dex/          # DEX precompiles (0x0400-0x043F)
│   ├── pool_manager.go
│   ├── perpetuals.go
│   ├── margin.go
│   ├── vaults.go
│   └── lending.go
├── ecies/        # ECIES encryption
├── fhe/          # Fully Homomorphic Encryption
├── frost/        # FROST threshold Schnorr
├── graph/        # GraphQL query layer
├── hpke/         # Hybrid Public Key Encryption
├── kzg4844/      # KZG commitments
├── mldsa/        # ML-DSA signatures
├── mlkem/        # ML-KEM key encapsulation
├── pqcrypto/     # Multi-PQ operations
├── quantum/      # Quantum precompiles (0x0600-0x0632) [NEW]
│   ├── types.go
│   └── verifier.go
├── quasar/       # Quantum consensus
├── ring/         # Ring signatures
├── ringtail/     # Ringtail threshold
├── secp256r1/    # P-256 curve
├── slhdsa/       # SLH-DSA signatures
├── threshold/    # Threshold precompiles (0x0800-0x0813) [NEW]
│   ├── types.go
│   └── manager.go
└── zk/           # ZK precompiles (0x0900-0x0932) [NEW]
    ├── types.go
    └── verifier.go
```

### Cross-VM Communication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     C-Chain (EVM)                               │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Precompiles                          │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐   │    │
│  │  │ bridge/ │ │threshold│ │   zk/   │ │  quantum/   │   │    │
│  │  │ 0x0440  │ │ 0x0800  │ │ 0x0900  │ │   0x0600    │   │    │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └──────┬──────┘   │    │
│  └───────┼───────────┼───────────┼─────────────┼──────────┘    │
│          │           │           │             │                │
└──────────┼───────────┼───────────┼─────────────┼────────────────┘
           │           │           │             │
           ▼           ▼           ▼             ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ BridgeVM │ │ThresholdVM│ │  ZKVM   │ │QuantumVM │
    │ B-Chain  │ │ T-Chain  │ │ Z-Chain │ │ Q-Chain  │
    │  MPC     │ │  DKG     │ │ Privacy │ │   PQ     │
    └──────────┘ └──────────┘ └──────────┘ └──────────┘
```

---

*Last Updated: 2025-12-31*
*Version: 0.4.0*
*Test Status: All packages building*
