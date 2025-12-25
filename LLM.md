# precompiles

## Overview

This directory contains all precompiled contracts (precompiles) for the Lux blockchain ecosystem. Precompiles are special smart contracts implemented natively in the node software for performance-critical operations that would be too expensive or slow to implement in Solidity. Precompiles are located at deterministic addresses starting from `0x0200000000000000000000000000000000000000`. They provide optimized implementations for cryptographic operations, cross-chain messaging, and chain configuration. 

## Package Information

- **Type**: go
- **Module**: github.com/luxfi/precompiles
- **Repository**: github.com/luxfi/precompiles

## Directory Structure

```
.
ai
cggmp21
contract
deployerallowlist
deployerallowlist/deployerallowlisttest
frost
mldsa
nativeminter
pqcrypto
precompileconfig
quasar
ringtail
slhdsa
txallowlist
```

## Key Files

- AIMining.sol
- go.mod
- IAllowList.sol
- TeleportBridge.sol

## Development

### Prerequisites

- Go 1.21+

### Build

```bash
go build ./...
```

### Test

```bash
go test -v ./...
```

## Integration with Lux Ecosystem

This package is part of the Lux blockchain ecosystem. See the main documentation at:
- GitHub: https://github.com/luxfi
- Docs: https://docs.lux.network

---

*Auto-generated for AI assistants. Last updated: 2025-12-24*
