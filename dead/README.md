# Dead Precompile (LP-0150)

**Address**: Multiple (0x0, 0xdead, 0xdEaD...)  
**Gas Cost**: 10,000 base  
**Status**: Implemented

## Overview

The Dead Precompile intercepts transfers to "dead" addresses (commonly used for token burns) and routes them to a 50/50 split between:

1. **Actual Burn (50%)** - Value is permanently destroyed (deflationary)
2. **DAO Treasury (50%)** - Value goes to Protocol-Owned Liquidity (POL)

This creates sustainable protocol revenue from burn activities instead of purely destroying value.

## Registered Addresses

| Address | Description | ConfigKey |
|---------|-------------|-----------|
| `0x0000000000000000000000000000000000000000` | Zero address | `deadZeroConfig` |
| `0x000000000000000000000000000000000000dEaD` | Common dead address | `deadConfig` |
| `0xdEaD000000000000000000000000000000000000` | Full dead prefix | `deadFullConfig` |

## DAO Treasury

Funds are routed to: `0x9011E888251AB053B7bD1cdB598Db4f9DEd94714`

This address is on X-Chain and accumulates protocol-owned liquidity.

## Split Ratio

| Component | Percentage | BPS |
|-----------|------------|-----|
| Burn | 50% | 5000 |
| Treasury | 50% | 5000 |

When values cannot be split evenly (odd wei amounts), the treasury receives the extra wei.

## Usage

### Direct Interaction

The precompile is automatically invoked when calling or transferring to any registered dead address:

```solidity
// Solidity - transfer to dead address triggers precompile
address payable dead = payable(0x000000000000000000000000000000000000dEaD);
dead.transfer(1 ether);
// Result: 0.5 ETH burned, 0.5 ETH to treasury
```

### Programmatic Access

```go
package main

import (
    "github.com/luxfi/precompile/dead"
    "math/big"
)

func main() {
    value := big.NewInt(1e18) // 1 ETH
    
    // Check if address is a dead address
    if dead.IsDeadAddress(addr) {
        burn, treasury := dead.CalculateSplit(value)
        // burn = 0.5 ETH
        // treasury = 0.5 ETH
    }
}
```

## Mechanics

When a transaction targets a dead address:

1. EVM recognizes the address as a precompile
2. `DeadPrecompile.Run()` is invoked
3. The `value` (ETH sent) is split 50/50
4. 50% is left at the dead address (effectively burned)
5. 50% is transferred to DAO treasury
6. Transaction stats are recorded via event

## Events

```solidity
event DeadReceived(
    address indexed sender,
    address indexed deadAddress,
    uint256 totalValue,
    uint256 burnedAmount,
    uint256 treasuryAmount
);
```

## Gas Costs

| Operation | Gas |
|-----------|-----|
| Base cost | 10,000 |
| With balance transfer | +21,000 (standard transfer) |

## Security Considerations

1. **Deterministic Split**: Split ratio is hardcoded (not configurable) to prevent manipulation
2. **DAO Treasury**: Uses a fixed address, governance changes require contract upgrade
3. **Reentrancy**: The precompile is stateless and doesn't call external contracts in a reentrant manner
4. **Value Conservation**: Total value always equals burn + treasury (verified in tests)

## Files

| File | Description |
|------|-------------|
| `contract.go` | Core precompile implementation |
| `contract_test.go` | Unit tests |
| `module.go` | Module registration |
| `README.md` | This documentation |

## Related

- [LP-0150](https://github.com/luxfi/lps/blob/main/LPs/lp-0150-dead-precompile.md) - Full specification
- [IDead.sol](https://github.com/luxfi/standard/blob/main/contracts/precompile/interfaces/IDead.sol) - Solidity interface
