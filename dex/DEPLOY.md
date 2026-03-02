# DEX Precompile Deployment Guide (Lux Testnet)

## Status: Ready for Testnet

### Build Status

- Package: `github.com/luxfi/precompile/dex`
- Compiles: YES (`go build ./dex/`)
- Tests: 81 passing, 0 failing (`go test ./dex/`)

### Precompile Inventory

All precompiles are **implemented** (not stubs). Two modules are registered with the EVM
via `init()` functions in `module.go` and `router_module.go`:

| Component | Address | Config Key | Module Status | File |
|-----------|---------|------------|---------------|------|
| **LXPool** (PoolManager) | `0x...9010` | `dexConfig` | Registered | `module.go` |
| **LXOracle** | `0x...9011` | - | Impl only (no module) | - |
| **LXRouter** | `0x...9012` | `routerConfig` | Registered | `router_module.go` |
| **LXHooks** | `0x...9013` | - | Impl only (no module) | `hooks.go` |
| **LXFlash** | `0x...9014` | - | Integrated in PoolManager | `module.go` (Lock) |
| **LXBook** (CLOB) | `0x...9020` | - | Impl only (no module) | - |
| **LXVault** | `0x...9030` | - | Impl only (no module) | `vaults.go` |
| **LXFeed** | `0x...9040` | - | Impl only (no module) | - |
| **LXLend** | `0x...9050` | - | Impl only (no module) | `lending.go` |
| **LXLiquid** | `0x...9060` | - | Impl only (no module) | `liquid.go` |
| **Liquidator** | `0x...9070` | - | Impl only (no module) | `liquidation.go` |
| **LiquidFX** (Transmuter) | `0x...9080` | - | Impl only (no module) | `transmuter.go` |
| **Teleport** | `0x...6010` | - | Impl only (no module) | `teleport.go` |

Supporting files: `types.go`, `events.go`, `interest_rate.go`, `margin.go`,
`perpetuals.go`, `router.go`, `pool_manager.go`.

### EVM Registration

The DEX precompile is **already registered** in the subnet EVM at:

```
~/work/lux/evm/precompile/registry/registry.go:60
    _ "github.com/luxfi/precompile/dex" // Native DEX PoolManager (LP-9010)
```

Registration flow:
1. `dex/module.go` `init()` calls `modules.RegisterModule(Module)` for LXPool at 0x9010
2. `dex/router_module.go` `init()` calls `modules.RegisterModule(RouterModule)` for LXRouter at 0x9012
3. `evm/precompile/registry/registry.go` blank-imports `github.com/luxfi/precompile/dex`
4. `evm/precompile/registry/bridge.go` `init()` calls `bridgeExternalModules()` which copies
   external modules into the EVM's internal registry with adapter types
5. The EVM's `precompile_overrider.go` wraps them as `StatefulPrecompiledContract` at runtime

The EVM depends on `github.com/luxfi/precompile v0.4.10` (see `evm/go.mod:34`).

### ThresholdVM Status

ThresholdVM at `~/work/lux/node/vms/thresholdvm/` is **complete and registered**:

- Factory registered in `node/node/vms_allvms.go:50` under `constants.ThresholdVMID`
- Aliases: `T`, `threshold`, `thresholdvm`, `mpc`
- Implements `chain.ChainVM` interface
- Full MPC protocol suite (LSS, FROST, CGGMP21, Corona)
- FHE acceleration (GPU optional, CPU fallback)
- RPC client implementation
- 10+ Go files, extensive test coverage

Not directly relevant to DEX precompile deployment, but available for cross-chain MPC
signing if Teleport bridge is activated.

---

## Step 1: Update Precompile Version in EVM

The EVM currently pins `github.com/luxfi/precompile v0.4.10`. To deploy the latest
DEX code, tag a new version and update the EVM dependency.

```bash
# In precompile repo: tag and push
cd ~/work/lux/precompile
git tag v0.4.11
git push origin v0.4.11

# In EVM repo: update dependency
cd ~/work/lux/evm
go get github.com/luxfi/precompile@v0.4.11
go mod tidy
```

Or for local development, use a replace directive (do NOT commit):
```bash
cd ~/work/lux/evm
go mod edit -replace github.com/luxfi/precompile=../precompile
```

## Step 2: Configure Chain Config

The DEX precompiles are activated via the chain config JSON. Two precompile configs
are supported:

### dexConfig (LXPool - PoolManager)

```json
{
  "dexConfig": {
    "blockTimestamp": 0,
    "protocolFeeController": "0x9011E888251AB053B7bD1cdB598Db4f9DEd94714",
    "maxPools": 10000,
    "enableFlashLoans": true,
    "enableHooks": true
  }
}
```

### routerConfig (LXRouter)

```json
{
  "routerConfig": {
    "blockTimestamp": 0,
    "v3QuoterAddress": "0x0000000000000000000000000000000000000000",
    "v3FactoryAddress": "0x0000000000000000000000000000000000000000",
    "v2RouterAddress": "0x0000000000000000000000000000000000000000",
    "v2FactoryAddress": "0x0000000000000000000000000000000000000000"
  }
}
```

Setting `blockTimestamp: 0` activates the precompile from genesis (block 0).
Setting a future timestamp activates at that block time (for upgrade scheduling).

## Step 3: Create Testnet Chain Config

Place the config at `~/work/lux/universe/chain-configs/testnet-dex.json`.
See the file created alongside this document.

For a fresh subnet deployment, include the precompile configs in the **genesis JSON**
under the `config` key. For an existing C-Chain, add them to `upgrade.json`.

### Fresh Subnet Genesis (recommended for testnet)

```json
{
  "config": {
    "chainId": 96368,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "muirGlacierBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "shanghaiTime": 0,
    "feeConfig": {
      "gasLimit": 15000000,
      "targetBlockRate": 2,
      "minBaseFee": 25000000000,
      "targetGas": 60000000,
      "baseFeeChangeDenominator": 36,
      "minBlockGasCost": 0,
      "maxBlockGasCost": 1000000,
      "blockGasCostStep": 200000
    },
    "dexConfig": {
      "blockTimestamp": 0,
      "protocolFeeController": "0x9011E888251AB053B7bD1cdB598Db4f9DEd94714",
      "maxPools": 10000,
      "enableFlashLoans": true,
      "enableHooks": true
    },
    "routerConfig": {
      "blockTimestamp": 0
    }
  },
  "alloc": {
    "9011E888251AB053B7bD1cdB598Db4f9DEd94714": {
      "balance": "0x193e5939a08ce9dbd480000000"
    }
  },
  "timestamp": "0x0",
  "gasLimit": "0xe4e1c0",
  "difficulty": "0x0",
  "baseFeePerGas": "0x5d21dba00"
}
```

### Existing C-Chain Upgrade (alternative)

For an already-running C-Chain, create `upgrade.json` in the chain config directory:

```json
{
  "precompileUpgrades": [
    {
      "dexConfig": {
        "blockTimestamp": 1742500000,
        "protocolFeeController": "0x9011E888251AB053B7bD1cdB598Db4f9DEd94714",
        "maxPools": 10000,
        "enableFlashLoans": true,
        "enableHooks": true
      }
    },
    {
      "routerConfig": {
        "blockTimestamp": 1742500000
      }
    }
  ]
}
```

Place at: `~/.lux/chains/<BlockchainID>/upgrade.json`

## Step 4: Build and Install

```bash
# Build EVM plugin
cd ~/work/lux/evm
go build -o evm ./plugin

# Copy to plugins directory
VMID="mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6"
cp evm ~/.lux/plugins/$VMID

# Build node
cd ~/work/lux/node
go build -o build/luxd ./main
cp build/luxd ~/.lux/bin/luxd/luxdv1.23.28/luxd
```

## Step 5: Deploy to Testnet

### Option A: Fresh DEX Subnet

```bash
# Create subnet with DEX genesis
lux l2 create dex-testnet \
  --genesis ~/work/lux/universe/chain-configs/testnet-dex.json \
  --vm-binary ~/.lux/plugins/$VMID

# Deploy to testnet
lux l2 deploy dex-testnet --testnet
```

### Option B: Activate on Existing Testnet C-Chain

```bash
# Place upgrade.json
CHAIN_ID="2X5gN8uSRvubaP4jcJSCvnTfzoFqBaKHpgjWvSQBAvLdcgYtZ4"
mkdir -p ~/.lux/chains/$CHAIN_ID
cp upgrade.json ~/.lux/chains/$CHAIN_ID/upgrade.json

# Restart network
lux network stop --testnet
lux network start --testnet
```

## Step 6: Verify Deployment

```bash
# Check precompile responds at LXPool address
cast call 0x0000000000000000000000000000000000009010 \
  "0x08000000" \
  --rpc-url http://127.0.0.1:9740/ext/bc/C/rpc

# Check LXRouter
cast call 0x0000000000000000000000000000000000009012 \
  "0x0C000000" \
  --rpc-url http://127.0.0.1:9740/ext/bc/C/rpc

# Initialize a test pool (ETH/USDC 0.3% fee)
# Use the method selector 0x01000000 (SelectorInitialize)
```

## Gaps and Risks

### Modules Not Yet Registered

Only LXPool (0x9010) and LXRouter (0x9012) have `modules.Module` registrations
with config keys and `init()` functions. The remaining precompiles (LXLend, LXLiquid,
Liquidator, LiquidFX, LXVault, Perpetuals, Margin, Teleport) have full Go
implementations but are not registered as separate precompile modules.

**Impact**: They are not individually addressable by the EVM at their own addresses.
They are currently accessed through the main LXPool contract or used internally.

**To register them**, follow the pattern in `router_module.go`:
1. Define a `FooModule = modules.Module{...}` var
2. Add `init() { modules.RegisterModule(FooModule) }`
3. Implement `contract.StatefulPrecompiledContract` (`Run`, `RequiredGas`)
4. Implement `contract.Configurator` and `precompileconfig.Config`

### poolStateAdapter Incomplete

The `poolStateAdapter` in `module.go` has stub implementations for `AddBalance`
and `SubBalance` (lines 435-441). These need the `tracing.BalanceChangeReason`
parameter from the real EVM StateDB. In practice, the `stateDBBridge` in the
EVM registry handles this via type assertions to the underlying `vm.StateDB`.

### Exact Output Routing

`RouterContract.runExactOutputSingle` and `runExactOutput` return
"not yet implemented" errors (router_module.go lines 225, 235).

### Flash Accounting Lock Callback

The `runLock` method is a simplified version that returns success without actually
calling back to the caller contract. Full flash accounting requires EVM-level
callback support (CALL opcode from precompile context).

---

## Precompile Address Reference

Full LP-aligned addresses (20-byte EVM format):

```
LXPool:      0x0000000000000000000000000000000000009010
LXOracle:    0x0000000000000000000000000000000000009011
LXRouter:    0x0000000000000000000000000000000000009012
LXHooks:     0x0000000000000000000000000000000000009013
LXFlash:     0x0000000000000000000000000000000000009014
LXBook:      0x0000000000000000000000000000000000009020
LXVault:     0x0000000000000000000000000000000000009030
LXFeed:      0x0000000000000000000000000000000000009040
LXLend:      0x0000000000000000000000000000000000009050
LXLiquid:    0x0000000000000000000000000000000000009060
Liquidator:  0x0000000000000000000000000000000000009070
LiquidFX:    0x0000000000000000000000000000000000009080
Teleport:    0x0000000000000000000000000000000000006010
```

Old addresses (0x0400, 0x0401, 0x0403, 0x0432) are **deprecated**.
The codebase uses the LP-aligned 0x9010+ series exclusively.
