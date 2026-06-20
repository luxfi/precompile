# FHE + Attestation Mutex Fix Plan

**Status**: Analysis complete (agent a0677f0c, 2026-04-10). Implementation blocked by usage limit.

## Threat Model

- **Assets**: Consensus determinism across validator nodes
- **Adversary**: Concurrent EVM transaction execution within a block
- **Attack**: Unprotected map writes → data races → non-determinism → chain split

## Findings

### REAL bugs requiring fix

1. **FHE** — `/Users/z/work/lux/precompile/fhe/contract.go`
   - `ciphertextStore` — no lock
   - `ciphertextTypes` — no lock
   - Pattern: every operation reads & writes → heavy R+W
   - **Fix**: `sync.RWMutex` (reads are more frequent)
     - `getCiphertext` called 2× per binary op → RLock
     - `storeCiphertext` called 1× → Lock

2. **attestation** — `/Users/z/work/lux/precompile/attestation/`
   - `globalVerifier` — from `luxfi/ai` library, no visible internal locking
   - `nvtrustVerifier` — same, no guard
   - Library Verifier has internal mutable state (device registrations, job completions)
   - **Fix**: Wrap calls in package-level `sync.RWMutex`, OR upstream the fix to `luxfi/ai`

### Already protected (no fix needed)

| Package | Lock | Notes |
|---------|------|-------|
| zk/stark.go | `starkVerifiersMu` | OK |
| zk/pedersen.go | `sync.RWMutex` on pointCache + globalPedersen | OK |
| zk/poseidon.go | `cacheMu` | OK |
| zk/verifier.go | internal `mu` | OK |
| frost | `liftXCacheMu` | OK |
| quantum | `qv.mu` | OK |
| dex | per-struct `mu`; HookSignatures read-only after init | OK |
| bridge | gateway.go + signer.go have internal `mu` | OK |
| graph | OracleQueries + AMMQueries + PredefinedQueries are read-only literals | OK |
| ai | privacyMultipliers read-only; baseRewardPerMinute only `.Set()` reads | OK |
| threshold | only error sentinels (immutable) | OK |

## Implementation

```go
// fhe/contract.go additions:
var (
    ciphertextStoreMu sync.RWMutex
    ciphertextStore   = make(map[string]*tfhe.Ciphertext)
    ciphertextTypes   = make(map[string]int)
)

func storeCiphertext(key string, ct *tfhe.Ciphertext, fheType int) {
    ciphertextStoreMu.Lock()
    defer ciphertextStoreMu.Unlock()
    ciphertextStore[key] = ct
    ciphertextTypes[key] = fheType
}

func getCiphertext(key string) (*tfhe.Ciphertext, int, bool) {
    ciphertextStoreMu.RLock()
    defer ciphertextStoreMu.RUnlock()
    ct, ok := ciphertextStore[key]
    if !ok {
        return nil, 0, false
    }
    return ct, ciphertextTypes[key], true
}
```

## Test (must add)

```go
// fhe/concurrency_test.go
func TestFHE_ConcurrentAccess(t *testing.T) {
    const N = 100
    var wg sync.WaitGroup
    wg.Add(N)
    for i := 0; i < N; i++ {
        go func(i int) {
            defer wg.Done()
            // perform FHE op that reads+writes maps
            _, _ = runFheOp(/* ... */)
        }(i)
    }
    wg.Wait()
}
```

Run with: `go test -race -run TestFHE_ConcurrentAccess`

## Out-of-scope packages

Per analysis, all other packages already have proper synchronization. Do NOT add mutexes where not needed — that's just noise.

## Commits expected

1. `fhe: add sync.RWMutex to ciphertextStore and ciphertextTypes (prevents consensus split)`
2. `attestation: protect globalVerifier + nvtrustVerifier with sync.RWMutex`
3. `precompile: add concurrency tests for fhe + attestation`
