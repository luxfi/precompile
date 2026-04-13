# Test Coverage Gaps — Red Team Adversarial Review

**Date**: 2026-04-10
**Reviewer**: Red Team (adversarial security audit of test suite)
**Scope**: ~/work/lux/precompile/ — all 62 test files across 40+ packages
**Finding**: The test suite gives a false sense of security in several critical areas.

---

## Executive Summary

The test suite is broad (341+ tests across 62 files) but shallow in exactly the places that matter for consensus-critical precompile code. The three most dangerous gaps:

1. **FROST "valid signature" test never actually verifies a valid signature** — it uses mock data and only checks "no error", not "verification passed". This is a test that cannot fail even if verification is completely broken.
2. **Zero concurrency tests despite 15+ packages with global mutable state** — not a single `t.Parallel()` or goroutine-based test in the entire suite. The FROST liftX cache, FHE ciphertext store, ZK verifier caches, and DEX state all have data races that are untested.
3. **No Known Answer Tests (KATs) for FIPS algorithms** — ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and ML-KEM (FIPS 203) all generate fresh keys per test. No test verifies the exact output against a NIST reference vector. If the underlying library is silently wrong, no test catches it.

---

## 1. Per-Package Missing Tests

### 1.1 Packages With ZERO Tests

| Package | Exported Functions | Severity |
|---------|-------------------|----------|
| `modules` | `RegisterModule`, `GetPrecompileModuleByAddress`, `GetPrecompileModule`, `RegisteredModules`, `ReservedAddress`, `AddressRange.Contains` | **HIGH** — RegisterModule is the trust root for all precompile registration; untested validation logic could allow address collisions or out-of-range registration |
| `precompileconfig` | `Upgrade.Timestamp`, `Upgrade.IsDisabled`, `Upgrade.Equal`, `uint64PtrEqual` | **MEDIUM** — upgrade logic controls when precompiles activate; nil pointer edge cases in `Equal` are untested |

### 1.2 FROST — Tests That Prove Nothing

| Missing Test | File | Severity |
|-------------|------|----------|
| Valid signature with actual FROST threshold keygen + signing | `frost/contract_test.go:15` | **CRITICAL** — `TestFROSTVerify_ValidSignature` uses `byte(i)` mock data, never generates a real FROST signature. The test asserts `require.NoError` but the precompile returns `result[31]==0` (invalid) for this garbage input. The test never checks `result[31]==1`. This test passes whether verification works or is completely broken. |
| Concurrent liftXCache access | `frost/contract.go:151` | **HIGH** — `liftXCache` is a global `map[[32]byte]curve.Point` guarded by `sync.RWMutex`. No test exercises concurrent `Run()` calls. A lock ordering bug or missing lock would be a consensus-splitting data race. |
| Cache eviction / bounded size | `frost/contract.go:178` | **MEDIUM** — Cache is bounded to 1024 entries but no test verifies behavior at capacity or eviction semantics. |
| Gas overflow with max uint32 totalSigners | `frost/contract_test.go` | **HIGH** — The CGGMP21 package has `security_test.go` testing gas overflow; FROST has the identical vulnerability pattern (`FROSTVerifyBaseGas + totalSigners*FROSTVerifyPerSignerGas`) but no equivalent test. |

### 1.3 CGGMP21

| Missing Test | Severity |
|-------------|----------|
| Empty input (0 bytes) | **MEDIUM** |
| Nil input | **MEDIUM** |
| All-zero input (MinInputSize bytes of 0x00) — threshold=0, total=0 | **MEDIUM** |
| All-ones input (0xFF bytes) | **LOW** |
| Input exactly one byte longer than MinInputSize | **LOW** |
| Concurrent Run() invocations | **HIGH** |
| Gas = 0 must return ErrOutOfGas | **HIGH** — not tested |
| Gas = RequiredGas - 1 must return ErrOutOfGas | **HIGH** — not tested |
| Gas = max uint64 must succeed without overflow | **MEDIUM** |

### 1.4 ML-DSA (mldsa/)

| Missing Test | Severity |
|-------------|----------|
| FIPS 204 KAT vectors (NIST ACVP test vectors for ML-DSA-44/65/87) | **HIGH** — Tests generate fresh keys; a library bug producing wrong output would pass all tests |
| Nil input | **MEDIUM** |
| Gas = 0 | **HIGH** |
| Batch verify with count > 255 (overflow in `byte(count)`) | **MEDIUM** — `createBatchInput` uses `byte(count >> 8), byte(count)` which caps at 65535, but no test probes the boundary |
| Concurrent Run() | **MEDIUM** |
| `batchVerifyGPU` — exported but untested | **MEDIUM** |
| `verifyGPU` — exported but untested | **MEDIUM** |
| `readUint256` — exported but untested | **LOW** |

### 1.5 SLH-DSA (slhdsa/)

| Missing Test | Severity |
|-------------|----------|
| FIPS 205 KAT vectors | **HIGH** |
| All 12 modes tested (only SHA2_128s, SHA2_128f, SHAKE_128s, SHAKE_128f tested; missing SHA2_192s/f, SHAKE_192s/f, SHA2_256s/f, SHAKE_256s/f) | **HIGH** — 8 of 12 modes have no end-to-end verification test |
| `ModeName` — exported but untested | **LOW** |
| `verifySLHDSAGPU` — exported but untested | **MEDIUM** |
| Gas = 0 (only tested once via `TestSLHDSAVerify_OutOfGas` with gas=1000, not gas=0) | **LOW** |

### 1.6 Ringtail Lattice Threshold (ringtail/)

| Missing Test | Severity |
|-------------|----------|
| `deserializeSignature` — exported, complex deserialization, untested directly | **MEDIUM** |
| `deserializePoly` — exported but untested directly | **MEDIUM** |
| `initializeVector`, `initializeMatrix` — exported but untested | **LOW** |
| Malformed polynomial coefficients (negative, overflow modulus) | **HIGH** — lattice signatures depend on coefficient bounds; out-of-range values could forge signatures |
| Gas = 0 | **MEDIUM** |
| Concurrent Run() | **MEDIUM** |

### 1.7 ML-KEM (mlkem/)

| Missing Test | Severity |
|-------------|----------|
| FIPS 203 KAT vectors (NIST ACVP for ML-KEM-512/768/1024) | **HIGH** |
| Determinism: two encapsulations with same seed must produce same output | **MEDIUM** — tests don't control randomness |
| Decapsulation with wrong ciphertext (CCA2 test) | **HIGH** — ML-KEM must reject tampered ciphertexts; no test corrupts a ciphertext and checks decapsulation fails |
| `getModeParams` — exported but untested directly | **LOW** |
| `encapsulateGPU` — exported but untested | **MEDIUM** |

### 1.8 secp256r1

| Missing Test | Severity |
|-------------|----------|
| Actual NIST CAVP test vectors (current `TestContract_NISTTestVector` generates random keys, does NOT use NIST vectors) | **HIGH** — the comment on line 241 says "In production, use full NIST test vectors" but the test uses `rand.Reader` |
| `verifyGPU` — exported but untested | **MEDIUM** |
| Gas accounting (test calls `c.Run(input)` without gas parameter — different signature than StatefulPrecompiledContract) | **MEDIUM** |

### 1.9 KZG4844 (kzg4844/)

| Missing Test | Severity |
|-------------|----------|
| EIP-4844 reference test vectors from consensus-specs | **HIGH** — no `trusted_setup.json` verification, no EIP-4844 KAT |
| `blobToCommitmentGPU` — exported but untested | **MEDIUM** |
| Blob with field element >= BLS12-381 modulus | **HIGH** — `createValidBlob` intentionally uses small values; no test verifies rejection of invalid field elements |
| Nil input | **MEDIUM** |

### 1.10 FHE (fhe/)

| Missing Test | Severity |
|-------------|----------|
| Concurrent ciphertext store access (`ciphertextStore` and `ciphertextTypes` are global maps with no mutex) | **CRITICAL** — `fhe/contract.go:916-917` — two unprotected global maps. Zero concurrency tests. This is a consensus-splitting data race. |
| Ciphertext handle collision (two different ciphertexts producing the same hash) | **MEDIUM** |
| Gas = 0 for Run() | **HIGH** |
| `TypeEuint128` and `TypeEuint256` arithmetic tests | **MEDIUM** — only uint8 tested |
| Noise budget exhaustion after chained operations | **HIGH** — no test chains 10+ FHE operations to verify noise doesn't corrupt results |

### 1.11 Packages With Thin But Adequate Tests

| Package | Assessment |
|---------|------------|
| blake3 | Good coverage for operations and gas. Missing: concurrent Run(), nil input, all-ones input |
| ed25519 | Good basic coverage. Missing: ed25519 RFC 8032 test vectors (uses random keys) |
| sr25519 | Has known test vector (Alice's Substrate key). Missing: concurrent test |
| x25519 | Has RFC 7748 vectors. Missing: low-order point rejection test |
| xwing | Good for encapsulation. Missing: determinism test (controlled seed), concurrent test |
| babyjubjub | Missing: concurrent test |
| bls12381 | Missing: EIP-2537 reference vectors, concurrent test |
| curve25519 | Missing: concurrent test |
| pasta | Missing: concurrent test |
| pedersen | Missing: concurrent test |
| poseidon | Missing: concurrent test |
| hpke | Missing: RFC 9180 test vectors, concurrent test |
| ring | Missing: concurrent test |
| math | Missing: concurrent test |
| stableswap | Missing: concurrent test |
| compute | Missing: concurrent test |

---

## 2. Cross-Cutting Gaps

### 2.1 Address Uniqueness (Partial)

The `registry/registry_test.go` has `TestNoAddressCollisions` which checks `AllPrecompiles` for duplicates. **However**: this only checks the registry metadata, not the actual `ContractAddress` constants declared in each package. A package could declare `ContractAddress = 0x1234` but register a different address in its `init()` function. No test cross-references.

**Missing**: A test that imports every package, calls `RegisteredModules()`, and verifies each module's `Address` matches its package-level `ContractAddress` constant.

### 2.2 LP Documentation vs Code Validation: NOT TESTED

No test parses the LP documentation (docs/) and verifies that documented addresses match code constants. The docs are a Next.js app (MDX), not machine-parseable test vectors.

### 2.3 Consensus Determinism: INADEQUATELY TESTED

Only `blake3/contract_test.go` has determinism tests (`TestHashDeterminism`, `TestMerkleRootDeterminism`). The following precompiles use randomness internally and have NO determinism test:

| Package | Source of Non-Determinism | Determinism Test? |
|---------|--------------------------|-------------------|
| xwing | `rand.Reader` in encapsulation | NO — test explicitly checks outputs DIFFER (`TestEncapsulate_DifferentInvocations`), which is correct for KEM but means determinism is untestable without seed control |
| mlkem | `rand.Reader` in encapsulation | NO |
| fhe | `tfheRandom` uses seed | Partial — tests exist but don't verify same seed produces same output across runs |
| pqcrypto | `rand.Reader` in ML-KEM encapsulation | NO |

### 2.4 Gas Griefing: SYSTEMATICALLY UNTESTED

No package has a complete gas edge case test suite. The required tests per precompile:

| Test | Packages That Have It | Packages Missing It |
|------|----------------------|---------------------|
| gas = 0 | NONE | ALL |
| gas = RequiredGas - 1 | ed25519 (implicitly) | frost, cggmp21, mldsa, slhdsa, ringtail, blake3, kzg4844, pqcrypto, mlkem, secp256r1, x25519, xwing, fhe, quantum, quasar, bls12381, babyjubjub, curve25519, pasta, pedersen, poseidon, hpke, ring, math, stableswap, compute |
| gas = RequiredGas (exact) | mldsa, slhdsa | Most others supply excess gas |
| gas = max uint64 | contract (partial) | ALL precompile packages |

### 2.5 Nil and Empty Input: INCONSISTENTLY TESTED

| Input Type | Packages Testing It |
|-----------|-------------------|
| `nil` input | NONE explicitly (some packages may handle it via length check) |
| `[]byte{}` empty | kzg4844, pasta, bls12381, xwing, poseidon, pedersen, curve25519, hpke, x25519, babyjubjub |
| All-zero input | secp256r1 (`TestContract_ZeroValues`) |
| All-0xFF input | NONE |
| Off-by-one short | cggmp21, frost, mldsa, slhdsa, sr25519, ed25519, x25519, xwing, kzg4844 |
| Off-by-one long | secp256r1 (`TestContract_InvalidInputLength` with 161 bytes) |

---

## 3. Test Anti-Patterns Found

### 3.1 CRITICAL: Test That Cannot Fail

**File**: `frost/contract_test.go:15-58`
**Issue**: `TestFROSTVerify_ValidSignature` fills input with `byte(i)` sequential data (not a real FROST signature). The test asserts `require.NoError(t, err)` and `require.NotNil(t, result)` but never checks `result[31] == 1`. Since the precompile returns `result[31] == 0` for invalid signatures without error, this test passes whether FROST verification works or is entirely broken. **This is a test that gives false assurance about the most critical Schnorr threshold signature precompile.**

### 3.2 CRITICAL: Unprotected Global State in FHE

**File**: `fhe/contract.go:916-917`
```go
var ciphertextStore = make(map[common.Hash][]byte)
var ciphertextTypes = make(map[common.Hash]uint8)
```
These global maps have NO mutex. The FHE test file (`fhe/fhe_test.go`) calls `storeCiphertext` and `getCiphertext` but never from concurrent goroutines. In production, multiple EVM transactions in the same block could execute FHE operations concurrently, causing a data race that crashes the node or produces inconsistent state.

### 3.3 HIGH: No `subtle.ConstantTimeCompare` in Tests

Zero test files use `crypto/subtle.ConstantTimeCompare` for comparing cryptographic outputs. While test-time timing leaks don't matter directly, the pattern of using `require.Equal` for byte comparisons means tests don't verify that the *production code* uses constant-time comparison. A grep for `subtle.ConstantTimeCompare` or `hmac.Equal` in non-test code would determine whether this is an actual production vulnerability.

### 3.4 HIGH: secp256r1 Tests Use Wrong Interface

**File**: `secp256r1/contract_test.go:54`
The test calls `c.Run(input)` (2 args), but the `StatefulPrecompiledContract` interface uses `Run(accessibleState, caller, addr, input, gas, readOnly)` (6 args). The `Contract` type in secp256r1 implements a different, simpler interface. This means gas accounting, caller validation, and read-only enforcement are completely untested for secp256r1.

### 3.5 HIGH: secp256r1 "NIST Test Vector" Uses Random Keys

**File**: `secp256r1/contract_test.go:237-258`
```go
func TestContract_NISTTestVector(t *testing.T) {
    // NIST CAVP test vector (simplified example)
    // In production, use full NIST test vectors from FIPS 186-3
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
```
The function is named `TestContract_NISTTestVector` but generates a random key. This is not a test vector. The comment acknowledges this is a placeholder ("simplified example") but it was never replaced with actual NIST CAVP vectors.

### 3.6 MEDIUM: Benchmark Errors Silently Ignored

Multiple benchmark functions discard errors:
- `frost/contract_test.go:166`: `_, _, _ = precompile.Run(...)`
- `cggmp21/contract_test.go:266`: `_, _, _ = precompile.Run(...)`
- `mldsa/contract_test.go:420`: `_, _, _ = MLDSAVerifyPrecompile.Run(...)`
- `ed25519/contract_test.go:145`: `Ed25519VerifyPrecompile.Run(...)` (return values discarded)
- `secp256r1/contract_test.go:272`: `c.Run(input)` (error discarded)

If the precompile starts returning errors, benchmarks silently measure error-path performance, not verification performance.

### 3.7 MEDIUM: Tests Don't Verify Gas Consumption Exactly

Most tests check `remainingGas > 0` or `remainingGas == 0` but don't verify `suppliedGas - remainingGas == RequiredGas(input)`. This means a precompile could consume more or less gas than advertised and tests would not catch it.

### 3.8 LOW: Overlapping Test Files

`dex/pause_freeze_test.go` and `dex/pausefreeze_test.go` are two separate files that likely test the same functionality with different names. Potential for confusion or test collision.

---

## 4. Severity Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 3 | FROST false-positive test, FHE unprotected global maps, zero concurrency tests for 15+ stateful packages |
| HIGH | 18 | Missing KATs for FIPS algorithms, missing gas=0 tests, missing gas overflow tests for FROST, SLH-DSA mode coverage gap, secp256r1 wrong interface, KZG4844 missing field modulus rejection |
| MEDIUM | 22 | Missing nil/empty inputs, untested exported functions, missing determinism tests, benchmark error swallowing |
| LOW | 8 | Untested utility functions, duplicate test file names, missing off-by-one-long tests |

---

## 5. Priority Fix Order for Blue

1. **FROST: Write a real threshold keygen+sign+verify test** — generate actual FROST keys, sign a message, verify through the precompile, assert `result[31] == 1`. The current test is security theater.

2. **FHE: Add mutex to ciphertextStore/ciphertextTypes OR document that concurrent access is impossible** — if the EVM guarantees single-threaded execution within a block, document this assumption. If not, add `sync.RWMutex`.

3. **Add concurrency tests for FROST liftXCache, ZK caches, threshold manager, DEX state** — run 100 goroutines calling `Run()` simultaneously with `-race` flag. Start with FROST (consensus-critical) and FHE (global maps).

4. **Add FIPS 203/204/205 KAT vectors** — obtain test vectors from NIST ACVP and add them for ML-KEM, ML-DSA, and SLH-DSA. The current tests only prove "the library is internally consistent" not "the library is correct".

5. **Add gas=0 and gas=RequiredGas-1 tests to every precompile** — a systematic table-driven test that calls `Run()` with insufficient gas and verifies `ErrOutOfGas`.

6. **Fix FROST gas overflow** — port the CGGMP21 `security_test.go` pattern to FROST.

7. **Test modules/RegisterModule** — verify address collision rejection, reserved range enforcement, config key uniqueness, BlackholeAddr rejection.

8. **Test precompileconfig/Upgrade.Equal** — nil pointers, matching timestamps, disabled flags.

9. **Add secp256r1 NIST CAVP vectors** — replace the fake "NISTTestVector" test with actual vectors.

10. **Test SLH-DSA modes 192 and 256** — 8 of 12 modes have no verification test.
