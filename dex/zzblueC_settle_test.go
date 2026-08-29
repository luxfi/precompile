// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"math"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/luxfi/vm/chains/atomic"
	"github.com/stretchr/testify/require"
)

// zzblueC_settle_test.go pins the 0x9999 SETTLEMENT surface — the sole DEX money
// path — along the six axes that decide whether money moves correctly:
//
//	replay      a settlement object and an intent are each consumable exactly once,
//	            and the second attempt names a DISTINCT error rather than no-op'ing.
//	custody     every credit comes out of the seam reserve and the sum is conserved;
//	            a refusal moves neither the pot nor the balance.
//	windows     settle-open and reclaim-open are complementary across the deadline —
//	            never both, never neither — swept, not point-checked.
//	halt        exactly which arms a halt closes, and which it deliberately leaves
//	            open so funds can always exit.
//	static      every value-moving selector refuses readOnly, driven through Run.
//	calldata    short input, a declared length past the end, and the SAME input with
//	            attacker-chosen bytes in the spare capacity must agree on the verdict.

// ---------------------------------------------------------------------------
// Adversarial input + capability doubles.
// ---------------------------------------------------------------------------

// blueCPoisoned returns b with `spare` attacker-chosen bytes living PAST len(b) but
// inside cap(b). Production calldata is `scope.Memory.GetPtr(off, size)`, a two-index
// slice of live EVM memory, so a handler that reads past len() reads bytes the caller
// wrote with MSTORE instead of panicking. A missing bounds check is therefore a wrong
// verdict over unpaid-for input, not a crash — which is why every bounds assertion
// below is repeated against a poisoned twin.
func blueCPoisoned(b []byte, spare int) []byte {
	full := make([]byte, len(b)+spare)
	for i := range full {
		full[i] = 0xA5
	}
	copy(full, b)
	return full[:len(b)]
}

// blueCPlainState is an AccessibleState with NO cross-chain atomic capability — a
// single-chain dev host. Value must never cross on it.
type blueCPlainState struct{ inner *nativeAtomicState }

func (s *blueCPlainState) GetStateDB() contract.StateDB                     { return s.inner.GetStateDB() }
func (s *blueCPlainState) GetBlockContext() contract.BlockContext           { return s.inner.GetBlockContext() }
func (s *blueCPlainState) GetConsensusContext() context.Context             { return s.inner.GetConsensusContext() }
func (s *blueCPlainState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (s *blueCPlainState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

var _ contract.AccessibleState = (*blueCPlainState)(nil)

// blueCNilMemoryState DOES carry the atomic capability but its shared memory is nil —
// a host that wired the interface without the channel. This is the second half of the
// `!ok || AtomicMemory() == nil` guard, and it fails differently from blueCPlainState,
// so the two together pin both disjuncts.
type blueCNilMemoryState struct{ *nativeAtomicState }

func (s *blueCNilMemoryState) AtomicMemory() atomic.SharedMemory { return nil }

var _ contract.AtomicState = (*blueCNilMemoryState)(nil)

// blueCNativeOnlyResolver resolves the native coin and REFUSES every ERC-20. The
// harness market is (native, ERC-20), so it admits the base side and refuses the
// quote side — the asymmetry that separates the two admission calls.
type blueCNativeOnlyResolver struct {
	networkID uint32
	chainID   ids.ID
}

func (r *blueCNativeOnlyResolver) ResolveAsset(kind dexcore.AssetKind, ref []byte) (ids.ID, uint8, error) {
	if kind != dexcore.AssetKindEVMNative {
		return ids.Empty, 0, errBlueCQuoteRefused
	}
	id, err := dexcore.DeriveAssetID(r.networkID, r.chainID, kind, ref)
	if err != nil {
		return ids.Empty, 0, err
	}
	return id, 18, nil
}

var errBlueCQuoteRefused = &blueCErr{"blueC: this resolver admits only the native coin"}

type blueCErr struct{ s string }

func (e *blueCErr) Error() string { return e.s }

// blueCInstallResolver swaps the process-global resolver for `r` and restores the
// prior value. The restore is registered BEFORE the mutation, and nil is stored first
// because InstallAssetResolver refuses a re-install under a different identity.
func blueCInstallResolver(t *testing.T, h *settleHarness, r dexcore.AssetResolver) {
	t.Helper()
	prev := installedAssetResolver.Load()
	t.Cleanup(func() { installedAssetResolver.Store(prev) })
	installedAssetResolver.Store(nil)
	require.NoError(t, InstallAssetResolver(r, h.networkID, h.cChainID))
}

// blueCAmount asserts two big.Int values are numerically equal. big.NewInt(0) and a
// value decoded from an empty slot are the same NUMBER but different structs, so a
// struct comparison would fail on a correct result.
func blueCAmount(t *testing.T, want, got *big.Int, msg string, args ...any) {
	t.Helper()
	require.Zerof(t, want.Cmp(got), msg+" (want %s, got %s)", append(append([]any{}, args...), want, got)...)
}

// blueCLedger renders every observable value in the harness state as a comparable
// string map: non-zero storage slots, native balances, and ERC-20 holdings. The
// package's `fingerprint` covers the first two; on the money path the token ledger is
// the half that matters most, and a settle that moved tokens but no slots would
// compare equal without it. Strings keep a failure readable — a struct of unexported
// maps makes the assertion library panic while trying to print the diff.
//
// A slot explicitly written to zero is omitted: it is indistinguishable from an absent
// slot to every reader and to the trie, and the custody guard is exactly such a
// transient flag.
func blueCLedger(h *settleHarness) map[string]string {
	out := map[string]string{}
	for addr, kv := range h.state.stateDB.states {
		for k, v := range kv {
			if v == (common.Hash{}) {
				continue
			}
			out["slot "+addr.Hex()+" "+k.Hex()] = v.Hex()
		}
	}
	for addr, bal := range h.state.stateDB.balances {
		if bal.IsZero() {
			continue
		}
		out["native "+addr.Hex()] = bal.String()
	}
	for tok, holders := range h.state.stateDB.tokenBalances {
		for holder, v := range holders {
			if v.Sign() == 0 {
				continue
			}
			out["token "+tok.Hex()+" "+holder.Hex()] = v.String()
		}
	}
	return out
}

// blueCVaultToken reads the 0x9999 vault's real ERC-20 holding of tok.
func blueCVaultToken(h *settleHarness, tok common.Address) *big.Int {
	return h.wrapper().TokenBalanceOf(tok, poolManagerAddr9999)
}

// blueCSwapIn builds swap calldata (selector + args) for the harness pool.
func blueCSwapIn(h *settleHarness, hookData []byte) []byte {
	return prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
}

// ---------------------------------------------------------------------------
// 1. The defaulted reclaim horizon must SATURATE, never wrap.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 2. Every swap refusal arm, driven through Run as real calldata.
// ---------------------------------------------------------------------------

// blueCSetHalt flips a halt layer through the REAL governance-gated selector, so the
// tests below halt the way a network actually halts.
func blueCSetHalt(t *testing.T, h *settleHarness, selector uint32, scope [32]byte, on bool) {
	t.Helper()
	data := make([]byte, 64)
	copy(data[0:32], scope[:])
	if selector == SelectorSetHaltGlobal {
		if on {
			data[31] = 1
		}
	} else if on {
		data[63] = 1
	}
	_, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999, prependSelector(selector, data), 5_000_000, false)
	require.NoError(t, err, "the governance controller must be able to move the halt")
}

// ---------------------------------------------------------------------------
// 3. No atomic capability => no value crosses, on EITHER disjunct.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 4. Static-call refusal across EVERY value-moving selector.
// ---------------------------------------------------------------------------

// blueCArm is one value-moving selector together with the setup that makes its
// calldata a LIVE call. `live` is what makes the read-only assertion mean something:
// a selector fed garbage refuses for the wrong reason and proves nothing about
// readOnly, so every arm is first shown to SUCCEED with readOnly=false.
type blueCArm struct {
	name    string
	prepare func(t *testing.T, h *settleHarness) (common.Address, []byte)
	live    bool // false only for donate, which is unsupported in both modes
}

// TestBlueCDonateIsUnsupportedInBothModes pins donate's two distinct arms. donate is
// not a stub: there is no C-side LP fee-growth ledger, so a C-only donate could only
// pretend to distribute. Both modes name the same boundary, and the gas differs —
// the static arm returns the whole budget, the mutating arm charges the base lookup.
func TestBlueCDonateIsUnsupportedInBothModes(t *testing.T) {
	h := newSettleHarness(t)
	in := prependSelector(SelectorDonate, make([]byte, 224))

	_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 1_000_000, true)
	require.ErrorIs(t, err, ErrUnsupported)
	require.Equal(t, uint64(1_000_000), left, "the static donate refusal returns the full supplied gas (measured)")

	_, left, err = h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 1_000_000, false)
	require.ErrorIs(t, err, ErrUnsupported)
	require.Equal(t, uint64(1_000_000)-GasPoolLookup, left, "the mutating donate refusal charges the base lookup")

	// Below the base lookup it is an out-of-gas, and the whole budget is consumed.
	for _, g := range []uint64{0, GasPoolLookup - 1} {
		_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, g, false)
		require.Errorf(t, err, "donate with %d gas", g)
		require.NotErrorIs(t, err, ErrUnsupported, "below the base lookup the answer is out-of-gas, not the boundary")
		require.Zero(t, left)
	}
}

// TestBlueCViewsIgnoreReadOnly is the complement of the sweep above: the three read
// selectors answer identically whether or not the caller is static. A view that
// refused inside eth_call would make the whole surface unreadable off-chain.
func TestBlueCViewsIgnoreReadOnly(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)

	slot := settleVaultKey(h.outAssetID())
	arrIn := make([]byte, 96)
	arrIn[31] = 0x20 // offset
	arrIn[63] = 1    // length
	copy(arrIn[64:96], slot[:])

	for name, in := range map[string][]byte{
		"balanceOf":      prependSelector(SelectorBalanceOf, make([]byte, 64)),
		"extsload":       prependSelector(SelectorExtsload, slot[:]),
		"extsload array": prependSelector(SelectorExtsloadArray, arrIn),
	} {
		outRW, leftRW, errRW := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 1_000_000, false)
		require.NoErrorf(t, errRW, "%s must answer a mutating call", name)
		outRO, leftRO, errRO := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 1_000_000, true)
		require.NoErrorf(t, errRO, "%s must answer a static call — it never writes", name)
		require.Equalf(t, outRW, outRO, "%s answered differently under readOnly", name)
		require.Equalf(t, leftRW, leftRO, "%s charged differently under readOnly", name)
	}
}

// ---------------------------------------------------------------------------
// 5. The halt map — exactly which arms a halt closes.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 7. Settle-open and reclaim-open are complementary windows.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 8. Custody conservation across the value arms.
// ---------------------------------------------------------------------------

// TestBlueCInitializeGuardsAreNotReachableTwice pins what each arm of the initialize
// path can and cannot do, so a future change that alters reachability shows up here
// rather than as silently dead — or silently live — code.
//
//   - the PoolKey decode: it used to refuse only on length, so at the 192 bytes the
//     handler has already required, its error arm was dead. It now also refuses a fee
//     or tick spacing wider than the 24 bits the wire format declares, so the arm is
//     LIVE and every fill below except the zero one exercises it.
//   - the tick derivation: the handler range-checks the price against [MinSqrtRatio,
//     MaxSqrtRatio) and GetTickAtSqrtRatio refuses on exactly that same predicate over
//     exactly that same value. Its error arm is dead unless the two bounds diverge.
func TestBlueCInitializeGuardsAreNotReachableTwice(t *testing.T) {
	// Length is no longer the only reason a 160-byte input is refused: the fee and
	// tick-spacing slots must fit their declared widths. A slot of 0x01 repeated is
	// a 249-bit fee, so only the zero fill survives.
	for _, fill := range []byte{0x00, 0x01, 0x7F, 0x80, 0xFF} {
		body := make([]byte, 160)
		for i := range body {
			body[i] = fill
		}
		_, err := DecodePoolKey(body)
		if fill == 0x00 {
			require.NoError(t, err, "an all-zero PoolKey is in range and must decode")
		} else {
			require.ErrorIsf(t, err, ErrInvalidFee,
				"a 32-byte fee slot of %#x is far wider than uint24 and must be refused", fill)
		}
		_, err = DecodePoolKey(blueCPoisoned(body[:159], 64))
		require.Errorf(t, err, "159 bytes is short, and spare capacity must not complete it (fill %#x)", fill)
	}

	// The tick derivation agrees with the handler's range check at every boundary, so
	// no admitted price can reach the tick error arm.
	for name, p := range map[string]*big.Int{
		"below min":     new(big.Int).Sub(MinSqrtRatio, big.NewInt(1)),
		"at min":        new(big.Int).Set(MinSqrtRatio),
		"one above min": new(big.Int).Add(MinSqrtRatio, big.NewInt(1)),
		"one below max": new(big.Int).Sub(MaxSqrtRatio, big.NewInt(1)),
		"at max":        new(big.Int).Set(MaxSqrtRatio),
		"above max":     new(big.Int).Add(MaxSqrtRatio, big.NewInt(1)),
		"zero":          big.NewInt(0),
		"Q96":           new(big.Int).Set(Q96),
	} {
		admitted := p.Cmp(MinSqrtRatio) >= 0 && p.Cmp(MaxSqrtRatio) < 0
		_, err := GetTickAtSqrtRatio(p)
		require.Equalf(t, admitted, err == nil,
			"%s: the handler's admission and the tick derivation must agree, or the tick error arm becomes reachable", name)
	}

	// End to end: every price the handler refuses names the range error, never a
	// derivation failure, and none of them writes a record.
	h := newSettleHarness(t)
	h.admitMarketKey(t)
	before := blueCLedger(h)
	for name, p := range map[string]*big.Int{
		"zero":      big.NewInt(0),
		"below min": new(big.Int).Sub(MinSqrtRatio, big.NewInt(1)),
		"at max":    new(big.Int).Set(MaxSqrtRatio),
		"far above": new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
	} {
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, p), 5_000_000, false)
		require.ErrorIsf(t, err, ErrInitSqrtRange, "%s must be refused by the range check", name)
	}
	require.Equal(t, before, blueCLedger(h), "a refused initialize must leave no record")
}

// ---------------------------------------------------------------------------
// 9. extsload — bounds, gas, and poisoned spare capacity.
// ---------------------------------------------------------------------------

// TestBlueCExtsloadBounds pins the raw slot readers. extsloadArray is the one place a
// caller supplies BOTH an offset and a count, so it is the one place an attacker
// chooses how far past the end the handler reaches — the exact shape that becomes a
// validator crash if the guard is written with a signed cast.
func TestBlueCExtsloadBounds(t *testing.T) {
	h := newSettleHarness(t)
	slot := settleVaultKey(h.outAssetID())

	t.Run("single: gas floor then length floor", func(t *testing.T) {
		for _, g := range []uint64{0, GasPoolLookup - 1} {
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsload, slot[:]), g, false)
			require.Errorf(t, err, "extsload with %d gas", g)
			require.Zero(t, left, "an out-of-gas read consumes the budget")
		}
		// Exactly the floor: funded, and the length check is what answers now.
		_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsload, make([]byte, 31)), GasPoolLookup, false)
		require.Error(t, err, "31 bytes is not a bytes32 slot")
		require.Zero(t, left)
		for n := 0; n < 32; n++ {
			clean := prependSelector(SelectorExtsload, make([]byte, n))
			_, _, cleanErr := h.c.Run(h.state, h.caller, poolManagerAddr9999, clean, 1_000_000, false)
			require.Errorf(t, cleanErr, "a %d-byte extsload argument is short", n)
			_, _, poisonErr := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCPoisoned(clean, 256), 1_000_000, false)
			require.Errorf(t, poisonErr, "n=%d: poisoned spare capacity must not satisfy the length check", n)
			require.Equal(t, cleanErr.Error(), poisonErr.Error(), "n=%d: the verdict changed with attacker bytes past len", n)
		}
	})

	t.Run("array: every refusal arm", func(t *testing.T) {
		good := func(n int) []byte {
			in := make([]byte, 64+n*32)
			in[31] = 0x20
			putWordUint64(in[32:64], uint64(n))
			for i := 0; i < n; i++ {
				copy(in[64+i*32:], slot[:])
			}
			return in
		}

		// gas floor
		for _, g := range []uint64{0, GasPoolLookup - 1} {
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, good(1)), g, false)
			require.Errorf(t, err, "extsload array with %d gas", g)
			require.Zero(t, left)
		}

		// under two words: offset+length do not both fit
		for n := 0; n < 64; n++ {
			clean := prependSelector(SelectorExtsloadArray, make([]byte, n))
			_, left, cleanErr := h.c.Run(h.state, h.caller, poolManagerAddr9999, clean, 1_000_000, false)
			require.Errorf(t, cleanErr, "a %d-byte array argument carries no offset+length", n)
			require.Equalf(t, uint64(1_000_000)-GasPoolLookup, left, "n=%d: the base lookup is charged before the shape check", n)
			_, _, poisonErr := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCPoisoned(clean, 512), 1_000_000, false)
			require.Equalf(t, cleanErr.Error(), poisonErr.Error(),
				"n=%d: 0xA5 bytes past len must not turn a short array into a readable one", n)
		}

		// an offset pointing past the end, including the signed-overflow shape
		for name, off := range map[string]uint64{
			"one past the end": 64,
			"far past the end": 1 << 32,
			"int64 max":        uint64(math.MaxInt64),
			"uint64 max":       math.MaxUint64,
		} {
			in := good(1)
			putWordUint64(in[0:32], off)
			require.NotPanicsf(t, func() {
				_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, in), 1_000_000, false)
				require.Errorf(t, err, "an offset %s must be refused", name)
			}, "an offset %s must not panic — there is no recover() on block execution", name)
		}

		// a declared count that overruns the supplied words
		for _, n := range []uint64{2, 3, 1 << 20, uint64(math.MaxInt64), math.MaxUint64} {
			in := good(1)
			putWordUint64(in[32:64], n)
			require.NotPanicsf(t, func() {
				_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, in), 1_000_000, false)
				require.Errorf(t, err, "a declared count of %d over one supplied word must be refused", n)
			}, "count %d must not panic", n)
		}

		// gas that covers the base lookup but not the per-slot cost
		for _, n := range []int{1, 4, 16} {
			cost := GasPoolLookup * uint64(n+1)
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, good(n)), cost-1, false)
			require.Errorf(t, err, "n=%d must be refused below its %d-gas cost", n, cost)
			require.Zerof(t, left, "n=%d: the whole budget is consumed", n)

			out, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, good(n)), cost, false)
			require.NoErrorf(t, err, "n=%d must be served at exactly its cost — reads scale with slots", n)
			require.Zero(t, left)
			require.Lenf(t, out, 64+n*32, "n=%d: the reply is offset|length|n words", n)
			require.Equalf(t, uint64(n), readLowU64(out[32:64]), "n=%d: the reply must declare the count it served", n)
		}
	})
}

// ---------------------------------------------------------------------------
// 10. Pure routing + accounting arms, asserted as properties.
// ---------------------------------------------------------------------------

// TestBlueCWordHelpersRefuseShortSlices pins the two 32-byte word helpers. Both are
// defensive: every caller inside the package guards the length first, so the short
// arms are unreachable from calldata. They are still the right shape — returning 0 /
// writing nothing beats indexing off the end of a slice on a consensus path.
func TestBlueCWordHelpersRefuseShortSlices(t *testing.T) {
	for n := 0; n < 32; n++ {
		require.Equalf(t, uint64(0), readLowU64(make([]byte, n)), "a %d-byte word cannot carry a value", n)
		// Poisoned: the bytes ARE there in the backing array, and must still not be read.
		require.Equalf(t, uint64(0), readLowU64(blueCPoisoned(make([]byte, n), 64)),
			"n=%d: readLowU64 must go by len, never by cap", n)

		b := make([]byte, n)
		putWordUint64(b, math.MaxUint64)
		require.Equalf(t, make([]byte, n), b, "putWordUint64 must not write into a %d-byte slice", n)
	}
	require.Nil(t, func() []byte { var nilSlice []byte; putWordUint64(nilSlice, 1); return nilSlice }())

	// At exactly 32 bytes both are live and are exact inverses across the range.
	for _, v := range []uint64{0, 1, 255, 256, 1 << 32, math.MaxUint64 - 1, math.MaxUint64} {
		b := make([]byte, 32)
		putWordUint64(b, v)
		require.Equalf(t, v, readLowU64(b), "the pair must round-trip %d", v)
		require.Equalf(t, make([]byte, 24), b[0:24], "v=%d: the high 24 bytes of an ABI word stay zero", v)
	}
}

// TestBlueCAnalyticsShardsAndIgnoresNonPositive pins the sharded fee/volume keys. The
// shard is what keeps analytics off a single global hot slot — two settlements in one
// block must be able to touch DIFFERENT slots, or Block-STM serializes the money path.
func TestBlueCAnalyticsShardsAndIgnoresNonPositive(t *testing.T) {
	asset := [32]byte{0xAA}
	other := [32]byte{0xBB}

	// The epoch folds modulo the shard count: epoch and epoch+shards collide by design,
	// epoch and epoch+1 must not.
	require.Equal(t, feeBucketKey(asset, 0), feeBucketKey(asset, feeShards), "the fee epoch folds modulo the shard count")
	require.NotEqual(t, feeBucketKey(asset, 0), feeBucketKey(asset, 1), "adjacent epochs must land in different shards")
	require.NotEqual(t, feeBucketKey(asset, 0), feeBucketKey(other, 0), "two assets must never share a bucket")
	require.NotEqual(t, feeBucketKey(asset, 0), volBucketKey(asset, 0), "the fee and volume namespaces must be disjoint")

	seen := map[common.Hash]bool{}
	for e := uint64(0); e < feeShards; e++ {
		k := feeBucketKey(asset, e)
		require.Falsef(t, seen[k], "epoch %d collided with an earlier shard — the fold is not injective over one period", e)
		seen[k] = true
	}
	require.Len(t, seen, feeShards, "one period must occupy every shard exactly once")

	// accrueVolume ignores a non-positive amount rather than writing a zero.
	h := newSettleHarness(t)
	db := newPoolStateAdapter(h.state)
	poolID := h.key.ID()
	before := blueCLedger(h)
	for name, amt := range map[string]*big.Int{
		"nil":      nil,
		"zero":     big.NewInt(0),
		"negative": big.NewInt(-1),
	} {
		accrueVolume(db, poolID, amt, 1)
		require.Equalf(t, before, blueCLedger(h), "accrueVolume(%s) must write nothing", name)
	}
	accrueVolume(db, poolID, big.NewInt(7), 1)
	require.Equal(t, big.NewInt(7), new(big.Int).SetBytes(db.GetState(poolManagerAddr9999, volBucketKey(poolID, 1)).Bytes()))
	accrueVolume(db, poolID, big.NewInt(5), 1)
	require.Equal(t, big.NewInt(12), new(big.Int).SetBytes(db.GetState(poolManagerAddr9999, volBucketKey(poolID, 1)).Bytes()),
		"volume must accumulate within a shard, not overwrite")
}

// TestBlueCOperatorValueRefusesOverWideAmount pins the seed path's range guard against
// an amount wider than a uint256. It is unreachable from calldata (decodeAssetAmount's
// isWord check refuses first, and a 32-byte word cannot exceed 2^256-1 anyway), so it
// is driven directly — it is the guard that would matter if a future internal caller
// ever passed an unchecked big.Int.
func TestBlueCOperatorValueRefusesOverWideAmount(t *testing.T) {
	h := newSettleHarness(t)
	db := newPoolStateAdapter(h.state)
	native := h.inAssetID()
	h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(1000))

	recorded := false
	over := new(big.Int).Lsh(big.NewInt(1), 256) // one past the uint256 ceiling
	got, err := receiveOperatorValue(db, h.operator(), h.key.Currency0, native, over, func(*big.Int) error {
		recorded = true
		return nil
	})
	require.ErrorIs(t, err, ErrSeedBadAmount, "an amount wider than uint256 cannot be received")
	require.Nil(t, got)
	require.False(t, recorded, "the pot must not be credited for an amount that cannot be moved")

	// The boundary: 2^256-1 fits, and is refused for a different reason — undelivered.
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	_, err = receiveOperatorValue(db, h.operator(), h.key.Currency0, native, max256, func(*big.Int) error {
		recorded = true
		return nil
	})
	require.ErrorIs(t, err, ErrSeedUndelivered, "2^256-1 is representable; it simply was not delivered")
	require.False(t, recorded)

	// And a real delivery records exactly what arrived.
	delivered, err := receiveOperatorValue(db, h.operator(), h.key.Currency0, native, big.NewInt(1000), func(amt *big.Int) error {
		require.Equal(t, big.NewInt(1000), amt)
		recorded = true
		return nil
	})
	require.NoError(t, err)
	require.True(t, recorded)
	require.Equal(t, big.NewInt(1000), delivered)
}

// ---------------------------------------------------------------------------
// 11. Governance calldata shapes, checked AS the governance controller.
// ---------------------------------------------------------------------------

// TestBlueCGovernanceRefusesShortCalldata pins the halt setters' argument widths for
// the ONLY caller that gets past the authority gate. A stranger is refused earlier, so
// the width check is only reachable as governance — and it matters: reading a bool out
// of a short word would let a malformed governance tx flip the chain's kill switch by
// accident.
func TestBlueCGovernanceRefusesShortCalldata(t *testing.T) {
	h := newSettleHarness(t)
	before := blueCLedger(h)

	for n := 0; n < 32; n++ {
		clean := prependSelector(SelectorSetHaltGlobal, make([]byte, n))
		_, left, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999, clean, 1_000_000, false)
		require.Errorf(t, err, "setHaltGlobal needs a full bool word; %d bytes is short", n)
		require.Equalf(t, uint64(1_000_000)-gasHaltAdmin, left, "n=%d: the admin fee is charged before the width check", n)

		_, _, poisonErr := h.c.Run(h.state, h.operator(), poolManagerAddr9999, blueCPoisoned(clean, 128), 1_000_000, false)
		require.Errorf(t, poisonErr, "n=%d: 0xA5 spare capacity must not complete the bool word", n)
		require.Equal(t, err.Error(), poisonErr.Error(), "n=%d: the verdict changed with attacker bytes past len", n)
	}

	for _, sel := range []uint32{SelectorSetHaltMarket, SelectorSetHaltAsset} {
		for n := 0; n < 64; n++ {
			clean := prependSelector(sel, make([]byte, n))
			_, left, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999, clean, 1_000_000, false)
			require.Errorf(t, err, "selector %#x needs two words; %d bytes is short", sel, n)
			require.Equal(t, uint64(1_000_000)-gasHaltAdmin, left)

			_, _, poisonErr := h.c.Run(h.state, h.operator(), poolManagerAddr9999, blueCPoisoned(clean, 128), 1_000_000, false)
			require.Errorf(t, poisonErr, "selector %#x n=%d: poisoned capacity must not complete the words", sel, n)
			require.Equal(t, err.Error(), poisonErr.Error())
		}
	}
	require.Equal(t, before, blueCLedger(h),
		"a malformed governance call must not move a halt layer")

	// Below the admin fee it is out-of-gas, and the whole budget is consumed.
	for _, sel := range []uint32{SelectorSetHaltGlobal, SelectorSetHaltMarket, SelectorSetHaltAsset} {
		for _, g := range []uint64{0, gasHaltAdmin - 1} {
			_, left, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999,
				prependSelector(sel, make([]byte, 64)), g, false)
			require.Errorf(t, err, "selector %#x with %d gas", sel, g)
			require.Zero(t, left)
		}
	}
}

// ---------------------------------------------------------------------------
// 12. Market admission runs on BOTH sides of the pair.
// ---------------------------------------------------------------------------

// TestBlueCInitializeAdmitsBothSides pins that market admission checks the QUOTE side
// too. Checking only the base would let a market record be written over (real, fake)
// — a pair the swap path later refuses, but whose registry entry and Initialize log
// have already leaked onto C and into every indexer reading them.
func TestBlueCInitializeAdmitsBothSides(t *testing.T) {
	h := newSettleHarness(t)
	// A resolver that admits the native base and refuses the ERC-20 quote.
	blueCInstallResolver(t, h, &blueCNativeOnlyResolver{networkID: h.networkID, chainID: h.cChainID})
	h.state.stateDB.SetCodeSize(h.key.Currency1.Address, 1) // real code: only IDENTITY is refused

	before := blueCLedger(h)
	_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, false)
	require.Error(t, err, "a market whose QUOTE side does not resolve must be refused")
	require.ErrorIs(t, err, dexcore.ErrAssetNotResolved, "and it must fail closed with the resolve error")
	require.Equal(t, uint64(5_000_000)-GasPoolCreate, left)
	require.Equal(t, before, blueCLedger(h),
		"a refused initialize must write no market record and emit no log")
	require.False(t, MarketExists(newPoolStateAdapter(h.state), h.key),
		"a refused initialize must leave no registry entry behind")

	// The same call with a resolver that admits BOTH sides succeeds — proving the
	// refusal above was the quote side, not the calldata.
	h2 := newSettleHarness(t)
	h2.admitMarketKey(t)
	_, _, err = h2.c.Run(h2.state, h2.caller, poolManagerAddr9999, initCalldata(h2.key, new(big.Int).Set(Q96)), 5_000_000, false)
	require.NoError(t, err, "two admitted sides must register permissionlessly")
	require.True(t, MarketExists(newPoolStateAdapter(h2.state), h2.key))
}

// ---------------------------------------------------------------------------
// 13. The module is registered exactly once.
// ---------------------------------------------------------------------------

// TestBlueCSettleModuleRegistersOnce pins the invariant behind the panic in init: the
// registry refuses a second registration of the same key/address. Two registrations
// would mean two dispatch entries for one money path.
func TestBlueCSettleModuleRegistersOnce(t *testing.T) {
	require.True(t, SettleModule.AlwaysOn)
	require.Equal(t, poolManagerAddr9999, SettleModule.Address)
	require.Equal(t, settleConfigKey, SettleModule.ConfigKey)
	require.Same(t, SettlePrecompile, SettleModule.Contract, "the registered contract is the singleton")

	err := modules.RegisterModule(SettleModule)
	require.Error(t, err,
		"a second registration must be refused — init() turns exactly this error into a boot panic")

	// The registry still resolves 0x9999 to the settle module afterwards.
	got, ok := modules.GetPrecompileModuleByAddress(poolManagerAddr9999)
	require.True(t, ok, "0x9999 must still be registered")
	require.Equal(t, settleConfigKey, got.ConfigKey, "the rejected re-registration must not have replaced it")

	// The configurator's type check is the other loud-failure surface.
	cfg := (&settleConfigurator{}).MakeConfig()
	require.IsType(t, &SettleConfig{}, cfg)
	require.NoError(t, (&settleConfigurator{}).Configure(nil, cfg, nil, nil))
	require.Error(t, (&settleConfigurator{}).Configure(nil, nil, nil, nil),
		"a wrong config type must surface loudly, not be silently accepted")
}

// ---------------------------------------------------------------------------
// 14. Write cost versus fixed fee — measured, reported, not changed.
// ---------------------------------------------------------------------------

// blueCCountFreshWrites runs fn and reports how many DISTINCT 0x9999 slots it takes
// from zero to non-zero and leaves non-zero. That is the count that costs 20,000 gas
// each at reference prices; a slot set and cleared inside the call (the custody guard)
// is excluded because it does not grow the trie.
func blueCCountFreshWrites(h *settleHarness, fn func()) int {
	addr := poolManagerAddr9999
	before := map[common.Hash]common.Hash{}
	for k, v := range h.state.stateDB.states[addr] {
		before[k] = v
	}
	fn()
	fresh := 0
	for k, v := range h.state.stateDB.states[addr] {
		if v == (common.Hash{}) {
			continue
		}
		if before[k] == (common.Hash{}) {
			fresh++
		}
	}
	return fresh
}
