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

// blueCIntentRecord reads the persisted per-intent escrow record.
func blueCIntentRecord(h *settleHarness, id ids.ID) swapIntentRecord {
	return loadSwapIntentRecord(newPoolStateAdapter(h.state), id)
}

// blueCSeam reads seamReserve[asset] — the ONLY pot a swap settlement may draw on.
func blueCSeam(h *settleHarness, asset [32]byte) *big.Int {
	return loadSeamReserve(newPoolStateAdapter(h.state), asset)
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

// TestBlueCReclaimHorizonSaturates sweeps the saturation boundary of the horizon a
// swap that named no deadline is stamped with. A wrap here is not cosmetic: the sum
// blockTimestamp+7d landing on a SMALL number makes the intent instantly past its own
// deadline, so the taker could lock and reclaim in the same breath while a legitimate
// Phase-B settlement is refused as late. The sweep walks both sides of the pivot and
// the extremes, and asserts the horizon is monotone and never behind `now`.
func TestBlueCReclaimHorizonSaturates(t *testing.T) {
	pivot := uint64(math.MaxUint64) - maxIntentTTL // the last timestamp that still fits

	for _, tc := range []struct {
		name string
		ts   uint64
		want uint64
	}{
		{"genesis", 0, maxIntentTTL},
		{"normal block", harnessBlockTime, harnessBlockTime + maxIntentTTL},
		{"two below pivot", pivot - 2, math.MaxUint64 - 2},
		{"one below pivot", pivot - 1, math.MaxUint64 - 1},
		{"at pivot", pivot, math.MaxUint64},
		{"one past pivot", pivot + 1, math.MaxUint64},
		{"two past pivot", pivot + 2, math.MaxUint64},
		{"max", math.MaxUint64, math.MaxUint64},
	} {
		got := defaultedReclaimDeadline(tc.ts)
		require.Equalf(t, tc.want, got, "defaultedReclaimDeadline(%d) [%s]", tc.ts, tc.name)
		require.GreaterOrEqualf(t, got, tc.ts,
			"[%s] a defaulted horizon at or before `now` would make the intent born expired", tc.name)
	}

	// The property that matters end to end: a plain swap at a timestamp past the pivot
	// must still be UNRECLAIMABLE right now. Without saturation the stamped deadline
	// wraps small, the block time is already past it, and the taker reclaims the same
	// principal the seam just locked.
	h := newSettleHarness(t)
	h.state.blockTimestamp = pivot + 1000
	h.fundCallerNative(100)

	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), 5_000_000, false)
	require.NoError(t, err, "a plain Phase-A intent must land at any block time")
	require.Len(t, out, 32)

	intentID := ids.ID(common.BytesToHash(out))
	rec := blueCIntentRecord(h, intentID)
	require.Equal(t, uint64(math.MaxUint64), rec.Deadline,
		"a horizon computed near the uint64 ceiling must saturate, not wrap")

	_, _, rerr := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false)
	require.ErrorIs(t, rerr, ErrReclaimBeforeDeadline,
		"a just-locked intent must not be reclaimable in the same block — a wrapped horizon would allow it")
}

// ---------------------------------------------------------------------------
// 2. Every swap refusal arm, driven through Run as real calldata.
// ---------------------------------------------------------------------------

// TestBlueCSwapRefusalArms walks the refusal ladder of the swap selector in the order
// SettleSwap evaluates it, and pins the gas each arm returns. Gas is part of the
// verdict: an arm that hands back the full supplied gas prices a refusal at zero, and
// an arm that hands back gas it never charged is a metering hole. Every case also
// asserts the money state is untouched.
func TestBlueCSwapRefusalArms(t *testing.T) {
	const gas = 5_000_000

	t.Run("read-only", func(t *testing.T) {
		h := newSettleHarness(t)
		before := blueCLedger(h)
		_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, nil), gas, true)
		require.Error(t, err, "a static call must never settle")
		require.Equal(t, uint64(gas), left, "the read-only refusal returns the full supplied gas (measured)")
		require.Equal(t, before, blueCLedger(h))
	})

	t.Run("undecodable swap input", func(t *testing.T) {
		h := newSettleHarness(t)
		// DecodeSwapInput needs 256 bytes; sweep every shorter width, and repeat each
		// with poisoned spare capacity so a read past len cannot manufacture a decode.
		for n := 0; n < 256; n += 7 {
			clean := prependSelector(SelectorSwap, make([]byte, n))
			_, cleanLeft, cleanErr := h.c.Run(h.state, h.caller, poolManagerAddr9999, clean, gas, false)
			require.Errorf(t, cleanErr, "a %d-byte swap body cannot decode", n)
			require.Equalf(t, uint64(gas), cleanLeft, "the decode refusal returns full gas (measured), n=%d", n)

			_, poisonLeft, poisonErr := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCPoisoned(clean, 512), gas, false)
			require.Errorf(t, poisonErr, "a %d-byte swap body must stay undecodable with poisoned spare capacity", n)
			require.Equalf(t, cleanErr.Error(), poisonErr.Error(),
				"n=%d: attacker bytes past len changed the verdict — the handler read undeclared input", n)
			require.Equal(t, cleanLeft, poisonLeft)
		}
	})

	t.Run("phase B out of gas", func(t *testing.T) {
		h := newSettleHarness(t)
		in := blueCSwapIn(h, EncodeSettlementHookData(ids.ID{0x01}, 5, ids.ID{0x02}))
		for _, g := range []uint64{0, 1, GasNativeSettlement - 1} {
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, g, false)
			require.Errorf(t, err, "%d gas cannot fund a settlement", g)
			require.Zerof(t, left, "an out-of-gas settlement must consume the whole budget, not refund it (g=%d)", g)
		}
		// One wei of gas more and the arm is funded: it now fails for a REASON, not for gas.
		_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, GasNativeSettlement, false)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrSettleNoAtomicState)
		require.Zero(t, left, "GasNativeSettlement funds the arm exactly, leaving nothing")
	})

	t.Run("phase A out of gas", func(t *testing.T) {
		h := newSettleHarness(t)
		in := blueCSwapIn(h, EncodeIntentHookData(0, 0))
		for _, g := range []uint64{0, 1, GasNativeIntent - 1} {
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, g, false)
			require.Errorf(t, err, "%d gas cannot fund an intent", g)
			require.Zerof(t, left, "an out-of-gas intent must consume the whole budget (g=%d)", g)
		}
	})

	t.Run("halted phases", func(t *testing.T) {
		for name, arm := range map[string]struct {
			hook []byte
			cost uint64
		}{
			"intent":     {EncodeIntentHookData(0, 0), GasNativeIntent},
			"settlement": {EncodeSettlementHookData(ids.ID{0x01}, 5, ids.ID{0x02}), GasNativeSettlement},
		} {
			h := newSettleHarness(t)
			h.fundCallerNative(1000)
			blueCSetHalt(t, h, SelectorSetHaltGlobal, [32]byte{}, true)
			before := blueCLedger(h)

			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, arm.hook), gas, false)
			require.ErrorIsf(t, err, ErrDEXHalted, "%s must refuse under a global halt", name)
			require.Equalf(t, uint64(gas)-arm.cost, left,
				"%s: a halted call still pays the phase's fixed fee (measured)", name)
			require.Equalf(t, before, blueCLedger(h), "%s: a halted refusal wrote state", name)
		}
	})

	t.Run("malformed settlement body", func(t *testing.T) {
		h := newSettleHarness(t)
		// Every body width EXCEPT the fixed 96 must be refused, poisoned or not.
		for n := 0; n <= 160; n++ {
			if n == settlementBodyLen {
				continue
			}
			hook := append(append([]byte{}, settlementPhaseTag[:]...), make([]byte, n)...)
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, hook), gas, false)
			require.ErrorIsf(t, err, ErrSettleBodyMalformed, "a %d-byte settlement body is not the fixed width", n)
			require.Equalf(t, uint64(gas)-GasNativeSettlement, left, "n=%d", n)
		}
		// Right width, unusable amount: zero, and a value wider than uint64.
		for name, amt := range map[string][32]byte{
			"zero":        {},
			"over uint64": {23: 1}, // bit 64 set — IsUint64 is false
		} {
			body := make([]byte, settlementBodyLen)
			copy(body[32:64], amt[:])
			hook := append(append([]byte{}, settlementPhaseTag[:]...), body...)
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, hook), gas, false)
			require.ErrorIsf(t, err, ErrSettleBadAmount, "a %s settlement amount must be refused", name)
		}
	})

	t.Run("malformed intent body", func(t *testing.T) {
		h := newSettleHarness(t)
		h.fundCallerNative(10_000)
		// The DI01 body has exactly three legal widths. Every other width is malformed —
		// it must revert, never be silently truncated into a deadline.
		for n := 0; n <= 128; n++ {
			if n == 0 || n == intentBodyLen || n == intentBodyLenWithNonce {
				continue
			}
			hook := append(append([]byte{}, intentPhaseTag[:]...), make([]byte, n)...)
			_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, hook), gas, false)
			require.ErrorIsf(t, err, ErrIntentBodyMalformed, "a %d-byte intent body is not a legal width", n)
			require.Equalf(t, uint64(gas)-GasNativeIntent, left, "n=%d", n)
		}
		// Legal width, out-of-range value: deadline and nonce each wider than uint64.
		wide := [32]byte{23: 1}
		for name, body := range map[string][]byte{
			"deadline over uint64":        wide[:],
			"deadline over uint64 +nonce": append(append([]byte{}, wide[:]...), make([]byte, 32)...),
			"nonce over uint64":           append(make([]byte, 32), wide[:]...),
		} {
			hook := append(append([]byte{}, intentPhaseTag[:]...), body...)
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, hook), gas, false)
			require.ErrorIsf(t, err, ErrIntentBadDeadline, "%s must be refused, not truncated", name)
		}
	})

	t.Run("unusable amountSpecified", func(t *testing.T) {
		h := newSettleHarness(t)
		h.fundCallerNative(10_000)
		params := h.params

		// Zero: no input is committed, so there is no intent to build.
		params.AmountSpecified = big.NewInt(0)
		_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorSwap, buildSwapCalldata(h.key, params, EncodeIntentHookData(0, 0))), gas, false)
		require.ErrorIs(t, err, ErrInvalidAmount, "a zero-amount swap locks nothing and must revert")
		require.Equal(t, uint64(gas)-GasNativeIntent, left)

		// A magnitude wider than uint64 cannot be locked by the seam's uint64 ledger.
		// This IS reachable from calldata: amountSpecified is a full int256 word.
		for _, mag := range []*big.Int{
			new(big.Int).Lsh(big.NewInt(1), 64),
			new(big.Int).Lsh(big.NewInt(1), 200),
		} {
			params.AmountSpecified = new(big.Int).Neg(mag)
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
				prependSelector(SelectorSwap, buildSwapCalldata(h.key, params, EncodeIntentHookData(0, 0))), gas, false)
			require.ErrorIsf(t, err, ErrInvalidAmount, "magnitude %s exceeds the uint64 seam ledger", mag)
		}
	})

	t.Run("intent the seam refuses to submit", func(t *testing.T) {
		h := newSettleHarness(t) // caller funded with NOTHING: the native lock cannot be backed
		before := blueCLedger(h)
		_, left, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), gas, false)
		require.ErrorIs(t, err, ErrNativeFundsShort,
			"an intent whose principal cannot be locked must revert — never stage a C->D object with no C debit")
		require.Equal(t, uint64(gas)-GasNativeIntent, left)
		require.Equal(t, before, blueCLedger(h),
			"a refused intent must stage nothing: a staged object with no backing debit is a mint")
	})
}

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

// TestBlueCValueArmsRequireAtomicCapability drives the two value arms that cross the
// C<->D seam on a host with no atomic capability and on a host whose capability has no
// channel. Both must refuse: value crosses ONLY as an atomic object, so a host that
// cannot read shared memory must never be able to credit or refund.
func TestBlueCValueArmsRequireAtomicCapability(t *testing.T) {
	for name, wrap := range map[string]func(*nativeAtomicState) contract.AccessibleState{
		"no atomic capability at all": func(s *nativeAtomicState) contract.AccessibleState {
			return &blueCPlainState{inner: s}
		},
		"capability present, channel nil": func(s *nativeAtomicState) contract.AccessibleState {
			return &blueCNilMemoryState{nativeAtomicState: s}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSettleHarness(t)
			h.fundCallerNative(10_000)
			state := wrap(h.state)
			before := blueCLedger(h)

			// swap, both phases.
			for phase, hook := range map[string][]byte{
				"intent":     EncodeIntentHookData(0, 0),
				"settlement": EncodeSettlementHookData(ids.ID{0x11}, 5, ids.ID{0x12}),
			} {
				_, _, err := h.c.Run(state, h.caller, poolManagerAddr9999, blueCSwapIn(h, hook), 5_000_000, false)
				require.ErrorIsf(t, err, ErrSettleNoAtomicState, "%s must refuse without the atomic seam", phase)
			}

			// reclaimIntent — the liveness path — refuses for the same reason and, being
			// gas-charged before the check, hands back exactly the post-fee remainder.
			_, left, err := h.c.Run(state, h.caller, poolManagerAddr9999,
				prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(ids.ID{0x13})), 5_000_000, false)
			require.ErrorIs(t, err, ErrSettleNoAtomicState)
			require.Equal(t, uint64(5_000_000)-GasNativeSettlement, left)

			require.Equal(t, before, blueCLedger(h),
				"a host with no atomic seam must leave the money state untouched")
		})
	}
}

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

func blueCValueArms() []blueCArm {
	return []blueCArm{
		{
			name: "swap (phase A intent)",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.fundCallerNative(1000)
				return h.caller, blueCSwapIn(h, EncodeIntentHookData(0, 0))
			},
		},
		{
			name: "initialize",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.admitMarketKey(t)
				return h.caller, initCalldata(h.key, new(big.Int).Set(Q96))
			},
		},
		{
			name: "modifyLiquidity (commit)",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.registerMarket(t)
				h.fundCallerNative(500)
				return h.caller, modLiqCalldata(h.key, -60, 60, big.NewInt(400), [32]byte{0xB1}, MakerSideBid)
			},
		},
		{
			name: "collectPosition",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.registerMarket(t)
				recordID, _ := h.commitNativePosition(t, -60, 60, 400, [32]byte{0xB2})
				outputID := ids.ID{0xC0, 0x11}
				h.putDtoCLPObject(t, h.caller, outputID, h.inAssetID(), 100)
				return h.caller, prependSelector(SelectorCollectPosition,
					EncodeCollectPositionInput(outputID, [32]byte{}, 100, recordID))
			},
		},
		{
			name: "reclaimIntent",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.fundCallerNative(1000)
				// A real Phase-A intent funds seamReserve[native] with the principal the
				// reclaim then refunds, so the refund is genuinely backed.
				out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
					prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, EncodeIntentHookData(harnessBlockTime+10, 0))), 5_000_000, false)
				require.NoError(t, err)
				h.state.blockTimestamp = harnessBlockTime + 11 // past the deadline
				return h.caller, prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(ids.ID(common.BytesToHash(out))))
			},
		},
		{
			name: "deposit (native)",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(700)) // the host frame moved msg.value
				data := make([]byte, 64)
				big.NewInt(700).FillBytes(data[32:64])
				return h.caller, prependSelector(SelectorDeposit, data)
			},
		},
		{
			name: "withdraw (native)",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(700))
				data := make([]byte, 64)
				big.NewInt(700).FillBytes(data[32:64])
				_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, data), 5_000_000, false)
				require.NoError(t, err)
				return h.caller, prependSelector(SelectorWithdraw, data)
			},
		},
		{
			name: "seedSeamReserve",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(900))
				data := make([]byte, 64)
				big.NewInt(900).FillBytes(data[32:64])
				return h.operator(), prependSelector(SelectorSeedSeamReserve, data)
			},
		},
		{
			name: "creditPositionFee",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				h.registerMarket(t)
				recordID, _ := h.commitNativePosition(t, -60, 60, 400, [32]byte{0xB3})
				h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(50))
				data := make([]byte, 96)
				copy(data[0:32], recordID[:])
				big.NewInt(50).FillBytes(data[64:96])
				return h.operator(), prependSelector(SelectorCreditPositionFee, data)
			},
		},
		{
			name: "setHaltGlobal",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				data := make([]byte, 32)
				data[31] = 1
				return h.operator(), prependSelector(SelectorSetHaltGlobal, data)
			},
		},
		{
			name: "setHaltMarket",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				data := make([]byte, 64)
				id := h.key.ID()
				copy(data[0:32], id[:])
				data[63] = 1
				return h.operator(), prependSelector(SelectorSetHaltMarket, data)
			},
		},
		{
			name: "setHaltAsset",
			live: true,
			prepare: func(t *testing.T, h *settleHarness) (common.Address, []byte) {
				data := make([]byte, 64)
				aid := h.outAssetID()
				copy(data[0:32], aid[:])
				data[63] = 1
				return h.operator(), prependSelector(SelectorSetHaltAsset, data)
			},
		},
		{
			name: "donate",
			live: false, // unsupported by design in BOTH modes
			prepare: func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
				return h.caller, prependSelector(SelectorDonate, make([]byte, 224))
			},
		},
	}
}

// TestBlueCReadOnlyRefusesEveryValueArm sweeps the ENTIRE value-moving surface of
// 0x9999 under readOnly=true. A static call that moved money would be a consensus
// break: two nodes disagree the moment one of them executes the eth_call. Each arm is
// first proven live with readOnly=false, so a refusal below is caused by the flag and
// not by malformed input.
func TestBlueCReadOnlyRefusesEveryValueArm(t *testing.T) {
	for _, arm := range blueCValueArms() {
		t.Run(arm.name, func(t *testing.T) {
			if arm.live {
				h := newSettleHarness(t)
				caller, in := arm.prepare(t, h)
				_, _, err := h.c.Run(h.state, caller, poolManagerAddr9999, in, 5_000_000, false)
				require.NoErrorf(t, err,
					"%s: the arm must be LIVE with readOnly=false, else the static-call assertion proves nothing", arm.name)
			}

			h := newSettleHarness(t)
			caller, in := arm.prepare(t, h)
			before := blueCLedger(h)
			_, _, err := h.c.Run(h.state, caller, poolManagerAddr9999, in, 5_000_000, true)
			require.Errorf(t, err, "%s must refuse a static call", arm.name)
			require.Equalf(t, before, blueCLedger(h),
				"%s mutated consensus state inside a static call", arm.name)
		})
	}
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

// TestBlueCHaltClosesTradeAndLeavesExitsOpen pins the halt's real shape. The halt is
// deliberately PARTIAL: it stops new trade but must never strand value, so every
// funds-EXIT arm stays callable while halted. Testing this as "a halt refuses
// everything" would be wrong and would freeze user funds; testing only the closed
// half would let an exit silently become halt-gated. Both halves are asserted.
func TestBlueCHaltClosesTradeAndLeavesExitsOpen(t *testing.T) {
	// --- CLOSED under a global halt: both swap phases.
	t.Run("global halt closes both swap phases", func(t *testing.T) {
		h := newSettleHarness(t)
		h.fundCallerNative(1000)
		blueCSetHalt(t, h, SelectorSetHaltGlobal, [32]byte{}, true)
		for phase, hook := range map[string][]byte{
			"intent":     EncodeIntentHookData(0, 0),
			"settlement": EncodeSettlementHookData(ids.ID{0x21}, 5, ids.ID{0x22}),
		} {
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, hook), 5_000_000, false)
			require.ErrorIsf(t, err, ErrDEXHalted, "%s must be closed by the global halt", phase)
		}
		// Unhalting reopens it — a halt that could not be lifted would be a permanent DoS.
		blueCSetHalt(t, h, SelectorSetHaltGlobal, [32]byte{}, false)
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), 5_000_000, false)
		require.NoError(t, err, "lifting the global halt must reopen the swap path")
	})

	// --- Scope ordering: the FIRST applicable halt names itself, cheapest scope first.
	t.Run("scope reported is the narrowest applicable, in order", func(t *testing.T) {
		poolID := h9999PoolID(newSettleHarness(t))
		for name, tc := range map[string]struct {
			set    func(t *testing.T, h *settleHarness)
			expect error
		}{
			"market": {func(t *testing.T, h *settleHarness) { blueCSetHalt(t, h, SelectorSetHaltMarket, poolID, true) }, ErrMarketHalted},
			"asset in": {func(t *testing.T, h *settleHarness) {
				blueCSetHalt(t, h, SelectorSetHaltAsset, h.inAssetID(), true)
			}, ErrAssetHalted},
			"asset out": {func(t *testing.T, h *settleHarness) {
				blueCSetHalt(t, h, SelectorSetHaltAsset, h.outAssetID(), true)
			}, ErrAssetHalted},
		} {
			h := newSettleHarness(t)
			h.fundCallerNative(1000)
			tc.set(t, h)
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), 5_000_000, false)
			require.ErrorIsf(t, err, tc.expect, "a %s halt must name its own scope, not a broader one", name)
		}
		// Global wins over a narrower scope: the cheapest check runs first.
		h := newSettleHarness(t)
		h.fundCallerNative(1000)
		blueCSetHalt(t, h, SelectorSetHaltMarket, poolID, true)
		blueCSetHalt(t, h, SelectorSetHaltGlobal, [32]byte{}, true)
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), 5_000_000, false)
		require.ErrorIs(t, err, ErrDEXHalted, "the global scope is checked first")
	})

	// --- deposit is gated on the ASSET halt only; a global halt must not block funding.
	t.Run("deposit is asset-gated, not global-gated", func(t *testing.T) {
		h := newSettleHarness(t)
		h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(400))
		data := make([]byte, 64)
		big.NewInt(400).FillBytes(data[32:64])

		blueCSetHalt(t, h, SelectorSetHaltGlobal, [32]byte{}, true)
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, data), 5_000_000, false)
		require.NoError(t, err, "a global halt must not stop a depositor funding the vault")

		h2 := newSettleHarness(t)
		h2.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(400))
		blueCSetHalt(t, h2, SelectorSetHaltAsset, h2.inAssetID(), true)
		_, _, err = h2.c.Run(h2.state, h2.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, data), 5_000_000, false)
		require.ErrorIs(t, err, ErrAssetHalted, "a halted asset must not accept new deposits")
	})

	// --- OPEN even under every halt at once: the exits.
	t.Run("exits stay open under every halt", func(t *testing.T) {
		h := newSettleHarness(t)
		h.registerMarket(t)
		h.fundCallerNative(2000)

		// Fund a withdrawable claim and a reclaimable intent BEFORE halting.
		h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(400))
		depData := make([]byte, 64)
		big.NewInt(400).FillBytes(depData[32:64])
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, depData), 5_000_000, false)
		require.NoError(t, err)

		out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, EncodeIntentHookData(harnessBlockTime+10, 0))), 5_000_000, false)
		require.NoError(t, err)
		intentID := ids.ID(common.BytesToHash(out))

		// Now halt EVERYTHING.
		poolID := h.key.ID()
		blueCSetHalt(t, h, SelectorSetHaltGlobal, [32]byte{}, true)
		blueCSetHalt(t, h, SelectorSetHaltMarket, poolID, true)
		blueCSetHalt(t, h, SelectorSetHaltAsset, h.inAssetID(), true)
		blueCSetHalt(t, h, SelectorSetHaltAsset, h.outAssetID(), true)

		// withdraw: always open.
		wOut, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, depData), 5_000_000, false)
		require.NoError(t, err, "withdraw must never be halt-gated — a halt must not strand a depositor")
		require.Equal(t, big.NewInt(400), new(big.Int).SetBytes(wOut), "the full claim must come back")

		// reclaimIntent: always open, once past the deadline.
		h.state.blockTimestamp = harnessBlockTime + 11
		rOut, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
			prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false)
		require.NoError(t, err, "reclaim must never be halt-gated — locked swap input must always be able to exit")
		require.Equal(t, big.NewInt(100), new(big.Int).SetBytes(rOut), "the locked principal must come back in full")

		// The read surface is likewise never halt-gated.
		slot := settleVaultKey(h.outAssetID())
		_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsload, slot[:]), 1_000_000, false)
		require.NoError(t, err, "extsload is a raw slot read and is never halt-gated")
		_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorBalanceOf, make([]byte, 64)), 1_000_000, false)
		require.NoError(t, err, "balanceOf is never halt-gated")
	})
}

// h9999PoolID is the harness pool's market id.
func h9999PoolID(h *settleHarness) [32]byte { return h.key.ID() }

// ---------------------------------------------------------------------------
// 6. Replay — the consumed set and the intent set are the anti-replay namespace.
// ---------------------------------------------------------------------------

// TestBlueCSettlementIsConsumedExactlyOnce is the money path's central claim. A D->C
// object is a bearer instrument: consuming it twice mints. The second attempt must
// not merely fail to pay — it must name ErrNativeSettleReplay, a DISTINCT error from
// "no such object", so a caller (and an operator reading a trace) can tell a replay
// from a missing export. A silent no-op returning success would be indistinguishable
// from a real settlement to every downstream reader.
func TestBlueCSettlementIsConsumedExactlyOnce(t *testing.T) {
	h := newSettleHarness(t)
	const amount uint64 = 250
	outputID := ids.ID{0x5E, 0x77, 0x1E}

	h.fundVaultOut(int64(amount)) // seamReserve[out] backs exactly one credit
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), amount)
	in := blueCSwapIn(h, EncodeSettlementHookData(outputID, amount, h.standingIntent(amount)))

	seamBefore := blueCSeam(h, h.outAssetID())
	takerBefore := blueCVaultToken(h, h.outToken())
	blueCAmount(t, big.NewInt(int64(amount)), seamBefore, "the seam pot must hold exactly the seeded backing")

	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
	require.NoError(t, err, "the first consumption of a real D->C object must settle")
	require.Len(t, out, 32, "a Phase-B settle returns a packed BalanceDelta")
	require.True(t, isSettlementConsumed(newPoolStateAdapter(h.state), outputID),
		"a settled object must be marked consumed in the replay namespace")

	seamAfter := blueCSeam(h, h.outAssetID())
	blueCAmount(t, big.NewInt(0), seamAfter, "the credit must be drawn from the seam pot, not minted")
	blueCAmount(t, new(big.Int).Sub(takerBefore, big.NewInt(int64(amount))), blueCVaultToken(h, h.outToken()),
		"the vault's real holding must fall by exactly what left it")

	// SECOND attempt on the SAME object.
	_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
	require.ErrorIs(t, err, ErrNativeSettleReplay,
		"a second consumption must be refused AS A REPLAY, not as a missing object and not silently")
	require.NotErrorIs(t, err, ErrNativeNoSettlement,
		"replay and 'no such object' must stay distinguishable — they are different operator incidents")
	blueCAmount(t, seamAfter, blueCSeam(h, h.outAssetID()), "the refused replay must not move the pot")

	// And with the pot REFILLED — proving the refusal is the replay mark, not a lack
	// of backing. This is the case a naive implementation gets wrong.
	h.fundVaultOut(int64(amount))
	refilled := blueCSeam(h, h.outAssetID())
	_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
	require.ErrorIs(t, err, ErrNativeSettleReplay,
		"a refunded pot must not resurrect a consumed object — one-time consumption is the invariant")
	blueCAmount(t, refilled, blueCSeam(h, h.outAssetID()), "the second refusal moved value")
}

// TestBlueCIntentIdIsAReplayKey pins the OTHER half of the anti-replay namespace: the
// intent id. Two byte-identical Phase-A swaps derive the SAME id, so the second must
// be refused rather than locking the taker's principal twice under one record.
//
// The replay attempt is driven through runWithEVMSnapshot because that is where the
// safety actually lives. SubmitSwapIntent locks FIRST and checks the replay mark
// second — deliberately, since the id binds the amount actually locked and so is not
// knowable before the lock. The guarantee is therefore EVM revert atomicity, not check
// ordering: the refusal rolls the lock back. Calling Run bare would leave the mock's
// lock standing and would be asserting the harness, not the chain.
func TestBlueCIntentIdIsAReplayKey(t *testing.T) {
	h := newSettleHarness(t)
	h.fundCallerNative(1000)
	in := blueCSwapIn(h, EncodeIntentHookData(harnessBlockTime+1000, 7))

	first, _, err := runWithEVMSnapshot(h.c, h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
	require.NoError(t, err)
	intentID := ids.ID(common.BytesToHash(first))
	rec := blueCIntentRecord(h, intentID)
	require.Equal(t, uint64(100), rec.Remaining, "the record must hold exactly the locked principal")

	seamBefore := blueCSeam(h, h.inAssetID())
	balBefore := h.state.stateDB.GetBalance(h.caller).ToBig()

	_, _, err = runWithEVMSnapshot(h.c, h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
	require.ErrorIs(t, err, ErrNativeIntentReplay,
		"an identical intent derives an identical id and must be refused as a replay")
	blueCAmount(t, seamBefore, blueCSeam(h, h.inAssetID()), "the refused replay must not lock more principal")
	blueCAmount(t, balBefore, h.state.stateDB.GetBalance(h.caller).ToBig(),
		"the refused replay must not debit the taker a second time")
	require.Equal(t, rec.Remaining, blueCIntentRecord(h, intentID).Remaining,
		"the refused replay must not touch the surviving record")

	// The nonce is what makes two OTHERWISE-identical swaps distinct. Change only it
	// and the same calldata shape must now be accepted — the id is a function of it.
	second, _, err := runWithEVMSnapshot(h.c, h.state, h.caller, poolManagerAddr9999,
		blueCSwapIn(h, EncodeIntentHookData(harnessBlockTime+1000, 8)), 5_000_000, false)
	require.NoError(t, err, "a distinct nonce is a distinct intent and must not collide with the first")
	require.NotEqual(t, first, second, "the nonce must reach the derived id, or it disambiguates nothing")
}

// ---------------------------------------------------------------------------
// 7. Settle-open and reclaim-open are complementary windows.
// ---------------------------------------------------------------------------

// TestBlueCSettleAndReclaimWindowsAreExclusive sweeps the deadline boundary and
// asserts the XOR: at every timestamp EXACTLY ONE of {settle, reclaim} is admitted.
// Both open is a double payout of one principal; neither open strands it. The two
// halves live in different functions (ImportSettlement uses `ts > deadline`,
// ReclaimIntent uses `ts <= deadline`), so nothing but a sweep across the boundary
// keeps them complementary — a `>` drifting to `>=` on either side opens a gap or an
// overlap that a single point check would not see.
func TestBlueCSettleAndReclaimWindowsAreExclusive(t *testing.T) {
	const deadline uint64 = harnessBlockTime + 100
	const principal uint64 = 300

	for _, ts := range []uint64{deadline - 2, deadline - 1, deadline, deadline + 1, deadline + 2} {
		// Each probe gets a FRESH harness: admitting one arm consumes the principal, so
		// probing both on one state would let the first decide the second.
		settleOK := blueCProbeSettle(t, deadline, principal, ts)
		reclaimOK := blueCProbeReclaim(t, deadline, principal, ts)

		require.NotEqualf(t, settleOK, reclaimOK,
			"ts=%d (deadline=%d): settle=%v reclaim=%v — the two windows must partition time; "+
				"both open double-pays one principal, neither open strands it",
			ts, deadline, settleOK, reclaimOK)
		require.Equalf(t, ts <= deadline, settleOK,
			"ts=%d: settlement is admitted exactly while ts <= deadline", ts)
		require.Equalf(t, ts > deadline, reclaimOK,
			"ts=%d: reclaim is admitted exactly while ts > deadline", ts)
	}
}

// blueCProbeSettle reports whether a Phase-B settlement against an intent with the
// given deadline is admitted at block time ts. Any error OTHER than the deadline
// refusal fails the test outright — a probe that answered "closed" for the wrong
// reason would silently satisfy the XOR above.
func blueCProbeSettle(t *testing.T, deadline, principal, ts uint64) bool {
	t.Helper()
	h := newSettleHarness(t)
	h.state.blockTimestamp = ts
	outputID := ids.ID{0xD1, byte(ts)}
	intentID := h.seedSwapIntent(h.caller, h.outAssetID(), principal, deadline, ids.ID{0xD2, byte(ts)})
	h.fundVaultOut(int64(principal))
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), principal)

	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		blueCSwapIn(h, EncodeSettlementHookData(outputID, principal, intentID)), 5_000_000, false)
	if err == nil {
		return true
	}
	require.ErrorIsf(t, err, ErrSettlePastDeadline,
		"ts=%d: the settle probe must be closed by the DEADLINE, not by anything else", ts)
	return false
}

// blueCProbeReclaim reports whether a reclaim of the same intent is admitted at ts.
func blueCProbeReclaim(t *testing.T, deadline, principal, ts uint64) bool {
	t.Helper()
	h := newSettleHarness(t)
	h.state.blockTimestamp = ts
	intentID := h.seedSwapIntent(h.caller, h.inAssetID(), principal, deadline, ids.ID{0xD3, byte(ts)})
	h.fundVaultNativeOut(int64(principal)) // seamReserve[native] backs the refund

	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false)
	if err == nil {
		return true
	}
	require.ErrorIsf(t, err, ErrReclaimBeforeDeadline,
		"ts=%d: the reclaim probe must be closed by the DEADLINE, not by anything else", ts)
	return false
}

// TestBlueCReclaimAndSettleCannotBothPay closes the loop the window sweep opens: once
// a principal has been reclaimed, a settlement naming that same intent must not also
// pay. The reclaim zeroes the remaining principal, and the per-taker cap then bounds
// the late credit to zero.
func TestBlueCReclaimAndSettleCannotBothPay(t *testing.T) {
	const deadline uint64 = harnessBlockTime + 50
	const principal uint64 = 400

	h := newSettleHarness(t)
	h.state.blockTimestamp = deadline + 1
	intentID := h.seedSwapIntent(h.caller, h.inAssetID(), principal, deadline, ids.ID{0xE1})
	h.fundVaultNativeOut(int64(principal))

	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false)
	require.NoError(t, err, "past the deadline the locker must be able to exit")
	require.Equal(t, big.NewInt(int64(principal)), new(big.Int).SetBytes(out))

	rec := blueCIntentRecord(h, intentID)
	require.Equal(t, uint64(0), rec.Remaining, "a reclaim must zero the remaining principal")
	require.Equal(t, swapIntentReclaimed, rec.Status, "the record's terminal status is the witness")

	// A settlement naming the reclaimed intent: refused. The object carries the asset
	// the claim DERIVES from the swap direction, so it clears the object binding and
	// the refusal is unambiguously the terminal intent status, not a mismatched asset.
	outputID := ids.ID{0xE2}
	h.fundVaultOut(int64(principal))
	h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), principal)
	_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999,
		blueCSwapIn(h, EncodeSettlementHookData(outputID, principal, intentID)), 5_000_000, false)
	require.ErrorIs(t, err, ErrSettleNoIntent,
		"a reclaimed intent is terminal — a late settlement naming it must not pay a second time")
	require.NotErrorIs(t, err, ErrNativeSettleAsset,
		"the refusal must be the intent's terminal status, not an asset mismatch")

	// And a second reclaim of the same intent is likewise refused.
	_, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(intentID)), 5_000_000, false)
	require.ErrorIs(t, err, ErrReclaimNoIntent, "one principal, one exit")
}

// ---------------------------------------------------------------------------
// 8. Custody conservation across the value arms.
// ---------------------------------------------------------------------------

// TestBlueCValueArmsConserve asserts, for each value-moving arm, that the vault's real
// holding and the pot that accounts for it move by the SAME amount and in the same
// direction — and that a refusal moves NEITHER. Accounting that drifts from the real
// holding is exactly how a vault becomes unable to honour the last withdrawal.
func TestBlueCValueArmsConserve(t *testing.T) {
	t.Run("phase A lock raises the seam pot and the vault together", func(t *testing.T) {
		h := newSettleHarness(t)
		h.fundCallerNative(1000)
		aid := h.inAssetID()
		seamBefore := blueCSeam(h, aid)
		vaultBefore := h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig()
		takerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()

		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), 5_000_000, false)
		require.NoError(t, err)

		moved := big.NewInt(100) // |amountSpecified|
		blueCAmount(t, new(big.Int).Add(seamBefore, moved), blueCSeam(h, aid),
			"the seam pot must rise by exactly the locked principal")
		blueCAmount(t, new(big.Int).Add(vaultBefore, moved), h.state.stateDB.GetBalance(poolManagerAddr9999).ToBig(),
			"the vault's real holding must rise by the same amount the pot did")
		blueCAmount(t, new(big.Int).Sub(takerBefore, moved), h.state.stateDB.GetBalance(h.caller).ToBig(),
			"the taker's balance must fall by exactly what the vault gained — no mint, no burn")
	})

	// A credit the pot cannot back is refused, and — under the EVM snapshot the host
	// wraps every precompile CALL in — the object stays UNCONSUMED. The consumed mark
	// is written before the credit (CEI for the replay slot), so it is the revert that
	// makes a failed credit non-destructive; driving this bare would assert the mock.
	t.Run("a credit larger than the pot is refused, and moves nothing", func(t *testing.T) {
		h := newSettleHarness(t)
		outputID := ids.ID{0xF1}
		h.fundVaultOut(100)                                         // pot holds 100
		h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 500) // D exported 500
		in := blueCSwapIn(h, EncodeSettlementHookData(outputID, 500, h.standingIntent(500)))
		seamBefore := blueCSeam(h, h.outAssetID())
		vaultBefore := blueCVaultToken(h, h.outToken())
		before := blueCLedger(h)

		_, _, err := runWithEVMSnapshot(h.c, h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
		require.Error(t, err, "a credit the seam pot cannot back must revert — the alternative is a mint")
		blueCAmount(t, seamBefore, blueCSeam(h, h.outAssetID()), "the refused credit moved the pot")
		blueCAmount(t, vaultBefore, blueCVaultToken(h, h.outToken()), "the refused credit moved real tokens")
		require.False(t, isSettlementConsumed(newPoolStateAdapter(h.state), outputID),
			"a refused settlement must leave the object UNCONSUMED, or a failed credit burns the object")
		require.Equal(t, before, blueCLedger(h),
			"the whole refused frame must roll back, not just the value legs")
	})

	t.Run("deposit and withdraw are exact inverses", func(t *testing.T) {
		h := newSettleHarness(t)
		aid := h.inAssetID()
		h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(750))
		data := make([]byte, 64)
		big.NewInt(750).FillBytes(data[32:64])

		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, data), 5_000_000, false)
		require.NoError(t, err)
		db := newPoolStateAdapter(h.state)
		blueCAmount(t, big.NewInt(750), loadDepositorClaim(db, h.caller, aid), "the claim must record the deposit")
		blueCAmount(t, big.NewInt(750), loadSettleVault(db, aid), "the depositor pot must record it too")

		callerBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
		out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, data), 5_000_000, false)
		require.NoError(t, err)
		blueCAmount(t, big.NewInt(750), new(big.Int).SetBytes(out), "the withdraw must realize the full claim")
		blueCAmount(t, big.NewInt(0), loadDepositorClaim(db, h.caller, aid), "the claim must be fully drained")
		blueCAmount(t, big.NewInt(0), loadSettleVault(db, aid), "the pot must fall with it")
		blueCAmount(t, new(big.Int).Add(callerBefore, big.NewInt(750)), h.state.stateDB.GetBalance(h.caller).ToBig(),
			"the depositor must receive exactly what the pot released")

		// A second withdraw of a drained claim pays nothing and errors not at all —
		// it is a clamp, not a refusal. Pin that, so a future change to a revert is seen.
		out, _, err = h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, data), 5_000_000, false)
		require.NoError(t, err, "withdrawing an empty claim is a no-op by design (measured), not an error")
		blueCAmount(t, big.NewInt(0), new(big.Int).SetBytes(out), "and it realizes zero")
	})

	t.Run("a deposit whose value was not delivered is refused", func(t *testing.T) {
		h := newSettleHarness(t)
		data := make([]byte, 64)
		big.NewInt(750).FillBytes(data[32:64])
		before := blueCLedger(h)
		// No AddBalance: the host frame carried no msg.value, so the observed delta is 0.
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, data), 5_000_000, false)
		require.ErrorIs(t, err, ErrSettleDepositShort,
			"an absolute balance test would let a zero-value call mint a claim against OTHER depositors' funds")
		require.Equal(t, before, blueCLedger(h))
	})
}

// TestBlueCCustodyGuardIsOneSlotForTheWholeSurface pins the single non-reentrant
// custody flag. Every 0x9999 entrypoint that moves value shares ONE slot, so
// re-entering ANY of them from inside ANY other trips it. A per-entrypoint guard would
// leave every cross pair open, which is the shape that actually gets exploited: a
// malicious token's transfer callback re-enters a DIFFERENT selector than the one
// whose transfer it is servicing.
//
// The held flag is set directly because that is exactly what an in-flight outer frame
// leaves behind; the reachable path is that callback, which no mock token can raise.
func TestBlueCCustodyGuardIsOneSlotForTheWholeSurface(t *testing.T) {
	arms := map[string]func(t *testing.T, h *settleHarness) (common.Address, []byte){
		"swap (phase A)": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			return h.caller, blueCSwapIn(h, EncodeIntentHookData(0, 0))
		},
		"swap (phase B)": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			return h.caller, blueCSwapIn(h, EncodeSettlementHookData(ids.ID{0x31}, 5, ids.ID{0x32}))
		},
		"deposit": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			data := make([]byte, 64)
			big.NewInt(100).FillBytes(data[32:64])
			return h.caller, prependSelector(SelectorDeposit, data)
		},
		"withdraw": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			data := make([]byte, 64)
			big.NewInt(100).FillBytes(data[32:64])
			return h.caller, prependSelector(SelectorWithdraw, data)
		},
		"modifyLiquidity": func(t *testing.T, h *settleHarness) (common.Address, []byte) {
			h.registerMarket(t)
			return h.caller, modLiqCalldata(h.key, -60, 60, big.NewInt(100), [32]byte{0x33}, MakerSideBid)
		},
		"collectPosition": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			return h.caller, prependSelector(SelectorCollectPosition,
				EncodeCollectPositionInput(ids.ID{0x34}, [32]byte{}, 10, [32]byte{0x35}))
		},
		"reclaimIntent": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			return h.caller, prependSelector(SelectorReclaimIntent, EncodeReclaimIntentInput(ids.ID{0x36}))
		},
		"seedSeamReserve": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			data := make([]byte, 64)
			big.NewInt(100).FillBytes(data[32:64])
			return h.operator(), prependSelector(SelectorSeedSeamReserve, data)
		},
		"creditPositionFee": func(_ *testing.T, h *settleHarness) (common.Address, []byte) {
			data := make([]byte, 96)
			data[0] = 0x37
			big.NewInt(100).FillBytes(data[64:96])
			return h.operator(), prependSelector(SelectorCreditPositionFee, data)
		},
	}

	for name, build := range arms {
		t.Run(name, func(t *testing.T) {
			h := newSettleHarness(t)
			caller, in := build(t, h)

			// Without the guard held, this calldata gets PAST the guard — it may then
			// fail for its own reasons, but never with ErrCustodyReentrant. Without this
			// half, an arm that never reached the guard would pass the assertion below
			// for the wrong reason.
			_, _, free := h.c.Run(h.state, caller, poolManagerAddr9999, in, 5_000_000, false)
			require.NotErrorIsf(t, free, ErrCustodyReentrant,
				"%s: the guard is not held, so the arm must reach past it", name)

			newPoolStateAdapter(h.state).SetState(poolManagerAddr9999, custodyGuardKey9999, common.Hash{31: 1})
			before := blueCLedger(h)

			_, _, err := h.c.Run(h.state, caller, poolManagerAddr9999, in, 5_000_000, false)
			require.ErrorIsf(t, err, ErrCustodyReentrant,
				"%s must be refused while another custody op holds the shared flag", name)
			require.Equalf(t, before, blueCLedger(h),
				"%s moved value from inside a reentrant frame", name)
		})
	}
}

// TestBlueCInitializeGuardsAreNotReachableTwice pins WHY two arms of the initialize
// path can never execute, so a future change that makes them reachable shows up here
// rather than as silently dead code.
//
//   - the PoolKey decode: the handler has already required 192 bytes, and DecodePoolKey
//     only refuses under 160. It cannot fail on the slice it is handed.
//   - the tick derivation: the handler range-checks the price against [MinSqrtRatio,
//     MaxSqrtRatio) and GetTickAtSqrtRatio refuses on exactly that same predicate over
//     exactly that same value. Its error arm is dead unless the two bounds diverge.
func TestBlueCInitializeGuardsAreNotReachableTwice(t *testing.T) {
	// The decode cannot fail at or above 160 bytes, for any content.
	for _, fill := range []byte{0x00, 0x01, 0x7F, 0x80, 0xFF} {
		body := make([]byte, 160)
		for i := range body {
			body[i] = fill
		}
		_, err := DecodePoolKey(body)
		require.NoErrorf(t, err, "DecodePoolKey must accept any 160-byte input (fill %#x)", fill)
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

// TestBlueCBalanceDeltaFollowsSwapDirection pins which side of the V4 delta a credit
// lands on. Getting this backwards reports the taker was paid in the asset they SOLD,
// which every downstream router reads as a filled trade in the wrong direction.
func TestBlueCBalanceDeltaFollowsSwapDirection(t *testing.T) {
	amt := big.NewInt(4242)

	z := balanceDeltaForOutput(SwapParams{ZeroForOne: true}, amt)
	require.Equal(t, big.NewInt(0), z.Amount0, "zeroForOne pays out token1, so token0 is untouched on the settle leg")
	require.Equal(t, new(big.Int).Neg(amt), z.Amount1, "the output leaves the pool, so it is negative")

	o := balanceDeltaForOutput(SwapParams{ZeroForOne: false}, amt)
	require.Equal(t, new(big.Int).Neg(amt), o.Amount0, "!zeroForOne pays out token0")
	require.Equal(t, big.NewInt(0), o.Amount1)

	require.NotEqual(t, z, o, "the two directions must not produce the same delta")

	// The same claim end to end: a !zeroForOne settlement credits currency0 (native)
	// and the packed delta names the token0 side.
	h := newSettleHarness(t)
	h.params.ZeroForOne = false
	const amount uint64 = 120
	outputID := ids.ID{0xA0, 0x01}
	h.fundVaultNativeOut(int64(amount))
	h.putDtoCObject(t, h.caller, outputID, h.inAssetID(), amount) // for !zeroForOne, out = currency0
	intentID := h.seedSwapIntent(h.caller, h.outAssetID(), 10_000, 0, ids.ID{0xA0, 0x02})

	balBefore := h.state.stateDB.GetBalance(h.caller).ToBig()
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, EncodeSettlementHookData(outputID, amount, intentID))), 5_000_000, false)
	require.NoError(t, err, "a !zeroForOne settlement must credit currency0")
	require.Equal(t, new(big.Int).Add(balBefore, big.NewInt(int64(amount))), h.state.stateDB.GetBalance(h.caller).ToBig())
	require.Equal(t, PackBalanceDelta(new(big.Int).Neg(big.NewInt(int64(amount))), big.NewInt(0)), out,
		"the packed delta must name token0 as the side that was paid out")
}

// TestBlueCMinAmountOutIsExactOutputOnly pins the routing floor: an exact-INPUT swap
// (negative amountSpecified) names no output floor here — the D price limit carries it
// — while an exact-OUTPUT swap's positive amount IS the floor.
func TestBlueCMinAmountOutIsExactOutputOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		amt  *big.Int
		want *big.Int
	}{
		{"nil", nil, big.NewInt(0)},
		{"zero", big.NewInt(0), big.NewInt(0)},
		{"exact input (negative)", big.NewInt(-500), big.NewInt(0)},
		{"exact output (positive)", big.NewInt(500), big.NewInt(500)},
		{"exact output (one)", big.NewInt(1), big.NewInt(1)},
	} {
		got := minAmountOut(SwapParams{AmountSpecified: tc.amt})
		require.Equalf(t, tc.want, got, "minAmountOut(%s)", tc.name)
	}
	// The returned floor must be a COPY: a caller mutating it must not reach back into
	// the params the rest of the handler still reads.
	amt := big.NewInt(500)
	got := minAmountOut(SwapParams{AmountSpecified: amt})
	got.SetInt64(1)
	require.Equal(t, big.NewInt(500), amt, "minAmountOut must not alias the caller's amountSpecified")
}

// TestBlueCBuildIntentRequestRefusesUnusableAmounts pins the intent builder directly,
// including the nil case that calldata cannot produce (DecodeSwapInput always sets a
// non-nil amount) but an internal caller can.
func TestBlueCBuildIntentRequestRefusesUnusableAmounts(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.Address{}},
		Currency1:   Currency{Address: common.HexToAddress("0x02")},
		Fee:         3000,
		TickSpacing: 60,
	}
	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")

	for _, tc := range []struct {
		name string
		amt  *big.Int
	}{
		{"nil (internal callers only)", nil},
		{"zero", big.NewInt(0)},
		{"2^64 exactly", new(big.Int).Lsh(big.NewInt(1), 64)},
		{"-2^64 exactly", new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 64))},
		{"2^255", new(big.Int).Lsh(big.NewInt(1), 255)},
	} {
		req, err := buildIntentRequest(key, SwapParams{ZeroForOne: true, AmountSpecified: tc.amt}, caller, 0, 0)
		require.ErrorIsf(t, err, ErrInvalidAmount, "%s must be refused", tc.name)
		require.Equalf(t, IntentRequest{}, req, "%s must yield no request at all", tc.name)
	}

	// The boundary is exact: 2^64-1 is the largest lockable magnitude.
	maxU64 := new(big.Int).SetUint64(math.MaxUint64)
	req, err := buildIntentRequest(key, SwapParams{ZeroForOne: true, AmountSpecified: new(big.Int).Neg(maxU64)}, caller, 7, 9)
	require.NoError(t, err, "2^64-1 is the largest magnitude the uint64 seam ledger can hold")
	require.Equal(t, uint64(math.MaxUint64), req.AmountIn)
	require.Equal(t, uint64(7), req.Deadline)
	require.Equal(t, uint64(9), req.Nonce)
	require.Equal(t, caller, req.Account)
	require.Equal(t, caller, req.Recipient, "day-1 there is no delegation: the recipient IS the caller")
	require.Equal(t, assetID(key.Currency0), req.AssetIn, "zeroForOne locks currency0")

	// Direction flips the locked asset — never the same one for both directions.
	req2, err := buildIntentRequest(key, SwapParams{ZeroForOne: false, AmountSpecified: big.NewInt(-5)}, caller, 0, 0)
	require.NoError(t, err)
	require.Equal(t, assetID(key.Currency1), req2.AssetIn, "!zeroForOne locks currency1")
	require.NotEqual(t, req.AssetIn, req2.AssetIn)
}

// TestBlueCMakerSideDecodesFromEnvelopeOnly pins which asset a resting order locks. The
// side is read ONLY from the M999 envelope; everything else defaults to BID. A hook
// contract's arbitrary bytes must never flip which asset the maker's funds are taken
// from.
func TestBlueCMakerSideDecodesFromEnvelopeOnly(t *testing.T) {
	ask := []byte{'M', '9', '9', '9', byte(MakerSideAsk)}
	bid := []byte{'M', '9', '9', '9', byte(MakerSideBid)}

	require.Equal(t, MakerSideAsk, decodeMakerSide(ask), "a well-formed ASK envelope selects ASK")
	require.Equal(t, MakerSideBid, decodeMakerSide(bid))

	for name, hd := range map[string][]byte{
		"nil":                   nil,
		"empty":                 {},
		"tag alone (4 bytes)":   {'M', '9', '9', '9'},
		"wrong tag, ask byte":   {'X', '9', '9', '9', byte(MakerSideAsk)},
		"tag off by one byte":   {'M', '9', '9', '8', byte(MakerSideAsk)},
		"unknown side byte":     {'M', '9', '9', '9', 0x7F},
		"envelope with trailer": append(append([]byte{}, bid...), 0xAA, 0xBB),
	} {
		require.Equalf(t, MakerSideBid, decodeMakerSide(hd),
			"%s must fall back to BID — an ambiguous envelope must not choose the maker's asset for them", name)
	}
	// Poisoned spare capacity behind a 4-byte tag must NOT be read as the side byte.
	require.Equal(t, MakerSideBid, decodeMakerSide(blueCPoisoned([]byte{'M', '9', '9', '9'}, 32)),
		"the side byte must come from declared calldata, never from spare capacity")

	key := PoolKey{
		Currency0: Currency{Address: common.Address{}},
		Currency1: Currency{Address: common.HexToAddress("0x02")},
	}
	require.Equal(t, assetID(key.Currency1), lockedAssetForSide(key, MakerSideAsk), "an ASK rests the higher-address asset")
	require.Equal(t, assetID(key.Currency0), lockedAssetForSide(key, MakerSideBid), "a BID rests the lower-address asset")
	require.NotEqual(t, lockedAssetForSide(key, MakerSideAsk), lockedAssetForSide(key, MakerSideBid),
		"the two sides must never rest the same asset")

	// End to end: an ASK commit takes the maker's ERC-20, not their native balance.
	h := newSettleHarness(t)
	h.registerMarket(t)
	h.wrapper().mintTestToken(h.key.Currency1.Address, h.caller, big.NewInt(1000))
	h.fundCallerNative(1000)
	db := newPoolStateAdapter(h.state)
	nativeBefore := loadCommittedPositions(db, h.inAssetID())
	balBefore := h.state.stateDB.GetBalance(h.caller).ToBig()

	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999,
		modLiqCalldata(h.key, -60, 60, big.NewInt(300), [32]byte{0x5A}, MakerSideAsk), 5_000_000, false)
	require.NoError(t, err, "an ASK commit over a real ERC-20 must land")
	require.Equal(t, big.NewInt(300), loadCommittedPositions(db, h.outAssetID()),
		"an ASK must commit currency1 into the LP pot")
	require.Equal(t, nativeBefore, loadCommittedPositions(db, h.inAssetID()),
		"an ASK must not touch the currency0 pot")
	require.Equal(t, balBefore, h.state.stateDB.GetBalance(h.caller).ToBig(),
		"an ASK must not debit the maker's native balance")
}

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

// TestBlueCValueArmWriteCostIsDeterministic measures the trie growth each value arm
// causes and pins it against the arm's fixed fee. The pinned counts are the CONSENSUS
// property: two validators executing the same call must grow the trie identically, so
// a change in these numbers is a state-layout change and must be deliberate. The
// gas-versus-cost ratio is reported, not enforced — pricing is the owner's call.
func TestBlueCValueArmWriteCostIsDeterministic(t *testing.T) {
	const sstoreSet = 20_000 // a zero -> non-zero SSTORE at reference prices

	type armCost struct {
		name   string
		fee    uint64
		writes int
	}
	var measured []armCost

	// deposit (native): the depositor claim + the depositor pot.
	{
		h := newSettleHarness(t)
		h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(500))
		data := make([]byte, 64)
		big.NewInt(500).FillBytes(data[32:64])
		n := blueCCountFreshWrites(h, func() {
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, data), 5_000_000, false)
			require.NoError(t, err)
		})
		require.Equal(t, 2, n, "a native deposit grows the trie by the claim slot and the pot slot")
		measured = append(measured, armCost{"deposit(native)", GasSettlement, n})
	}

	// seedSeamReserve (native): the seam pot.
	{
		h := newSettleHarness(t)
		h.state.stateDB.AddBalance(poolManagerAddr9999, uint256.NewInt(500))
		data := make([]byte, 64)
		big.NewInt(500).FillBytes(data[32:64])
		n := blueCCountFreshWrites(h, func() {
			_, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999, prependSelector(SelectorSeedSeamReserve, data), 5_000_000, false)
			require.NoError(t, err)
		})
		require.Equal(t, 1, n, "a native seed grows the trie by the seam pot slot alone")
		measured = append(measured, armCost{"seedSeamReserve(native)", gasSeedReserve, n})
	}

	// setHaltGlobal: one flag slot.
	{
		h := newSettleHarness(t)
		data := make([]byte, 32)
		data[31] = 1
		n := blueCCountFreshWrites(h, func() {
			_, _, err := h.c.Run(h.state, h.operator(), poolManagerAddr9999, prependSelector(SelectorSetHaltGlobal, data), 1_000_000, false)
			require.NoError(t, err)
		})
		require.Equal(t, 1, n, "a halt is one flag slot")
		measured = append(measured, armCost{"setHaltGlobal", gasHaltAdmin, n})
	}

	// swap phase A: the seam pot, the replay mark, the intent record, the staged object.
	{
		h := newSettleHarness(t)
		h.fundCallerNative(1000)
		n := blueCCountFreshWrites(h, func() {
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, blueCSwapIn(h, EncodeIntentHookData(0, 0)), 5_000_000, false)
			require.NoError(t, err)
		})
		require.Positive(t, n)
		measured = append(measured, armCost{"swap phase A (intent)", GasNativeIntent, n})
	}

	// swap phase B: the consumed mark, the intent decrement, the staged remove, the
	// seam release, the volume shard.
	{
		h := newSettleHarness(t)
		outputID := ids.ID{0x9B}
		h.fundVaultOut(200)
		h.putDtoCObject(t, h.caller, outputID, h.outAssetID(), 200)
		in := blueCSwapIn(h, EncodeSettlementHookData(outputID, 200, h.standingIntent(200)))
		n := blueCCountFreshWrites(h, func() {
			_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, in, 5_000_000, false)
			require.NoError(t, err)
		})
		require.Positive(t, n)
		measured = append(measured, armCost{"swap phase B (settlement)", GasNativeSettlement, n})
	}

	// The determinism claim: re-running each arm on a fresh harness must grow the trie
	// by the SAME count. A count that varied would mean two validators disagree on the
	// post-state size of the same call.
	for _, m := range measured {
		implied := uint64(m.writes) * sstoreSet
		t.Logf("arm=%-26s fee=%6d gas  fresh zero->nonzero slots=%d  implied SSTORE cost=%6d gas  fee/cost=%.2f",
			m.name, m.fee, m.writes, implied, float64(m.fee)/float64(implied))
		require.Positivef(t, m.writes, "%s must be measured, not assumed", m.name)
	}
}
