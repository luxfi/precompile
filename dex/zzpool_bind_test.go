// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzpool_bind_test.go covers the AUTHORIZATION PRIMITIVES of pool_manager.go: the
// key derivations (swapBindKey / modifyBindKey / custodyBindKey / cancelAuthKey),
// the parameter digests they fold in (swapParamsDigest / modifyParamsDigest), and
// the load/store pairs that read and write them.
//
// The property that matters is PARAMETER BINDING: the key must be a function of
// EVERY field of the operation it authorizes. A digest that ignores a field is an
// authorization bypass — two materially different operations share one slot, so a
// binding minted for one is consumable by the other. So every test below varies
// ONE field at a time and demands the key move. "Different in some way" is not
// enough; the per-field tables are the assertion.

// zzpDistinct fails if any two entries of the map collide, naming both. It is the
// shared shape of every per-field binding test: build one variant per field, then
// demand all of them (plus the base) are pairwise distinct.
func zzpDistinct(t *testing.T, what string, got map[string]string) {
	t.Helper()
	seen := make(map[string]string, len(got))
	for name, v := range got {
		if prior, dup := seen[v]; dup {
			t.Errorf("%s: field %q and field %q produce the SAME key — that field is not bound, which is an authorization bypass", what, prior, name)
			continue
		}
		seen[v] = name
	}
}

// =========================================================================
// swapParamsDigest — per-field binding
// =========================================================================

func zzpBaseSwapParams() SwapParams {
	// Every field is non-default so DROPPING a field from the digest changes the
	// output. A base with a zero field would make that field's mutation invisible.
	return SwapParams{
		ZeroForOne:        true,
		AmountSpecified:   big.NewInt(-1_000),
		SqrtPriceLimitX96: new(big.Int).Lsh(big.NewInt(1), 96), // Q96 — a realistic price limit
	}
}

func TestZzpSwapParamsDigestBindsEveryField(t *testing.T) {
	base := zzpBaseSwapParams()

	flip := base
	flip.ZeroForOne = false

	sign := base
	sign.AmountSpecified = new(big.Int).Neg(base.AmountSpecified) // same magnitude, opposite sign

	mag := base
	mag.AmountSpecified = big.NewInt(-1_001)

	limit := base
	limit.SqrtPriceLimitX96 = new(big.Int).Add(base.SqrtPriceLimitX96, big.NewInt(1))

	zzpDistinct(t, "swapParamsDigest", map[string]string{
		"base":              swapParamsDigest(base),
		"ZeroForOne":        swapParamsDigest(flip),
		"AmountSpecified±":  swapParamsDigest(sign),
		"|AmountSpecified|": swapParamsDigest(mag),
		"SqrtPriceLimitX96": swapParamsDigest(limit),
	})

	// Determinism: the same params must digest identically on every validator.
	if swapParamsDigest(base) != swapParamsDigest(zzpBaseSwapParams()) {
		t.Error("swapParamsDigest is not deterministic for equal params — validators would derive different slots")
	}
	// Fixed width: the digest is a fixed-size serialization, so no field can eat
	// another's bytes by varying length.
	if len(swapParamsDigest(base)) != len(swapParamsDigest(SwapParams{})) {
		t.Error("swapParamsDigest is not fixed-width; a variable-length encoding lets one field impersonate another")
	}
}

func TestZzpSwapParamsDigestNilFieldsAreSafe(t *testing.T) {
	// A nil AmountSpecified / SqrtPriceLimitX96 must not panic (a panic on a
	// precompile entry path is a chain halt) and must be distinguishable from an
	// explicit zero only insofar as the encoding says so.
	nilBoth := swapParamsDigest(SwapParams{})
	zeroBoth := swapParamsDigest(SwapParams{AmountSpecified: big.NewInt(0), SqrtPriceLimitX96: big.NewInt(0)})
	if nilBoth != zeroBoth {
		t.Error("nil and zero must encode identically — both mean 'no amount', and a split would give one order two slots")
	}
	// A negative price limit is ignored by the encoding (only Sign() > 0 is written),
	// so it must not panic and must equal the zero-limit encoding.
	neg := swapParamsDigest(SwapParams{AmountSpecified: big.NewInt(5), SqrtPriceLimitX96: big.NewInt(-1)})
	if neg != swapParamsDigest(SwapParams{AmountSpecified: big.NewInt(5), SqrtPriceLimitX96: big.NewInt(0)}) {
		t.Error("a negative price limit must encode as no-limit, not as a distinct slot")
	}
}

// =========================================================================
// swapBindKey — tx / pool / params binding, and the unbound refusal
// =========================================================================

func TestZzpSwapBindKeyBindsTxPoolAndParams(t *testing.T) {
	poolA := [32]byte{0xAA}
	poolB := [32]byte{0xBB}
	params := zzpBaseSwapParams()

	db1 := zzpNewTxDB(zzpTx1)
	db2 := zzpNewTxDB(zzpTx2)

	k := func(db StateDB, pool [32]byte, p SwapParams) string {
		key, ok := swapBindKey(db, pool, p)
		if !ok {
			t.Fatal("swapBindKey refused a StateDB that names a non-zero tx")
		}
		return string(key[:])
	}

	other := params
	other.ZeroForOne = false

	zzpDistinct(t, "swapBindKey", map[string]string{
		"base":   k(db1, poolA, params),
		"txHash": k(db2, poolA, params),
		"poolId": k(db1, poolB, params),
		"params": k(db1, poolA, other),
	})
}

func TestZzpSwapBindKeyRefusesWithoutTxIdentity(t *testing.T) {
	// A StateDB that cannot name the tx must yield ok=false rather than collide
	// every unbound swap onto the zero-hash slot.
	if _, ok := swapBindKey(NewMockStateDB(), [32]byte{1}, zzpBaseSwapParams()); ok {
		t.Error("swapBindKey bound a StateDB with no tx identity — every such swap would share one slot")
	}
	// A txIdentified StateDB reporting the ZERO hash is the same hazard.
	if _, ok := swapBindKey(zzpNewTxDB(common.Hash{}), [32]byte{1}, zzpBaseSwapParams()); ok {
		t.Error("swapBindKey bound a zero txHash — every unbound swap would share the zero-hash slot")
	}
}

// =========================================================================
// swap binding storage — presence flag, signed deltas, cross-key isolation
// =========================================================================

func TestZzpSwapBindingRoundTripsIncludingZeroAndNegative(t *testing.T) {
	db := zzpNewTxDB(zzpTx1)
	key, _ := swapBindKey(db, [32]byte{0xAA}, zzpBaseSwapParams())

	if _, settled := loadSwapBinding(db, key); settled {
		t.Fatal("an untouched slot reads as settled — every swap would be short-circuited")
	}

	for _, tc := range []struct{ a0, a1 int64 }{
		{0, 0}, {5, -7}, {-5, 7}, {-1, -1}, {1 << 62, -(1 << 62)},
	} {
		fresh := zzpNewTxDB(zzpTx1)
		want := NewBalanceDelta(big.NewInt(tc.a0), big.NewInt(tc.a1))
		storeSwapBinding(fresh, key, want)
		got, settled := loadSwapBinding(fresh, key)
		if !settled {
			// The genuine zero/zero delta is exactly why a presence FLAG exists.
			t.Fatalf("stored delta (%d,%d) did not read back as settled", tc.a0, tc.a1)
		}
		if got.Amount0.Cmp(want.Amount0) != 0 || got.Amount1.Cmp(want.Amount1) != 0 {
			t.Errorf("delta round-trip: got (%s,%s), want (%s,%s)", got.Amount0, got.Amount1, want.Amount0, want.Amount1)
		}
	}
}

func TestZzpSwapBindingDoesNotLeakAcrossKeys(t *testing.T) {
	// A binding minted for tx1/poolA must be invisible to tx2 and to poolB.
	// Otherwise one settled swap silently satisfies a DIFFERENT swap.
	db := zzpNewTxDB(zzpTx1)
	mine, _ := swapBindKey(db, [32]byte{0xAA}, zzpBaseSwapParams())
	storeSwapBinding(db, mine, NewBalanceDelta(big.NewInt(9), big.NewInt(-9)))

	otherPool, _ := swapBindKey(db, [32]byte{0xBB}, zzpBaseSwapParams())
	if _, settled := loadSwapBinding(db, otherPool); settled {
		t.Error("a binding for one pool is readable under another pool's key")
	}
	otherParams := zzpBaseSwapParams()
	otherParams.ZeroForOne = false
	otherOrder, _ := swapBindKey(db, [32]byte{0xAA}, otherParams)
	if _, settled := loadSwapBinding(db, otherOrder); settled {
		t.Error("a binding for one order is readable under a different order's key")
	}
	// And the modify namespace must not see the swap binding: the two derive
	// their slots under different prefixes precisely so they cannot cross.
	if _, settled := loadModifyBinding(db, mine); settled {
		t.Error("a SWAP binding is readable through the MODIFY slot derivation — the namespaces collide")
	}
}

func TestZzpDeriveSlotSeparatesFieldsAndNamespaces(t *testing.T) {
	base := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000ff")
	got := map[string]string{}
	for _, s := range [][]byte{swapBindFlagSuffix, swapBindAmt0Suffix, swapBindAmt1Suffix} {
		got["swap/"+string(s)] = string(deriveSlot(base, s).Bytes())
		got["mod/"+string(s)] = string(deriveModSlot(base, s).Bytes())
		got["cancel/"+string(s)] = string(deriveCancelAuthSlot(base, s).Bytes())
	}
	zzpDistinct(t, "deriveSlot family", got)

	// deriveSlot must not mutate its caller's base hash (it appends to base[:]).
	before := base
	_ = deriveSlot(base, swapBindAmt0Suffix)
	if base != before {
		t.Error("deriveSlot mutated the base hash it was handed")
	}
}

// =========================================================================
// modifyParamsDigest / modifyBindKey — per-field binding
// =========================================================================

func zzpBaseModifyParams() ModifyLiquidityParams {
	return ModifyLiquidityParams{
		TickLower:      -120,
		TickUpper:      240,
		LiquidityDelta: big.NewInt(-1_000),
		Salt:           [32]byte{0x5A},
	}
}

func TestZzpModifyParamsDigestBindsEveryField(t *testing.T) {
	base := zzpBaseModifyParams()

	lower := base
	lower.TickLower = -60

	upper := base
	upper.TickUpper = 300

	sign := base
	sign.LiquidityDelta = new(big.Int).Neg(base.LiquidityDelta)

	mag := base
	mag.LiquidityDelta = big.NewInt(-1_001)

	salt := base
	salt.Salt = [32]byte{0x5B}

	zzpDistinct(t, "modifyParamsDigest", map[string]string{
		"base":             modifyParamsDigest(base),
		"TickLower":        modifyParamsDigest(lower),
		"TickUpper":        modifyParamsDigest(upper),
		"LiquidityDelta±":  modifyParamsDigest(sign),
		"|LiquidityDelta|": modifyParamsDigest(mag),
		"Salt":             modifyParamsDigest(salt),
	})

	// The tick fields must not be interchangeable: swapping lower and upper is a
	// DIFFERENT position, so it must land on a different slot.
	swapped := base
	swapped.TickLower, swapped.TickUpper = base.TickUpper, base.TickLower
	if modifyParamsDigest(swapped) == modifyParamsDigest(base) {
		t.Error("TickLower and TickUpper are interchangeable in the digest — the range is not bound")
	}
	// A nil delta must not panic and must encode as the zero delta.
	if modifyParamsDigest(ModifyLiquidityParams{}) != modifyParamsDigest(ModifyLiquidityParams{LiquidityDelta: big.NewInt(0)}) {
		t.Error("nil and zero LiquidityDelta must encode identically")
	}
}

func TestZzpModifyBindKeyBindsTxPoolAndParams(t *testing.T) {
	db1 := zzpNewTxDB(zzpTx1)
	db2 := zzpNewTxDB(zzpTx2)
	base := zzpBaseModifyParams()

	k := func(db StateDB, pool [32]byte, p ModifyLiquidityParams) string {
		key, ok := modifyBindKey(db, pool, p)
		if !ok {
			t.Fatal("modifyBindKey refused a StateDB that names a non-zero tx")
		}
		return string(key[:])
	}
	other := base
	other.Salt = [32]byte{0xEE}

	zzpDistinct(t, "modifyBindKey", map[string]string{
		"base":   k(db1, [32]byte{0xAA}, base),
		"txHash": k(db2, [32]byte{0xAA}, base),
		"poolId": k(db1, [32]byte{0xBB}, base),
		"params": k(db1, [32]byte{0xAA}, other),
	})

	if _, ok := modifyBindKey(NewMockStateDB(), [32]byte{1}, base); ok {
		t.Error("modifyBindKey bound a StateDB with no tx identity")
	}
	if _, ok := modifyBindKey(zzpNewTxDB(common.Hash{}), [32]byte{1}, base); ok {
		t.Error("modifyBindKey bound a zero txHash")
	}
}

func TestZzpModifyBindingRoundTripsAndIsolates(t *testing.T) {
	db := zzpNewTxDB(zzpTx1)
	key, _ := modifyBindKey(db, [32]byte{0xAA}, zzpBaseModifyParams())

	if _, settled := loadModifyBinding(db, key); settled {
		t.Fatal("an untouched modify slot reads as settled")
	}
	want := NewBalanceDelta(big.NewInt(-4_242), big.NewInt(4_242))
	storeModifyBinding(db, key, want)
	got, settled := loadModifyBinding(db, key)
	if !settled {
		t.Fatal("stored modify binding did not read back as settled")
	}
	if got.Amount0.Cmp(want.Amount0) != 0 || got.Amount1.Cmp(want.Amount1) != 0 {
		t.Errorf("modify delta round-trip: got (%s,%s), want (%s,%s)", got.Amount0, got.Amount1, want.Amount0, want.Amount1)
	}
	// Zero delta still reads settled — the presence flag is what carries "done".
	fresh := zzpNewTxDB(zzpTx1)
	storeModifyBinding(fresh, key, ZeroBalanceDelta())
	if _, ok := loadModifyBinding(fresh, key); !ok {
		t.Error("a genuine zero modify delta must still read as settled")
	}
	// The swap namespace must not see the modify binding.
	if _, ok := loadSwapBinding(db, key); ok {
		t.Error("a MODIFY binding is readable through the SWAP slot derivation")
	}
}

// =========================================================================
// custodyBindKey — tx / caller / asset / amount, plus the deposit|withdraw split
// =========================================================================

func TestZzpCustodyBindKeyBindsEveryField(t *testing.T) {
	db1 := zzpNewTxDB(zzpTx1)
	db2 := zzpNewTxDB(zzpTx2)
	amt := big.NewInt(1_000)

	k := func(db StateDB, prefix []byte, caller common.Address, asset Currency, a *big.Int) string {
		key, ok := custodyBindKey(db, prefix, caller, asset, a)
		if !ok {
			t.Fatal("custodyBindKey refused a StateDB that names a non-zero tx")
		}
		return string(key[:])
	}

	zzpDistinct(t, "custodyBindKey", map[string]string{
		"base":   k(db1, depBindPrefix, zzpAlice, zzpToken, amt),
		"txHash": k(db2, depBindPrefix, zzpAlice, zzpToken, amt),
		"caller": k(db1, depBindPrefix, zzpBob, zzpToken, amt),
		"asset":  k(db1, depBindPrefix, zzpAlice, NativeCurrency, amt),
		"amount": k(db1, depBindPrefix, zzpAlice, zzpToken, big.NewInt(1_001)),
		"prefix": k(db1, wdrBindPrefix, zzpAlice, zzpToken, amt),
		// nil and zero amount deliberately share one slot; see the next test.
		"zeroAmt": k(db1, depBindPrefix, zzpAlice, zzpToken, big.NewInt(0)),
	})
}

func TestZzpCustodyBindKeyNilAmountEqualsZero(t *testing.T) {
	// nil and 0 both write the zero word: they must be the SAME slot, not two.
	db := zzpNewTxDB(zzpTx1)
	a, _ := custodyBindKey(db, depBindPrefix, zzpAlice, zzpToken, nil)
	b, _ := custodyBindKey(db, depBindPrefix, zzpAlice, zzpToken, big.NewInt(0))
	if a != b {
		t.Error("nil and zero amount derive different custody slots")
	}
}

func TestZzpDepositAndWithdrawBindKeysNeverCollide(t *testing.T) {
	// A deposit binding must never satisfy a withdraw of the same shape (that
	// would let one op consume the other's idempotency slot).
	db := zzpNewTxDB(zzpTx1)
	dep, okD := depositBindKey(db, zzpAlice, zzpToken, big.NewInt(1_000))
	wdr, okW := withdrawBindKey(db, zzpAlice, zzpToken, big.NewInt(1_000))
	if !okD || !okW {
		t.Fatal("custody bind keys refused a StateDB that names a non-zero tx")
	}
	if dep == wdr {
		t.Fatal("deposit and withdraw bind keys collide for identical (tx, caller, asset, amount)")
	}
	// And the stored records live in different namespaces too.
	storeCustodyBinding(db, dep)
	if !loadCustodyBinding(db, dep) {
		t.Error("a stored deposit binding does not read back")
	}
	if loadCustodyBinding(db, wdr) {
		t.Error("a deposit binding is readable under the withdraw key")
	}
	if _, settled := loadWithdrawBinding(db, dep); settled {
		t.Error("a deposit binding reads as a settled withdraw")
	}
}

func TestZzpCustodyBindKeyRefusesWithoutTxIdentity(t *testing.T) {
	if _, ok := custodyBindKey(NewMockStateDB(), depBindPrefix, zzpAlice, zzpToken, big.NewInt(1)); ok {
		t.Error("custodyBindKey bound a StateDB with no tx identity")
	}
	if _, ok := custodyBindKey(zzpNewTxDB(common.Hash{}), depBindPrefix, zzpAlice, zzpToken, big.NewInt(1)); ok {
		t.Error("custodyBindKey bound a zero txHash — the D-Chain seen: key would collide")
	}
	if _, ok := depositBindKey(NewMockStateDB(), zzpAlice, zzpToken, big.NewInt(1)); ok {
		t.Error("depositBindKey bound a StateDB with no tx identity")
	}
	if _, ok := withdrawBindKey(NewMockStateDB(), zzpAlice, zzpToken, big.NewInt(1)); ok {
		t.Error("withdrawBindKey bound a StateDB with no tx identity")
	}
}

func TestZzpCustodyRefIsTheTxHash(t *testing.T) {
	// The D-Chain dedup ref and the EVM-side replay key must be ONE identity.
	if got := custodyRef(zzpNewTxDB(zzpTx1)); got != [32]byte(zzpTx1) {
		t.Errorf("custodyRef: got %x, want the tx hash %x", got, zzpTx1)
	}
	if got := custodyRef(NewMockStateDB()); got != ([32]byte{}) {
		t.Errorf("custodyRef for a StateDB with no tx identity: got %x, want the zero ref", got)
	}
}

func TestZzpWithdrawBindingCarriesRealizedAmount(t *testing.T) {
	db := zzpNewTxDB(zzpTx1)
	key, _ := withdrawBindKey(db, zzpAlice, zzpToken, big.NewInt(1_000))

	amt, settled := loadWithdrawBinding(db, key)
	if settled || amt.Sign() != 0 {
		t.Fatal("an untouched withdraw slot reads as settled")
	}
	// A realized ZERO is a genuine outcome (nothing was available) and must be
	// distinguishable from "not yet settled" — that is what the flag word buys.
	storeWithdrawBinding(db, key, big.NewInt(0))
	amt, settled = loadWithdrawBinding(db, key)
	if !settled {
		t.Fatal("a realized-zero withdraw must read as settled, else the burn replays")
	}
	if amt.Sign() != 0 {
		t.Errorf("realized-zero round-trip: got %s", amt)
	}
	// And a real amount round-trips.
	fresh := zzpNewTxDB(zzpTx1)
	storeWithdrawBinding(fresh, key, big.NewInt(4_242))
	amt, settled = loadWithdrawBinding(fresh, key)
	if !settled || amt.Cmp(big.NewInt(4_242)) != 0 {
		t.Errorf("realized round-trip: got %s settled=%v, want 4242 true", amt, settled)
	}
	// A nil realized must not panic and must record zero.
	nilDB := zzpNewTxDB(zzpTx1)
	storeWithdrawBinding(nilDB, key, nil)
	amt, settled = loadWithdrawBinding(nilDB, key)
	if !settled || amt.Sign() != 0 {
		t.Errorf("nil realized round-trip: got %s settled=%v, want 0 true", amt, settled)
	}
}

// =========================================================================
// cancelAuthKey — the durable (maker, poolId, salt) resting-order handle
// =========================================================================

func TestZzpCancelAuthKeyBindsEveryField(t *testing.T) {
	poolA := [32]byte{0xAA}
	poolB := [32]byte{0xBB}
	saltA := [32]byte{0x01}
	saltB := [32]byte{0x02}

	zzpDistinct(t, "cancelAuthKey", map[string]string{
		"base":   string(cancelAuthKey(zzpAlice, poolA, saltA).Bytes()),
		"maker":  string(cancelAuthKey(zzpBob, poolA, saltA).Bytes()),
		"poolId": string(cancelAuthKey(zzpAlice, poolB, saltA).Bytes()),
		"salt":   string(cancelAuthKey(zzpAlice, poolA, saltB).Bytes()),
	})
}

func TestZzpCancelAuthIsPerMakerAndNotReplayable(t *testing.T) {
	db := zzpNewTxDB(zzpTx1)
	pool := [32]byte{0xAA}
	salt := [32]byte{0x5A}

	if _, ok := loadCancelAuth(db, zzpAlice, pool, salt); ok {
		t.Fatal("an unbound handle reports a resting order — a cancel would be authorized with nothing placed")
	}

	storeCancelAuth(db, zzpAlice, pool, salt, 4242)
	id, ok := loadCancelAuth(db, zzpAlice, pool, salt)
	if !ok || id != 4242 {
		t.Fatalf("stored cancel auth: got id=%d ok=%v, want 4242 true", id, ok)
	}

	// IDOR: Bob forging Alice's salt computes a handle under BOB's address, which
	// has no binding. The attacker cannot cancel Alice's order.
	if _, ok := loadCancelAuth(db, zzpBob, pool, salt); ok {
		t.Error("another maker's forged salt resolves to a resting order — the cancel IDOR is open")
	}
	// Nor can the same maker reach across pools.
	if _, ok := loadCancelAuth(db, zzpAlice, [32]byte{0xBB}, salt); ok {
		t.Error("a binding in one pool authorizes a cancel in another pool")
	}

	// orderID 0 is a REAL order id: the presence flag, not the value, says bound.
	zero := zzpNewTxDB(zzpTx1)
	storeCancelAuth(zero, zzpAlice, pool, salt, 0)
	if id, ok := loadCancelAuth(zero, zzpAlice, pool, salt); !ok || id != 0 {
		t.Errorf("orderID 0 must read as bound: got id=%d ok=%v", id, ok)
	}

	// Consumed binding cannot be replayed: after clear, the handle is dead, so a
	// stale cancel cannot be aimed at a recycled server order id.
	clearCancelAuth(db, zzpAlice, pool, salt)
	if _, ok := loadCancelAuth(db, zzpAlice, pool, salt); ok {
		t.Error("a cleared cancel authorization is still consumable — a stale handle can be replayed")
	}
}

func TestZzpCancelAuthOrderIDRoundTripsFullRange(t *testing.T) {
	db := zzpNewTxDB(zzpTx1)
	pool := [32]byte{0xAA}
	for _, id := range []uint64{0, 1, 255, 256, 1 << 32, ^uint64(0)} {
		salt := [32]byte{}
		salt[0] = byte(id)
		salt[1] = byte(id >> 8)
		storeCancelAuth(db, zzpAlice, pool, salt, id)
		got, ok := loadCancelAuth(db, zzpAlice, pool, salt)
		if !ok || got != id {
			t.Errorf("orderID %d round-trip: got %d ok=%v", id, got, ok)
		}
	}
}

// =========================================================================
// makeStorageKey — the shared derivation every binding above stands on
// =========================================================================

func TestZzpMakeStorageKeySeparatesPrefixFromIdentifier(t *testing.T) {
	// Same input, same key, every time (consensus determinism).
	if makeStorageKey(swapBindPrefix, []byte{1, 2, 3}) != makeStorageKey(swapBindPrefix, []byte{1, 2, 3}) {
		t.Error("makeStorageKey is not deterministic")
	}
	// Every prefix in the pool-manager storage layout must be distinct for the
	// same identifier; a collision merges two unrelated records.
	got := map[string]string{}
	for name, p := range map[string][]byte{
		"poolState": poolStatePrefix, "poolLiquidity": poolLiquidityPrefix, "position": positionPrefix,
		"tick": tickPrefix, "protocolFee": protocolFeePrefix, "hookRegistry": hookRegistryPrefix,
		"pause": pauseStatePrefix, "freeze": freezeStatePrefix, "swapBind": swapBindPrefix,
		"modBind": modBindPrefix, "depBind": depBindPrefix, "wdrBind": wdrBindPrefix,
		"cancelAuth": cancelAuthPrefix, "custodyGuard": custodyGuardPrefix, "vaultLedger": vaultLedgerPrefix,
	} {
		got[name] = string(makeStorageKey(p, []byte{0x42}).Bytes())
	}
	zzpDistinct(t, "storage prefixes", got)

	// The binding key itself must never alias one of the field slots derived FROM
	// it — a binding whose base slot is also its own flag slot would read as
	// settled the instant anything wrote the base.
	base, _ := swapBindKey(zzpNewTxDB(zzpTx1), [32]byte{0xAA}, zzpBaseSwapParams())
	zzpDistinct(t, "bindKey vs its own field slots", map[string]string{
		"bindKey": string(base.Bytes()),
		"flag":    string(deriveSlot(base, swapBindFlagSuffix).Bytes()),
		"amt0":    string(deriveSlot(base, swapBindAmt0Suffix).Bytes()),
		"amt1":    string(deriveSlot(base, swapBindAmt1Suffix).Bytes()),
	})
}
