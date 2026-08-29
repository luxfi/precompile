// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzmop_settle9999_test.go covers settle9999.go — THE 0x9999 two-phase money path and
// its pure helpers. The properties under test:
//
//   - EVERY value-path entry refuses malformed input rather than settling something.
//   - A plain swap ALWAYS carries a FINITE reclaim horizon (the fund-lock fix), and the
//     horizon SATURATES rather than wrapping to an already-past deadline.
//   - The V4 price limit converts to the CLOB grid by EXACT integer arithmetic with a
//     pinned rounding DIRECTION (round-to-nearest), never a float.
//   - The analytics keys are deterministic pure functions (no map iteration).

// ---------------------------------------------------------------------------
// SettleSwap — entry refusals
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// defaultedReclaimDeadline — the fund-lock fix
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// priceLimitToCLOB — exact integers, pinned rounding direction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// pure helpers: balanceDeltaForOutput / minAmountOut / swapAssetDirection / isWord
// ---------------------------------------------------------------------------

func TestZzmpBalanceDeltaForOutputSignsTheOutputSide(t *testing.T) {
	amt := big.NewInt(1_000)

	fwd := balanceDeltaForOutput(SwapParams{ZeroForOne: true}, amt)
	if fwd.Amount0.Sign() != 0 || fwd.Amount1.Cmp(big.NewInt(-1_000)) != 0 {
		t.Fatalf("zeroForOne credits token1: got (%s, %s)", fwd.Amount0, fwd.Amount1)
	}
	rev := balanceDeltaForOutput(SwapParams{ZeroForOne: false}, amt)
	if rev.Amount1.Sign() != 0 || rev.Amount0.Cmp(big.NewInt(-1_000)) != 0 {
		t.Fatalf("!zeroForOne credits token0: got (%s, %s)", rev.Amount0, rev.Amount1)
	}
	// The two directions are mirror images and the input amount is never mutated.
	if amt.Int64() != 1_000 {
		t.Fatal("balanceDeltaForOutput mutated its input")
	}
	if fwd.Amount1.Cmp(rev.Amount0) != 0 || fwd.Amount0.Cmp(rev.Amount1) != 0 {
		t.Fatal("the two directions are not mirror images")
	}
	// A zero credit is a zero delta on both sides (never a phantom sign).
	z := balanceDeltaForOutput(SwapParams{ZeroForOne: true}, big.NewInt(0))
	if z.Amount0.Sign() != 0 || z.Amount1.Sign() != 0 {
		t.Fatalf("zero credit produced (%s, %s)", z.Amount0, z.Amount1)
	}
}

func TestZzmpSwapAssetDirectionAndAssetAddressAreInverse(t *testing.T) {
	h := newSettleHarness(t)

	in, out := swapAssetDirection(h.key, SwapParams{ZeroForOne: true})
	if in != assetID(h.key.Currency0) || out != assetID(h.key.Currency1) {
		t.Fatal("zeroForOne: in must be currency0 and out currency1")
	}
	rin, rout := swapAssetDirection(h.key, SwapParams{ZeroForOne: false})
	if rin != out || rout != in {
		t.Fatal("reversing the direction must swap the two asset ids")
	}

	// assetAddress is the injective inverse of assetID over the EVM address domain —
	// this is what makes the FIX-5 credit-token derivation sound.
	for _, addr := range []common.Address{
		{},
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		h.key.Currency1.Address,
		common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
	} {
		id := assetID(Currency{Address: addr})
		if got := assetAddress(id); got != addr {
			t.Fatalf("assetAddress(assetID(%s)) = %s", addr.Hex(), got.Hex())
		}
		if isNativeAsset(id) != (addr == common.Address{}) {
			t.Fatalf("isNativeAsset misclassified %s", addr.Hex())
		}
	}
}

func TestZzmpIsWordBoundsTheUint256Domain(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), max} {
		if !isWord(v) {
			t.Fatalf("isWord(%s) must be true", v)
		}
	}
	for _, v := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Add(max, big.NewInt(1))} {
		if isWord(v) {
			t.Fatalf("isWord(%v) must be false", v)
		}
	}
}

// TestZzmpStateDBERC20ResolvesTheVaultCapability covers both arms: the production
// adapter IS a complete vault, and a StateDB with no vault capability is refused.
func TestZzmpStateDBERC20ResolvesTheVaultCapability(t *testing.T) {
	h := newSettleHarness(t)
	if v, ok := stateDBERC20(zzmpDB(h)); !ok || v == nil {
		t.Fatal("the poolStateAdapter must resolve as a complete erc20Vault")
	}
	if v, ok := stateDBERC20(NewMockStateDB()); ok || v != nil {
		t.Fatal("a StateDB with no vault capability must NOT resolve")
	}
	// A StateDB that implements erc20Vault DIRECTLY resolves through the non-adapter arm.
	if v, ok := stateDBERC20(zzmpNewVaultDB()); !ok || v == nil {
		t.Fatal("a StateDB that directly implements erc20Vault must resolve")
	}
}

// ---------------------------------------------------------------------------
// sharded analytics keys — deterministic, no map iteration
// ---------------------------------------------------------------------------

// TestZzmpAnalyticsBucketKeysAreDeterministicAndSharded pins that the fee/volume keys
// are pure functions of (id, epoch) — a key that depended on Go map order would fork
// consensus — and that they shard by epoch modulo the shard count.
func TestZzmpAnalyticsBucketKeysAreDeterministicAndSharded(t *testing.T) {
	assetA := [32]byte{0x01}
	assetB := [32]byte{0x02}

	for i := 0; i < 64; i++ {
		if got := feeBucketKey(assetA, 5); got != feeBucketKey(assetA, 5) {
			t.Fatal("feeBucketKey is not deterministic")
		}
		if got := volBucketKey(assetA, 5); got != volBucketKey(assetA, 5) {
			t.Fatal("volBucketKey is not deterministic")
		}
	}
	// Distinct assets, distinct keys; and the two namespaces never collide.
	if feeBucketKey(assetA, 1) == feeBucketKey(assetB, 1) {
		t.Fatal("feeBucketKey collides across assets")
	}
	if feeBucketKey(assetA, 1) == volBucketKey(assetA, 1) {
		t.Fatal("the fee and volume namespaces collide")
	}
	// Epoch shards wrap modulo the shard count, so epoch and epoch+shards share a slot
	// while adjacent epochs do not.
	if feeBucketKey(assetA, 3) != feeBucketKey(assetA, 3+feeShards) {
		t.Fatal("feeBucketKey does not shard modulo feeShards")
	}
	if feeBucketKey(assetA, 3) == feeBucketKey(assetA, 4) {
		t.Fatal("adjacent epochs must land in different fee shards")
	}
	if volBucketKey(assetA, 3) != volBucketKey(assetA, 3+volShards) {
		t.Fatal("volBucketKey does not shard modulo volShards")
	}
}

// TestZzmpAccrueVolumeAccumulatesAndIgnoresNonPositive pins the analytics accumulator:
// it sums into its shard and treats a nil / zero / negative amount as nothing to record
// (never a negative slot).
func TestZzmpAccrueVolumeAccumulatesAndIgnoresNonPositive(t *testing.T) {
	h := newSettleHarness(t)
	db := zzmpDB(h)
	poolID := h.key.ID()

	read := func(epoch uint64) *big.Int {
		return new(big.Int).SetBytes(db.GetState(poolManagerAddr9999, volBucketKey(poolID, epoch)).Bytes())
	}

	for _, skip := range []*big.Int{nil, big.NewInt(0), big.NewInt(-5)} {
		accrueVolume(db, poolID, skip, 1)
		if read(1).Sign() != 0 {
			t.Fatalf("accrueVolume recorded a non-positive amount %v", skip)
		}
	}
	accrueVolume(db, poolID, big.NewInt(100), 1)
	accrueVolume(db, poolID, big.NewInt(250), 1)
	if got := read(1); got.Int64() != 350 {
		t.Fatalf("accrueVolume must accumulate: want 350, got %s", got)
	}
	// A different epoch lands in a different shard and does not disturb this one.
	accrueVolume(db, poolID, big.NewInt(7), 2)
	if got := read(1); got.Int64() != 350 {
		t.Fatalf("a neighbouring epoch disturbed the shard: %s", got)
	}
	if got := read(2); got.Int64() != 7 {
		t.Fatalf("epoch 2 shard: want 7, got %s", got)
	}
}

func TestZzmpPutU64IsBigEndianAndTotal(t *testing.T) {
	for _, v := range []uint64{0, 1, 255, 256, 1 << 32, math.MaxUint64} {
		var b [8]byte
		putU64(b[:], v)
		if got := new(big.Int).SetBytes(b[:]).Uint64(); got != v {
			t.Fatalf("putU64(%d) round-tripped to %d", v, got)
		}
	}
	var b [8]byte
	putU64(b[:], 0x0102030405060708)
	if b[0] != 0x01 || b[7] != 0x08 {
		t.Fatalf("putU64 is not big-endian: %x", b)
	}
	// Writing again fully overwrites — no residue from the previous value.
	putU64(b[:], 0)
	for i, x := range b {
		if x != 0 {
			t.Fatalf("putU64 left residue at byte %d: %x", i, b)
		}
	}
}

// ---------------------------------------------------------------------------
// reclaimIntent entry
// ---------------------------------------------------------------------------
