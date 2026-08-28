// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Event data is consensus-visible: logs are committed in the receipt root, so an
// encoder that drops a sign or mis-pads a word changes the block hash. These tests
// assert the ABI encoding exactly, and assert the SIGN handling in particular —
// two's complement is where a signed amount silently becomes an enormous positive.

// TestABIEncodeBigIntSignExtends covers the signed word encoder at both signs, at
// zero, and on nil. A negative amount must come back negative when read as an
// int256, not as ~2^256.
func TestABIEncodeBigIntSignExtends(t *testing.T) {
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	readInt256 := func(word []byte) *big.Int {
		v := new(big.Int).SetBytes(word)
		if word[0]&0x80 != 0 { // high bit set => negative
			v.Sub(v, mod)
		}
		return v
	}

	// nil must encode as a zero word rather than panicking or producing a short slice.
	require.Equal(t, make([]byte, 32), abiEncodeBigInt(nil),
		"a nil amount must encode as zero, not panic")

	for _, v := range []int64{0, 1, -1, 255, -255, 1 << 40, -(1 << 40)} {
		word := abiEncodeBigInt(big.NewInt(v))
		require.Lenf(t, word, 32, "%d must encode to exactly one word", v)
		require.Equalf(t, v, readInt256(word).Int64(), "%d must survive as an int256", v)
	}

	// A negative value must be sign-EXTENDED with 0xff, which is what makes Solidity
	// read it as negative. A zero-padded negative would read as a huge positive.
	require.Equal(t, byte(0xff), abiEncodeBigInt(big.NewInt(-1))[0],
		"a negative amount must be 0xff-padded")
	require.Equal(t, byte(0x00), abiEncodeBigInt(big.NewInt(1))[0],
		"a positive amount must be zero-padded")

	// -1 is all ones; 0 is all zeros. These are the two extremes of the padding loop.
	allOnes := make([]byte, 32)
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	require.Equal(t, allOnes, abiEncodeBigInt(big.NewInt(-1)))

	// Random sweep over both signs and a wide magnitude range. Deterministic seed
	// 4242424 so a failure reproduces exactly.
	const seed = 4242424
	r := rand.New(rand.NewSource(seed))
	for range 5000 {
		mag := new(big.Int).Rand(r, new(big.Int).Lsh(big.NewInt(1), uint(1+r.Intn(200))))
		if r.Intn(2) == 0 {
			mag.Neg(mag)
		}
		require.Equalf(t, 0, readInt256(abiEncodeBigInt(mag)).Cmp(mag),
			"seed=%d value %v must survive the round trip", seed, mag)
	}
}

// TestABIEncodeInt24SignExtends: the tick is an int24 and negative ticks are
// ordinary (half the price range). A tick that lost its sign would place liquidity
// at the reciprocal price.
func TestABIEncodeInt24SignExtends(t *testing.T) {
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	read := func(word []byte) int64 {
		v := new(big.Int).SetBytes(word)
		if word[0]&0x80 != 0 {
			v.Sub(v, mod)
		}
		return v.Int64()
	}

	for _, tick := range []int32{0, 1, -1, 60, -60, 887272, -887272, MinTick, MaxTick} {
		word := abiEncodeInt24(tick)
		require.Lenf(t, word, 32, "tick %d must encode to one word", tick)
		require.Equalf(t, int64(tick), read(word), "tick %d must survive as an int24", tick)
	}

	require.Equal(t, byte(0xff), abiEncodeInt24(-1)[0], "a negative tick must be 0xff-padded")
	require.Equal(t, byte(0x00), abiEncodeInt24(1)[0], "a positive tick must be zero-padded")
	require.Equal(t, make([]byte, 32), abiEncodeInt24(0), "tick zero is a zero word")
}

// TestABIEncodeUint24 is unsigned: no padding branch, and the value sits in the
// last three bytes.
func TestABIEncodeUint24(t *testing.T) {
	for _, fee := range []uint24{0, 1, 500, 3000, FeeMax, 0xFFFFFF} {
		word := abiEncodeUint24(fee)
		require.Len(t, word, 32)
		require.Equal(t, make([]byte, 29), word[:29], "a uint24 must never set a high byte")
		got := uint32(word[29])<<16 | uint32(word[30])<<8 | uint32(word[31])
		require.Equalf(t, uint32(fee), got, "fee %d must survive", fee)
	}
}

// TestEmitSwapEventShapeAndTopics pins the Swap log exactly: which topics are
// indexed, in what order, and the 6-word data layout. Indexers filter on topic
// order, so a reordering silently breaks every consumer; and topic0 must be the
// keccak of the canonical signature, not a transcribed constant.
func TestEmitSwapEventShapeAndTopics(t *testing.T) {
	db := NewMockStateDB()

	var poolId [32]byte
	poolId[0], poolId[31] = 0xAB, 0xCD
	sender := common.HexToAddress("0x1234567890123456789012345678901234567890")
	delta := BalanceDelta{Amount0: big.NewInt(-1000), Amount1: big.NewInt(2000)}
	sqrtPrice := new(big.Int).Lsh(big.NewInt(1), 96)
	liquidity := big.NewInt(1e18)

	emitSwapEvent(db, poolId, sender, delta, sqrtPrice, liquidity, -60, 3000)

	logs := db.Logs()
	require.Len(t, logs, 1, "exactly one Swap log must be emitted")
	lg := logs[0]

	// topic0 is derived from the canonical signature, not hand-entered.
	want := common.BytesToHash(crypto.Keccak256(
		[]byte("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")))
	require.Len(t, lg.Topics, 3, "Swap indexes exactly poolId and sender")
	require.Equal(t, want, lg.Topics[0], "topic0 must be keccak of the canonical signature")
	require.Equal(t, common.BytesToHash(poolId[:]), lg.Topics[1], "topic1 is the pool id")
	require.Equal(t, common.BytesToHash(sender.Bytes()), lg.Topics[2], "topic2 is the sender")

	// Six non-indexed words, in the documented order.
	require.Len(t, lg.Data, 6*32, "Swap carries exactly six data words")
	require.Equal(t, abiEncodeBigInt(delta.Amount0), lg.Data[0:32], "word 0 is amount0")
	require.Equal(t, abiEncodeBigInt(delta.Amount1), lg.Data[32:64], "word 1 is amount1")
	require.Equal(t, abiEncodeBigInt(sqrtPrice), lg.Data[64:96], "word 2 is sqrtPriceX96")
	require.Equal(t, abiEncodeBigInt(liquidity), lg.Data[96:128], "word 3 is liquidity")
	require.Equal(t, abiEncodeInt24(-60), lg.Data[128:160], "word 4 is the tick")
	require.Equal(t, abiEncodeUint24(3000), lg.Data[160:192], "word 5 is the fee")

	// The NEGATIVE amount0 must be sign-extended in the log, not written as a huge
	// positive — this is the field an indexer reads as "tokens leaving the pool".
	require.Equal(t, byte(0xff), lg.Data[0], "a negative amount0 must be sign-extended in the log")

	// Nil amounts are tolerated and encode as zero words rather than panicking.
	require.NotPanics(t, func() {
		emitSwapEvent(db, poolId, sender, BalanceDelta{}, nil, nil, 0, 0)
	}, "a swap with nil amounts must not panic while building its log")
	require.Len(t, db.Logs(), 2)
	require.Equal(t, make([]byte, 4*32), db.Logs()[1].Data[0:128],
		"nil amounts encode as zero words")
}

// TestEventSignaturesAreDerivedNotTranscribed: every topic0 in this file must be
// the keccak of its canonical signature string. A transcribed constant can drift
// from the ABI it claims to describe, and an indexer filtering on the real hash
// would then see nothing.
func TestEventSignaturesAreDerivedNotTranscribed(t *testing.T) {
	for sig, got := range map[string]common.Hash{
		"Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)": initializeEventSig,
		"Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)":       swapEventSig,
		"ModifyLiquidity(bytes32,address,int24,int24,int256,bytes32)":            modifyLiquidityEventSig,
		"DEXFill(bytes32,address,uint256,uint256)":                               dexFillEventSig,
		"DEXPaused(address)":           dexPausedEventSig,
		"DEXResumed(address)":          dexResumedEventSig,
		"PoolPaused(bytes32,address)":  poolPausedEventSig,
		"PoolResumed(bytes32,address)": poolResumedEventSig,
		"PoolFrozen(bytes32,address)":  poolFrozenEventSig,
	} {
		require.Equalf(t, common.BytesToHash(crypto.Keccak256([]byte(sig))), got,
			"topic0 for %q must be the keccak of its signature", sig)
	}

	// And they must all be DISTINCT — two events sharing a topic0 would be
	// indistinguishable to every consumer.
	seen := map[common.Hash]bool{}
	for _, h := range []common.Hash{
		initializeEventSig, swapEventSig, modifyLiquidityEventSig, dexFillEventSig,
		dexPausedEventSig, dexResumedEventSig, poolPausedEventSig, poolResumedEventSig,
		poolFrozenEventSig,
	} {
		require.Falsef(t, seen[h], "duplicate event signature %s", h.Hex())
		seen[h] = true
	}
}

// TestABIEncodeBigIntPaddingLoopIsUnreachable proves that the 0xff sign-extension
// loop at events.go:88-90 is DEAD for every value the encoder can legitimately see,
// and records why — so the next reader does not mistake its absence of coverage for
// an untested path.
//
// The negative branch computes twos = 2^256 + v. For any v in the int256 range
// (v >= -2^255) that lands in [2^255, 2^256), which is EXACTLY 32 bytes. `32-len(b)`
// is therefore always 0 and the loop body never executes; the sign extension is
// already carried by the full-width value itself.
//
// This is why a mutation deleting the loop changes nothing observable — it is an
// equivalent mutant, not a hole in the tests.
func TestABIEncodeBigIntPaddingLoopIsUnreachable(t *testing.T) {
	twoTo256 := new(big.Int).Lsh(big.NewInt(1), 256)
	twoTo255 := new(big.Int).Lsh(big.NewInt(1), 255)

	// The extreme negative an int256 can hold, and a spread of ordinary ones.
	for _, v := range []*big.Int{
		new(big.Int).Neg(twoTo255),
		new(big.Int).Add(new(big.Int).Neg(twoTo255), big.NewInt(1)),
		big.NewInt(-1), big.NewInt(-255), big.NewInt(-(1 << 62)),
	} {
		twos := new(big.Int).Add(twoTo256, v)
		require.GreaterOrEqualf(t, twos.Cmp(twoTo255), 0,
			"2^256+%v must be at least 2^255", v)
		require.Lenf(t, twos.Bytes(), 32,
			"2^256+%v occupies the full 32 bytes, so the padding loop cannot run", v)

		// And the encoding is still correct without any padding.
		require.Equal(t, twos.FillBytes(make([]byte, 32)), abiEncodeBigInt(v))
	}
}
