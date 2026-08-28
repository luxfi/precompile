// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package frost

import (
	"encoding/binary"
	"math"
	"sync"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/require"
)

// secp256k1 boundary values, as 32-byte big-endian x-only encodings.
const (
	groupOrderHex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" // n
	fieldPrimeHex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f" // p
	allOnesHex    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" // 2^256-1
	zeroHex       = "0000000000000000000000000000000000000000000000000000000000000000"
)

// runRaw executes the precompile over arbitrary calldata with the quoted fee.
func runRaw(t *testing.T, input []byte) ([]byte, error) {
	t.Helper()
	res, _, err := FROSTVerifyPrecompile.Run(
		nil, common.Address{}, ContractFROSTVerifyAddress,
		input, FROSTVerifyPrecompile.RequiredGas(input), true,
	)
	return res, err
}

// TestFROST_RefuseShortInput: everything below MinInputSize is refused with
// the length error, and exactly MinInputSize is admitted. The boundary is the
// whole point -- one byte either side must land on opposite sides.
func TestFROST_RefuseShortInput(t *testing.T) {
	for _, size := range []int{0, 1, 8, 135} {
		_, err := runRaw(t, make([]byte, size))
		require.ErrorIs(t, err, ErrInvalidInputLength, "len=%d must be refused as short", size)
	}
	require.Equal(t, MinInputSize-1, 135, "the short boundary must track MinInputSize")

	_, err := runRaw(t, nil)
	require.ErrorIs(t, err, ErrInvalidInputLength, "nil calldata must be refused as short")

	// Exactly MinInputSize is long enough: it fails on the threshold, not the length.
	_, err = runRaw(t, make([]byte, MinInputSize))
	require.ErrorIs(t, err, ErrInvalidThreshold, "at MinInputSize the length check must pass")
	require.NotErrorIs(t, err, ErrInvalidInputLength)

	// One byte longer is also admitted.
	pk, mh, sig := katVector(t)
	long := append(buildFrostInput(3, 5, pk, mh, sig), 0x00)
	res, err := runRaw(t, long)
	require.NoError(t, err)
	require.Equal(t, byte(1), res[31])
}

// TestFROST_RefuseThreshold: the structural (t, n) claim. t == 0 is
// meaningless and t > n is unsatisfiable; t == n is a legitimate n-of-n
// committee and MUST be admitted. Rejecting t == n would silently break every
// unanimous quorum on chain, so it is asserted as an acceptance.
func TestFROST_RefuseThreshold(t *testing.T) {
	pk, mh, sig := katVector(t)
	verdict := func(threshold, n uint32) (byte, error) {
		res, err := runRaw(t, buildFrostInput(threshold, n, pk, mh, sig))
		if err != nil {
			return 0, err
		}
		return res[31], nil
	}

	for _, tn := range [][2]uint32{
		{0, 0}, {0, 1}, {0, math.MaxUint32}, // t == 0
		{1, 0}, {6, 5}, {math.MaxUint32, 1}, // t > n
	} {
		_, err := verdict(tn[0], tn[1])
		require.ErrorIs(t, err, ErrInvalidThreshold, "t=%d n=%d must be refused", tn[0], tn[1])
	}

	for _, tn := range [][2]uint32{
		{1, 1}, {5, 5}, {1, 5}, {math.MaxUint32, math.MaxUint32}, {1, math.MaxUint32},
	} {
		got, err := verdict(tn[0], tn[1])
		require.NoError(t, err, "t=%d n=%d must be admitted", tn[0], tn[1])
		require.Equal(t, byte(1), got, "t=%d n=%d must verify", tn[0], tn[1])
	}

	// t == n is the boundary: n is admitted, n+1 is not.
	_, err := verdict(5, 5)
	require.NoError(t, err)
	_, err = verdict(6, 5)
	require.ErrorIs(t, err, ErrInvalidThreshold)
}

// TestFROST_RefuseAllZeroInput: a fully zero envelope of exactly MinInputSize
// is refused on the threshold, and a zero key/signature under a *valid*
// threshold is refused by the curve. Neither may be mistaken for a signature.
func TestFROST_RefuseAllZeroInput(t *testing.T) {
	_, err := runRaw(t, make([]byte, MinInputSize))
	require.ErrorIs(t, err, ErrInvalidThreshold)

	zeroed := make([]byte, MinInputSize)
	binary.BigEndian.PutUint32(zeroed[0:4], 1)
	binary.BigEndian.PutUint32(zeroed[4:8], 1)
	res, err := runRaw(t, zeroed)
	require.NoError(t, err)
	require.Equal(t, byte(0), res[31], "an all-zero key and signature must not verify")
}

// TestFROST_RefuseTruncatedSignature: a signature that is not exactly 64
// bytes never reaches the equation. Run always slices 64, so this exercises
// the verifier core directly -- the guard that a caller from anywhere else in
// the process depends on.
func TestFROST_RefuseTruncatedSignature(t *testing.T) {
	pk, mh, sig := katVector(t)
	require.True(t, verifySchnorrSignature(pk, mh, sig), "control")

	for _, n := range []int{0, 1, 32, 63, 65, 128} {
		bad := make([]byte, n)
		copy(bad, sig)
		require.False(t, verifySchnorrSignature(pk, mh, bad),
			"signature of %d bytes must be refused", n)
	}
	for _, n := range []int{0, 31, 33, 64} {
		bad := make([]byte, n)
		copy(bad, pk)
		require.False(t, verifySchnorrSignature(bad, mh, sig),
			"public key of %d bytes must be refused", n)
		bad = make([]byte, n)
		copy(bad, mh)
		require.False(t, verifySchnorrSignature(pk, bad, sig),
			"message hash of %d bytes must be refused", n)
	}
}

// TestFROST_RefuseScalarOutOfRange: the response scalar z must be a canonical
// field element below the group order. n, n+1 and 2^256-1 all encode in 32
// bytes and must all be refused, otherwise the same signature has several
// accepted encodings.
func TestFROST_RefuseScalarOutOfRange(t *testing.T) {
	pk, mh, sig := katVector(t)
	order := mustHex(t, groupOrderHex)

	nPlusOne := append([]byte(nil), order...)
	nPlusOne[31]++

	for _, tc := range []struct {
		name string
		z    []byte
	}{
		{"z == n", order},
		{"z == n+1", nPlusOne},
		{"z == 2^256-1", mustHex(t, allOnesHex)},
	} {
		bad := append([]byte(nil), sig...)
		copy(bad[32:64], tc.z)
		require.False(t, verifySchnorrSignature(pk, mh, bad), "%s must be refused", tc.name)
		require.Equal(t, byte(0), runFROST(t, pk, mh, bad), "%s must be refused on-chain", tc.name)
	}

	// n-1 is in range: it decodes, and then fails the equation. A rejection
	// here for the *decoding* reason would mean the range check is off by one.
	inRange := append([]byte(nil), order...)
	inRange[31]--
	bad := append([]byte(nil), sig...)
	copy(bad[32:64], inRange)
	require.False(t, verifySchnorrSignature(pk, mh, bad), "z == n-1 decodes but must not verify")
}

// TestFROST_RefuseDegenerateCurvePoints: the commitment R and the public key
// are both carried as bare x-coordinates, so the verifier must refuse an x
// that is not on the curve, an x at or above the field prime, and the zero x
// (which is the closest an x-only encoding gets to the identity -- secp256k1
// has no point at x = 0, and the identity has no affine x at all).
func TestFROST_RefuseDegenerateCurvePoints(t *testing.T) {
	pk, mh, sig := katVector(t)
	group := curve.Secp256k1{}

	for _, tc := range []struct {
		name string
		xHex string
	}{
		{"zero (no such point, and the nearest encoding of the identity)", zeroHex},
		{"field prime p (out of range)", fieldPrimeHex},
		{"2^256-1 (out of range)", allOnesHex},
	} {
		x := mustHex(t, tc.xHex)
		_, err := group.LiftX(x)
		require.Error(t, err, "LiftX must refuse %s", tc.name)

		badR := append([]byte(nil), sig...)
		copy(badR[0:32], x)
		require.False(t, verifySchnorrSignature(pk, mh, badR), "R_x = %s must be refused", tc.name)
		require.Equal(t, byte(0), runFROST(t, pk, mh, badR), "R_x = %s must be refused on-chain", tc.name)

		require.False(t, verifySchnorrSignature(x, mh, sig), "pubkey = %s must be refused", tc.name)
		require.Equal(t, byte(0), runFROST(t, x, mh, sig), "pubkey = %s must be refused on-chain", tc.name)
	}

	// A concrete x that is in range but has no square root: y^2 = 5^3 + 7 = 132
	// is a non-residue mod p. LiftX must refuse it as off-curve rather than as
	// out-of-range, which pins that both arms of the check are live.
	offCurve := make([]byte, 32)
	offCurve[31] = 5
	_, err := group.LiftX(offCurve)
	require.ErrorContains(t, err, "not on curve")
	require.False(t, verifySchnorrSignature(offCurve, mh, sig), "off-curve pubkey must be refused")
}

// TestFROST_RefuseForgeryUnderAnUnliftableKey is the forgery this verifier
// would admit if the LiftX failure were swallowed instead of refused.
//
// The equation is z*G == R + c*Y. Substituting the identity for an
// unliftable Y collapses c*Y to the identity and the equation to z*G == R --
// which anyone can satisfy without a secret: pick z, publish R = z*G, and the
// pair verifies under ANY public key that fails to lift. So the LiftX refusal
// is not a hygiene check, it is the only thing standing between an off-curve
// x-coordinate and a free signature. This asserts the refusal by presenting
// exactly that forged pair.
func TestFROST_RefuseForgeryUnderAnUnliftableKey(t *testing.T) {
	group := curve.Secp256k1{}
	_, mh, _ := katVector(t)

	// z is arbitrary and public; R = z*G, forced to even Y so that lifting
	// R_x returns R itself and the forged equation closes.
	z := group.NewScalar()
	require.NoError(t, z.UnmarshalBinary(mustHex(t,
		"000000000000000000000000000000000000000000000000000000000000002a")))
	R := z.ActOnBase()
	if !R.(*curve.Secp256k1Point).HasEvenY() {
		z = z.Negate()
		R = z.ActOnBase()
	}
	zBytes, err := z.MarshalBinary()
	require.NoError(t, err)
	forged := make([]byte, 64)
	copy(forged[:32], R.(*curve.Secp256k1Point).XBytes())
	copy(forged[32:], zBytes)

	offCurve := make([]byte, 32)
	offCurve[31] = 5
	for _, tc := range []struct {
		name string
		pk   []byte
	}{
		{"zero", mustHex(t, zeroHex)},
		{"field prime p", mustHex(t, fieldPrimeHex)},
		{"2^256-1", mustHex(t, allOnesHex)},
		{"off-curve x=5", offCurve},
	} {
		_, err := group.LiftX(tc.pk)
		require.Error(t, err, "precondition: %s must not lift", tc.name)
		require.False(t, verifySchnorrSignature(tc.pk, mh, forged),
			"a secret-free (R = z*G, z) pair must not verify under %s", tc.name)
		require.Equal(t, byte(0), runFROST(t, tc.pk, mh, forged),
			"a secret-free (R = z*G, z) pair must not verify on-chain under %s", tc.name)
	}

	// The same pair must also fail under a key that DOES lift: the forgery
	// only ever worked because c*Y vanished.
	katPK, _, _ := katVector(t)
	require.False(t, verifySchnorrSignature(katPK, mh, forged),
		"the forged pair must not verify under a real key either")
}

// xOnlyKeys returns count distinct, valid x-only public keys (the x
// coordinates of 1*G .. count*G). Deterministic: no randomness, no clock.
func xOnlyKeys(t *testing.T, count int) [][]byte {
	t.Helper()
	group := curve.Secp256k1{}
	one := group.NewScalar()
	require.NoError(t, one.UnmarshalBinary(append(make([]byte, 31), 1)))

	acc := group.NewScalar().Set(one)
	out := make([][]byte, 0, count)
	seen := make(map[string]bool, count)
	for i := 0; i < count; i++ {
		p := acc.ActOnBase().(*curve.Secp256k1Point)
		x := append([]byte(nil), p.XBytes()...)
		require.False(t, seen[string(x)], "keys must be distinct")
		seen[string(x)] = true
		out = append(out, x)
		acc = acc.Add(one)
	}
	return out
}

// TestFROST_CacheHitIsStable: the LiftX cache is process-global mutable state
// on the verify path, so a key verified twice must give the same verdict --
// once cold, once warm. A cache that hands back a stale or wrong point is a
// forgery surface.
func TestFROST_CacheHitIsStable(t *testing.T) {
	pk, mh, sig := katVector(t)
	first := verifySchnorrSignature(pk, mh, sig)
	require.True(t, first)
	for i := 0; i < 8; i++ {
		require.Equal(t, first, verifySchnorrSignature(pk, mh, sig),
			"warm lookup %d disagreed with the cold one", i)
	}

	// The same cached key with a tampered signature must still reject: the
	// cache keys on the public key only, and must not carry a verdict.
	bad := append([]byte(nil), sig...)
	bad[63] ^= 0x01
	require.False(t, verifySchnorrSignature(pk, mh, bad),
		"a cached key must not make a bad signature verify")
	require.True(t, verifySchnorrSignature(pk, mh, sig),
		"the good signature must still verify after the bad one")
}

// TestFROST_CacheConcurrentDistinctKeys: many goroutines verifying many
// distinct keys at once must be race-free (run under -race) and each must get
// the verdict it would have got alone.
func TestFROST_CacheConcurrentDistinctKeys(t *testing.T) {
	katPK, mh, sig := katVector(t)
	keys := xOnlyKeys(t, 64)

	// Sequential baseline.
	want := make([]bool, len(keys))
	for i, k := range keys {
		want[i] = verifySchnorrSignature(k, mh, sig)
	}

	var wg sync.WaitGroup
	for round := 0; round < 8; round++ {
		for i, k := range keys {
			wg.Add(1)
			go func(i int, k []byte) {
				defer wg.Done()
				if got := verifySchnorrSignature(k, mh, sig); got != want[i] {
					t.Errorf("key %d: concurrent verdict %v != sequential %v", i, got, want[i])
				}
			}(i, k)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !verifySchnorrSignature(katPK, mh, sig) {
				t.Error("KAT must verify concurrently with unrelated keys")
			}
		}()
	}
	wg.Wait()
}

// TestFROST_CacheBounded: filling the cache past its bound must neither grow
// it without limit nor corrupt what is already in it. The bound is a
// first-writer-wins ceiling, so an attacker can occupy it -- that costs speed,
// never correctness, and this pins the correctness half.
func TestFROST_CacheBounded(t *testing.T) {
	pk, mh, sig := katVector(t)
	require.True(t, verifySchnorrSignature(pk, mh, sig), "seed the cache with the KAT key")

	for _, k := range xOnlyKeys(t, 1200) {
		verifySchnorrSignature(k, mh, sig)
	}

	liftXCacheMu.RLock()
	size := len(liftXCache)
	liftXCacheMu.RUnlock()
	require.Equal(t, 1024, size, "the cache must stop growing at its bound")

	require.True(t, verifySchnorrSignature(pk, mh, sig),
		"the KAT must still verify after the cache filled")
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01
	require.False(t, verifySchnorrSignature(pk, mh, bad),
		"a tampered signature must still reject after the cache filled")
	require.Equal(t, byte(1), runFROST(t, pk, mh, sig),
		"the on-chain verdict must survive a full cache")
}

// cached reports whether a public key currently has a cache entry.
func cached(pk []byte) bool {
	var key [32]byte
	copy(key[:], pk)
	liftXCacheMu.RLock()
	defer liftXCacheMu.RUnlock()
	_, ok := liftXCache[key]
	return ok
}

// forget drops a key's cache entry, so a test can put a chosen key on the cold
// path on purpose instead of hoping about test order.
func forget(pk []byte) {
	var key [32]byte
	copy(key[:], pk)
	liftXCacheMu.Lock()
	defer liftXCacheMu.Unlock()
	delete(liftXCache, key)
}

// cacheSize reads the cache occupancy.
func cacheSize() int {
	liftXCacheMu.RLock()
	defer liftXCacheMu.RUnlock()
	return len(liftXCache)
}

// TestFROST_CacheDoesNotEvict pins the bound's SEMANTICS, not just its number.
//
// The bound is `if len(liftXCache) < 1024`, taken under the write lock, so a
// full cache stops INSERTING rather than evicting. Two consequences, and this
// asserts both:
//
//   - Safety, which is why the shape is worth keeping: an entry is never
//     replaced, so no lookup can ever be served a point that belongs to a
//     different key. The 1025th distinct key onwards simply takes the LiftX
//     path every time and must return the identical verdict.
//   - The cost, which is not a correctness bug and should not be "fixed" into
//     an eviction policy casually: which keys are cached depends on which
//     arrived first, so a validator whose key shows up late permanently pays
//     full price.
//
// The test drives the cache directly rather than depending on the order the
// other tests ran in: it forgets the KAT key, fills the cache to its bound with
// unrelated keys, and then verifies the KAT on a guaranteed-cold path.
func TestFROST_CacheDoesNotEvict(t *testing.T) {
	pk, mh, sig := katVector(t)

	forget(pk)
	for _, k := range xOnlyKeys(t, 1200) {
		verifySchnorrSignature(k, mh, sig)
	}
	require.Equal(t, 1024, cacheSize(), "precondition: the cache must be at its bound")
	require.False(t, cached(pk), "precondition: the KAT key must be evicted and not re-added")

	// Cold path, repeatedly: correct every time, and never admitted.
	for i := 0; i < 4; i++ {
		require.True(t, verifySchnorrSignature(pk, mh, sig),
			"an uncacheable key must still verify (round %d)", i)
		require.False(t, cached(pk), "a full cache must not admit a new key (round %d)", i)
		require.Equal(t, 1024, cacheSize(), "a full cache must not grow (round %d)", i)
	}
	tampered := append([]byte(nil), sig...)
	tampered[40] ^= 0x01
	require.False(t, verifySchnorrSignature(pk, mh, tampered),
		"an uncacheable key must still reject a bad signature")

	// Now make room and let the same key in. The warm verdict must equal the
	// cold one -- that equality is the whole contract of the cache.
	forget(xOnlyKeys(t, 1)[0])
	require.Equal(t, 1023, cacheSize(), "precondition: one slot free")
	require.True(t, verifySchnorrSignature(pk, mh, sig), "cold verdict with a slot free")
	require.True(t, cached(pk), "a key must be admitted when there is room")
	require.True(t, verifySchnorrSignature(pk, mh, sig),
		"the warm verdict must match the cold verdict")
	require.False(t, verifySchnorrSignature(pk, mh, tampered),
		"a cached key must not make a bad signature verify")
}
