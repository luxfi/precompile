// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ATOMICITY. For any swap, EXACTLY ONE of claim or refund can ever succeed —
// never both, never twice. The two windows are separated by a single `>=` on the
// block timestamp, so the whole property rests on that comparison being at the
// same boundary in both directions.
// ---------------------------------------------------------------------------

// TestZZExactlyOneOutcomeAtEveryClock sweeps the clock across the timeout and
// asserts that at EVERY instant exactly one of {claim, refund} succeeds on a
// fresh swap. A boundary that admitted both (or neither) shows up here.
func TestZZExactlyOneOutcomeAtEveryClock(t *testing.T) {
	pre := preimageOf(0x5A)
	h := hashOf(pre)
	amt := big.NewInt(1000)

	// Instants around the boundary, plus the lock instant and the far future.
	for _, now := range []uint64{t0, timeout - 2, timeout - 1, timeout, timeout + 1, timeout + 2, timeout + 1_000_000} {
		// Try to claim at `now`.
		claimOK := func() bool {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err)
			e.setNow(now)
			_, err = e.claim(user, id, pre, false)
			if err != nil {
				require.ErrorIs(t, err, ErrExpired, "the only lawful refusal of a valid claim is expiry")
				return false
			}
			zzEqBig(t, amt, e.db().bal(usdc, user))
			return true
		}()

		// Try to refund at `now`, on an independent swap.
		refundOK := func() bool {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err)
			e.setNow(now)
			_, err = e.refund(maker, id, false)
			if err != nil {
				require.ErrorIs(t, err, ErrNotExpired, "the only lawful refusal of a refund is a live timeout")
				return false
			}
			zzEqBig(t, amt, e.db().bal(usdc, maker))
			return true
		}()

		require.NotEqualf(t, claimOK, refundOK,
			"at t=%d exactly one of claim/refund must succeed (claim=%v refund=%v)", now, claimOK, refundOK)
		// And the split is at the timeout itself: claim strictly before, refund at/after.
		require.Equalf(t, now < timeout, claimOK, "claim window is [lock, timeout) — failed at t=%d", now)
		require.Equalf(t, now >= timeout, refundOK, "refund window is [timeout, inf) — failed at t=%d", now)
	}
}

// TestZZSettledSwapIsTerminal drives every ordering of a second settlement
// attempt against an already-settled swap, at both clock positions.
func TestZZSettledSwapIsTerminal(t *testing.T) {
	pre := preimageOf(0x5B)
	h := hashOf(pre)
	amt := big.NewInt(4242)

	settle := map[string]struct {
		at   uint64
		act  func(e *env, id common.Hash) error
		want uint8
	}{
		"claimed": {t0, func(e *env, id common.Hash) error { _, err := e.claim(user, id, pre, false); return err }, StatusClaimed},
		"refunded": {timeout, func(e *env, id common.Hash) error {
			_, err := e.refund(maker, id, false)
			return err
		}, StatusRefunded},
	}

	for name, s := range settle {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err)

			e.setNow(s.at)
			require.NoError(t, s.act(e, id))
			require.Equal(t, s.want, zzStatus(t, e, id))
			zzConserved(t, e, usdc)
			paidUser := e.db().bal(usdc, user)
			paidMaker := e.db().bal(usdc, maker)

			// Nothing further settles, at ANY clock, from ANY caller, with the
			// correct secret in hand.
			zzUnchanged(t, e.db(), func() {
				for _, now := range []uint64{t0, timeout - 1, timeout, timeout + 1_000_000} {
					e.setNow(now)
					for _, who := range []common.Address{user, maker, watcher} {
						_, err := e.claim(who, id, pre, false)
						require.ErrorIsf(t, err, ErrNotLocked, "claim at t=%d by %s", now, who.Hex())
						_, err = e.refund(who, id, false)
						require.ErrorIsf(t, err, ErrNotLocked, "refund at t=%d by %s", now, who.Hex())
					}
				}
			})

			// Balances are exactly what the single settlement paid.
			zzEqBig(t, paidUser, e.db().bal(usdc, user))
			zzEqBig(t, paidMaker, e.db().bal(usdc, maker))
			zzEqBig(t, big.NewInt(0), e.reserve(usdc))
			require.Equal(t, s.want, zzStatus(t, e, id), "a settled swap's status is terminal")
		})
	}
}

// TestZZRaceAtTheBoundary is the adversarial ordering: the recipient claims one
// second before expiry while the refunder's transaction lands one second after.
// The claim wins and the refund finds nothing to take back.
func TestZZRaceAtTheBoundary(t *testing.T) {
	pre := preimageOf(0x5C)
	h := hashOf(pre)
	amt := big.NewInt(9000)

	t.Run("claim_lands_first", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)

		e.setNow(timeout - 1)
		_, err = e.claim(user, id, pre, false)
		require.NoError(t, err)

		e.setNow(timeout)
		_, err = e.refund(maker, id, false)
		require.ErrorIs(t, err, ErrNotLocked)
		zzEqBig(t, amt, e.db().bal(usdc, user))
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, maker))
	})

	t.Run("refund_lands_first", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)

		e.setNow(timeout)
		_, err = e.refund(maker, id, false)
		require.NoError(t, err)

		// Even holding the correct secret, the recipient is too late.
		_, err = e.claim(user, id, pre, false)
		require.ErrorIs(t, err, ErrNotLocked)
		zzEqBig(t, amt, e.db().bal(usdc, maker))
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, user))
	})
}

// ---------------------------------------------------------------------------
// HASHLOCK. Claim requires SHA256(preimage) == hashlock — Bitcoin's OP_SHA256,
// not keccak, so one 32-byte secret unlocks both legs of a cross-chain swap.
// ---------------------------------------------------------------------------

func TestZZHashlockIsSHA256NotKeccak(t *testing.T) {
	pre := preimageOf(0x6A)
	sha := hashOf(pre)
	kec := common.BytesToHash(crypto.Keccak256(pre[:]))
	require.NotEqual(t, sha, kec, "the two digests must differ for this test to mean anything")

	amt := big.NewInt(1000)

	// A swap locked under the KECCAK digest is NOT unlockable by that preimage:
	// the contract hashes with SHA-256 and gets a different value.
	e := newEnv(t0)
	e.db().fund(usdc, maker, amt)
	id, _, err := e.lock(maker, kec, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	_, err = e.claim(user, id, pre, false)
	require.ErrorIs(t, err, ErrBadPreimage, "hashlock must be SHA-256, so a keccak commitment cannot open")

	// The same preimage against the SHA-256 digest opens immediately.
	e2 := newEnv(t0)
	e2.db().fund(usdc, maker, amt)
	id2, _, err := e2.lock(maker, sha, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	_, err = e2.claim(user, id2, pre, false)
	require.NoError(t, err)
	zzEqBig(t, amt, e2.db().bal(usdc, user))
}

// TestZZWrongPreimageRefused covers the shapes an attacker actually submits: a
// near-miss, a zero secret, a secret truncated or shifted inside the bytes32
// word, and the hashlock itself replayed as if it were the secret.
func TestZZWrongPreimageRefused(t *testing.T) {
	pre := preimageOf(0x6B)
	h := hashOf(pre)
	amt := big.NewInt(1000)

	var offByOne [preimageLen]byte
	copy(offByOne[:], pre[:])
	offByOne[31] ^= 0x01

	var flippedFirst [preimageLen]byte
	copy(flippedFirst[:], pre[:])
	flippedFirst[0] ^= 0x80

	// The 31-byte secret, right-padded and left-padded into the 32-byte word: a
	// caller who hashed a SHORTER value off-chain cannot open a bytes32 lock.
	var rightPad, leftPad32 [preimageLen]byte
	copy(rightPad[:], pre[:31])
	copy(leftPad32[1:], pre[:31])

	bad := map[string][preimageLen]byte{
		"off_by_one_last_byte":  offByOne,
		"flipped_high_bit":      flippedFirst,
		"all_zero":              {},
		"all_ones":              preimageOf(0xFF),
		"unrelated_secret":      preimageOf(0x6C),
		"short_secret_rightpad": rightPad,
		"short_secret_leftpad":  leftPad32,
		"hashlock_as_preimage":  [preimageLen]byte(h),
	}

	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err)

			zzUnchanged(t, e.db(), func() {
				_, err := e.claim(user, id, p, false)
				require.ErrorIs(t, err, ErrBadPreimage)
			})

			// Still locked, still fully funded, and no secret leaked to the relay.
			require.Equal(t, StatusLocked, zzStatus(t, e, id))
			zzEqBig(t, amt, e.reserve(usdc))
			zzConserved(t, e, usdc)
			got, err := e.getPreimage(h, true)
			require.NoError(t, err)
			require.Equal(t, [preimageLen]byte{}, got)

			// And the RIGHT secret still opens it afterwards.
			_, err = e.claim(user, id, pre, false)
			require.NoError(t, err)
			zzEqBig(t, amt, e.db().bal(usdc, user))
		})
	}
}

// TestZZPreimageRelayLifecycle pins the cross-leg secret relay: zero before the
// claim, the exact secret after, and keyed by HASHLOCK (not by swapId) so the
// counterparty's watchtower — which only knows the shared hashlock — can read it.
func TestZZPreimageRelayLifecycle(t *testing.T) {
	pre := preimageOf(0x6D)
	h := hashOf(pre)
	amt := big.NewInt(1000)

	e := newEnv(t0)
	e.db().fund(usdc, maker, amt)

	// Unknown hashlocks read zero, and so does a live-but-unclaimed one.
	for _, probe := range []common.Hash{h, hashOf(preimageOf(0x6E)), {}, {0xFF}} {
		got, err := e.getPreimage(probe, true)
		require.NoError(t, err)
		require.Equal(t, [preimageLen]byte{}, got, "no secret exists before any claim")
	}

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	got, err := e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, [preimageLen]byte{}, got, "locking must not reveal anything")

	_, err = e.claim(user, id, pre, false)
	require.NoError(t, err)

	got, err = e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, pre, got, "the claim publishes the secret under its hashlock")
	require.Equal(t, h, hashOf(got), "and the published secret really opens that hashlock")

	// Unrelated hashlocks are untouched by this reveal.
	other, err := e.getPreimage(hashOf(preimageOf(0x6E)), true)
	require.NoError(t, err)
	require.Equal(t, [preimageLen]byte{}, other)

	// getSwap carries the same secret in its preimage word.
	out, err := e.getSwap(id, true)
	require.NoError(t, err)
	require.Equal(t, pre[:], out[7*32:8*32])
}

// TestZZZeroPreimageIsAcceptedButUnreadableViaRelay documents a real asymmetry:
// a ZERO hashlock is refused at lock, but a zero PREIMAGE is a legal secret. It
// settles correctly — and then getPreimage returns bytes32(0), which is the same
// answer it gives for "never claimed". The relay cannot distinguish the two; the
// Claimed event and getSwap's status word still can.
func TestZZZeroPreimageIsAcceptedButUnreadableViaRelay(t *testing.T) {
	var zero [preimageLen]byte
	h := common.BytesToHash(func() []byte { s := sha256.Sum256(zero[:]); return s[:] }())
	require.NotEqual(t, common.Hash{}, h, "SHA256(0^32) is not itself zero, so this hashlock is lockable")

	amt := big.NewInt(1000)
	e := newEnv(t0)
	e.db().fund(usdc, maker, amt)

	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)

	// The zero secret opens it — the contract special-cases nothing.
	_, err = e.claim(user, id, zero, false)
	require.NoError(t, err)
	zzEqBig(t, amt, e.db().bal(usdc, user))
	require.Equal(t, StatusClaimed, zzStatus(t, e, id))

	// But the relay is now ambiguous: this reads identically to "unclaimed".
	got, err := e.getPreimage(h, true)
	require.NoError(t, err)
	require.Equal(t, [preimageLen]byte{}, got)
	unrelated, err := e.getPreimage(hashOf(preimageOf(0x01)), true)
	require.NoError(t, err)
	require.Equal(t, got, unrelated, "a zero secret is indistinguishable from no secret via getPreimage")

	// The status word remains the unambiguous signal.
	require.NotEqual(t, StatusNone, zzStatus(t, e, id))
}

// ---------------------------------------------------------------------------
// CALLER-AGNOSTIC SETTLEMENT. Both payouts go to the address fixed at lock time,
// whoever submits. A watchtower earns nothing by relaying.
// ---------------------------------------------------------------------------

func TestZZPayoutIgnoresSubmitter(t *testing.T) {
	pre := preimageOf(0x7A)
	h := hashOf(pre)
	amt := big.NewInt(31337)
	stranger := common.HexToAddress("0x9999999999999999999999999999999999999999")

	for _, submitter := range []common.Address{user, maker, watcher, stranger, swapAddr} {
		t.Run("claim_by_"+submitter.Hex(), func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err)

			_, err = e.claim(submitter, id, pre, false)
			require.NoError(t, err)

			zzEqBig(t, amt, e.db().bal(usdc, user), "the STORED recipient is paid")
			if submitter != user {
				zzEqBig(t, big.NewInt(0), e.db().bal(usdc, submitter), "the submitter earns nothing")
			}
			zzConserved(t, e, usdc)
		})

		t.Run("refund_by_"+submitter.Hex(), func(t *testing.T) {
			e := newEnv(t0)
			e.db().fund(usdc, maker, amt)
			id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
			require.NoError(t, err)
			e.setNow(timeout)

			_, err = e.refund(submitter, id, false)
			require.NoError(t, err)

			zzEqBig(t, amt, e.db().bal(usdc, maker), "the STORED refund address is paid")
			if submitter != maker {
				zzEqBig(t, big.NewInt(0), e.db().bal(usdc, submitter), "the submitter earns nothing")
			}
			zzConserved(t, e, usdc)
		})
	}
}

// TestZZRecipientAndRefundMayDiffer separates the four roles — locker, recipient,
// refund address, submitter — so no path can be quietly paying `caller`.
func TestZZRecipientAndRefundMayDiffer(t *testing.T) {
	pre := preimageOf(0x7B)
	h := hashOf(pre)
	amt := big.NewInt(555)
	refundee := common.HexToAddress("0x4444444444444444444444444444444444444444")

	t.Run("claim_pays_recipient_not_locker", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, refundee, usdc, amt, timeout, false)
		require.NoError(t, err)
		_, err = e.claim(watcher, id, pre, false)
		require.NoError(t, err)
		zzEqBig(t, amt, e.db().bal(usdc, user))
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, refundee))
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, maker))
	})

	t.Run("refund_pays_refund_address_not_locker", func(t *testing.T) {
		e := newEnv(t0)
		e.db().fund(usdc, maker, amt)
		id, _, err := e.lock(maker, h, user, refundee, usdc, amt, timeout, false)
		require.NoError(t, err)
		e.setNow(timeout)
		_, err = e.refund(watcher, id, false)
		require.NoError(t, err)
		zzEqBig(t, amt, e.db().bal(usdc, refundee), "refund goes to the STORED refund address")
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, maker), "not back to whoever locked")
		zzEqBig(t, big.NewInt(0), e.db().bal(usdc, user))
	})
}

// ---------------------------------------------------------------------------
// REPLAY / COLLISION.
// ---------------------------------------------------------------------------

// TestZZSwapIDCollisionRefused seeds the exact id the next lock will compute and
// proves the collision check refuses it WITHOUT pulling any funds. Honest locks
// cannot reach this (the nonce makes ids distinct); a hash collision or a
// corrupted trie could.
func TestZZSwapIDCollisionRefused(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	e.db().fund(usdc, maker, amt)
	h := hashOf(preimageOf(0x8A))

	// The nonce starts at zero, so the id of the next lock is fully determined.
	require.Equal(t, uint64(0), loadNonce(e.db()))
	collide := computeSwapID(h, user, maker, usdc, amt, timeout, maker, 0)
	zzSeedLocked(e.db(), collide, h, user, maker, usdc, amt, timeout)

	_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.ErrorIs(t, err, ErrSwapExists)

	// Refused BEFORE the funds move: the maker still holds everything.
	zzEqBig(t, amt, e.db().bal(usdc, maker))
	zzEqBig(t, big.NewInt(0), e.db().bal(usdc, swapAddr))
	zzEqBig(t, big.NewInt(0), e.reserve(usdc))
	require.Equal(t, uint64(0), loadNonce(e.db()), "a refused lock does not burn a nonce")

	// Any other status at that id is equally refused — Claimed and Refunded slots
	// are never recycled.
	for _, st := range []uint8{StatusClaimed, StatusRefunded} {
		storeStatus(e.db(), collide, st)
		_, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.ErrorIsf(t, err, ErrSwapExists, "status %d must not be reusable", st)
	}

	// Cleared to None, the same terms lock cleanly at the same id.
	storeStatus(e.db(), collide, StatusNone)
	id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	require.Equal(t, collide, id, "the id is a pure function of the terms, caller and nonce")
	require.Equal(t, uint64(1), loadNonce(e.db()))
}

// TestZZNonceMakesIdenticalTermsDistinct pins the binding that stops a replayed
// lock from colliding: same terms, same caller, same block — different ids.
func TestZZNonceMakesIdenticalTermsDistinct(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(100)
	n := 8
	e.db().fund(usdc, maker, new(big.Int).Mul(amt, big.NewInt(int64(n))))
	h := hashOf(preimageOf(0x8B))

	seen := map[common.Hash]bool{}
	for i := 0; i < n; i++ {
		require.Equal(t, uint64(i), loadNonce(e.db()), "the nonce advances once per successful lock")
		id, _, err := e.lock(maker, h, user, maker, usdc, amt, timeout, false)
		require.NoError(t, err)
		require.Falsef(t, seen[id], "lock %d reused an id", i)
		seen[id] = true
		require.Equal(t, id, computeSwapID(h, user, maker, usdc, amt, timeout, maker, uint64(i)))
	}
	require.Len(t, seen, n)
	zzEqBig(t, new(big.Int).Mul(amt, big.NewInt(int64(n))), e.reserve(usdc))
	zzConserved(t, e, usdc)
}

// TestZZSwapIDBindsEveryTerm changes one field at a time and asserts the id
// moves. A field left out of the digest would let two different swaps share a
// slot and overwrite each other.
func TestZZSwapIDBindsEveryTerm(t *testing.T) {
	h := hashOf(preimageOf(0x8C))
	amt := big.NewInt(1000)
	base := computeSwapID(h, user, maker, usdc, amt, timeout, maker, 0)

	variants := map[string]common.Hash{
		"hashlock":  computeSwapID(hashOf(preimageOf(0x8D)), user, maker, usdc, amt, timeout, maker, 0),
		"recipient": computeSwapID(h, watcher, maker, usdc, amt, timeout, maker, 0),
		"refund":    computeSwapID(h, user, watcher, usdc, amt, timeout, maker, 0),
		"asset":     computeSwapID(h, user, maker, wbtc, amt, timeout, maker, 0),
		"amount":    computeSwapID(h, user, maker, usdc, big.NewInt(1001), timeout, maker, 0),
		"timeout":   computeSwapID(h, user, maker, usdc, amt, timeout+1, maker, 0),
		"caller":    computeSwapID(h, user, maker, usdc, amt, timeout, user, 0),
		"nonce":     computeSwapID(h, user, maker, usdc, amt, timeout, maker, 1),
	}
	all := map[common.Hash]string{base: "base"}
	for name, id := range variants {
		require.NotEqualf(t, base, id, "%s is not bound into the swapId", name)
		prev, dup := all[id]
		require.Falsef(t, dup, "%s collides with %s", name, prev)
		all[id] = name
	}

	// Deterministic: the same terms always yield the same id.
	require.Equal(t, base, computeSwapID(h, user, maker, usdc, new(big.Int).Set(amt), timeout, maker, 0))
}

// TestZZCrossCallerIsolation proves two makers locking identical terms cannot
// touch each other's swap.
func TestZZCrossCallerIsolation(t *testing.T) {
	e := newEnv(t0)
	amt := big.NewInt(1000)
	pre := preimageOf(0x8E)
	h := hashOf(pre)
	e.db().fund(usdc, maker, amt)
	e.db().fund(usdc, user, amt)

	idA, _, err := e.lock(maker, h, watcher, maker, usdc, amt, timeout, false)
	require.NoError(t, err)
	idB, _, err := e.lock(user, h, watcher, user, usdc, amt, timeout, false)
	require.NoError(t, err)
	require.NotEqual(t, idA, idB)

	// Settling A leaves B untouched, even though both share the hashlock.
	_, err = e.claim(watcher, idA, pre, false)
	require.NoError(t, err)
	require.Equal(t, StatusClaimed, zzStatus(t, e, idA))
	require.Equal(t, StatusLocked, zzStatus(t, e, idB))
	zzEqBig(t, amt, e.reserve(usdc))
	zzConserved(t, e, usdc)

	// B refunds to ITS locker, not A's.
	e.setNow(timeout)
	_, err = e.refund(watcher, idB, false)
	require.NoError(t, err)
	zzEqBig(t, amt, e.db().bal(usdc, user))
	zzEqBig(t, big.NewInt(0), e.db().bal(usdc, maker))
	zzEqBig(t, big.NewInt(0), e.reserve(usdc))
}
