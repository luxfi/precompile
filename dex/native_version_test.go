// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
)

// native_version_test.go pins the two version stamps on the C side of the funding rail:
// the staged-op record's leading version byte, and the object commitment's domain.
//
// Both stayed put across the change that shrank the cross-chain object from the braided
// 118-byte form to the 60-byte funding claim, which is the one event they exist to
// mark. A version that does not move when the thing it versions moves is not a version,
// and every guarantee downstream of it is decoration.

// TestVersion_StagedRecordFromTheBraidedEraIsRefused is M2. A C-Chain holding an
// unflushed Put written by the previous release carries the old layout under the old
// stamp. It must be refused BY VERSION — explicitly, at the first byte — rather than by
// a width comparison that happens to disagree, because widths are a coincidence and
// versions are a statement.
func TestVersion_StagedRecordFromTheBraidedEraIsRefused(t *testing.T) {
	h := newSettleHarness(t)
	kv := newPoolStateAdapter(h.state)

	// The braided-era record: version 1, a 118-byte object.
	const oldObjectSize = 118
	old := make([]byte, 1+32+32+oldObjectSize)
	old[0] = 1
	writeBytesToSlots(kv, stagePutPrefix, 0, old)
	markStageKind(kv, 0, stageKindPut)
	setStageSeq(kv, 1)

	if _, err := CollectStagedAtomicRange(h.state.stateDB, 0, 1); err != ErrStagedOpMalformed {
		t.Fatalf("a staged Put from the braided era must be refused, got: %v", err)
	}

	// And a record at the CURRENT stamp and the current width is accepted, so the
	// refusal above discriminates on the era and not on staging in general.
	dChainID := ids.ID{0xD0}
	key := ids.ID{0x0C}
	object := encodeClaim(common.HexToAddress("0xabcd"), [32]byte{}, 7)
	writeBytesToSlots(kv, stagePutPrefix, 1, packPut(dChainID, key, object))
	markStageKind(kv, 1, stageKindPut)
	setStageSeq(kv, 2)

	reqs, err := CollectStagedAtomicRange(h.state.stateDB, 1, 2)
	if err != nil {
		t.Fatalf("a record at the current version was refused: %v", err)
	}
	if len(reqs[dChainID].PutRequests) != 1 {
		t.Fatalf("collected %d puts, want 1", len(reqs[dChainID].PutRequests))
	}
}

// TestVersion_StagedStampMatchesTheObjectItStamps is the standing check that keeps M2
// from happening again. The staged record's width is derived from claimSize, so if the
// claim ever changes width this test still passes — but it fails the moment the two
// versions disagree about which era they are in, which is the mistake that was made.
func TestVersion_StagedStampMatchesTheObjectItStamps(t *testing.T) {
	rec := packPut(ids.ID{0x01}, ids.ID{0x02}, encodeClaim(common.Address{}, [32]byte{}, 1))
	if len(rec) != 1+32+32+claimSize {
		t.Fatalf("packPut wrote %d bytes, want %d", len(rec), 1+32+32+claimSize)
	}
	if rec[0] != stagedOpVersion {
		t.Fatalf("packPut stamped version %d, want %d", rec[0], stagedOpVersion)
	}
	if want := byte(2); stagedOpVersion != want {
		t.Fatalf("stagedOpVersion is %d; the 60-byte funding claim is era %d, and the stamp "+
			"must name the era of the record it introduces", stagedOpVersion, want)
	}
}

// TestVersion_ObjectCommitmentIsSeparatedAndVersioned is M3. The declaration a block
// emits is a hash plus a promise about what was hashed, and the domain is where that
// promise lives. It must not be a bare keccak of the object (any other 32-byte digest on
// the rail could then be presented as one), and it must not still claim the era of the
// object it no longer commits to.
func TestVersion_ObjectCommitmentIsSeparatedAndVersioned(t *testing.T) {
	object := encodeClaim(common.HexToAddress("0xbeef"), [32]byte{}, 1_000)
	got := SettleObjectHash(object)

	if got == common.BytesToHash(crypto.Keccak256(object)) {
		t.Fatal("the object commitment is a bare keccak of the bytes; without a domain any " +
			"32-byte digest on the rail can be presented as an object hash")
	}

	// The braided era's domain must produce a different digest over the same bytes, so a
	// commitment made under one era can never be presented as a commitment under the
	// other.
	v1 := common.BytesToHash(crypto.Keccak256([]byte("lux.dex.native.import.object.v1"), object))
	if got == v1 {
		t.Fatal("the commitment domain did not rotate with the object it commits to: a v1 " +
			"declaration and a v2 declaration are the same digest")
	}
	if want := "lux.dex.native.import.object.v2"; string(exportedObjectHashDomain) != want {
		t.Fatalf("commitment domain is %q, want %q — the 60-byte funding claim is era 2",
			exportedObjectHashDomain, want)
	}
}
