// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// zzmop_hooks_test.go covers hooks.go. The security-relevant properties:
//
//   - A hook's CAPABILITIES are carried by its ADDRESS, so a hook cannot claim a
//     permission its address does not encode, and an unregistered hook derives exactly
//     the permissions its trailing bits encode (never a default-open set).
//   - The commit-reveal MEV guard's digest must cover EVERY revealed field: a digest
//     that ignores a field is an authorization bypass (the revealer could swap that
//     field after committing), so each field is tampered independently.
//   - The hook selectors are the V4 IHooks keccak prefixes, byte for byte.

// zzmpHookAddr builds a hook address whose trailing two bytes encode `flags`.
func zzmpHookAddr(prefix byte, flags HookFlags) common.Address {
	var a common.Address
	a[0] = prefix
	a[18] = byte(flags >> 8)
	a[19] = byte(flags)
	return a
}

// ---------------------------------------------------------------------------
// selector derivation — the init() invariant, asserted independently
// ---------------------------------------------------------------------------

// TestZzmpHookSelectorsAreTheKeccakPrefixes recomputes every hook selector from its V4
// signature. This is the SAME invariant the package's init() hard-panics on, asserted
// here as a test so a signature drift is a red test rather than a boot-time crash.
func TestZzmpHookSelectorsAreTheKeccakPrefixes(t *testing.T) {
	sigs := map[string][]byte{
		"beforeInitialize":      SigBeforeInitialize,
		"afterInitialize":       SigAfterInitialize,
		"beforeAddLiquidity":    SigBeforeAddLiquidity,
		"afterAddLiquidity":     SigAfterAddLiquidity,
		"beforeRemoveLiquidity": SigBeforeRemoveLiquidity,
		"afterRemoveLiquidity":  SigAfterRemoveLiquidity,
		"beforeSwap":            SigBeforeSwap,
		"afterSwap":             SigAfterSwap,
		"beforeDonate":          SigBeforeDonate,
		"afterDonate":           SigAfterDonate,
	}
	if len(sigs) != len(HookSignatures) {
		t.Fatalf("the selector table and the signature table disagree: %d vs %d entries", len(sigs), len(HookSignatures))
	}
	seen := map[string]string{}
	for name, sel := range sigs {
		sig, ok := HookSignatures[name]
		if !ok {
			t.Fatalf("hook %q has no entry in HookSignatures", name)
		}
		want := crypto.Keccak256([]byte(sig))[:4]
		if !bytes.Equal(sel, want) {
			t.Fatalf("selector for %q = %x, want keccak(%q)[:4] = %x", name, sel, sig, want)
		}
		if len(sel) != 4 {
			t.Fatalf("selector for %q is %d bytes, want 4", name, len(sel))
		}
		if prev, dup := seen[string(sel)]; dup {
			t.Fatalf("selectors collide: %q and %q both derive %x", prev, name, sel)
		}
		seen[string(sel)] = name
	}
	// hookSig itself is the keccak prefix and is deterministic.
	for i := 0; i < 64; i++ {
		if !bytes.Equal(hookSig("beforeSwap(address)"), crypto.Keccak256([]byte("beforeSwap(address)"))[:4]) {
			t.Fatal("hookSig is not the keccak prefix")
		}
	}
}

// ---------------------------------------------------------------------------
// permissions live in the address
// ---------------------------------------------------------------------------

// TestZzmpHookPermissionsRoundTripOverTheWholeBitmap pins encode/decode as exact
// inverses across every single flag AND the full mask, so no permission can be silently
// dropped or invented in translation.
func TestZzmpHookPermissionsRoundTripOverTheWholeBitmap(t *testing.T) {
	all := []HookFlags{
		HookBeforeInitialize, HookAfterInitialize,
		HookBeforeAddLiquidity, HookAfterAddLiquidity,
		HookBeforeRemoveLiquidity, HookAfterRemoveLiquidity,
		HookBeforeSwap, HookAfterSwap,
		HookBeforeDonate, HookAfterDonate,
		HookBeforeSwapReturnsDelta, HookAfterSwapReturnsDelta,
		HookAfterAddLiquidityReturnsDelta, HookAfterRemoveLiquidityReturnsDelta,
	}
	// One flag at a time: decode-then-encode must return exactly that one bit.
	for _, f := range all {
		if got := EncodeHookPermissions(DecodeHookPermissions(f)); got != f {
			t.Fatalf("single flag %#x did not round-trip, got %#x", f, got)
		}
		if !HasPermission(zzmpHookAddr(0x11, f), f) {
			t.Fatalf("HasPermission missed the flag %#x encoded in the address", f)
		}
		// And it grants NOTHING else.
		for _, other := range all {
			if other == f {
				continue
			}
			if HasPermission(zzmpHookAddr(0x11, f), other) {
				t.Fatalf("a hook with only %#x also claims %#x", f, other)
			}
		}
	}
	// The empty and full sets.
	if got := EncodeHookPermissions(HookPermissions{}); got != 0 {
		t.Fatalf("the empty permission set encodes to %#x", got)
	}
	if got := EncodeHookPermissions(DecodeHookPermissions(HookAllMask)); got != HookAllMask {
		t.Fatalf("the full mask did not round-trip: %#x", got)
	}
	// Every bit in the mask is accounted for by exactly one named flag.
	var union HookFlags
	for _, f := range all {
		if union&f != 0 {
			t.Fatalf("flag %#x overlaps an earlier flag", f)
		}
		union |= f
	}
	if union != HookAllMask {
		t.Fatalf("the named flags cover %#x, want HookAllMask %#x", union, HookAllMask)
	}
}

// TestZzmpValidateHookAddressBindsCapabilitiesToTheAddress pins the V4 rule: a hook may
// only claim what its trailing bits encode.
func TestZzmpValidateHookAddressBindsCapabilitiesToTheAddress(t *testing.T) {
	perms := HookPermissions{BeforeSwap: true, AfterSwap: true}
	flags := EncodeHookPermissions(perms)
	addr := zzmpHookAddr(0xAB, flags)

	if err := ValidateHookAddress(addr, perms); err != nil {
		t.Fatalf("an address encoding exactly its claim must validate, got %v", err)
	}
	// Claiming MORE than the address encodes is refused.
	more := perms
	more.BeforeDonate = true
	if err := ValidateHookAddress(addr, more); err != ErrHookInvalidAddress {
		t.Fatalf("over-claiming: want ErrHookInvalidAddress, got %v", err)
	}
	// Claiming LESS is refused too (the address is the exact statement, not a bound).
	less := HookPermissions{BeforeSwap: true}
	if err := ValidateHookAddress(addr, less); err != ErrHookInvalidAddress {
		t.Fatalf("under-claiming: want ErrHookInvalidAddress, got %v", err)
	}
	// Only the trailing two bytes matter: the leading bytes are free.
	other := zzmpHookAddr(0x01, flags)
	if err := ValidateHookAddress(other, perms); err != nil {
		t.Fatalf("the address prefix must not affect validation, got %v", err)
	}
	if GetHookPermissionsFromAddress(addr) != perms {
		t.Fatalf("GetHookPermissionsFromAddress: want %+v, got %+v", perms, GetHookPermissionsFromAddress(addr))
	}
}

// TestZzmpIsHookEnabledDerivesFromTheAddressWhenUnregistered pins the fallback: an
// address that was never registered still resolves exactly the permissions its trailing
// bits encode — it is never treated as fully-permitted, and never as fully-denied when
// its bits say otherwise.
func TestZzmpIsHookEnabledDerivesFromTheAddressWhenUnregistered(t *testing.T) {
	hr := NewHookRegistry()
	addr := zzmpHookAddr(0x22, HookBeforeSwap|HookAfterDonate)

	if _, ok := hr.GetHookFlags(addr); ok {
		t.Fatal("precondition: the hook must be unregistered")
	}
	if !hr.IsHookEnabled(addr, HookBeforeSwap) {
		t.Fatal("an unregistered hook must still resolve the flags its address encodes")
	}
	if !hr.IsHookEnabled(addr, HookAfterDonate) {
		t.Fatal("an unregistered hook must resolve EVERY flag its address encodes")
	}
	if hr.IsHookEnabled(addr, HookAfterSwap) {
		t.Fatal("an unregistered hook must NOT be granted a flag its address does not encode")
	}
	// An address encoding nothing grants nothing.
	empty := zzmpHookAddr(0x33, 0)
	for _, f := range []HookFlags{HookBeforeSwap, HookAfterSwap, HookAllMask} {
		if hr.IsHookEnabled(empty, f) {
			t.Fatalf("a zero-flag address granted %#x", f)
		}
	}

	// Registration requires the address to MATCH the claimed flags...
	if err := hr.RegisterHook(addr, HookBeforeSwap); err != ErrHookInvalidAddress {
		t.Fatalf("registering mismatched flags: want ErrHookInvalidAddress, got %v", err)
	}
	if _, ok := hr.GetHookFlags(addr); ok {
		t.Fatal("a refused registration was recorded")
	}
	// ...and once registered the registry answers from the record.
	if err := hr.RegisterHook(addr, HookBeforeSwap|HookAfterDonate); err != nil {
		t.Fatalf("RegisterHook: %v", err)
	}
	flags, ok := hr.GetHookFlags(addr)
	if !ok || flags != HookBeforeSwap|HookAfterDonate {
		t.Fatalf("GetHookFlags: %#x/%v", flags, ok)
	}
	if !hr.IsHookEnabled(addr, HookBeforeSwap) || hr.IsHookEnabled(addr, HookAfterSwap) {
		t.Fatal("the registered answer must equal the address-derived answer")
	}
}

// TestZzmpGenerateHookAddressStampsTheFlagsDeterministically pins the CREATE2-style
// derivation: same (deployer, salt, permissions) => same address, byte for byte, with
// the permission bits stamped into the trailing two bytes.
func TestZzmpGenerateHookAddressStampsTheFlagsDeterministically(t *testing.T) {
	deployer := common.HexToAddress("0x000000000000000000000000000000000000D001")
	salt := [32]byte{0xAA, 0xBB}
	perms := HookPermissions{BeforeSwap: true, AfterSwap: true, AfterSwapReturnsDelta: true}

	first := GenerateHookAddress(deployer, salt, perms)
	for i := 0; i < 64; i++ {
		if got := GenerateHookAddress(deployer, salt, perms); got != first {
			t.Fatalf("GenerateHookAddress is not deterministic on iteration %d", i)
		}
	}
	if err := ValidateHookAddress(first, perms); err != nil {
		t.Fatalf("a generated address must validate against its own permissions, got %v", err)
	}
	// A different salt, deployer or permission set yields a different address.
	if GenerateHookAddress(deployer, [32]byte{0xAA, 0xBC}, perms) == first {
		t.Fatal("a different salt produced the same address")
	}
	if GenerateHookAddress(common.HexToAddress("0x000000000000000000000000000000000000D002"), salt, perms) == first {
		t.Fatal("a different deployer produced the same address")
	}
	if GenerateHookAddress(deployer, salt, HookPermissions{BeforeSwap: true}) == first {
		t.Fatal("a different permission set produced the same address")
	}
}

// ---------------------------------------------------------------------------
// param packing
// ---------------------------------------------------------------------------

// TestZzmpPackSwapParamsEncodesTheDirectionBitBothWays pins the ZeroForOne byte in both
// packers for BOTH directions — a packer that only ever wrote 1 would hand every hook
// the wrong direction on a !zeroForOne swap.
func TestZzmpPackSwapParamsEncodesTheDirectionBitBothWays(t *testing.T) {
	key := newTestPoolKey()
	sender := common.HexToAddress("0x0000000000000000000000000000000000000501")
	delta := NewBalanceDelta(big.NewInt(11), big.NewInt(22))
	hookData := []byte{0xF0, 0x0D}

	for _, zeroForOne := range []bool{true, false} {
		params := SwapParams{ZeroForOne: zeroForOne, AmountSpecified: big.NewInt(1_234), SqrtPriceLimitX96: big.NewInt(5_678)}

		before := PackBeforeSwapParams(sender, key, params, hookData)
		off := 4 + 20 + len(key.ToBytes())
		wantBit := byte(0)
		if zeroForOne {
			wantBit = 1
		}
		if before[off] != wantBit {
			t.Fatalf("beforeSwap direction byte for zeroForOne=%v: want %d, got %d", zeroForOne, wantBit, before[off])
		}
		if !bytes.Equal(before[:4], SigBeforeSwap) {
			t.Fatalf("beforeSwap packing must lead with its selector, got %x", before[:4])
		}
		if !bytes.HasSuffix(before, hookData) {
			t.Fatal("beforeSwap packing dropped the hookData tail")
		}
		if got := new(big.Int).SetBytes(before[off+1 : off+33]); got.Int64() != 1_234 {
			t.Fatalf("beforeSwap amountSpecified: want 1234, got %s", got)
		}
		if got := new(big.Int).SetBytes(before[off+33 : off+65]); got.Int64() != 5_678 {
			t.Fatalf("beforeSwap sqrtPriceLimit: want 5678, got %s", got)
		}

		after := PackAfterSwapParams(sender, key, params, delta, hookData)
		if after[off] != wantBit {
			t.Fatalf("afterSwap direction byte for zeroForOne=%v: want %d, got %d", zeroForOne, wantBit, after[off])
		}
		if !bytes.Equal(after[:4], SigAfterSwap) {
			t.Fatalf("afterSwap packing must lead with its selector, got %x", after[:4])
		}
		if got := new(big.Int).SetBytes(after[off+33 : off+65]); got.Int64() != 11 {
			t.Fatalf("afterSwap delta0: want 11, got %s", got)
		}
		if got := new(big.Int).SetBytes(after[off+65 : off+97]); got.Int64() != 22 {
			t.Fatalf("afterSwap delta1: want 22, got %s", got)
		}
		// The two directions produce DIFFERENT bytes — the direction is really carried.
		flipped := params
		flipped.ZeroForOne = !zeroForOne
		if bytes.Equal(before, PackBeforeSwapParams(sender, key, flipped, hookData)) {
			t.Fatal("flipping zeroForOne did not change the packed beforeSwap bytes")
		}
		if bytes.Equal(after, PackAfterSwapParams(sender, key, flipped, delta, hookData)) {
			t.Fatal("flipping zeroForOne did not change the packed afterSwap bytes")
		}
	}
}

func TestZzmpUnpackHookDeltaReturnNeedsTwoFullWords(t *testing.T) {
	// Anything under two words is "no delta modification", never a partial read.
	for n := 0; n < 64; n++ {
		delta, err := UnpackHookDeltaReturn(make([]byte, n))
		if err != nil {
			t.Fatalf("UnpackHookDeltaReturn(%d bytes): unexpected error %v", n, err)
		}
		if delta != nil {
			t.Fatalf("UnpackHookDeltaReturn(%d bytes) invented a delta %+v", n, delta)
		}
	}
	data := make([]byte, 64)
	big.NewInt(7).FillBytes(data[0:32])
	big.NewInt(9).FillBytes(data[32:64])
	delta, err := UnpackHookDeltaReturn(data)
	if err != nil || delta == nil {
		t.Fatalf("UnpackHookDeltaReturn(64 bytes): %+v/%v", delta, err)
	}
	if delta.Amount0.Int64() != 7 || delta.Amount1.Int64() != 9 {
		t.Fatalf("unpacked delta: got (%s, %s), want (7, 9)", delta.Amount0, delta.Amount1)
	}
	// Trailing bytes past the two words are ignored, not misread.
	long, err := UnpackHookDeltaReturn(append(data, 0xFF, 0xFF))
	if err != nil || long.Amount0.Int64() != 7 || long.Amount1.Int64() != 9 {
		t.Fatalf("trailing bytes changed the unpacked delta: %+v/%v", long, err)
	}
}

// ---------------------------------------------------------------------------
// dynamic fee
// ---------------------------------------------------------------------------

// TestZzmpCalculateFeeFallsBackToBaseAndCapsAtMax pins both degenerate inputs (too few
// observations, and two observations at the SAME timestamp — a division by zero if it
// were not guarded) and the ceiling.
func TestZzmpCalculateFeeFallsBackToBaseAndCapsAtMax(t *testing.T) {
	vfc := &VolatilityFeeCalculator{BaseFee: 3_000, MaxFee: 10_000, VolatilityScale: 100, WindowSize: 60}

	if got := vfc.CalculateFee(nil); got != vfc.BaseFee {
		t.Fatalf("no observations: want the base fee %d, got %d", vfc.BaseFee, got)
	}
	if got := vfc.CalculateFee([]TWAPObservation{{Timestamp: 1, TickCumulative: big.NewInt(0)}}); got != vfc.BaseFee {
		t.Fatalf("one observation: want the base fee %d, got %d", vfc.BaseFee, got)
	}
	// TWO observations at the SAME timestamp: timeDelta == 0. Without the guard this is
	// a division by zero — a panic reachable from fee calculation.
	same := []TWAPObservation{
		{Timestamp: 42, TickCumulative: big.NewInt(0)},
		{Timestamp: 42, TickCumulative: big.NewInt(1_000)},
	}
	zzmpNoPanic(t, "CalculateFee with a zero time delta", func() {
		if got := vfc.CalculateFee(same); got != vfc.BaseFee {
			t.Errorf("zero time delta: want the base fee %d, got %d", vfc.BaseFee, got)
		}
	})

	// A real move raises the fee above the base but never past the ceiling.
	moved := []TWAPObservation{
		{Timestamp: 100, TickCumulative: big.NewInt(0)},
		{Timestamp: 110, TickCumulative: big.NewInt(10_000_000)},
	}
	got := vfc.CalculateFee(moved)
	if got <= vfc.BaseFee {
		t.Fatalf("a large tick move must raise the fee above the base %d, got %d", vfc.BaseFee, got)
	}
	if got > vfc.MaxFee {
		t.Fatalf("the fee must be capped at MaxFee %d, got %d", vfc.MaxFee, got)
	}
	// A NEGATIVE move is symmetric (volatility is a magnitude, not a direction).
	down := []TWAPObservation{
		{Timestamp: 100, TickCumulative: big.NewInt(0)},
		{Timestamp: 110, TickCumulative: big.NewInt(-10_000_000)},
	}
	if vfc.CalculateFee(down) != got {
		t.Fatalf("volatility must be direction-symmetric: up=%d down=%d", got, vfc.CalculateFee(down))
	}
	// A small move stays at (or just above) the base rather than exploding.
	small := []TWAPObservation{
		{Timestamp: 100, TickCumulative: big.NewInt(0)},
		{Timestamp: 110, TickCumulative: big.NewInt(10)},
	}
	if s := vfc.CalculateFee(small); s < vfc.BaseFee || s > vfc.MaxFee {
		t.Fatalf("a small move produced %d, outside [%d, %d]", s, vfc.BaseFee, vfc.MaxFee)
	}
}

// ---------------------------------------------------------------------------
// commit-reveal — EVERY digest field
// ---------------------------------------------------------------------------

// zzmpCommitHash recomputes the commitment preimage the validator expects.
func zzmpCommitHash(r *RevealedSwap) [32]byte {
	data := make([]byte, 0, 20+1+32+32)
	data = append(data, r.Sender.Bytes()...)
	if r.ZeroForOne {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	amount := make([]byte, 32)
	r.Amount.FillBytes(amount)
	data = append(data, amount...)
	minOut := make([]byte, 32)
	r.MinOutput.FillBytes(minOut)
	data = append(data, minOut...)
	var h [32]byte
	copy(h[:], crypto.Keccak256(data))
	return h
}

// TestZzmpValidateRevealCoversEveryCommittedField is the authorization test that matters:
// the commitment digest must bind EVERY revealed field. Each field is tampered on its own
// — a digest that ignored any one of them would let a revealer swap that field after the
// commit landed, which is exactly the front-running the commit-reveal exists to stop.
func TestZzmpValidateRevealCoversEveryCommittedField(t *testing.T) {
	crv := &CommitRevealValidator{CommitmentPeriod: 3}
	honest := &RevealedSwap{
		Sender:     common.HexToAddress("0x0000000000000000000000000000000000000601"),
		ZeroForOne: true,
		Amount:     big.NewInt(1_000),
		MinOutput:  big.NewInt(950),
	}
	commit := &CommittedSwap{CommitHash: zzmpCommitHash(honest), Sender: honest.Sender, CommitBlock: 10}

	if err := crv.ValidateReveal(commit, honest); err != nil {
		t.Fatalf("the honest reveal must validate, got %v", err)
	}

	for _, tc := range []struct {
		field  string
		mutate func(*RevealedSwap)
	}{
		{"Sender", func(r *RevealedSwap) {
			r.Sender = common.HexToAddress("0x0000000000000000000000000000000000000602")
		}},
		{"ZeroForOne", func(r *RevealedSwap) { r.ZeroForOne = !r.ZeroForOne }},
		{"Amount", func(r *RevealedSwap) { r.Amount = big.NewInt(1_001) }},
		{"MinOutput", func(r *RevealedSwap) { r.MinOutput = big.NewInt(1) }},
	} {
		tampered := *honest
		tc.mutate(&tampered)
		if err := crv.ValidateReveal(commit, &tampered); err == nil {
			t.Fatalf("a reveal with a tampered %s was ACCEPTED — the commitment digest does not bind that field", tc.field)
		}
	}

	// The digest is deterministic: the same reveal always hashes the same way.
	for i := 0; i < 64; i++ {
		if zzmpCommitHash(honest) != commit.CommitHash {
			t.Fatalf("the commitment digest is not deterministic on iteration %d", i)
		}
	}
	// Two DIFFERENT reveals never share a commitment.
	other := *honest
	other.Amount = big.NewInt(999)
	if zzmpCommitHash(&other) == commit.CommitHash {
		t.Fatal("two distinct reveals produced the same commitment")
	}
	// A commitment over a DIFFERENT reveal does not validate this one.
	if err := crv.ValidateReveal(&CommittedSwap{CommitHash: zzmpCommitHash(&other)}, honest); err == nil {
		t.Fatal("a reveal validated against another reveal's commitment")
	}
	// A zero commitment (never committed) validates nothing.
	if err := crv.ValidateReveal(&CommittedSwap{}, honest); err == nil {
		t.Fatal("a reveal validated against an empty commitment")
	}
}

// TestZzmpValidateCommitmentEnforcesTheWaitingPeriod pins the timing half of the guard:
// a reveal before the commitment period has elapsed is refused, at the exact boundary.
func TestZzmpValidateCommitmentEnforcesTheWaitingPeriod(t *testing.T) {
	crv := &CommitRevealValidator{CommitmentPeriod: 5}
	commit := &CommittedSwap{CommitBlock: 100}

	for _, block := range []uint64{0, 100, 101, 104} {
		if err := crv.ValidateCommitment(commit, block); err == nil {
			t.Fatalf("reveal at block %d (committed at 100, period 5) must be refused", block)
		}
	}
	for _, block := range []uint64{105, 106, 1_000} {
		if err := crv.ValidateCommitment(commit, block); err != nil {
			t.Fatalf("reveal at block %d must be allowed, got %v", block, err)
		}
	}
	// A zero period is immediately revealable.
	if err := (&CommitRevealValidator{}).ValidateCommitment(commit, 100); err != nil {
		t.Fatalf("a zero commitment period must allow an immediate reveal, got %v", err)
	}
}
