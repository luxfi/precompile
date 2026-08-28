// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// module_config_test.go — the module/config surface, the calldata refusal paths, and
// the PRICE-vs-CHARGE relationship between RequiredGas (what the precompile advertises
// a call will cost) and Run (what it actually consumes).
//
// The gas tests here assert a RELATIONSHIP, never a number: gas constants are the
// operator's dial, and a test that pins them fails on a re-price instead of on a bug.
// The relationship that matters is
//
//	RequiredGas(input) >= gas Run consumes for that same input        (always)
//	RequiredGas(input) == gas Run consumes, for a WELL-FORMED frame   (tightness)
//
// Under-reporting is the unsafe direction — a host that deducts the advertised price
// up front would hand out the difference as free work. Over-reporting only wastes a
// caller's budget on a frame that was going to revert anyway.

package aivmbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/luxfi/crypto/poi"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
)

// --- fakes -------------------------------------------------------------------

// countingIntentStore is an IntentStore that COUNTS writes, so a refusal can be shown
// to have written nothing at all — not merely to have returned an error.
type countingIntentStore struct {
	status map[[32]byte]OutboxStatus
	writes int
}

func newCountingIntentStore() *countingIntentStore {
	return &countingIntentStore{status: make(map[[32]byte]OutboxStatus)}
}

func (s *countingIntentStore) IntentStatus(id [32]byte) OutboxStatus { return s.status[id] }

func (s *countingIntentStore) PutPendingIntent(id [32]byte, _ OutboxIntent) {
	s.writes++
	s.status[id] = OutboxPending
}

// scriptedVerifierState is a ReceiptVerifierState whose outbox record the test sets
// directly, so the verify core can be driven to states the real store never produces
// (an out-of-range status) and its single effect can be counted.
type scriptedVerifierState struct {
	roots    map[[32]byte]bool
	intent   OutboxIntent
	consumed int
}

func (v *scriptedVerifierState) ReceiptRootCommitted(r [32]byte) bool { return v.roots[r] }
func (v *scriptedVerifierState) LoadIntent([32]byte) OutboxIntent     { return v.intent }
func (v *scriptedVerifierState) MarkIntentConsumed([32]byte, uint64) {
	v.consumed++
	v.intent.Status = OutboxConsumed
}

// foreignConfig is another precompile's config type — a valid precompileconfig.Config
// that is not *aivmbridge.Config.
type foreignConfig struct{}

func (foreignConfig) Key() string                               { return "someOtherPrecompileConfig" }
func (foreignConfig) Timestamp() *uint64                        { return nil }
func (foreignConfig) IsDisabled() bool                          { return false }
func (foreignConfig) Verify(precompileconfig.ChainConfig) error { return nil }
func (foreignConfig) Equal(precompileconfig.Config) bool        { return false }

var (
	_ IntentStore             = (*countingIntentStore)(nil)
	_ ReceiptVerifierState    = (*scriptedVerifierState)(nil)
	_ precompileconfig.Config = foreignConfig{}
)

// --- shared Pattern-B fixture (no Run layer) ----------------------------------

// committedReceipt returns a receipt, a GENUINE inclusion proof for it, and a factory
// for a verifier state that has the proof's root committed and the bound intent pending.
// It is the smallest fully-consistent Pattern-B input, independent of the Run fixture.
func committedReceipt() (AInferenceReceipt, AInferenceProof, func() *scriptedVerifierState) {
	r := AInferenceReceipt{
		Version:             ReceiptVersion,
		IntentID:            h32(0x1D),
		TaskID:              h32(0x7A),
		CChainID:            h32(0xCC),
		AChainID:            h32(0xA0),
		Requester:           common.Address{0x42},
		ModelSpecHash:       h32(0x5E),
		PromptHash:          h32(0x9D),
		CanonicalOutputHash: h32(0x0F),
		Status:              StatusCompleted,
		N:                   3,
		Threshold:           2,
	}
	tree := buildMerkleTree([][32]byte{h32(0x01), ReceiptHash(r), h32(0x03)})
	p := tree.proof(1)
	newState := func() *scriptedVerifierState {
		return &scriptedVerifierState{
			roots: map[[32]byte]bool{p.ReceiptRoot: true},
			intent: OutboxIntent{
				Status:        OutboxPending,
				Caller:        r.Requester,
				CChainID:      r.CChainID,
				AChainID:      r.AChainID,
				ModelSpecHash: r.ModelSpecHash,
				PromptHash:    r.PromptHash,
				N:             r.N,
				Threshold:     r.Threshold,
				BlockNumber:   77,
			},
		}
	}
	return r, p, newState
}

// --- calldata builders used only here -----------------------------------------

// proofBytesOfDepth encodes a WELL-FORMED proof frame of the given path depth: the
// header's declared pathLen and the bytes that follow agree.
func proofBytesOfDepth(root [32]byte, depth int) []byte {
	p := AInferenceProof{ReceiptRoot: root, Path: make([][32]byte, depth)}
	for i := range p.Path {
		p.Path[i] = h32(byte(i + 1))
	}
	return encodeProof(p)
}

// proofBytesClaiming builds a path-FREE (42-byte) proof whose header DECLARES `declared`
// path nodes that are not present. This is the frame whose declared depth and actual
// length disagree.
func proofBytesClaiming(root [32]byte, declared uint16) []byte {
	b := proofBytesOfDepth(root, 0)
	binary.BigEndian.PutUint16(b[40:42], declared)
	return b
}

// verifyFrameDeclaring builds a verify frame whose DECLARED lengths differ from the
// bytes actually carried, so each framing position can be corrupted on its own.
func verifyFrameDeclaring(receipt, proof []byte, declRcpt, declProof uint16) []byte {
	out := encodeVerify(receipt, proof)
	binary.BigEndian.PutUint16(out[4:6], declRcpt)
	binary.BigEndian.PutUint16(out[6:8], declProof)
	return out
}

func receiptBytesWithVersion(r AInferenceReceipt, v uint16) []byte {
	b := EncodeReceipt(r)
	binary.BigEndian.PutUint16(b[0:2], v)
	return b
}

func computeFrame(opening []byte) []byte {
	in := make([]byte, 4+len(opening))
	putU32(in[0:4], SelectorVerifyComputeProof)
	copy(in[4:], opening)
	return in
}

// --- module registration + configurator ---------------------------------------

// The bridge must occupy its OWN slot in the AI range and must store its state under
// that same identity. A copy-pasted address would silently squat the AI-mining or the
// deterministic-inference precompile.
func TestModule_RegisteredAtItsOwnDisjointAddress(t *testing.T) {
	got, ok := modules.GetPrecompileModuleByAddress(ContractAddress)
	if !ok {
		t.Fatalf("init() left the bridge unregistered at %s", ContractAddress)
	}
	if got.ConfigKey != ConfigKey {
		t.Fatalf("registered under config key %q, want %q", got.ConfigKey, ConfigKey)
	}
	if got.Contract != BridgePrecompile {
		t.Fatal("the registered contract is not the bridge singleton")
	}
	if got.Configurator == nil {
		t.Fatal("the registered module carries no configurator")
	}
	if bridgeStateAddr != ContractAddress {
		t.Fatal("bridge state must live under the precompile's own address")
	}
	for _, taken := range []common.Address{
		common.HexToAddress("0x0300000000000000000000000000000000000000"), // AI mining
		common.HexToAddress("0x0300000000000000000000000000000000000003"), // deterministic inference
	} {
		if ContractAddress == taken {
			t.Fatalf("the bridge squats %s, an address another AI precompile owns", taken)
		}
	}
}

// MakeConfig must hand back a FRESH config each call — the host builds one per network
// upgrade entry and then fills it in; a shared instance would let one chain's upgrade
// timestamp leak into another's. Configure initializes no genesis state.
func TestConfigurator_MakeConfigIsFreshAndConfigureWritesNoState(t *testing.T) {
	cfgr := Module.Configurator

	a, ok := cfgr.MakeConfig().(*Config)
	if !ok || a == nil {
		t.Fatal("MakeConfig must return a non-nil *Config")
	}
	b, ok := cfgr.MakeConfig().(*Config)
	if !ok || b == nil {
		t.Fatal("MakeConfig must return a non-nil *Config")
	}
	if a == b {
		t.Fatal("MakeConfig handed back the same instance twice; two upgrade entries would alias")
	}
	if a.Key() != ConfigKey || a.IsDisabled() || a.Timestamp() != nil {
		t.Fatalf("a fresh config must be the zero upgrade under %q, got disabled=%v ts=%v",
			ConfigKey, a.IsDisabled(), a.Timestamp())
	}

	ts := uint64(99)
	a.Upgrade.BlockTimestamp = &ts
	a.Upgrade.Disable = true
	if b.Timestamp() != nil || b.IsDisabled() {
		t.Fatal("configs from MakeConfig share backing state")
	}

	db := newMemStateDB()
	if err := cfgr.Configure(nil, a, db, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if n := len(db.slots); n != 0 {
		t.Fatalf("Configure wrote %d storage accounts; the bridge has no genesis state", n)
	}
}

// The config's read surface is a pass-through onto the Upgrade it holds — a host that
// edits the upgrade sees the change, and Verify accepts every well-formed shape (the
// bridge takes no per-network parameters, so there is nothing to reject).
func TestConfig_SurfaceTracksTheUpgradeItHolds(t *testing.T) {
	var c Config
	if c.Key() != ConfigKey || c.Key() != Module.ConfigKey {
		t.Fatalf("Key() = %q, want %q (and it must match the registered module)", c.Key(), ConfigKey)
	}
	if c.Timestamp() != nil {
		t.Fatal("an unset upgrade must report no activation timestamp (never enabled)")
	}
	if c.IsDisabled() {
		t.Fatal("an unset upgrade is not a disable")
	}
	if err := c.Verify(nil); err != nil {
		t.Fatalf("Verify rejected the zero config: %v", err)
	}

	for _, want := range []uint64{0, 1, 1 << 40} {
		v := want
		c.Upgrade.BlockTimestamp = &v
		got := c.Timestamp()
		if got == nil || *got != want {
			t.Fatalf("Timestamp() = %v, want %d", got, want)
		}
	}

	c.Upgrade.Disable = true
	if !c.IsDisabled() {
		t.Fatal("IsDisabled() must follow Upgrade.Disable")
	}
	if err := c.Verify(nil); err != nil {
		t.Fatalf("Verify must accept a disabling config too: %v", err)
	}
}

// Equal must react to EVERY field it is supposed to compare, in both directions. The
// reflection guards make a newly-added field a loud failure here instead of a silently
// ignored one at the comparison site.
func TestConfig_EqualComparesEveryField(t *testing.T) {
	if n := reflect.TypeOf(Config{}).NumField(); n != 1 {
		t.Fatalf("Config has %d fields but Equal only forwards Upgrade — extend Equal and this test", n)
	}
	if n := reflect.TypeOf(precompileconfig.Upgrade{}).NumField(); n != 2 {
		t.Fatalf("Upgrade has %d fields but this test mutates 2 — extend the mutator list", n)
	}

	ptr := func(v uint64) *uint64 { return &v }

	mutators := []struct {
		field  string
		mutate func(*Config)
	}{
		{"Upgrade.BlockTimestamp", func(c *Config) { c.Upgrade.BlockTimestamp = ptr(7) }},
		{"Upgrade.Disable", func(c *Config) { c.Upgrade.Disable = true }},
	}

	for _, m := range mutators {
		t.Run(m.field, func(t *testing.T) {
			a, b := &Config{}, &Config{}
			if !a.Equal(b) || !b.Equal(a) {
				t.Fatal("two zero configs must compare equal")
			}
			m.mutate(b)
			if a.Equal(b) {
				t.Fatalf("Equal ignored %s", m.field)
			}
			if b.Equal(a) {
				t.Fatalf("Equal ignored %s in the reverse direction", m.field)
			}
			// Applying the SAME mutation to both restores equality — so Equal reacted to
			// the difference, not merely to the mutated value.
			m.mutate(a)
			if !a.Equal(b) || !b.Equal(a) {
				t.Fatalf("Equal is not symmetric after both sides took %s", m.field)
			}
		})
	}

	t.Run("timestamp compares by value not pointer", func(t *testing.T) {
		a := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(9)}}
		b := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(9)}}
		if !a.Equal(b) || !b.Equal(a) {
			t.Fatal("distinct pointers holding the same timestamp must compare equal")
		}
		c := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: ptr(10)}}
		if a.Equal(c) || c.Equal(a) {
			t.Fatal("different timestamps must not compare equal")
		}
		// nil and set are distinguishable in both directions.
		z := &Config{}
		if a.Equal(z) || z.Equal(a) {
			t.Fatal("an unset timestamp must not equal a set one")
		}
	})

	t.Run("foreign type and nil", func(t *testing.T) {
		a := &Config{}
		if a.Equal(foreignConfig{}) {
			t.Fatal("Equal accepted another precompile's config type")
		}
		if a.Equal(&foreignConfig{}) {
			t.Fatal("Equal accepted a pointer to another precompile's config type")
		}
		if a.Equal(nil) {
			t.Fatal("Equal accepted a nil config")
		}
	})
}

// --- RequiredGas vs what Run charges ------------------------------------------

// The price the precompile advertises must never be BELOW what Run consumes for the
// same bytes (that direction hands out free work), and for a frame Run actually
// decodes it must be EXACT (drift either way is an accounting bug).
func TestRequiredGas_NeverBelowWhatRunCharges(t *testing.T) {
	seed := newVerifyFixture(t)
	root := seed.proof.ReceiptRoot
	receipt := EncodeReceipt(seed.receipt)

	type frame struct {
		name  string
		in    []byte
		exact bool // Run decodes this frame, so the advertised price must match exactly
	}
	frames := []frame{
		{"submit", encodeSubmit(h32(0x11), h32(0x22), 3, 2, feeWord(5), [32]byte{}), true},
		{"compute proof, honest opening", computeFrame(buildOpening(false)), true},
		{"compute proof, undecodable", computeFrame([]byte{1, 2, 3, 4, 5}), true},
		// A frame Run refuses before it can meter anything: it returns the whole budget,
		// so charged is 0 and only the >= half of the invariant is meaningful.
		{"unknown selector", []byte{0xFF, 0xFF, 0xFF, 0xFF}, false},
		{"below the selector", []byte{0x11, 0x00}, false},
		// A verify frame whose declared proof length is under the 42-byte proof header.
		{"proof shorter than its header", encodeVerify(receipt, make([]byte, 10)), true},
		// A verify frame whose receipt does not decode: the proof is well formed, so the
		// advertised price includes the merkle walk that Run never performs.
		{"undecodable receipt", encodeVerify(receiptBytesWithVersion(seed.receipt, ReceiptVersion+1), proofBytesOfDepth(root, 2)), false},
		// The frame LIES about its depth: 42 proof bytes, header claiming MaxProofDepth.
		{"proof header lies about depth", encodeVerify(receipt, proofBytesClaiming(root, MaxProofDepth)), false},
		{"proof header lies by one node", encodeVerify(receipt, proofBytesClaiming(root, 1)), false},
		{"declared depth over the cap", encodeVerify(receipt, proofBytesClaiming(root, MaxProofDepth+1)), true},
	}
	// Every WELL-FORMED depth, including both sides of the cap boundary.
	for _, d := range []int{0, 1, 2, 3, 17, MaxProofDepth - 1, MaxProofDepth} {
		frames = append(frames, frame{
			name:  "well-formed proof depth " + strconv.Itoa(d),
			in:    encodeVerify(receipt, proofBytesOfDepth(root, d)),
			exact: true,
		})
	}

	for _, f := range frames {
		t.Run(f.name, func(t *testing.T) {
			fx := newVerifyFixture(t)
			charged, advertised, _ := chargedGas(t, fx.st, fx.caller, f.in)
			if advertised < charged {
				t.Fatalf("UNDER-PRICED: RequiredGas advertised %d, Run consumed %d — %d gas of work for free",
					advertised, charged, charged-advertised)
			}
			if f.exact && advertised != charged {
				t.Fatalf("price drift on a frame Run decodes: advertised %d, charged %d", advertised, charged)
			}
			if advertised != charged {
				t.Logf("over-priced by %d (advertised %d, charged %d) — safe direction", advertised-charged, advertised, charged)
			}
		})
	}
}

// REGRESSION. module.go prices verifyInferenceReceipt from the pathLen the CALLER
// DECLARES in the proof header (module.go:124) without checking it against the proof's
// actual byte length; bridge.go prices from the DERIVED len(p.Path) after DecodeProof
// has enforced len(proof) == 42 + pathLen*32 (proof.go:118-126). A 42-byte proof whose
// header claims MaxProofDepth therefore advertises the deepest possible walk while Run
// bails at decode and charges only the base.
//
// The direction is what matters. Over-pricing (advertised > charged) only wastes the
// caller's own budget on a frame that reverts anyway. UNDER-pricing would be the bug:
// a host that deducts the advertised price up front would execute the difference for
// free. This test pins the direction, not the size of the gap, so it keeps holding if
// the cross-check is added and the gap closes to zero.
func TestRequiredGas_DeclaredDepthIsNotCheckedAgainstProofLength(t *testing.T) {
	fx := newVerifyFixture(t)
	receipt := EncodeReceipt(fx.receipt)
	root := fx.proof.ReceiptRoot

	lying := encodeVerify(receipt, proofBytesClaiming(root, MaxProofDepth))
	charged, advertised, err := chargedGas(t, fx.st, fx.caller, lying)
	if !errors.Is(err, ErrProofDecode) {
		t.Fatalf("a proof whose header contradicts its length must be refused, got %v", err)
	}
	if advertised < charged {
		t.Fatalf("UNDER-PRICED: advertised %d < charged %d", advertised, charged)
	}
	t.Logf("declared-depth frame: advertised %d, charged %d, slack %d", advertised, charged, advertised-charged)

	// The honest frame at the same declared depth prices identically to what Run
	// charges — so the slack above comes from the missing cross-check, not from the
	// depth pricing itself.
	honestFx := newVerifyFixture(t)
	honest := encodeVerify(receipt, proofBytesOfDepth(root, MaxProofDepth))
	honestCharged, honestAdvertised, err := chargedGas(t, honestFx.st, honestFx.caller, honest)
	if !errors.Is(err, ErrMerkleVerify) {
		t.Fatalf("the honest deep frame must reach the merkle check, got %v", err)
	}
	if honestAdvertised != honestCharged {
		t.Fatalf("a well-formed deep frame must be priced exactly: advertised %d, charged %d",
			honestAdvertised, honestCharged)
	}
	if honestAdvertised != advertised {
		t.Fatalf("the lying frame and the honest frame of the same declared depth priced differently (%d vs %d)",
			advertised, honestAdvertised)
	}
	t.Logf("honest frame at the same declared depth: advertised == charged == %d", honestAdvertised)
}

// --- selector routing ----------------------------------------------------------

// The compute-proof selector routes to the native proof-of-inference check, and that
// check is PURE: it writes no C state, so it is legal inside a static call.
func TestRun_RoutesComputeProofAndStaysPureUnderStaticCall(t *testing.T) {
	st := newMockState(common.HexToHash("0xC0DE"))
	caller := common.Address{0x1}

	for _, tc := range []struct {
		name    string
		in      []byte
		verdict byte
	}{
		{"honest opening", computeFrame(buildOpening(false)), resultIncluded | resultFreivaldsOK},
		{"fabricated output", computeFrame(buildOpening(true)), resultIncluded},
	} {
		advertised := BridgePrecompile.RequiredGas(tc.in)
		if advertised <= GasVerifyComputeProofBase {
			t.Fatalf("%s: a real opening must price above the base, got %d", tc.name, advertised)
		}
		for _, readOnly := range []bool{false, true} {
			ret, rem, err := BridgePrecompile.Run(st, caller, ContractAddress, tc.in, advertised, readOnly)
			if err != nil {
				t.Fatalf("%s readOnly=%v: %v", tc.name, readOnly, err)
			}
			if len(ret) != 32 {
				t.Fatalf("%s: verdict must be one word, got %d bytes", tc.name, len(ret))
			}
			if ret[31] != tc.verdict {
				t.Fatalf("%s: verdict = %d, want %d", tc.name, ret[31], tc.verdict)
			}
			if rem != 0 {
				t.Fatalf("%s: the advertised price must be exactly consumed, %d left", tc.name, rem)
			}
		}
	}
	if n := len(st.db.slots); n != 0 {
		t.Fatalf("compute-proof verification wrote %d storage accounts; it must touch no state", n)
	}

	// An undecodable opening prices at the base and reverts there.
	garbage := computeFrame([]byte{1, 2, 3})
	if g := BridgePrecompile.RequiredGas(garbage); g != GasVerifyComputeProofBase {
		t.Fatalf("an undecodable opening must price at the base, got %d", g)
	}
	if _, _, err := BridgePrecompile.Run(st, caller, ContractAddress, garbage, GasVerifyComputeProofBase, false); err == nil {
		t.Fatal("an undecodable opening must revert")
	}
}

// --- the fixed-width word decoder ----------------------------------------------

// readUint16Word takes the value from the low two bytes and refuses anything smuggled
// above the declared width. Every high byte is checked one at a time, so a loop that
// stops early is caught.
func TestReadUint16Word_RefusesShortAndDirtyWords(t *testing.T) {
	for _, n := range []int{0, 1, 30, 31} {
		if _, err := readUint16Word(make([]byte, n)); !errors.Is(err, ErrInputTooShort) {
			t.Fatalf("a %d-byte word must be refused, not zero-extended: %v", n, err)
		}
	}

	for _, want := range []uint16{0, 1, 255, 256, 0xFF00, 0xFFFF} {
		w := make([]byte, 32)
		binary.BigEndian.PutUint16(w[30:32], want)
		got, err := readUint16Word(w)
		if err != nil || got != want {
			t.Fatalf("value %d: got %d, err %v", want, got, err)
		}
	}

	for i := 0; i < 30; i++ {
		w := make([]byte, 32)
		binary.BigEndian.PutUint16(w[30:32], 0x2A)
		w[i] = 0x01
		if _, err := readUint16Word(w); !errors.Is(err, ErrDirtyWord) {
			t.Fatalf("a non-zero byte at high position %d was not refused: %v", i, err)
		}
	}

	// The decoder is bounded to the first word: bytes past 32 are neither read as value
	// nor treated as dirt.
	long := make([]byte, 64)
	binary.BigEndian.PutUint16(long[30:32], 7)
	for i := 32; i < 64; i++ {
		long[i] = 0xFF
	}
	got, err := readUint16Word(long)
	if err != nil || got != 7 {
		t.Fatalf("a longer slice must read only its first word: got %d, err %v", got, err)
	}
}

// The threshold word is hardened exactly like the N word: a caller cannot smuggle bits
// above the declared uint16, and the refusal happens before any state is written.
func TestSubmit_RefusesDirtyThresholdWord(t *testing.T) {
	installNative(t, h32(0xA0), nil)
	good := encodeSubmit(h32(0x11), h32(0x22), 3, 2, feeWord(5), [32]byte{})
	caller := common.Address{0x1}

	// The threshold word is args[96:128], i.e. input[100:132]; its high bytes are
	// input[100:130].
	for _, off := range []int{100, 115, 129} {
		in := append([]byte(nil), good...)
		in[off] = 0x01
		st := newMockState(common.HexToHash("0x02"))
		_, _, err := BridgePrecompile.Run(st, caller, ContractAddress, in, BridgePrecompile.RequiredGas(in), false)
		if !errors.Is(err, ErrDirtyWord) {
			t.Fatalf("dirty byte at input[%d]: err = %v, want %v", off, err, ErrDirtyWord)
		}
		if n := len(st.db.slots); n != 0 {
			t.Fatalf("dirty byte at input[%d]: a refused submit wrote %d storage accounts", off, n)
		}
	}

	// Control: the clean frame still submits, so the refusals above are not vacuous.
	st := newMockState(common.HexToHash("0x03"))
	if _, _, err := BridgePrecompile.Run(st, caller, ContractAddress, good, BridgePrecompile.RequiredGas(good), false); err != nil {
		t.Fatalf("the clean frame must submit: %v", err)
	}
}

// --- verify framing refusals ---------------------------------------------------

// Every framing position is exact: a declared length that disagrees with the bytes
// carried is refused, and so is a payload that does not decode. No refusal may consume
// the pending intent.
func TestVerify_RefusesEveryFramingMismatch(t *testing.T) {
	// Control first, on its own fixture, so "refused" below is a real distinction.
	ctrl := newVerifyFixture(t)
	if _, err := ctrl.run(t, ctrl.receipt, ctrl.proof); err != nil {
		t.Fatalf("the well-formed frame must verify: %v", err)
	}

	f := newVerifyFixture(t)
	receipt := EncodeReceipt(f.receipt)
	proof := encodeProof(f.proof)
	rl, pl := uint16(len(receipt)), uint16(len(proof))
	root := f.proof.ReceiptRoot

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"args below the 4-byte header", encodeVerify(receipt, proof)[:4+3], ErrInputTooShort},
		{"receiptLen one short", verifyFrameDeclaring(receipt, proof, rl-1, pl), ErrInputOversized},
		{"receiptLen one long", verifyFrameDeclaring(receipt, proof, rl+1, pl), ErrInputOversized},
		{"receiptLen zero", verifyFrameDeclaring(receipt, proof, 0, pl), ErrInputOversized},
		{"proofLen one short", verifyFrameDeclaring(receipt, proof, rl, pl-1), ErrInputOversized},
		{"proofLen one long", verifyFrameDeclaring(receipt, proof, rl, pl+1), ErrInputOversized},
		{"trailing junk", append(encodeVerify(receipt, proof), 0xAA), ErrInputOversized},
		{"receipt truncated", encodeVerify(receipt[:len(receipt)-1], proof), ErrReceiptDecode},
		{"receipt one byte long", encodeVerify(append(append([]byte(nil), receipt...), 0x00), proof), ErrReceiptDecode},
		{"receipt version unknown", encodeVerify(receiptBytesWithVersion(f.receipt, ReceiptVersion+1), proof), ErrReceiptDecode},
		{"proof below its header", encodeVerify(receipt, proof[:41]), ErrProofDecode},
		{"proof header lies about depth", encodeVerify(receipt, proofBytesClaiming(root, MaxProofDepth)), ErrProofDecode},
		{"proof depth over the cap", encodeVerify(receipt, proofBytesClaiming(root, MaxProofDepth+1)), ErrProofDecode},
		{"proof carries an extra node", encodeVerify(receipt, append(append([]byte(nil), proof...), make([]byte, 32)...)), ErrProofDecode},
	}

	store := newStateKVStore(f.st.db, f.st.blockNumber)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gas := BridgePrecompile.RequiredGas(tc.in)
			_, rem, err := BridgePrecompile.Run(f.st, f.caller, ContractAddress, tc.in, gas, false)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if rem > gas {
				t.Fatalf("a refusal returned more gas than it was given (%d > %d)", rem, gas)
			}
			if got := store.IntentStatus(f.intentID); got != OutboxPending {
				t.Fatalf("a refused verify moved the intent to status %d; it must stay pending", got)
			}
		})
	}

	// After every refusal the intent still settles on a well-formed frame.
	if _, err := f.run(t, f.receipt, f.proof); err != nil {
		t.Fatalf("the intent must still be settleable after the refusals: %v", err)
	}
}

// --- merkle ---------------------------------------------------------------------

// VerifyMerkle answers false — it never errors and never panics — for a path that does
// not reconstruct the root, and it refuses a path deeper than MaxProofDepth even when
// that path WOULD reconstruct the declared root.
func TestVerifyMerkle_RefusesOverDepthAndNonReconstructingPath(t *testing.T) {
	leaves := [][32]byte{h32(0x01), h32(0x02), h32(0x03), h32(0x04), h32(0x05)}
	tree := buildMerkleTree(leaves)
	leaf := leafHash(h32(0x03))
	p := tree.proof(2)

	if !VerifyMerkle(leaf, p) {
		t.Fatal("a genuine proof must verify")
	}
	for i := range p.Path {
		bad := AInferenceProof{ReceiptRoot: p.ReceiptRoot, Index: p.Index, Path: append([][32]byte(nil), p.Path...)}
		bad.Path[i][0] ^= 0xFF
		if VerifyMerkle(leaf, bad) {
			t.Fatalf("a corrupted sibling at level %d still reconstructed the root", i)
		}
	}
	if VerifyMerkle(leafHash(h32(0x99)), p) {
		t.Fatal("a leaf that is not in the tree must not verify under a genuine path")
	}
	if VerifyMerkle(leaf, AInferenceProof{ReceiptRoot: h32(0xEE), Index: p.Index, Path: p.Path}) {
		t.Fatal("a genuine path must not verify against a different root")
	}

	// fold builds a path of n siblings and the root it reconstructs to, with every index
	// bit zero (leaf stays the LEFT child at every level).
	fold := func(n int) AInferenceProof {
		node := leaf
		path := make([][32]byte, n)
		for i := range path {
			path[i] = h32(byte(i + 1))
			node = hashPair(node, path[i])
		}
		return AInferenceProof{ReceiptRoot: node, Path: path, Index: 0}
	}
	if !VerifyMerkle(leaf, fold(MaxProofDepth)) {
		t.Fatal("a path of exactly MaxProofDepth must be accepted — the cap is inclusive")
	}
	if VerifyMerkle(leaf, fold(MaxProofDepth+1)) {
		t.Fatal("a path past MaxProofDepth must be refused even though it folds to the declared root")
	}
}

// --- the A-Chain on-ramp handle -------------------------------------------------

// With no on-ramp wired, Pattern A refuses cleanly and writes nothing, while Pattern B
// keeps working — verifying a committed receipt against committed C state never needs A.
func TestAChainUnavailable_RefusesSubmitButStillVerifies(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)

	c := currentAChainClient()
	if c.Brand() == "" {
		t.Fatal("even the closed on-ramp must name itself; InstallAChainClient refuses an empty brand")
	}
	if !isZero32(c.AChainID()) {
		t.Fatal("the closed on-ramp declares no rail peer")
	}

	store := newCountingIntentStore()
	id, err := c.SubmitInferenceIntent(context.Background(), store, InferenceIntent{ModelSpecHash: h32(0x11)})
	if !errors.Is(err, ErrAChainUnavailable) {
		t.Fatalf("submit with no on-ramp: err = %v, want %v", err, ErrAChainUnavailable)
	}
	if !isZero32(id) {
		t.Fatal("a refused submit must not mint an id")
	}
	if store.writes != 0 {
		t.Fatalf("a refused submit wrote the outbox %d times", store.writes)
	}

	r, p, newState := committedReceipt()
	direct, indirect := newState(), newState()
	wantV, wantErr := verifyInferenceReceipt(direct, r, p)
	if wantErr != nil {
		t.Fatalf("the fixture receipt must verify: %v", wantErr)
	}
	gotV, gotErr := c.VerifyInferenceReceipt(context.Background(), indirect, r, p)
	if gotErr != nil || gotV != wantV {
		t.Fatalf("the closed on-ramp's verify diverged from the state core: (%v, %v) vs (%v, %v)",
			gotV, gotErr, wantV, wantErr)
	}
	if direct.consumed != 1 || indirect.consumed != 1 {
		t.Fatalf("a verified receipt consumes its intent exactly once (direct %d, via client %d)",
			direct.consumed, indirect.consumed)
	}
}

// The singleton is never dereferenced blind: an unset pointer resolves to the closed
// on-ramp, so a Run() in flight reverts instead of panicking.
func TestCurrentAChainClient_UnsetPointerYieldsTheClosedOnRamp(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)

	aChainClient.Store(nil)

	c := currentAChainClient()
	if c == nil {
		t.Fatal("currentAChainClient returned nil")
	}
	if c.Brand() == "" || !isZero32(c.AChainID()) {
		t.Fatal("an unset singleton must resolve to the closed on-ramp")
	}
	if _, err := c.SubmitInferenceIntent(context.Background(), newCountingIntentStore(), InferenceIntent{}); !errors.Is(err, ErrAChainUnavailable) {
		t.Fatalf("an unset singleton must refuse Pattern A: %v", err)
	}

	st := newMockState(common.HexToHash("0xFEED"))
	in := encodeSubmit(h32(0x11), h32(0x22), 1, 1, feeWord(1), [32]byte{})
	if _, _, err := BridgePrecompile.Run(st, common.Address{0x1}, ContractAddress, in, BridgePrecompile.RequiredGas(in), false); !errors.Is(err, ErrAChainUnavailable) {
		t.Fatalf("Run against an unset singleton: %v", err)
	}
	if n := len(st.db.slots); n != 0 {
		t.Fatalf("a refused submit wrote %d storage accounts", n)
	}
}

// --- the staged native client ---------------------------------------------------

// A host that passes no white-label name still gets an INSTALLABLE client, and an
// explicit brand survives verbatim.
func TestNativeClient_BrandDefaultsToSomethingInstallable(t *testing.T) {
	resetAChainClientForTest()
	t.Cleanup(resetAChainClientForTest)

	def := NewNativeAChainClient("", h32(0xA0), nil)
	if def.Brand() == "" {
		t.Fatal("an empty brand must fall back to a non-empty default")
	}
	if def.Brand() == (achainUnavailable{}).Brand() {
		t.Fatal("a wired client must be distinguishable from the closed on-ramp in a log line")
	}
	if err := InstallAChainClient(def); err != nil {
		t.Fatalf("a default-branded client must be installable: %v", err)
	}

	named := NewNativeAChainClient("Hanzo Inference", h32(0xA1), nil)
	if named.Brand() != "Hanzo Inference" {
		t.Fatalf("an explicit brand must survive verbatim, got %q", named.Brand())
	}
	if named.AChainID() != h32(0xA1) {
		t.Fatal("the client must report the rail peer it was constructed with")
	}
}

// The client binds its OWN rail peer into the derived id (a caller cannot mint an id
// for another rail), and the outbox is append-once.
func TestNativeClient_BindsItsRailAndWritesOnce(t *testing.T) {
	c := NewNativeAChainClient("Lux Inference", h32(0xA0), nil)
	store := newCountingIntentStore()

	in := InferenceIntent{
		CChainID:        h32(0xCC),
		AChainID:        h32(0xBB), // a rail the caller asked for; the client overrides it
		CTxHash:         h32(0x7A),
		CallIndex:       1,
		Caller:          common.Address{0x9},
		ModelSpecHash:   h32(0x5E),
		ModelPromptHash: h32(0x9D),
		N:               3,
		Threshold:       2,
		Fee:             feeWord(5),
	}
	bound := in
	bound.AChainID = h32(0xA0)

	id, err := c.SubmitInferenceIntent(context.Background(), store, in)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if id != DeriveIntentID(bound) {
		t.Fatal("the client must bind its own rail peer into the id, not the caller's")
	}
	if store.writes != 1 || store.IntentStatus(id) != OutboxPending {
		t.Fatalf("one committed pending record expected, got %d writes / status %d", store.writes, store.IntentStatus(id))
	}

	id2, err := c.SubmitInferenceIntent(context.Background(), store, in)
	if !errors.Is(err, ErrIntentReplay) {
		t.Fatalf("a second submit of the same intent: err = %v, want %v", err, ErrIntentReplay)
	}
	if !isZero32(id2) {
		t.Fatal("a refused replay must not return an id")
	}
	if store.writes != 1 {
		t.Fatalf("the replay wrote the outbox again (%d writes)", store.writes)
	}

	// A client on a different rail derives a different id from the same intent, so the
	// first rail's record does not block it.
	other := NewNativeAChainClient("Lux Inference", h32(0xA2), nil)
	id3, err := other.SubmitInferenceIntent(context.Background(), store, in)
	if err != nil {
		t.Fatalf("submit on a second rail: %v", err)
	}
	if id3 == id {
		t.Fatal("two rails must not share an intent id")
	}
	if store.writes != 2 {
		t.Fatalf("the second rail must write its own record, got %d writes", store.writes)
	}
}

// Pattern B on the native client is the package's state core, nothing more — same
// result, same single effect, same double-consume refusal.
func TestNativeClient_VerifyIsTheStateCore(t *testing.T) {
	r, p, newState := committedReceipt()
	c := NewNativeAChainClient("Lux Inference", h32(0xA0), nil)

	direct, viaClient := newState(), newState()
	wantV, wantErr := verifyInferenceReceipt(direct, r, p)
	if wantErr != nil {
		t.Fatalf("the fixture receipt must verify: %v", wantErr)
	}
	gotV, gotErr := c.VerifyInferenceReceipt(context.Background(), viaClient, r, p)
	if gotErr != nil || gotV != wantV {
		t.Fatalf("client verify diverged from the core: (%v, %v) vs (%v, %v)", gotV, gotErr, wantV, wantErr)
	}
	if viaClient.consumed != 1 {
		t.Fatalf("verify must consume the intent exactly once, got %d", viaClient.consumed)
	}
	if _, err := c.VerifyInferenceReceipt(context.Background(), viaClient, r, p); !errors.Is(err, ErrIntentConsumed) {
		t.Fatalf("a second verify: err = %v, want %v", err, ErrIntentConsumed)
	}
	if viaClient.consumed != 1 {
		t.Fatalf("a refused second verify consumed again (%d)", viaClient.consumed)
	}
}

// --- the verify core's outbox status switch --------------------------------------

// Only a PENDING outbox record settles. Anything else — absent, already consumed, or a
// value the store should never hold — refuses and leaves the record alone.
func TestVerify_OnlyPendingSettles(t *testing.T) {
	r, p, newState := committedReceipt()

	for _, tc := range []struct {
		status OutboxStatus
		want   error
	}{
		{OutboxNone, ErrNoMatchingIntent},
		{OutboxConsumed, ErrIntentConsumed},
		{OutboxStatus(3), ErrNoMatchingIntent},
		{OutboxStatus(255), ErrNoMatchingIntent},
	} {
		s := newState()
		s.intent.Status = tc.status
		v, err := verifyInferenceReceipt(s, r, p)
		if !errors.Is(err, tc.want) {
			t.Fatalf("outbox status %d: err = %v, want %v", tc.status, err, tc.want)
		}
		if v != (VerifiedAInferenceReceipt{}) {
			t.Fatalf("outbox status %d: a refusal must return the zero result", tc.status)
		}
		if s.consumed != 0 {
			t.Fatalf("outbox status %d: a refusal consumed the intent", tc.status)
		}
	}

	s := newState()
	if _, err := verifyInferenceReceipt(s, r, p); err != nil {
		t.Fatalf("a pending record must settle: %v", err)
	}
	if s.consumed != 1 {
		t.Fatalf("a settled record must be consumed once, got %d", s.consumed)
	}
}

// --- the A->C receipt-root checkpoint --------------------------------------------

// A zero root is never committed (the empty slot already reads as zero, so accepting it
// would make an unwritten root indistinguishable from a trusted one), and a root
// committed at height ZERO must still read as committed.
func TestCommitReceiptRoot_RefusesZeroAndRecordsHeightZero(t *testing.T) {
	db := newMemStateDB()
	s := newStateKVStore(db, 5)

	CommitReceiptRoot(db, [32]byte{}, 9)
	if n := len(db.slots); n != 0 {
		t.Fatalf("committing the zero root wrote %d storage accounts", n)
	}
	if s.ReceiptRootCommitted([32]byte{}) {
		t.Fatal("the zero root must never read as committed")
	}

	root := h32(0x77)
	if s.ReceiptRootCommitted(root) {
		t.Fatal("an unwritten root must not read as committed")
	}
	CommitReceiptRoot(db, root, 0)
	if !s.ReceiptRootCommitted(root) {
		t.Fatal("a root committed at height 0 must read as committed")
	}
	if s.ReceiptRootCommitted(h32(0x78)) {
		t.Fatal("a root that was never committed must not read as committed")
	}

	// Re-committing at a later height keeps it committed (the seam may see the same root
	// twice across an import replay).
	CommitReceiptRoot(db, root, 1_000)
	if !s.ReceiptRootCommitted(root) {
		t.Fatal("re-committing a root must not un-commit it")
	}
}

// --- the native proof-of-inference check ------------------------------------------

// An opening that decodes is priced from its decoded dimensions; one gas below that
// price is refused outright rather than half-executed, and an opening whose matrices
// cannot be multiplied is refused instead of yielding a verdict.
func TestComputeProof_RefusesUnderfundedAndUnmultipliableOpenings(t *testing.T) {
	honest := buildOpening(false)
	cost := computeProofRequiredGas(honest)
	if cost <= GasVerifyComputeProofBase {
		t.Fatalf("a real opening must price above the base, got %d", cost)
	}

	if _, rem, err := verifyComputeProof(honest, cost-1); err == nil {
		t.Fatal("an opening priced above the supplied gas must be refused")
	} else if rem != 0 {
		t.Fatalf("an out-of-gas refusal must leave no gas, got %d", rem)
	}
	if _, rem, err := verifyComputeProof(honest, cost); err != nil || rem != 0 {
		t.Fatalf("exactly the priced cost must succeed and consume all of it: rem %d, err %v", rem, err)
	}

	// A.Cols(3) != B.Rows(4): every matrix is individually well formed, so the frame
	// DECODES, but the product is undefined.
	mismatched := poi.EncodeOpening([32]byte{0x11}, []byte("beacon"), poi.Opening{
		Index: 0,
		A:     poi.NewMat(2, 3, make([]int64, 6)),
		B:     poi.NewMat(4, 5, make([]int64, 20)),
		C:     poi.NewMat(2, 5, make([]int64, 10)),
	})
	misCost := computeProofRequiredGas(mismatched)
	if misCost <= GasVerifyComputeProofBase {
		t.Fatalf("a decodable opening must price above the base, got %d", misCost)
	}
	ret, rem, err := verifyComputeProof(mismatched, misCost)
	if err == nil {
		t.Fatal("an opening whose matrices cannot be multiplied must error, not return a verdict")
	}
	if ret != nil {
		t.Fatal("a refusal must return no verdict word")
	}
	if rem != 0 {
		t.Fatalf("a decoded-then-refused opening consumes its priced cost, %d left", rem)
	}

	if g := computeProofRequiredGas([]byte{1, 2, 3}); g != GasVerifyComputeProofBase {
		t.Fatalf("an undecodable frame must price at the base, got %d", g)
	}
}
