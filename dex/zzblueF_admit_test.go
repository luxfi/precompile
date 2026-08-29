// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/vm/chains/atomic"
)

// zzblueF_admit_test.go pins the ADMISSION and ATTESTATION gates of 0x9999: the
// live-code asset verifier (asset_onchain_verifier.go), the process-global resolver
// latch (asset_resolver.go), the broker fill attestation lifecycle
// (fill_attestation.go), the cross-domain staging window (native_staging.go), and
// the arithmetic domain boundaries the swap path sits on.
//
// Every gate here is pinned by what it REFUSES. An admission check that is only
// exercised on its happy path proves nothing: the property is "a fabricated asset
// cannot trade", "a resolver bound to another chain cannot be installed", "a staged
// object is consumed exactly once", and each of those is a statement about a
// refusal.

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

// blueFPoisoned returns b backed by an array whose spare capacity is filled with
// 0xA5, modelling the attacker-controlled EVM memory that sits past a precompile
// input in production (geth hands Run the two-index slice m.store[off:off+size], so
// cap(input) is the rest of memory). A read past len does not panic there — it
// silently returns bytes the caller chose. A handler that bounds on len yields the
// same verdict for a poisoned input as for a clean one.
func blueFPoisoned(b []byte, spare int) []byte {
	full := make([]byte, len(b)+spare)
	for i := range full {
		full[i] = 0xA5
	}
	copy(full, b)
	return full[:len(b)]
}

// blueFPlainState is a dex.StateDB with NO code-size capability: it embeds the
// StateDB INTERFACE, so only StateDB's own methods are promoted and CodeSizeOf is
// not among them. It models a host that cannot answer EXTCODESIZE, which must make
// the value path fail closed rather than admit an unproven asset.
type blueFPlainState struct{ StateDB }

// blueFNoCodeStateDB is a contract.StateDB with NO GetCodeSize: same embedding
// trick, one level down. A poolStateAdapter over it reports CodeSizeOf == -1, which
// codeStaterFor must read as "not code-capable" (fail closed), never as "every
// address has zero code" (which would refuse even the native coin).
type blueFNoCodeStateDB struct{ contract.StateDB }

// blueFPlainEnv is a precompile environment with no Call surface — the non-DEX
// precompile case the ERC-20 seam must refuse rather than sub-call.
type blueFPlainEnv struct{}

func (blueFPlainEnv) ReadOnly() bool { return false }

// blueFCallEnv is a scriptable Call surface: it records the last sub-call and
// returns the programmed (ret, err), so the ERC-20 legs' fail-secure arms can be
// driven directly.
type blueFCallEnv struct {
	ret      []byte
	err      error
	gasLeft  uint64
	lastAddr common.Address
	lastIn   []byte
	calls    int
}

func (e *blueFCallEnv) ReadOnly() bool { return false }

func (e *blueFCallEnv) Call(addr common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	e.calls++
	e.lastAddr = addr
	e.lastIn = append([]byte(nil), input...)
	return e.ret, e.gasLeft, e.err
}

// blueFEnvState is a contract.AccessibleState that hands back a chosen precompile
// environment, so the adapter's callable() resolution can be driven across all
// three of its arms (no accessible state / nil env / non-callable env).
type blueFEnvState struct {
	contract.AccessibleState
	env contract.PrecompileEnvironment
}

func (s *blueFEnvState) GetPrecompileEnv() contract.PrecompileEnvironment { return s.env }

// blueFIsolateResolver takes the process-global asset-resolver latch private to the
// calling test: it saves the prior value, restores it on cleanup, and clears the
// latch FIRST so this test's install cannot be refused by whatever identity a
// previous test left installed. Every test in this file that touches
// installedAssetResolver calls this before it mutates.
func blueFIsolateResolver(t *testing.T) {
	t.Helper()
	prev := installedAssetResolver.Load()
	t.Cleanup(func() { installedAssetResolver.Store(prev) })
	installedAssetResolver.Store(nil)
}

// blueFTestResolver is a minimal permissionless dexcore.AssetResolver: it resolves
// any well-formed reference and never carries a membership set, so admission is
// decided by the on-chain code proof alone.
type blueFTestResolver struct {
	networkID uint32
	chainID   ids.ID
}

func (r *blueFTestResolver) ResolveAsset(kind dexcore.AssetKind, ref []byte) (ids.ID, uint8, error) {
	id, err := dexcore.DeriveAssetID(r.networkID, r.chainID, kind, ref)
	if err != nil {
		return ids.Empty, 0, err
	}
	if kind == dexcore.AssetKindEVMNative {
		return id, 18, nil
	}
	return id, 0, nil
}

// blueFCodeState is a code-size oracle whose answers can change between calls, so a
// verifier that caches a reality proof instead of reading live state is caught.
type blueFCodeState struct {
	StateDB
	sizes map[common.Address]int
}

func (s *blueFCodeState) CodeSizeOf(addr common.Address) int { return s.sizes[addr] }

func blueFNewCodeState() *blueFCodeState {
	return &blueFCodeState{StateDB: NewMockStateDB(), sizes: map[common.Address]int{}}
}

// ---------------------------------------------------------------------------
// asset_onchain_verifier.go — the live-code reality gate
// ---------------------------------------------------------------------------

// TestBlueF_VerifierRefusesAssetWithNoCode is the core admission property: an
// ERC-20 trades only if its 20-byte address carries contract bytecode in the state
// THIS block is mutating. Every address below is a shape an attacker can name — a
// never-deployed address, an ASCII ticker left-padded into an address, the
// precompile's own address, a self-destructed token — and each must be refused
// while it has no code.
func TestBlueF_VerifierRefusesAssetWithNoCode(t *testing.T) {
	st := blueFNewCodeState()
	v := onChainVerifierFor(st)
	if v == nil {
		t.Fatal("a code-capable StateDB must yield a verifier")
	}

	var ticker common.Address
	copy(ticker[16:], []byte("LUSD")) // an ASCII ticker masquerading as a token address

	for _, tc := range []struct {
		name string
		addr common.Address
	}{
		{"never deployed", common.HexToAddress("0xdead00000000000000000000000000000000beef")},
		{"ascii ticker as address", ticker},
		{"the precompile's own address", poolManagerAddr9999},
		{"the settlement config address", settlementAddr},
		{"one bit off a real token", common.HexToAddress("0x0000000000000000000000000000000000000003")},
	} {
		err := v.VerifyOnChainAsset(dexcore.AssetKindERC20, tc.addr.Bytes())
		if !errors.Is(err, ErrERC20NoOnChainCode) {
			t.Fatalf("%s: a code-less address must be refused with ErrERC20NoOnChainCode, got %v", tc.name, err)
		}
		// And the refusal must survive the value path's join, which is what the
		// swap handler actually matches on.
		if joined := dexcore.RequireRealOnChain(v, dexcore.AssetKindERC20, tc.addr.Bytes()); !errors.Is(joined, dexcore.ErrAssetNotOnChain) {
			t.Fatalf("%s: RequireRealOnChain must join ErrAssetNotOnChain, got %v", tc.name, joined)
		}
	}
}

// TestBlueF_VerifierReadsLiveCodeNotACachedProof pins that the verdict is taken from
// state at CALL time. The window this gate exists to close is exactly a code size
// that changes between registration and the swap: a token that gains code must
// become admissible, and a token that SELFDESTRUCTs must stop being admissible with
// no other state change.
func TestBlueF_VerifierReadsLiveCodeNotACachedProof(t *testing.T) {
	st := blueFNewCodeState()
	v := onChainVerifierFor(st)
	tok := common.HexToAddress("0x00000000000000000000000000000000000000A1")

	if err := v.VerifyOnChainAsset(dexcore.AssetKindERC20, tok.Bytes()); !errors.Is(err, ErrERC20NoOnChainCode) {
		t.Fatalf("before deployment the token must be refused, got %v", err)
	}
	st.sizes[tok] = 42 // the contract is deployed
	if err := v.VerifyOnChainAsset(dexcore.AssetKindERC20, tok.Bytes()); err != nil {
		t.Fatalf("after deployment the token must be admitted, got %v", err)
	}
	st.sizes[tok] = 0 // SELFDESTRUCT
	if err := v.VerifyOnChainAsset(dexcore.AssetKindERC20, tok.Bytes()); !errors.Is(err, ErrERC20NoOnChainCode) {
		t.Fatalf("after SELFDESTRUCT the token must be refused again, got %v", err)
	}
	// A code size cannot be negative in the EVM, but a host that reports one must
	// not be read as "has code": the check is > 0, not != 0.
	st.sizes[tok] = -1
	if err := v.VerifyOnChainAsset(dexcore.AssetKindERC20, tok.Bytes()); !errors.Is(err, ErrERC20NoOnChainCode) {
		t.Fatalf("a negative code size must refuse, got %v", err)
	}
}

// TestBlueF_VerifierRefusesIllFormedRef sweeps the reference SHAPE for all three
// kinds. An ill-formed reference must be refused BEFORE the code read: the verifier
// must never read code at an address it synthesised from the wrong number of bytes.
func TestBlueF_VerifierRefusesIllFormedRef(t *testing.T) {
	st := blueFNewCodeState()
	// Seed code at the zero address and at the address a short ref would left-pad
	// to, so a length-sloppy verifier would ADMIT and this test would catch it.
	st.sizes[common.Address{}] = 99
	st.sizes[common.BytesToAddress([]byte{0x01, 0x02, 0x03})] = 99
	v := onChainVerifierFor(st)

	twenty := common.HexToAddress("0x00000000000000000000000000000000000000A2").Bytes()
	thirtyTwo := make([]byte, 32)
	thirtyTwo[31] = 7

	for _, tc := range []struct {
		name string
		kind dexcore.AssetKind
		ref  []byte
	}{
		{"ERC20 ref too short", dexcore.AssetKindERC20, twenty[:19]},
		{"ERC20 ref too long", dexcore.AssetKindERC20, append(append([]byte(nil), twenty...), 0x00)},
		{"ERC20 ref empty", dexcore.AssetKindERC20, nil},
		{"ERC20 ref is the zero address", dexcore.AssetKindERC20, make([]byte, 20)},
		{"ERC20 ref is a 32-byte assetID", dexcore.AssetKindERC20, thirtyTwo},
		{"native ref not the zero marker", dexcore.AssetKindEVMNative, twenty},
		{"native ref wrong width", dexcore.AssetKindEVMNative, make([]byte, 32)},
		{"UTXO ref wrong width", dexcore.AssetKindUTXO, twenty},
		{"UTXO ref all zero", dexcore.AssetKindUTXO, make([]byte, 32)},
	} {
		if err := v.VerifyOnChainAsset(tc.kind, tc.ref); err == nil {
			t.Fatalf("%s: an ill-formed reference must be refused, got nil", tc.name)
		}
		// A poisoned backing array must not change the verdict: the shape check
		// reads len, never the spare capacity an attacker controls.
		if err := v.VerifyOnChainAsset(tc.kind, blueFPoisoned(tc.ref, 64)); err == nil {
			t.Fatalf("%s: poisoned spare capacity must not admit an ill-formed reference", tc.name)
		}
	}
}

// TestBlueF_VerifierAdmitsTheTwoNonEVMKinds pins the two kinds whose reality is NOT
// an EVM-state fact: the chain's own coin (not a contract, so no code to read) and
// an X-Chain UTXO asset (proven at the registry against the X-Chain). Both must be
// admitted on a well-formed reference and must NOT consult code size — an oracle
// that answers "no code" for every address must still admit them.
func TestBlueF_VerifierAdmitsTheTwoNonEVMKinds(t *testing.T) {
	st := blueFNewCodeState() // every address reports zero code
	v := onChainVerifierFor(st)

	if err := v.VerifyOnChainAsset(dexcore.AssetKindEVMNative, dexcore.EVMNativeMarker); err != nil {
		t.Fatalf("the native coin must always be real, got %v", err)
	}
	utxo := make([]byte, 32)
	utxo[0] = 0xAB
	if err := v.VerifyOnChainAsset(dexcore.AssetKindUTXO, utxo); err != nil {
		t.Fatalf("a well-formed UTXO assetID must be admitted (X-Chain proof, not EVM state), got %v", err)
	}
	if err := dexcore.RequireRealOnChain(v, dexcore.AssetKindUTXO, utxo); err != nil {
		t.Fatalf("RequireRealOnChain must admit a well-formed UTXO ref, got %v", err)
	}
}

// TestBlueF_VerifierRefusesUnknownKind pins that a kind outside the closed set of
// three is refused with ErrInvalidKind for every reference shape. The refusal comes
// from the canonical-reference check, which runs first — so the switch's own
// default arm is unreachable (recorded in the report, not patched here).
func TestBlueF_VerifierRefusesUnknownKind(t *testing.T) {
	st := blueFNewCodeState()
	st.sizes[common.HexToAddress("0x00000000000000000000000000000000000000A3")] = 1
	v := onChainVerifierFor(st)

	for _, kind := range []dexcore.AssetKind{0, 4, 5, 200, 255} {
		for _, ref := range [][]byte{
			nil,
			make([]byte, 20),
			make([]byte, 32),
			common.HexToAddress("0x00000000000000000000000000000000000000A3").Bytes(),
		} {
			err := v.VerifyOnChainAsset(kind, ref)
			if !errors.Is(err, dexcore.ErrInvalidKind) {
				t.Fatalf("kind %d ref %d bytes: must be refused with ErrInvalidKind, got %v", kind, len(ref), err)
			}
		}
		if kind.Valid() {
			t.Fatalf("kind %d must not report itself valid", kind)
		}
	}
}

// TestBlueF_CodeCapabilityResolution pins which StateDB shapes carry the EXTCODESIZE
// capability. The decisive property is fail-closed: a host that cannot answer must
// yield NO verifier (so RequireRealOnChain refuses with ErrNoOnChainVerifier), never
// a verifier that answers "no code" for everything — which would refuse the native
// coin and, worse, read as a real proof.
func TestBlueF_CodeCapabilityResolution(t *testing.T) {
	mock := NewMockStateDB()

	// 1. A StateDB that implements CodeSizeOf directly is code-capable.
	if cs, ok := codeStaterFor(mock); !ok || cs == nil {
		t.Fatal("a StateDB implementing CodeSizeOf must be code-capable")
	}
	if onChainVerifierFor(mock) == nil {
		t.Fatal("a code-capable StateDB must yield a verifier")
	}

	// 2. A StateDB with no code capability is NOT capable, yields no verifier, and
	//    the value path fails closed.
	plain := blueFPlainState{StateDB: mock}
	if cs, ok := codeStaterFor(plain); ok || cs != nil {
		t.Fatal("a StateDB without CodeSizeOf must not be reported code-capable")
	}
	if v := onChainVerifierFor(plain); v != nil {
		t.Fatal("a code-incapable StateDB must yield NO verifier (fail closed)")
	}
	if err := dexcore.RequireRealOnChain(onChainVerifierFor(plain), dexcore.AssetKindEVMNative, dexcore.EVMNativeMarker); !errors.Is(err, dexcore.ErrNoOnChainVerifier) {
		t.Fatalf("no verifier must fail closed with ErrNoOnChainVerifier, got %v", err)
	}

	// 3. The production adapter over a StateDB that CAN report code size is capable.
	h := newSettleHarness(t)
	adapter := newPoolStateAdapter(h.state)
	if cs, ok := codeStaterFor(adapter); !ok || cs == nil {
		t.Fatal("the adapter over a GetCodeSize-capable StateDB must be code-capable")
	}

	// 4. The adapter over a StateDB that CANNOT report code size reports -1, which
	//    must read as not-capable — not as "zero code everywhere".
	blind := &poolStateAdapter{stateDB: blueFNoCodeStateDB{StateDB: h.state.GetStateDB()}}
	if got := blind.CodeSizeOf(common.Address{}); got != -1 {
		t.Fatalf("an adapter over a code-blind StateDB must report -1, got %d", got)
	}
	if cs, ok := codeStaterFor(blind); ok || cs != nil {
		t.Fatal("a code-blind adapter must not be reported code-capable")
	}
	if v := onChainVerifierFor(blind); v != nil {
		t.Fatal("a code-blind adapter must yield NO verifier (fail closed)")
	}
}

// TestBlueF_OnChainAssetErrIsMatchable pins the refusal cause as a distinct, stable
// value: the swap path matches it with errors.Is under the joined
// dexcore.ErrAssetNotOnChain, and its message must name the reason.
func TestBlueF_OnChainAssetErrIsMatchable(t *testing.T) {
	msg := ErrERC20NoOnChainCode.Error()
	if msg == "" {
		t.Fatal("the refusal cause must carry a message")
	}
	if !errors.Is(ErrERC20NoOnChainCode, ErrERC20NoOnChainCode) {
		t.Fatal("the refusal cause must match itself")
	}
	other := errInvalidOnChainAsset("dex: a different cause")
	if errors.Is(other, ErrERC20NoOnChainCode) {
		t.Fatal("two distinct causes must not match each other")
	}
	if other.Error() != "dex: a different cause" {
		t.Fatalf("the cause must render its own message, got %q", other.Error())
	}
}

// ---------------------------------------------------------------------------
// asset_resolver.go — the process-global install latch
// ---------------------------------------------------------------------------

// TestBlueF_InstallAssetResolverRefusals pins the boot-time latch. It is a
// process-global with no uninstall, so a wrong install is permanent for the life of
// the node: the refusals are the whole safety story. A resolver bound to a
// DIFFERENT chain must never replace one already installed, while re-installing the
// SAME identity stays idempotent so a benign re-init does not fail boot.
func TestBlueF_InstallAssetResolverRefusals(t *testing.T) {
	blueFIsolateResolver(t)

	chainA := ids.ID{0xC0}
	chainB := ids.ID{0xC1}
	rA := &blueFTestResolver{networkID: 7, chainID: chainA}
	rB := &blueFTestResolver{networkID: 7, chainID: chainB}

	if AssetResolverInstalled() {
		t.Fatal("the latch must start clear inside an isolated test")
	}

	// A nil resolver is refused and installs nothing.
	if err := InstallAssetResolver(nil, 7, chainA); err == nil {
		t.Fatal("a nil resolver must be refused")
	}
	if AssetResolverInstalled() {
		t.Fatal("a refused install must leave the latch clear")
	}

	// An empty C-Chain id is refused: the id enters every derived AssetID, so an
	// empty one would make every asset identity collide.
	if err := InstallAssetResolver(rA, 7, ids.Empty); err == nil {
		t.Fatal("an empty C-Chain id must be refused")
	}
	if AssetResolverInstalled() {
		t.Fatal("a refused install must leave the latch clear")
	}

	// The first well-formed install takes.
	if err := InstallAssetResolver(rA, 7, chainA); err != nil {
		t.Fatalf("the first install must be accepted: %v", err)
	}
	if !AssetResolverInstalled() {
		t.Fatal("the latch must report installed after a successful install")
	}

	// Re-installing the SAME identity is idempotent (a benign re-init).
	if err := InstallAssetResolver(rB, 7, chainA); err != nil {
		t.Fatalf("a same-identity re-install must be allowed: %v", err)
	}

	// A DIFFERENT identity is refused on either coordinate, and the refusal must
	// not swap the installed resolver.
	for _, tc := range []struct {
		name      string
		networkID uint32
		chainID   ids.ID
	}{
		{"different C-Chain id", 7, chainB},
		{"different network id", 8, chainA},
		{"both different", 8, chainB},
	} {
		if err := InstallAssetResolver(rA, tc.networkID, tc.chainID); err == nil {
			t.Fatalf("%s: a re-install bound to another chain must be refused", tc.name)
		}
		got, err := resolverForRuntime(7, chainA)
		if err != nil || got == nil {
			t.Fatalf("%s: the original install must survive a refused re-install (%v)", tc.name, err)
		}
	}
}

// TestBlueF_ResolverForRuntimeIdentityBinding pins the swap-time half of the same
// property: the installed resolver is usable ONLY on the chain it was built for. A
// mismatch is a hard refusal, not a fallback — a resolver bound to another network
// derives different AssetIDs and would admit assets that do not exist here.
func TestBlueF_ResolverForRuntimeIdentityBinding(t *testing.T) {
	blueFIsolateResolver(t)

	chainA := ids.ID{0xA0}
	chainB := ids.ID{0xB0}

	// No resolver installed: nil resolver, nil error — the caller maps that to the
	// fail-closed ErrNoAssetResolver.
	got, err := resolverForRuntime(1, chainA)
	if got != nil || err != nil {
		t.Fatalf("an empty latch must yield (nil, nil), got (%v, %v)", got, err)
	}
	if e := func() error {
		_, _, e := dexcore.RequireResolvedAsset(nil, dexcore.AssetKindEVMNative, dexcore.EVMNativeMarker)
		return e
	}(); !errors.Is(e, dexcore.ErrNoAssetResolver) {
		t.Fatalf("a nil resolver must fail closed with ErrNoAssetResolver, got %v", e)
	}

	if err := InstallAssetResolver(&blueFTestResolver{networkID: 1, chainID: chainA}, 1, chainA); err != nil {
		t.Fatalf("install: %v", err)
	}

	for _, tc := range []struct {
		name      string
		networkID uint32
		chainID   ids.ID
		ok        bool
	}{
		{"exact identity", 1, chainA, true},
		{"wrong network", 2, chainA, false},
		{"wrong chain", 1, chainB, false},
		{"both wrong", 2, chainB, false},
		{"empty chain id", 1, ids.Empty, false},
	} {
		r, err := resolverForRuntime(tc.networkID, tc.chainID)
		if tc.ok {
			if err != nil || r == nil {
				t.Fatalf("%s: must resolve, got (%v, %v)", tc.name, r, err)
			}
			continue
		}
		if !errors.Is(err, ErrAssetResolverIdentityMismatch) {
			t.Fatalf("%s: must refuse with ErrAssetResolverIdentityMismatch, got %v", tc.name, err)
		}
		if r != nil {
			t.Fatalf("%s: a refused runtime lookup must hand back no resolver", tc.name)
		}
	}
}

// TestBlueF_AssetSideForCurrency pins the V4-currency -> (kind, ref) mapping the
// value path admits each side through. The zero address is the native coin and
// everything else is an ERC-20 whose reference IS its contract address; the mapping
// must be injective on the address so two currencies never share an identity, and
// must copy the address so a later mutation of the returned ref cannot retarget it.
func TestBlueF_AssetSideForCurrency(t *testing.T) {
	native := assetSideForCurrency(Currency{Address: common.Address{}})
	if native.Kind != dexcore.AssetKindEVMNative {
		t.Fatalf("the zero address must map to EVM_NATIVE, got %v", native.Kind)
	}
	if _, err := dexcore.CanonicalRefFor(native.Kind, native.Ref); err != nil {
		t.Fatalf("the native side must carry the canonical native marker: %v", err)
	}

	tok := common.HexToAddress("0x00000000000000000000000000000000000000C7")
	side := assetSideForCurrency(Currency{Address: tok})
	if side.Kind != dexcore.AssetKindERC20 {
		t.Fatalf("a non-zero address must map to ERC20, got %v", side.Kind)
	}
	if common.BytesToAddress(side.Ref) != tok {
		t.Fatalf("the ERC-20 reference must be the token address, got %x", side.Ref)
	}
	// The ref must be a copy: mutating it must not have retargeted the currency.
	side.Ref[0] ^= 0xFF
	again := assetSideForCurrency(Currency{Address: tok})
	if common.BytesToAddress(again.Ref) != tok {
		t.Fatal("assetSideForCurrency must copy the address, not alias it")
	}
}

// ---------------------------------------------------------------------------
// settle_addr.go — the commitment helper
// ---------------------------------------------------------------------------

// TestBlueF_Keccak32MatchesKeccak256 pins the settlement commitment helper against
// an independently computed keccak256 and against collision on the inputs the
// settle path commits. A commitment helper that truncated, padded, or reused a
// buffer would show up here as a mismatch or a collision.
func TestBlueF_Keccak32MatchesKeccak256(t *testing.T) {
	inputs := [][]byte{
		nil,
		{0x00},
		{0x01},
		[]byte("dex.precompile.v1.9999."),
		make([]byte, 32),
		make([]byte, 33),
		bytes32Seq(200),
	}
	seen := map[[32]byte]int{}
	for i, in := range inputs {
		got := keccak32(in)
		want := crypto.Keccak256(in)
		if len(want) != 32 {
			t.Fatalf("keccak256 must be 32 bytes, got %d", len(want))
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("input %d: keccak32 != keccak256 at byte %d (%x vs %x)", i, j, got, want)
			}
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("input %d collides with input %d — the commitment is not injective", i, prev)
		}
		seen[got] = i
	}
	// One flipped bit must change the commitment (no truncation to a short prefix).
	a := bytes32Seq(64)
	b := append([]byte(nil), a...)
	b[len(b)-1] ^= 0x01
	if keccak32(a) == keccak32(b) {
		t.Fatal("a one-bit change must change the commitment")
	}
}

// bytes32Seq builds a deterministic n-byte fixture.
func bytes32Seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

// ---------------------------------------------------------------------------
// fill_attestation.go — the broker fill lifecycle
// ---------------------------------------------------------------------------

// blueFAttest is the fixture for the attestation tests: a fresh state, a manager,
// and a registered attester.
type blueFAttest struct {
	db       *MockStateDB
	mgr      *SettlementManager
	attester common.Address
	rando    common.Address
	user     common.Address
}

func blueFNewAttest(t *testing.T) *blueFAttest {
	t.Helper()
	f := &blueFAttest{
		db:       NewMockStateDB(),
		mgr:      NewSettlementManager(),
		attester: common.HexToAddress("0xBF00000000000000000000000000000000000001"),
		rando:    common.HexToAddress("0xBF00000000000000000000000000000000000002"),
		user:     common.HexToAddress("0xBF00000000000000000000000000000000000003"),
	}
	if err := f.mgr.SetAttester(f.db, common.Address{}, f.attester); err != nil {
		t.Fatalf("SetAttester: %v", err)
	}
	return f
}

// setBlock moves the recorded block height the fraud window is measured against.
func (f *blueFAttest) setBlock(n uint64) {
	var w common.Hash
	new(big.Int).SetUint64(n).FillBytes(w[:])
	f.db.SetState(fillAttestAddr, makeStorageKey(fillConfigPrefix, []byte("block")), w)
}

// TestBlueF_AttestRefusesBeforeAnAttesterExists pins the genesis hole shut: with no
// attester registered, NOBODY may attest — including the zero address, which is what
// an unset attester slot reads back as. Without this arm a caller whose address
// compares equal to the empty slot would mint attestations on a fresh deployment.
func TestBlueF_AttestRefusesBeforeAnAttesterExists(t *testing.T) {
	db := NewMockStateDB()
	mgr := NewSettlementManager()
	order := OrderIDFromString("blueF-no-attester")
	amount := big.NewInt(3)
	price := big.NewInt(5)
	user := common.HexToAddress("0xBF00000000000000000000000000000000000003")

	for _, caller := range []common.Address{
		{},
		common.HexToAddress("0xBF00000000000000000000000000000000000009"),
	} {
		err := mgr.Attest(db, caller, order, SymbolToBytes32("AAPL"), amount, price, user, 1)
		if !errors.Is(err, ErrUnauthorizedAttester) {
			t.Fatalf("caller %s: attesting with no registered attester must be refused, got %v", caller, err)
		}
	}
	if att := mgr.GetAttestation(db, order); att != nil {
		t.Fatal("a refused attestation must record nothing")
	}
	if out := mgr.GetOutstanding(db); out.Sign() != 0 {
		t.Fatalf("a refused attestation must not move outstanding, got %s", out)
	}
}

// TestBlueF_ChallengeRefusals pins every arm that must turn a reversal away. The
// authorization check is what stands between a broker fill and an arbitrary caller
// burning a user's tokens, so each refusal is asserted together with the invariant
// that a refused challenge changes NOTHING: not the status, not the outstanding.
func TestBlueF_ChallengeRefusals(t *testing.T) {
	f := blueFNewAttest(t)
	order := OrderIDFromString("blueF-challenge")
	amount := big.NewInt(50)
	price := big.NewInt(800)
	fill := new(big.Int).Mul(amount, price)

	// An unknown order cannot be challenged.
	if err := f.mgr.Challenge(f.db, f.attester, OrderIDFromString("blueF-absent"), []byte("proof")); !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("challenging an unknown order must be refused, got %v", err)
	}

	if err := f.mgr.Attest(f.db, f.attester, order, SymbolToBytes32("NVDA"), amount, price, f.user, 1); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// A caller who is not the attester cannot reverse a fill.
	if err := f.mgr.Challenge(f.db, f.rando, order, []byte("proof")); !errors.Is(err, ErrUnauthorizedAttester) {
		t.Fatalf("a non-attester must not reverse a fill, got %v", err)
	}
	// An empty reversal proof is refused.
	for _, proof := range [][]byte{nil, {}} {
		if err := f.mgr.Challenge(f.db, f.attester, order, proof); !errors.Is(err, ErrInvalidReversalProof) {
			t.Fatalf("an empty reversal proof must be refused, got %v", err)
		}
	}
	// Every refusal above left the attestation pending and the outstanding intact.
	if att := f.mgr.GetAttestation(f.db, order); att == nil || att.Status != FillPending {
		t.Fatalf("a refused challenge must leave the attestation pending, got %+v", att)
	}
	if out := f.mgr.GetOutstanding(f.db); out.Cmp(fill) != 0 {
		t.Fatalf("a refused challenge must not move outstanding: got %s want %s", out, fill)
	}

	// The accepted challenge reverses exactly once; a second one is refused.
	if err := f.mgr.Challenge(f.db, f.attester, order, []byte("alpaca-reversal")); err != nil {
		t.Fatalf("the attester's challenge must be accepted: %v", err)
	}
	if err := f.mgr.Challenge(f.db, f.attester, order, []byte("alpaca-reversal")); !errors.Is(err, ErrAttestationReversed) {
		t.Fatalf("a reversed attestation must not be reversed twice, got %v", err)
	}
	if out := f.mgr.GetOutstanding(f.db); out.Sign() != 0 {
		t.Fatalf("outstanding must be released exactly once, got %s", out)
	}
	// And the state, not the manager's cache, carries the verdict: a manager that
	// never saw this order must read the same status.
	fresh := NewSettlementManager()
	if att := fresh.GetAttestation(f.db, order); att == nil || att.Status != FillReversed {
		t.Fatalf("a fresh manager must read FillReversed from state, got %+v", att)
	}
}

// TestBlueF_FinalizeRefusals pins the finalize arms. Finalize is callable by anyone,
// so its only protections are the fraud window and the terminal statuses — both must
// hold, and a refused finalize must not release the outstanding.
func TestBlueF_FinalizeRefusals(t *testing.T) {
	f := blueFNewAttest(t)
	if err := f.mgr.SetFraudWindow(f.db, f.attester, 10); err != nil {
		t.Fatalf("SetFraudWindow: %v", err)
	}
	order := OrderIDFromString("blueF-finalize")
	amount := big.NewInt(25)
	price := big.NewInt(400)
	fill := new(big.Int).Mul(amount, price)

	if err := f.mgr.Finalize(f.db, OrderIDFromString("blueF-absent-2")); !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("finalizing an unknown order must be refused, got %v", err)
	}
	if err := f.mgr.Attest(f.db, f.attester, order, SymbolToBytes32("MSFT"), amount, price, f.user, 1); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// Sweep the fraud-window boundary rather than probing one point. The
	// attestation was recorded at block 1 with a 10-block window, so 11 is the
	// first block at which it may finalize and 10 must still refuse.
	for blk := uint64(1); blk <= 10; blk++ {
		f.setBlock(blk)
		if err := f.mgr.Finalize(f.db, order); !errors.Is(err, ErrFraudWindowActive) {
			t.Fatalf("block %d is inside the fraud window and must refuse, got %v", blk, err)
		}
		if out := f.mgr.GetOutstanding(f.db); out.Cmp(fill) != 0 {
			t.Fatalf("block %d: a refused finalize must not release outstanding", blk)
		}
	}
	f.setBlock(11)
	if err := f.mgr.Finalize(f.db, order); err != nil {
		t.Fatalf("block 11 is the first block past the window and must finalize: %v", err)
	}
	if out := f.mgr.GetOutstanding(f.db); out.Sign() != 0 {
		t.Fatalf("finalize must release the outstanding, got %s", out)
	}

	// The terminal statuses are terminal in both directions.
	if err := f.mgr.Finalize(f.db, order); !errors.Is(err, ErrAttestationFinalized) {
		t.Fatalf("a finalized attestation must not finalize twice, got %v", err)
	}
	if err := f.mgr.Challenge(f.db, f.attester, order, []byte("late-reversal")); !errors.Is(err, ErrAttestationFinalized) {
		t.Fatalf("a finalized attestation must not be reversed, got %v", err)
	}

	// A reversed attestation must not finalize either.
	rev := OrderIDFromString("blueF-reversed-then-finalize")
	if err := f.mgr.Attest(f.db, f.attester, rev, SymbolToBytes32("TSLA"), amount, price, f.user, 1); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if err := f.mgr.Challenge(f.db, f.attester, rev, []byte("reversal")); err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	f.setBlock(100)
	if err := f.mgr.Finalize(f.db, rev); !errors.Is(err, ErrAttestationReversed) {
		t.Fatalf("a reversed attestation must not finalize, got %v", err)
	}
}

// TestBlueF_FraudWindowDefaultUntilSet pins the sentinel: an unset fraud window
// means the ~3-day default, not zero. A zero default would make every attestation
// finalizable in the same block it was recorded, which is the whole protection
// gone. Setting it explicitly to 0 must be honoured — that is what the sentinel is
// for.
func TestBlueF_FraudWindowDefaultUntilSet(t *testing.T) {
	f := blueFNewAttest(t)
	if got := f.mgr.getFraudWindow(f.db); got != DefaultFraudWindowBlocks {
		t.Fatalf("an unset fraud window must read the default %d, got %d", DefaultFraudWindowBlocks, got)
	}

	order := OrderIDFromString("blueF-default-window")
	if err := f.mgr.Attest(f.db, f.attester, order, SymbolToBytes32("AAPL"), big.NewInt(1), big.NewInt(1), f.user, 1); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	// Under the default window, a block just short of it must still refuse.
	f.setBlock(DefaultFraudWindowBlocks)
	if err := f.mgr.Finalize(f.db, order); !errors.Is(err, ErrFraudWindowActive) {
		t.Fatalf("the default window must still be open at block %d, got %v", DefaultFraudWindowBlocks, err)
	}

	// An explicit zero is a real value, not "unset": the sentinel says so.
	if err := f.mgr.SetFraudWindow(f.db, f.attester, 0); err != nil {
		t.Fatalf("SetFraudWindow(0): %v", err)
	}
	if got := f.mgr.getFraudWindow(f.db); got != 0 {
		t.Fatalf("an explicit zero fraud window must read back as 0, got %d", got)
	}
	if err := f.mgr.Finalize(f.db, order); err != nil {
		t.Fatalf("with a zero window the attestation must finalize: %v", err)
	}
}

// TestBlueF_AttestationAdminAuthorization pins who may move the two governance
// values. The first attester is set by anyone (genesis), and every later change —
// attester, ceiling, fraud window — requires the CURRENT attester. A refused admin
// call must leave the stored value untouched.
func TestBlueF_AttestationAdminAuthorization(t *testing.T) {
	f := blueFNewAttest(t)

	ceiling := new(big.Int).Mul(big.NewInt(1_000), big.NewInt(1e18))
	if err := f.mgr.SetCeiling(f.db, f.attester, ceiling); err != nil {
		t.Fatalf("the attester must be able to set the ceiling: %v", err)
	}
	if got := f.mgr.GetCeiling(f.db); got.Cmp(ceiling) != 0 {
		t.Fatalf("GetCeiling must read back the stored ceiling: got %s want %s", got, ceiling)
	}

	for _, caller := range []common.Address{f.rando, {}, f.user} {
		if err := f.mgr.SetCeiling(f.db, caller, big.NewInt(1)); !errors.Is(err, ErrUnauthorizedAttester) {
			t.Fatalf("caller %s must not set the ceiling, got %v", caller, err)
		}
		if err := f.mgr.SetFraudWindow(f.db, caller, 1); !errors.Is(err, ErrUnauthorizedAttester) {
			t.Fatalf("caller %s must not set the fraud window, got %v", caller, err)
		}
		if err := f.mgr.SetAttester(f.db, caller, caller); !errors.Is(err, ErrUnauthorizedAttester) {
			t.Fatalf("caller %s must not seize the attester role, got %v", caller, err)
		}
	}
	if got := f.mgr.GetCeiling(f.db); got.Cmp(ceiling) != 0 {
		t.Fatalf("a refused admin call must not change the ceiling: got %s want %s", got, ceiling)
	}
	if got := f.mgr.getFraudWindow(f.db); got != DefaultFraudWindowBlocks {
		t.Fatalf("a refused admin call must not change the fraud window, got %d", got)
	}
	if got := f.mgr.getAttester(f.db); got != f.attester {
		t.Fatalf("a refused admin call must not change the attester, got %s", got)
	}

	// The ceiling is enforced against the SUM of outstanding fills, not each fill
	// alone: two fills that each fit but together do not must be refused on the
	// second.
	small := new(big.Int).Mul(big.NewInt(600), big.NewInt(1e18))
	if err := f.mgr.Attest(f.db, f.attester, OrderIDFromString("blueF-ceil-1"), SymbolToBytes32("A"), big.NewInt(1), small, f.user, 1); err != nil {
		t.Fatalf("the first fill fits under the ceiling: %v", err)
	}
	err := f.mgr.Attest(f.db, f.attester, OrderIDFromString("blueF-ceil-2"), SymbolToBytes32("A"), big.NewInt(1), small, f.user, 1)
	if !errors.Is(err, ErrPrefundCeilingExceeded) {
		t.Fatalf("the second fill must breach the ceiling, got %v", err)
	}
	if out := f.mgr.GetOutstanding(f.db); out.Cmp(small) != 0 {
		t.Fatalf("a refused attestation must not add to outstanding: got %s want %s", out, small)
	}
}

// TestBlueF_OutstandingNeverGoesNegative pins the release arms' floor. Outstanding
// is a stored 32-byte word; releasing more than it holds must clamp at zero rather
// than wrap to a near-2^256 balance, which would silently disable the prefund
// ceiling for every later fill.
func TestBlueF_OutstandingNeverGoesNegative(t *testing.T) {
	for _, release := range []string{"challenge", "finalize"} {
		f := blueFNewAttest(t)
		order := OrderIDFromString("blueF-clamp-" + release)
		amount := big.NewInt(10)
		price := big.NewInt(7)
		if err := f.mgr.Attest(f.db, f.attester, order, SymbolToBytes32("AAPL"), amount, price, f.user, 1); err != nil {
			t.Fatalf("%s: Attest: %v", release, err)
		}
		// Model an outstanding that has already been drawn down elsewhere, so the
		// release is larger than the balance it reduces.
		f.mgr.setOutstanding(f.db, big.NewInt(1))

		var err error
		if release == "challenge" {
			err = f.mgr.Challenge(f.db, f.attester, order, []byte("reversal"))
		} else {
			if serr := f.mgr.SetFraudWindow(f.db, f.attester, 1); serr != nil {
				t.Fatalf("SetFraudWindow: %v", serr)
			}
			f.setBlock(1000)
			err = f.mgr.Finalize(f.db, order)
		}
		if err != nil {
			t.Fatalf("%s: must succeed: %v", release, err)
		}
		out := f.mgr.GetOutstanding(f.db)
		if out.Sign() != 0 {
			t.Fatalf("%s: outstanding must clamp at zero, got %s", release, out)
		}
		if out.BitLen() > 256 {
			t.Fatalf("%s: outstanding must never wrap, got a %d-bit value", release, out.BitLen())
		}
	}
}

// TestBlueF_AttestationStateIsTheSourceOfTruth pins that the attestation a manager
// writes is fully recoverable from state by a manager that never saw it. Two
// validators run separate processes over the same state; if any field lived only in
// one manager's memory they would disagree about a fill.
func TestBlueF_AttestationStateIsTheSourceOfTruth(t *testing.T) {
	f := blueFNewAttest(t)
	order := OrderIDFromString("blueF-roundtrip")
	symbol := SymbolToBytes32("GOOG")
	amount := big.NewInt(123)
	price := new(big.Int).Mul(big.NewInt(456), big.NewInt(1e18))
	if err := f.mgr.Attest(f.db, f.attester, order, symbol, amount, price, f.user, 1711036800); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	fresh := NewSettlementManager()
	got := fresh.GetAttestation(f.db, order)
	if got == nil {
		t.Fatal("a fresh manager must find the attestation in state")
	}
	if got.Status != FillPending {
		t.Fatalf("status must round-trip, got %d", got.Status)
	}
	if got.Amount.Cmp(amount) != 0 || got.Price.Cmp(price) != 0 {
		t.Fatalf("amount/price must round-trip: got %s/%s want %s/%s", got.Amount, got.Price, amount, price)
	}
	if got.User != f.user || got.Attester != f.attester {
		t.Fatalf("addresses must round-trip: got user %s attester %s", got.User, got.Attester)
	}
	if got.Symbol != symbol {
		t.Fatalf("symbol must round-trip, got %x", got.Symbol)
	}
	if got.Timestamp != 1711036800 {
		t.Fatalf("timestamp must round-trip, got %d", got.Timestamp)
	}
	if got.Block != 1 {
		t.Fatalf("recording block must round-trip, got %d", got.Block)
	}
	// The duplicate check reads state too: a fresh manager must refuse the same
	// order id.
	if err := fresh.Attest(f.db, f.attester, order, symbol, amount, price, f.user, 1); !errors.Is(err, ErrDuplicateAttestation) {
		t.Fatalf("a fresh manager must refuse a duplicate order id, got %v", err)
	}
}

// TestBlueF_OrderIDIsInjective pins the order-id derivation. The id is the only
// thing standing between two different broker fills, so distinct provider ids must
// not collide and the same id must be stable across calls.
func TestBlueF_OrderIDIsInjective(t *testing.T) {
	seen := map[[32]byte]string{}
	for _, s := range []string{"", "a", "b", "alpaca-1", "alpaca-2", "alpaca-1 ", " alpaca-1"} {
		id := OrderIDFromString(s)
		if again := OrderIDFromString(s); again != id {
			t.Fatalf("%q: the order id must be deterministic", s)
		}
		if prev, dup := seen[id]; dup {
			t.Fatalf("%q collides with %q", s, prev)
		}
		seen[id] = s
	}
	// The symbol encoding is a left-aligned truncation to 32 bytes; a symbol longer
	// than 32 bytes must not overflow the array.
	long := SymbolToBytes32("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if long[0] != 'A' || long[31] != '5' {
		t.Fatalf("a symbol longer than 32 bytes must truncate to the first 32, got %q", long)
	}
}

// ---------------------------------------------------------------------------
// native_staging.go — the cross-domain staging window
// ---------------------------------------------------------------------------

// blueFStageObject builds a canonical C->D atomic object for the harness's owner.
func blueFStageObject(owner common.Address, asset [32]byte, amount uint64) []byte {
	return encodeClaim(owner, asset, amount)
}

// TestBlueF_StagedRemoveRoundTrip pins the D->C REMOVE half of the staging window.
// A remove consumes a cross-chain object, so its record must decode to exactly the
// (destination chain, key) it was staged with — a misrouted or mis-keyed remove
// either consumes someone else's object or silently consumes nothing.
func TestBlueF_StagedRemoveRoundTrip(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB

	keyA := ids.ID{0x01, 0x02}
	keyB := ids.ID{0x03, 0x04}
	other := ids.ID{0xEE}

	stageAtomicRemove(kv, h.dChainID, keyA)
	stageAtomicRemove(kv, other, keyB)
	if got := stageSeq(kv); got != 2 {
		t.Fatalf("two staged ops must advance the seq to 2, got %d", got)
	}

	reqs, err := CollectStagedAtomicRange(kv, 0, 2)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("two destination chains must yield two request sets, got %d", len(reqs))
	}
	for chain, key := range map[ids.ID]ids.ID{h.dChainID: keyA, other: keyB} {
		r := reqs[chain]
		if r == nil {
			t.Fatalf("chain %s must have a request set", chain)
		}
		if len(r.PutRequests) != 0 {
			t.Fatalf("chain %s: a remove must not stage a put", chain)
		}
		if len(r.RemoveRequests) != 1 {
			t.Fatalf("chain %s: expected exactly one remove, got %d", chain, len(r.RemoveRequests))
		}
		if string(r.RemoveRequests[0]) != string(key[:]) {
			t.Fatalf("chain %s: remove key mismatch: got %x want %x", chain, r.RemoveRequests[0], key[:])
		}
	}

	// The window is half-open on both ends: a sub-window selects exactly its ops,
	// and an empty window selects none.
	first, err := CollectStagedAtomicRange(kv, 0, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("the window [0,1) must select exactly the first op, got %d (%v)", len(first), err)
	}
	if empty, err := CollectStagedAtomicRange(kv, 2, 2); err != nil || len(empty) != 0 {
		t.Fatalf("an empty window must select nothing, got %d (%v)", len(empty), err)
	}
	if past, err := CollectStagedAtomicRange(kv, 5, 2); err != nil || len(past) != 0 {
		t.Fatalf("an inverted window must select nothing, got %d (%v)", len(past), err)
	}
}

// TestBlueF_StagedOpMalformedFailsAndAppliesNothing pins the fatal arm: a staged
// record the flush cannot decode must FAIL block accept, never be skipped. Skipping
// one would move value on one side of the seam and not the other. The second half of
// the property matters just as much — a refused flush must leave shared memory
// untouched, including the ops that were well formed.
func TestBlueF_StagedOpMalformedFailsAndAppliesNothing(t *testing.T) {
	goodObject := blueFStageObject(common.HexToAddress("0x1111111111111111111111111111111111111111"), [32]byte{0x01}, 5)

	for _, tc := range []struct {
		name  string
		stage func(kv stateKV, dChainID ids.ID)
	}{
		{"put record with an over-long object", func(kv stateKV, d ids.ID) {
			rec := packPut(d, ids.ID{0x09}, append(append([]byte(nil), goodObject...), 0x00))
			writeBytesToSlots(kv, stagePutPrefix, 0, rec)
			markStageKind(kv, 0, stageKindPut)
			setStageSeq(kv, 1)
		}},
		{"put record truncated below the object width", func(kv stateKV, d ids.ID) {
			rec := packPut(d, ids.ID{0x09}, goodObject[:len(goodObject)-1])
			writeBytesToSlots(kv, stagePutPrefix, 0, rec)
			markStageKind(kv, 0, stageKindPut)
			setStageSeq(kv, 1)
		}},
		{"remove record too short", func(kv stateKV, d ids.ID) {
			writeBytesToSlots(kv, stageRemovePrefix, 0, []byte{stagedOpVersion, 0x01, 0x02})
			markStageKind(kv, 0, stageKindRemove)
			setStageSeq(kv, 1)
		}},
		{"remove record with an unknown version", func(kv stateKV, d ids.ID) {
			rec := packRemove(d, ids.ID{0x09})
			rec[0] = stagedOpVersion + 1
			writeBytesToSlots(kv, stageRemovePrefix, 0, rec)
			markStageKind(kv, 0, stageKindRemove)
			setStageSeq(kv, 1)
		}},
		{"remove record with no bytes at all", func(kv stateKV, d ids.ID) {
			markStageKind(kv, 0, stageKindRemove)
			setStageSeq(kv, 1)
		}},
		{"seq slot with an unrecognised kind", func(kv stateKV, d ids.ID) {
			markStageKind(kv, 0, 0x7F)
			setStageSeq(kv, 1)
		}},
		{"seq slot with no kind at all", func(kv stateKV, d ids.ID) {
			setStageSeq(kv, 1)
		}},
	} {
		h := newSettleHarness(t)
		kv := h.state.stateDB
		tc.stage(kv, h.dChainID)

		if _, err := CollectStagedAtomicRange(kv, 0, 1); !errors.Is(err, ErrStagedOpMalformed) {
			t.Fatalf("%s: must fail with ErrStagedOpMalformed, got %v", tc.name, err)
		}
		if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, kv, h.cSM, nil); !errors.Is(err, ErrStagedOpMalformed) {
			t.Fatalf("%s: the flush must fail block accept, got %v", tc.name, err)
		}
		// Nothing may have reached the D side.
		probeKey := ids.ID{0x09}
		vals, gerr := h.dSM.Get(h.cChainID, [][]byte{probeKey[:]})
		if gerr == nil && len(vals) > 0 && len(vals[0]) > 0 {
			t.Fatalf("%s: a refused flush must apply nothing to shared memory", tc.name)
		}
	}
}

// TestBlueF_CollectStagedAtomicPanicsOnMalformed pins the test-harness convenience
// wrapper's documented contract: it has no error return, so a malformed op is a
// panic rather than a silently empty request set. An empty set would read as "this
// block staged nothing" and quietly drop value.
func TestBlueF_CollectStagedAtomicPanicsOnMalformed(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB
	markStageKind(kv, 0, 0x5A) // an unrecognisable kind
	setStageSeq(kv, 1)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("CollectStagedAtomic must panic on a malformed staged op, not return an empty set")
		}
		if err, ok := r.(error); !ok || !errors.Is(err, ErrStagedOpMalformed) {
			t.Fatalf("the panic must carry ErrStagedOpMalformed, got %v", r)
		}
	}()
	_ = CollectStagedAtomic(kv)
}

// TestBlueF_CollectStagedAtomicWholeWindow pins the wrapper's happy path: it reads
// the whole [0, seq) window, so a harness sees every op the block staged.
func TestBlueF_CollectStagedAtomicWholeWindow(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB
	owner := common.HexToAddress("0x2222222222222222222222222222222222222222")

	stageAtomicPut(kv, h.dChainID, ids.ID{0xA1}, blueFStageObject(owner, [32]byte{0x02}, 11))
	stageAtomicRemove(kv, h.dChainID, ids.ID{0xA2})

	reqs := CollectStagedAtomic(kv)
	r := reqs[h.dChainID]
	if r == nil {
		t.Fatal("the staged ops must route to the D chain")
	}
	if len(r.PutRequests) != 1 || len(r.RemoveRequests) != 1 {
		t.Fatalf("expected one put and one remove, got %d/%d", len(r.PutRequests), len(r.RemoveRequests))
	}
	putKey := ids.ID{0xA1}
	if string(r.PutRequests[0].Key) != string(putKey[:]) {
		t.Fatalf("put key mismatch: %x", r.PutRequests[0].Key)
	}
	// The destination indexes the object by RECIPIENT: the trait must be the
	// owner decoded from the object, not the key and not the caller.
	if len(r.PutRequests[0].Traits) != 1 || string(r.PutRequests[0].Traits[0]) != string(owner.Bytes()) {
		t.Fatalf("the put trait must be the object's owner, got %x", r.PutRequests[0].Traits)
	}

	// Clearing resets the window to empty, and clearing again is harmless.
	ClearStagedAtomic(kv)
	if got := stageSeq(kv); got != 0 {
		t.Fatalf("clear must reset the seq, got %d", got)
	}
	if left := CollectStagedAtomic(kv); len(left) != 0 {
		t.Fatalf("clear must leave no staged ops, got %d", len(left))
	}
	ClearStagedAtomic(kv)
}

// TestBlueF_ClearStagedSkipsUnknownKinds pins that the harness reset walks past a
// slot it cannot classify instead of stopping: the seq counter must still come back
// to zero, or the next test's window would start mid-history.
func TestBlueF_ClearStagedSkipsUnknownKinds(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB
	owner := common.HexToAddress("0x3333333333333333333333333333333333333333")

	stageAtomicPut(kv, h.dChainID, ids.ID{0xB1}, blueFStageObject(owner, [32]byte{0x03}, 3))
	markStageKind(kv, 1, 0x6D) // an unclassifiable slot in the middle
	setStageSeq(kv, 2)
	stageAtomicRemove(kv, h.dChainID, ids.ID{0xB2})

	ClearStagedAtomic(kv)
	if got := stageSeq(kv); got != 0 {
		t.Fatalf("clear must reset the seq past an unknown kind, got %d", got)
	}
	if got := readBytesFromSlots(kv, stagePutPrefix, 0); got != nil {
		t.Fatalf("clear must zero the put record, got %x", got)
	}
	if got := readBytesFromSlots(kv, stageRemovePrefix, 2); got != nil {
		t.Fatalf("clear must zero the remove record, got %x", got)
	}
}

// TestBlueF_ReadBytesFromUnwrittenSlotIsEmpty pins that an unwritten staging slot
// reads as nothing rather than as a 32-byte zero record. A zero-length record is
// what makes the malformed check fire; a zero-FILLED one would decode as a version-0
// op and could be mistaken for a real staged object.
func TestBlueF_ReadBytesFromUnwrittenSlotIsEmpty(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB
	for _, prefix := range [][]byte{stagePutPrefix, stageRemovePrefix} {
		for _, seq := range []uint64{0, 1, 1 << 40} {
			if got := readBytesFromSlots(kv, prefix, seq); got != nil {
				t.Fatalf("an unwritten slot must read as nil, got %x", got)
			}
		}
	}
	// A written record reads back byte-identical across the multi-slot boundary.
	rec := packPut(h.dChainID, ids.ID{0xC1}, blueFStageObject(common.Address{0x44}, [32]byte{0x04}, 9))
	writeBytesToSlots(kv, stagePutPrefix, 3, rec)
	got := readBytesFromSlots(kv, stagePutPrefix, 3)
	if string(got) != string(rec) {
		t.Fatalf("a staged record must round-trip through the slots: got %x want %x", got, rec)
	}
}

// TestBlueF_StagedObjectIsConsumedExactlyOnce pins the exactly-once property the
// whole staging design exists for. Shared memory is NOT idempotent — re-applying a
// window errors — so the safety comes from the parent->current seq window advancing.
// The test proves both halves: the window applies once, and the NEXT window is empty
// so nothing is applied twice.
func TestBlueF_StagedObjectIsConsumedExactlyOnce(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB
	owner := common.HexToAddress("0x5555555555555555555555555555555555555555")
	key := ids.ID{0xD1}

	stageAtomicPut(kv, h.dChainID, key, blueFStageObject(owner, [32]byte{0x05}, 21))
	to := ReadStagedAtomicSeq(kv)
	if to != 1 {
		t.Fatalf("one staged op must advance the seq to 1, got %d", to)
	}

	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, kv, h.cSM, nil); err != nil {
		t.Fatalf("the first flush must apply: %v", err)
	}
	vals, err := h.dSM.Get(h.cChainID, [][]byte{key[:]})
	if err != nil {
		t.Fatalf("the D side must see the object: %v", err)
	}
	if len(vals) != 1 || len(vals[0]) != claimSize {
		t.Fatalf("the D side must see exactly one canonical object, got %d values", len(vals))
	}

	// Re-applying the SAME window is refused by shared memory: the window boundary
	// is what makes the flush exactly-once, not replay idempotency.
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, kv, h.cSM, nil); err == nil {
		t.Fatal("re-applying an already-applied window must be refused by shared memory")
	}

	// The next block's window starts where this one ended and applies nothing.
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: to}, kv, h.cSM, nil); err != nil {
		t.Fatalf("the next window must be an empty no-op: %v", err)
	}

	// A seq that went BACKWARDS is fatal, never papered over.
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 5}, kv, h.cSM, nil); !errors.Is(err, ErrAtomicSeqRegression) {
		t.Fatalf("a seq regression must be fatal, got %v", err)
	}
	// And with no shared memory wired the flush is a no-op rather than a panic.
	if err := FlushAcceptedAtomicOps(&seqOnlyState{seq: 0}, kv, nil, nil); err != nil {
		t.Fatalf("a nil shared memory must be a no-op, got %v", err)
	}
}

// TestBlueF_FlushViewIsReadOnly pins that the host's accept-time view cannot write.
// The staged records are part of the state root, fixed at block production; a flush
// that mutated state would change the root after the fact and fork the chain.
func TestBlueF_FlushViewIsReadOnly(t *testing.T) {
	h := newSettleHarness(t)
	kv := h.state.stateDB
	ro := roStateKV{r: kv}

	slot := makeStorageKey([]byte("blueF.readonly"), []byte{0x01})
	var poison common.Hash
	poison[31] = 0xFF
	ro.SetState(poolManagerAddr9999, slot, poison)
	if got := kv.GetState(poolManagerAddr9999, slot); got != (common.Hash{}) {
		t.Fatalf("the accept-time view must not write through, got %x", got)
	}
	// And it reads through faithfully.
	kv.SetState(poolManagerAddr9999, slot, poison)
	if got := ro.GetState(poolManagerAddr9999, slot); got != poison {
		t.Fatalf("the accept-time view must read through, got %x", got)
	}
	if got := ReadStagedAtomicSeq(ro); got != stageSeq(kv) {
		t.Fatalf("the seq read through the view must match state, got %d", got)
	}
}

// TestBlueF_StagedPutRejectsANonCanonicalObject pins the object-shape check on the
// PUT leg. The object is the value that lands in the destination chain's shared
// memory, so a record whose object is not EXACTLY the canonical width must fail the
// flush rather than be reinterpreted into a credit of the wrong amount.
func TestBlueF_StagedPutRejectsANonCanonicalObject(t *testing.T) {
	h := newSettleHarness(t)
	owner := common.HexToAddress("0x6666666666666666666666666666666666666666")
	good := blueFStageObject(owner, [32]byte{0x06}, 4)

	for n := 0; n <= claimSize+2; n++ {
		if n == claimSize {
			continue // the canonical width is covered by the round-trip test
		}
		hh := newSettleHarness(t)
		kv := hh.state.stateDB
		object := make([]byte, n)
		copy(object, good)
		writeBytesToSlots(kv, stagePutPrefix, 0, packPut(hh.dChainID, ids.ID{0xE1}, object))
		markStageKind(kv, 0, stageKindPut)
		setStageSeq(kv, 1)
		if _, err := CollectStagedAtomicRange(kv, 0, 1); !errors.Is(err, ErrStagedOpMalformed) {
			t.Fatalf("a %d-byte object must fail the flush (canonical is %d), got %v", n, claimSize, err)
		}
	}
	_ = h
}

// ---------------------------------------------------------------------------
// module_erc20.go — the token sub-call seam
// ---------------------------------------------------------------------------

// TestBlueF_ERC20SeamFailsSecureWithoutACallSurface pins the seam's fail-secure
// arms. Every one of them is a case where the precompile cannot reach the token
// contract; the only safe answer is "no balance" and "transfer refused", because
// reporting a balance it could not read, or a transfer it did not make, mints an
// unbacked claim.
func TestBlueF_ERC20SeamFailsSecureWithoutACallSurface(t *testing.T) {
	h := newSettleHarness(t)
	token := common.HexToAddress("0x00000000000000000000000000000000000000F1")
	owner := common.HexToAddress("0x00000000000000000000000000000000000000F2")
	base := blueFNoCodeStateDB{StateDB: h.state.GetStateDB()}

	for _, tc := range []struct {
		name    string
		adapter *poolStateAdapter
	}{
		{"no accessible state at all", &poolStateAdapter{stateDB: base}},
		{"an environment that is nil", &poolStateAdapter{stateDB: base, accessibleState: &blueFEnvState{AccessibleState: h.state, env: nil}}},
		{"an environment with no Call surface", &poolStateAdapter{stateDB: base, accessibleState: &blueFEnvState{AccessibleState: h.state, env: blueFPlainEnv{}}}},
	} {
		if c := tc.adapter.callable(); c != nil {
			t.Fatalf("%s: must expose no Call surface", tc.name)
		}
		if got := tc.adapter.TokenBalanceOf(token, owner); got.Sign() != 0 {
			t.Fatalf("%s: an unreadable balance must be 0, got %s", tc.name, got)
		}
		if err := tc.adapter.TransferTokenFrom(token, owner, poolManagerAddr9999, big.NewInt(1)); !errors.Is(err, ErrERC20VaultUnavailable) {
			t.Fatalf("%s: a pull with no Call surface must refuse, got %v", tc.name, err)
		}
		if err := tc.adapter.TransferTokenTo(token, owner, big.NewInt(1)); !errors.Is(err, ErrERC20VaultUnavailable) {
			t.Fatalf("%s: a push with no Call surface must refuse, got %v", tc.name, err)
		}
	}
}

// TestBlueF_ERC20BalanceReadFailsSecure pins the balance read over a LIVE Call
// surface. A reverted or short return must read as zero — a deposit sized from a
// balance the precompile could not actually read is an unbacked credit.
func TestBlueF_ERC20BalanceReadFailsSecure(t *testing.T) {
	h := newSettleHarness(t)
	token := common.HexToAddress("0x00000000000000000000000000000000000000F3")
	owner := common.HexToAddress("0x00000000000000000000000000000000000000F4")
	base := blueFNoCodeStateDB{StateDB: h.state.GetStateDB()}

	full := make([]byte, 32)
	full[31] = 0x2A // 42

	for _, tc := range []struct {
		name string
		ret  []byte
		err  error
		want int64
	}{
		{"the token reverted", nil, errors.New("revert"), 0},
		{"a short return", make([]byte, 31), nil, 0},
		{"an empty return", nil, nil, 0},
		{"a well-formed balance", full, nil, 42},
	} {
		env := &blueFCallEnv{ret: tc.ret, err: tc.err}
		a := &poolStateAdapter{stateDB: base, accessibleState: &blueFEnvState{AccessibleState: h.state, env: env}}
		got := a.TokenBalanceOf(token, owner)
		if got.Int64() != tc.want {
			t.Fatalf("%s: got %s want %d", tc.name, got, tc.want)
		}
		if env.calls != 1 {
			t.Fatalf("%s: the balance read must make exactly one sub-call, got %d", tc.name, env.calls)
		}
		if env.lastAddr != token {
			t.Fatalf("%s: the sub-call must target the token, got %s", tc.name, env.lastAddr)
		}
		if len(env.lastIn) != 36 || string(env.lastIn[:4]) != string(selERC20BalanceOf) {
			t.Fatalf("%s: the sub-call must be balanceOf(address), got %x", tc.name, env.lastIn)
		}
		if common.BytesToAddress(env.lastIn[4:36]) != owner {
			t.Fatalf("%s: the sub-call must ask about the owner, got %x", tc.name, env.lastIn[4:36])
		}
	}
}

// TestBlueF_ERC20TransferReturnSemantics pins SafeERC20 semantics on the push leg:
// a revert and an explicit false are both FAILED transfers; a bare success with no
// return data is accepted (non-compliant tokens). Treating a false return as success
// is how a token that silently refuses gets counted as delivered.
func TestBlueF_ERC20TransferReturnSemantics(t *testing.T) {
	h := newSettleHarness(t)
	token := common.HexToAddress("0x00000000000000000000000000000000000000F5")
	to := common.HexToAddress("0x00000000000000000000000000000000000000F6")
	base := blueFNoCodeStateDB{StateDB: h.state.GetStateDB()}

	trueWord := make([]byte, 32)
	trueWord[31] = 1

	for _, tc := range []struct {
		name string
		ret  []byte
		err  error
		ok   bool
	}{
		{"revert", nil, errors.New("revert"), false},
		{"explicit false", make([]byte, 32), nil, false},
		{"malformed short return", make([]byte, 4), nil, false},
		{"explicit true", trueWord, nil, true},
		{"no return data", nil, nil, true},
	} {
		env := &blueFCallEnv{ret: tc.ret, err: tc.err}
		a := &poolStateAdapter{stateDB: base, accessibleState: &blueFEnvState{AccessibleState: h.state, env: env}}
		err := a.TransferTokenTo(token, to, big.NewInt(7))
		if tc.ok && err != nil {
			t.Fatalf("%s: must succeed, got %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s: must be treated as a FAILED transfer", tc.name)
		}
		if len(env.lastIn) != 68 || string(env.lastIn[:4]) != string(selERC20Transfer) {
			t.Fatalf("%s: the sub-call must be transfer(address,uint256), got %x", tc.name, env.lastIn)
		}
	}
}

// ---------------------------------------------------------------------------
// types.go / module.go — calldata shape refusals
// ---------------------------------------------------------------------------

// TestBlueF_PoolKeyFromBytesRefusesShortInput sweeps the length boundary of the
// stored pool-key decoder. The read is 66 bytes wide, so every length below that
// must be refused on len — never on capacity, which in production is attacker-chosen
// EVM memory rather than the end of the record.
func TestBlueF_PoolKeyFromBytesRefusesShortInput(t *testing.T) {
	key := PoolKey{
		Currency0:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000D1")},
		Currency1:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000D2")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.HexToAddress("0x00000000000000000000000000000000000000D3"),
	}
	full := key.ToBytes()
	if len(full) != 66 {
		t.Fatalf("the stored pool key must be 66 bytes, got %d", len(full))
	}

	for n := 0; n < 66; n++ {
		if _, err := PoolKeyFromBytes(full[:n]); err == nil {
			t.Fatalf("a %d-byte record must be refused", n)
		}
		// The same verdict must hold when the bytes past len are attacker-chosen.
		if _, err := PoolKeyFromBytes(blueFPoisoned(full[:n], 128)); err == nil {
			t.Fatalf("a %d-byte record with poisoned spare capacity must still be refused", n)
		}
	}
	got, err := PoolKeyFromBytes(full)
	if err != nil {
		t.Fatalf("the exact width must decode: %v", err)
	}
	if got.Currency0.Address != key.Currency0.Address || got.Currency1.Address != key.Currency1.Address {
		t.Fatalf("currencies must round-trip, got %+v", got)
	}
	if got.Fee != key.Fee || got.TickSpacing != key.TickSpacing || got.Hooks != key.Hooks {
		t.Fatalf("fee/spacing/hooks must round-trip, got %+v", got)
	}
	// Poisoning past the exact width must not change the decoded key either.
	poisoned, err := PoolKeyFromBytes(blueFPoisoned(full, 128))
	if err != nil || poisoned != got {
		t.Fatalf("poisoned spare capacity must not change the decoded key (%v)", err)
	}
}

// TestBlueF_DecodeInputRefusesShortCalldata sweeps the two V4 decoders' length
// boundaries. Both read fixed-width fields at absolute offsets, so a caller that
// declares less calldata than the layout needs must be refused on len — otherwise
// the decode reads whatever the caller left in EVM memory past the declared input.
func TestBlueF_DecodeInputRefusesShortCalldata(t *testing.T) {
	swap := make([]byte, 256)
	copy(swap[12:32], common.HexToAddress("0x00000000000000000000000000000000000000D4").Bytes())
	copy(swap[44:64], common.HexToAddress("0x00000000000000000000000000000000000000D5").Bytes())
	swap[191] = 1 // zeroForOne

	for _, n := range []int{0, 1, 159, 160, 191, 255} {
		if _, _, _, err := DecodeSwapInput(swap[:n]); err == nil {
			t.Fatalf("a %d-byte swap input must be refused", n)
		}
		if _, _, _, err := DecodeSwapInput(blueFPoisoned(swap[:n], 512)); err == nil {
			t.Fatalf("a %d-byte swap input with poisoned spare capacity must still be refused", n)
		}
	}
	key, params, hookData, err := DecodeSwapInput(swap)
	if err != nil {
		t.Fatalf("the exact width must decode: %v", err)
	}
	if !params.ZeroForOne {
		t.Fatal("zeroForOne must decode from its own word")
	}
	if hookData != nil {
		t.Fatalf("a swap with no trailing bytes must carry no hook data, got %x", hookData)
	}
	if key.Currency0.Address != common.HexToAddress("0x00000000000000000000000000000000000000D4") {
		t.Fatalf("currency0 must decode, got %s", key.Currency0.Address)
	}

	modify := make([]byte, 288)
	copy(modify[12:32], common.HexToAddress("0x00000000000000000000000000000000000000D6").Bytes())
	for _, n := range []int{0, 159, 255, 287} {
		if _, _, _, err := DecodeModifyLiquidityInput(modify[:n]); err == nil {
			t.Fatalf("a %d-byte modifyLiquidity input must be refused", n)
		}
		if _, _, _, err := DecodeModifyLiquidityInput(blueFPoisoned(modify[:n], 512)); err == nil {
			t.Fatalf("a %d-byte modifyLiquidity input with poisoned spare capacity must still be refused", n)
		}
	}
	if _, _, _, err := DecodeModifyLiquidityInput(modify); err != nil {
		t.Fatalf("the exact width must decode: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tick_math.go / tick_bitmap_math.go / swap_math.go / liquidity_amounts.go
// ---------------------------------------------------------------------------

// TestBlueF_Msb256Domain sweeps the most-significant-bit helper across its whole
// domain. It feeds the tick derivation, so a wrong answer moves a pool's price: the
// sweep pins every power of two, the boundary at zero, and the non-positive inputs
// that must answer 0 rather than fall through to BitLen()-1 == -1.
func TestBlueF_Msb256Domain(t *testing.T) {
	for _, x := range []*big.Int{
		big.NewInt(0),
		big.NewInt(-1),
		new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 200)),
	} {
		if got := msb256(x); got != 0 {
			t.Fatalf("msb256(%s) must be 0 for a non-positive input, got %d", x, got)
		}
	}
	for i := 0; i < 300; i++ {
		p := new(big.Int).Lsh(big.NewInt(1), uint(i))
		if got := msb256(p); got != i {
			t.Fatalf("msb256(2^%d) must be %d, got %d", i, i, got)
		}
		// One below a power of two has the next-lower msb.
		if i > 0 {
			if got := msb256(new(big.Int).Sub(p, big.NewInt(1))); got != i-1 {
				t.Fatalf("msb256(2^%d-1) must be %d, got %d", i, i-1, got)
			}
		}
	}
}

// TestBlueF_Lsb256Domain sweeps the least-significant-bit helper. It is scanned over
// exactly 256 bit positions, so a value whose only set bits sit at or above 256 has
// no answer in range and must fall out as 0 rather than run off the end.
func TestBlueF_Lsb256Domain(t *testing.T) {
	for _, x := range []*big.Int{big.NewInt(0), big.NewInt(-1), big.NewInt(-1 << 20)} {
		if got := lsb256(x); got != 0 {
			t.Fatalf("lsb256(%s) must be 0 for a non-positive input, got %d", x, got)
		}
	}
	for i := 0; i < 256; i++ {
		p := new(big.Int).Lsh(big.NewInt(1), uint(i))
		if got := lsb256(p); got != i {
			t.Fatalf("lsb256(2^%d) must be %d, got %d", i, i, got)
		}
		// Setting a higher bit as well must not move the lowest one.
		q := new(big.Int).Or(p, new(big.Int).Lsh(big.NewInt(1), 255))
		if got := lsb256(q); got != i {
			t.Fatalf("lsb256(2^%d | 2^255) must be %d, got %d", i, i, got)
		}
	}
	// A positive value with no set bit below 256: the scan finds nothing and the
	// helper answers 0 rather than reporting a bit it never saw.
	for _, shift := range []uint{256, 257, 300} {
		if got := lsb256(new(big.Int).Lsh(big.NewInt(1), shift)); got != 0 {
			t.Fatalf("lsb256(2^%d) has no bit in range and must answer 0, got %d", shift, got)
		}
	}
}

// TestBlueF_TickAtSqrtRatioDomain sweeps the tick derivation across its declared
// domain and both sides of each edge. The derivation is the price->tick half of the
// market-open path, so an out-of-domain price must be REFUSED rather than folded
// into a tick, and every admitted price must land on a tick inside [MinTick,
// MaxTick] — including the top of the range, where the high-tick candidate itself
// falls out of range and the derivation must fall back rather than propagate.
func TestBlueF_TickAtSqrtRatioDomain(t *testing.T) {
	for _, bad := range []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(MinSqrtRatio, big.NewInt(1)),
		new(big.Int).Set(MaxSqrtRatio),
		new(big.Int).Add(MaxSqrtRatio, big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 300),
	} {
		if _, err := GetTickAtSqrtRatio(bad); err == nil {
			t.Fatalf("sqrtPriceX96 %s is outside the domain and must be refused", bad)
		}
	}

	// Sweep the whole admitted range, including both edges, and assert the derived
	// tick is in range and consistent with the forward map.
	one := big.NewInt(1)
	probes := []*big.Int{
		new(big.Int).Set(MinSqrtRatio),
		new(big.Int).Add(MinSqrtRatio, one),
		new(big.Int).Set(Q96),
		new(big.Int).Sub(MaxSqrtRatio, one),
		new(big.Int).Sub(MaxSqrtRatio, big.NewInt(2)),
	}
	for i := 1; i < 160; i++ {
		p := new(big.Int).Lsh(big.NewInt(1), uint(i))
		if p.Cmp(MinSqrtRatio) >= 0 && p.Cmp(MaxSqrtRatio) < 0 {
			probes = append(probes, p)
		}
	}
	for _, p := range probes {
		tick, err := GetTickAtSqrtRatio(p)
		if err != nil {
			t.Fatalf("sqrtPriceX96 %s is inside the domain and must derive a tick: %v", p, err)
		}
		if tick < MinTick || tick > MaxTick {
			t.Fatalf("sqrtPriceX96 %s derived tick %d outside [%d, %d]", p, tick, MinTick, MaxTick)
		}
		// The derived tick's own price must not exceed the probe: the derivation
		// must round DOWN, or a swap could cross a tick it never paid for.
		at, err := GetSqrtRatioAtTick(tick)
		if err != nil {
			t.Fatalf("the derived tick %d must itself be in the tick domain: %v", tick, err)
		}
		if at.Cmp(p) > 0 {
			t.Fatalf("sqrtPriceX96 %s derived tick %d whose price %s is above it", p, tick, at)
		}
	}

	// The forward map's own domain is closed on both ends.
	for _, bad := range []int32{MinTick - 1, MaxTick + 1, -1 << 30, 1 << 30} {
		if _, err := GetSqrtRatioAtTick(bad); err == nil {
			t.Fatalf("tick %d is outside [%d, %d] and must be refused", bad, MinTick, MaxTick)
		}
	}
	for _, ok := range []int32{MinTick, MinTick + 1, 0, MaxTick - 1, MaxTick} {
		v, err := GetSqrtRatioAtTick(ok)
		if err != nil {
			t.Fatalf("tick %d is inside the domain and must map: %v", ok, err)
		}
		if v.Sign() <= 0 {
			t.Fatalf("tick %d mapped to a non-positive price %s", ok, v)
		}
	}
}

// TestBlueF_SwapStepClampsRatherThanPropagate pins the fallback in the exact-output
// step: when the next price cannot be computed, the step CLAMPS to the target
// instead of propagating a failure. The clamp is the difference between a swap that
// stops at its limit and one that reverts a whole block's settlement.
func TestBlueF_SwapStepClampsRatherThanPropagate(t *testing.T) {
	// Sweep the well-formed domain first: the clamp must NOT fire there — every
	// step inside a real tick range must reach a price between current and target.
	liquidity := new(big.Int).Lsh(big.NewInt(1), 100)
	current := new(big.Int).Set(Q96)
	for _, target := range []*big.Int{
		new(big.Int).Div(Q96, big.NewInt(2)),
		new(big.Int).Sub(Q96, big.NewInt(1)),
		new(big.Int).Mul(Q96, big.NewInt(2)),
		new(big.Int).Add(Q96, big.NewInt(1)),
	} {
		for _, amount := range []*big.Int{big.NewInt(-1), big.NewInt(-1e9), big.NewInt(1), big.NewInt(1e9)} {
			res := ComputeSwapStep(current, target, liquidity, amount, 3000)
			if res.SqrtRatioNextX96 == nil || res.SqrtRatioNextX96.Sign() <= 0 {
				t.Fatalf("target %s amount %s: the next price must be positive, got %v", target, amount, res.SqrtRatioNextX96)
			}
			lo, hi := current, target
			if lo.Cmp(hi) > 0 {
				lo, hi = hi, lo
			}
			if res.SqrtRatioNextX96.Cmp(lo) < 0 || res.SqrtRatioNextX96.Cmp(hi) > 0 {
				t.Fatalf("target %s amount %s: the next price %s left [%s, %s]", target, amount, res.SqrtRatioNextX96, lo, hi)
			}
			if res.AmountIn.Sign() < 0 || res.AmountOut.Sign() < 0 || res.FeeAmount.Sign() < 0 {
				t.Fatalf("target %s amount %s: a step must not produce negative amounts (%s/%s/%s)",
					target, amount, res.AmountIn, res.AmountOut, res.FeeAmount)
			}
		}
	}

	// Now the fallback itself. A target BELOW the valid price domain makes the
	// exact-output price computation underflow; the step must clamp to the target
	// rather than hand back a nil or a price it could not compute.
	belowDomain := new(big.Int).Neg(Q96)
	liq := new(big.Int).Set(Q96)
	amountOut := new(big.Int).Div(new(big.Int).Mul(liq, big.NewInt(3)), big.NewInt(2)) // 1.5 * liq
	res := ComputeSwapStep(current, belowDomain, liq, amountOut, 3000)
	if res.SqrtRatioNextX96.Cmp(belowDomain) != 0 {
		t.Fatalf("an uncomputable next price must clamp to the target %s, got %s", belowDomain, res.SqrtRatioNextX96)
	}
	if res.AmountOut.Cmp(amountOut) > 0 {
		t.Fatalf("the clamped step must not hand out more than was asked: got %s want <= %s", res.AmountOut, amountOut)
	}
}

// TestBlueF_LiquidityForAmountsTakesTheBindingSide pins the in-range branch: with
// the price inside the range, the mintable liquidity is the MINIMUM of what each
// side funds. Taking the maximum would mint liquidity one side cannot back.
func TestBlueF_LiquidityForAmountsTakesTheBindingSide(t *testing.T) {
	a := new(big.Int).Set(Q96)
	b := new(big.Int).Mul(Q96, big.NewInt(4))
	mid := new(big.Int).Mul(Q96, big.NewInt(2))

	big0 := new(big.Int).Lsh(big.NewInt(1), 90)
	small := big.NewInt(1000)

	// token0 binding: a tiny amount0 against a large amount1.
	got := GetLiquidityForAmounts(mid, a, b, small, big0)
	want0 := GetLiquidityForAmount0(mid, b, small)
	if got.Cmp(want0) != 0 {
		t.Fatalf("token0 must bind: got %s want %s", got, want0)
	}
	// token1 binding: the mirror case.
	got = GetLiquidityForAmounts(mid, a, b, big0, small)
	want1 := GetLiquidityForAmount1(a, mid, small)
	if got.Cmp(want1) != 0 {
		t.Fatalf("token1 must bind: got %s want %s", got, want1)
	}
	// Whichever side binds, the answer is never more than either side funds.
	for _, amt0 := range []*big.Int{small, big0, big.NewInt(1)} {
		for _, amt1 := range []*big.Int{small, big0, big.NewInt(1)} {
			l := GetLiquidityForAmounts(mid, a, b, amt0, amt1)
			l0 := GetLiquidityForAmount0(mid, b, amt0)
			l1 := GetLiquidityForAmount1(a, mid, amt1)
			if l.Cmp(l0) > 0 || l.Cmp(l1) > 0 {
				t.Fatalf("in-range liquidity %s exceeded a funding side (%s / %s)", l, l0, l1)
			}
		}
	}
	// Reversing the range bounds must not change the answer: the helper sorts.
	if GetLiquidityForAmounts(mid, b, a, small, big0).Cmp(want0) != 0 {
		t.Fatal("the range bounds must be order-independent")
	}
	// Outside the range only one side funds.
	below := GetLiquidityForAmounts(a, a, b, small, big.NewInt(0))
	if below.Cmp(GetLiquidityForAmount0(a, b, small)) != 0 {
		t.Fatalf("below the range only token0 funds, got %s", below)
	}
	above := GetLiquidityForAmounts(b, a, b, big.NewInt(0), small)
	if above.Cmp(GetLiquidityForAmount1(a, b, small)) != 0 {
		t.Fatalf("above the range only token1 funds, got %s", above)
	}
}

// blueFUnusedGuards keeps the imports honest for helpers used only in some builds.
var (
	_ = uint256.NewInt
	_ ethtypes.Log
	_ atomic.Requests
)

func TestBlueFProbeTickHigh(t *testing.T) {
	factor, _ := new(big.Int).SetString("255738958999603826347141", 10)
	sub1, _ := new(big.Int).SetString("3402992956809132418596140100660247210", 10)
	add1, _ := new(big.Int).SetString("291339464771989622907027621153398088495", 10)
	maxU := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	calc := func(sq *big.Int) (int32, int32) {
		ratio := new(big.Int).Lsh(sq, 32)
		msb := uint(msb256(ratio))
		if msb >= 128 {
			ratio.Rsh(ratio, msb-127)
		} else {
			ratio.Lsh(ratio, 127-msb)
		}
		u256 := new(big.Int).Lsh(big.NewInt(1), 256)
		log2 := big.NewInt(int64(msb) - 128)
		log2.Lsh(log2, 64)
		if log2.Sign() < 0 {
			log2.Add(log2, u256)
		}
		for i := uint(63); i >= 50; i-- {
			ratio.Mul(ratio, ratio)
			ratio.Rsh(ratio, 127)
			f := new(big.Int).Rsh(ratio, 128)
			log2.Or(log2, new(big.Int).Lsh(f, i))
			if f.Sign() > 0 {
				ratio.Rsh(ratio, uint(f.Uint64()))
			}
			if i == 50 {
				break
			}
		}
		log2.And(log2, maxU)
		ls := new(big.Int).Mul(uint256ToInt256(log2), factor)
		return signedRsh128(new(big.Int).Sub(ls, sub1)), signedRsh128(new(big.Int).Add(ls, add1))
	}
	span := new(big.Int).Sub(MaxSqrtRatio, MinSqrtRatio)
	minHi, maxHi := int32(1<<30), int32(-1<<30)
	bad := 0
	for i := 0; i < 4000; i++ {
		off := new(big.Int).Div(new(big.Int).Mul(span, big.NewInt(int64(i))), big.NewInt(4000))
		sq := new(big.Int).Add(MinSqrtRatio, off)
		_, hi := calc(sq)
		if hi < minHi {
			minHi = hi
		}
		if hi > maxHi {
			maxHi = hi
		}
		if hi < MinTick || hi > MaxTick {
			bad++
		}
	}
	// also log-spaced probes
	for b := 33; b < 161; b++ {
		sq := new(big.Int).Lsh(big.NewInt(1), uint(b))
		if sq.Cmp(MinSqrtRatio) < 0 || sq.Cmp(MaxSqrtRatio) >= 0 {
			continue
		}
		_, hi := calc(sq)
		if hi < minHi {
			minHi = hi
		}
		if hi > maxHi {
			maxHi = hi
		}
		if hi < MinTick || hi > MaxTick {
			bad++
		}
	}
	t.Logf("tickHigh range over the domain: [%d, %d]; out-of-range count=%d; MinTick=%d MaxTick=%d", minHi, maxHi, bad, MinTick, MaxTick)

	// swap_math exact-input clamp probe: the only route needs feePips > feeDenominator.
	func() {
		defer func() { t.Logf("feePips>1e6 exact-input outcome: recover=%v", recover()) }()
		res := ComputeSwapStep(new(big.Int).Mul(Q96, big.NewInt(2)), new(big.Int).Set(Q96), big.NewInt(0), big.NewInt(-1000), 2_000_000)
		t.Logf("no panic: next=%s in=%s out=%s fee=%s", res.SqrtRatioNextX96, res.AmountIn, res.AmountOut, res.FeeAmount)
	}()
}
