// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package swap

import (
	"context"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Raw call encoders. The harness helpers (e.lock/e.claim/...) always encode a
// well-formed call at a fixed gas budget; these return the raw input so a test
// can vary the length or the gas independently and observe what Run charges.
// ---------------------------------------------------------------------------

func zzLockInput(hashlock common.Hash, recipient, refundAddr, asset common.Address, amount *big.Int, timeout uint64) []byte {
	in := selBytes(selLock)
	in = append(in, hashlock[:]...)
	in = append(in, addrArg(recipient)...)
	in = append(in, addrArg(refundAddr)...)
	in = append(in, addrArg(asset)...)
	in = append(in, amountArg(amount)...)
	in = append(in, u64Arg(timeout)...)
	return in
}

func zzClaimInput(swapId common.Hash, preimage [preimageLen]byte) []byte {
	in := selBytes(selClaim)
	in = append(in, swapId[:]...)
	in = append(in, preimage[:]...)
	return in
}

func zzRefundInput(swapId common.Hash) []byte {
	return append(selBytes(selRefund), swapId[:]...)
}

func zzGetSwapInput(swapId common.Hash) []byte {
	return append(selBytes(selGetSwap), swapId[:]...)
}

func zzGetPreimageInput(hashlock common.Hash) []byte {
	return append(selBytes(selGetPreimage), hashlock[:]...)
}

// zzWellFormedLock is the canonical valid lock payload used by the length and
// gas tables, so those tables vary exactly one thing.
func zzWellFormedLock() []byte {
	return zzLockInput(hashOf(preimageOf(0xE1)), user, maker, usdc, big.NewInt(1000), timeout)
}

// ---------------------------------------------------------------------------
// zzSeedLocked writes a Locked swap straight into the trie WITHOUT moving any
// value. It fabricates the corrupted / adversarial states that the conservation
// guards exist to refuse and that no honest sequence can reach.
// ---------------------------------------------------------------------------

func zzSeedLocked(db stateRW, swapId, hashlock common.Hash, recipient, refundAddr, asset common.Address, amount *big.Int, expiry uint64) {
	storeStatus(db, swapId, StatusLocked)
	storeHash(db, swapId, fHashlock, hashlock)
	storeAddress(db, swapId, fRecipient, recipient)
	storeAddress(db, swapId, fRefund, refundAddr)
	storeAddress(db, swapId, fAsset, asset)
	storeAmount(db, swapId, fAmount, amount)
	storeTimeout(db, swapId, expiry)
}

// ---------------------------------------------------------------------------
// zzNoVault is a contract.StateDB that deliberately does NOT carry the optional
// erc20Vault capability: every ERC-20 path must refuse cleanly (ErrVaultUnavailable)
// rather than fake a credit. Method forwarding is explicit — embedding *mockState
// would promote the token methods and hand it the capability by accident.
// ---------------------------------------------------------------------------

type zzNoVault struct{ m *mockState }

var _ contract.StateDB = (*zzNoVault)(nil)

func zzNewNoVault() *zzNoVault { return &zzNoVault{m: newMockState()} }

func (s *zzNoVault) GetState(a common.Address, k common.Hash) common.Hash { return s.m.GetState(a, k) }

func (s *zzNoVault) SetState(a common.Address, k, v common.Hash) common.Hash {
	return s.m.SetState(a, k, v)
}

func (s *zzNoVault) SetNonce(a common.Address, n uint64, r tracing.NonceChangeReason) {
	s.m.SetNonce(a, n, r)
}
func (s *zzNoVault) GetNonce(a common.Address) uint64         { return s.m.GetNonce(a) }
func (s *zzNoVault) GetBalance(a common.Address) *uint256.Int { return s.m.GetBalance(a) }

func (s *zzNoVault) AddBalance(a common.Address, v *uint256.Int, r tracing.BalanceChangeReason) uint256.Int {
	return s.m.AddBalance(a, v, r)
}

func (s *zzNoVault) SubBalance(a common.Address, v *uint256.Int, r tracing.BalanceChangeReason) uint256.Int {
	return s.m.SubBalance(a, v, r)
}

func (s *zzNoVault) GetBalanceMultiCoin(a common.Address, h common.Hash) *big.Int {
	return s.m.GetBalanceMultiCoin(a, h)
}
func (s *zzNoVault) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (s *zzNoVault) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (s *zzNoVault) CreateAccount(common.Address)                              {}
func (s *zzNoVault) Exist(common.Address) bool                                 { return true }
func (s *zzNoVault) AddLog(l *ethtypes.Log)                                    { s.m.AddLog(l) }
func (s *zzNoVault) Logs() []*ethtypes.Log                                     { return s.m.Logs() }
func (s *zzNoVault) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}
func (s *zzNoVault) TxHash() common.Hash  { return common.Hash{} }
func (s *zzNoVault) Snapshot() int        { return 0 }
func (s *zzNoVault) RevertToSnapshot(int) {}

// ---------------------------------------------------------------------------
// zzState is an AccessibleState whose StateDB and BlockContext are both settable,
// so a test can hand Run a vault-less StateDB or a nil BlockContext.
// ---------------------------------------------------------------------------

type zzState struct {
	db  contract.StateDB
	blk contract.BlockContext
}

var _ contract.AccessibleState = (*zzState)(nil)

func (a *zzState) GetStateDB() contract.StateDB                     { return a.db }
func (a *zzState) GetBlockContext() contract.BlockContext           { return a.blk }
func (a *zzState) GetConsensusContext() context.Context             { return context.Background() }
func (a *zzState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (a *zzState) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

// ---------------------------------------------------------------------------
// Invariant assertions reused across the behavioural suites.
// ---------------------------------------------------------------------------

// zzEqBig is eqBig with an OPTIONAL explanation attached. Same Cmp-based
// comparison, avoiding the nil-vs-empty `abs` pitfall of reflect-based equality
// on big.Int.
func zzEqBig(t require.TestingT, want, got *big.Int, msgAndArgs ...any) {
	if len(msgAndArgs) == 0 {
		require.Truef(t, want.Cmp(got) == 0, "want %s, got %s", want, got)
		return
	}
	format, ok := msgAndArgs[0].(string)
	require.True(t, ok, "zzEqBig message must be a format string")
	require.Truef(t, want.Cmp(got) == 0, "want %s, got %s: "+format,
		append([]any{want, got}, msgAndArgs[1:]...)...)
}

// zzConserved asserts the conservation invariant for one ERC-20 asset: the
// precompile's own reserve ledger equals the value actually sitting in the vault.
func zzConserved(t require.TestingT, e *env, asset common.Address) {
	eqBig(t, e.reserve(asset), e.db().bal(asset, swapAddr))
}

// zzConservedNative is the same statement for native LUX, read off the real EVM
// balance ledger.
func zzConservedNative(t require.TestingT, e *env) {
	eqBig(t, e.reserve(native), e.db().nativeBal(swapAddr))
}

// zzFingerprint is the OBSERVABLE state of the mock: every storage slot that
// READS non-zero, every non-zero balance, and the event log height.
//
// A slot explicitly written to zero is deliberately excluded. GetState cannot
// tell such a slot from one never written, and the EVM trie stores neither — so
// the transient reentrancy guard, which enterGuard sets on the way in and the
// deferred exitGuard clears on the way out, leaves a zero-valued map entry that
// is NOT a state change. Comparing raw maps would flag that no-op; comparing
// fingerprints asserts the property actually wanted ("nothing observable moved")
// while still catching any genuine write, including an emitted event.
//
// Do not "tighten" this back into a raw map comparison: it fails on every
// refusal that reaches the guarded region.
func zzFingerprint(m *mockState) string {
	lines := make([]string, 0, len(m.storage))
	for k, v := range m.storage {
		if v == (common.Hash{}) {
			continue
		}
		lines = append(lines, "slot "+k.addr.Hex()+" "+k.key.Hex()+" = "+v.Hex())
	}
	for token, owners := range m.tokens {
		for owner, bal := range owners {
			if bal == nil || bal.Sign() == 0 {
				continue
			}
			lines = append(lines, "token "+token.Hex()+" "+owner.Hex()+" = "+bal.String())
		}
	}
	for addr, bal := range m.native {
		if bal == nil || bal.Sign() == 0 {
			continue
		}
		lines = append(lines, "native "+addr.Hex()+" = "+bal.String())
	}
	sort.Strings(lines)
	return strconv.Itoa(len(m.logs)) + " logs\n" + strings.Join(lines, "\n")
}

// zzUnchanged asserts that running `act` moves no observable state — the
// invariant every refusal owes.
func zzUnchanged(t require.TestingT, m *mockState, act func()) {
	before := zzFingerprint(m)
	act()
	require.Equal(t, before, zzFingerprint(m), "a refused call must not change observable state")
}

// zzStatus reads the on-chain status word through the public view, not the
// package-private loader, so the view and the storage cannot drift apart.
func zzStatus(t require.TestingT, e *env, swapId common.Hash) uint8 {
	out, err := e.getSwap(swapId, true)
	require.NoError(t, err)
	require.Len(t, out, 8*32)
	return out[31]
}
