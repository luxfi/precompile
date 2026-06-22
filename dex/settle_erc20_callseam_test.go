// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// settle_erc20_callseam_test.go proves the PRODUCTION ERC-20 settlement path: the one
// where the StateDB does NOT itself implement erc20Vault (the real chain's StateDB is
// the evm registry's stateDBBridge, which has no token methods), so the precompile
// must reach the token contract through the EVM execution environment's Call surface —
// poolStateAdapter.callable() -> AccessibleState.GetPrecompileEnv() -> callableEnv.Call.
//
// The existing 0x9999 ERC-20 tests (native_harness_test.go / redteam_fixes_test.go)
// wire a StateDB that DIRECTLY implements erc20Vault (contractStateDBWrapper), which
// exercises branch (a) of stateDBERC20 — the in-state ledger, NOT the EVM sub-call.
// That proves the settlement LEDGER logic but NOT the env wiring. This test fills the
// gap: it drives the deposit / balanceOf / withdraw money path through branch (b), the
// Call seam, against a real in-memory ERC-20 token contract reached only via Call —
// exactly the path that returned ErrERC20VaultUnavailable until the env was plumbed
// (evm/core accessibleStateAdapter.GetPrecompileEnv + evm/registry accessibleStateBridge
// .GetPrecompileEnv). It asserts conservation: every token the depositor loses arrives
// in the 0x9999 vault, the precompile's per-... wait, the 0x9999 vault is the settle
// path; the conservation invariant here is the vault-account balance identity
//
//	realVaultTokenBalance == settleVault[token]  (claims) + 0 (no other pots touched)
//
// at every step, and the depositor + vault token balances always sum to the constant
// total supply (no mint, no burn).

// ─────────────────────────────────────────────────────────────────────────────
// tokenContract is an in-memory ERC-20 reached ONLY through callableEnv.Call. It
// implements balanceOf / transfer / transferFrom with OpenZeppelin allowance
// semantics: transferFrom checks allowance[from][msg.sender]. Because the env's Call
// uses the precompile SELF (0x9999) as msg.sender (no caller proxying), the allowance
// the depositor grants is approve(0x9999) — modelled here by seedAllowance(holder,
// 0x9999). This is the exact on-chain contract a depositor interacts with.
type tokenContract struct {
	addr      common.Address
	balances  map[common.Address]*big.Int
	allowance map[common.Address]map[common.Address]*big.Int // owner -> spender -> amount
}

func newTokenContract(addr common.Address) *tokenContract {
	return &tokenContract{
		addr:      addr,
		balances:  make(map[common.Address]*big.Int),
		allowance: make(map[common.Address]map[common.Address]*big.Int),
	}
}

func (t *tokenContract) bal(a common.Address) *big.Int {
	if t.balances[a] == nil {
		t.balances[a] = big.NewInt(0)
	}
	return t.balances[a]
}

func (t *tokenContract) mint(a common.Address, amt *big.Int) {
	t.balances[a] = new(big.Int).Add(t.bal(a), amt)
}

func (t *tokenContract) approve(owner, spender common.Address, amt *big.Int) {
	if t.allowance[owner] == nil {
		t.allowance[owner] = make(map[common.Address]*big.Int)
	}
	t.allowance[owner][spender] = new(big.Int).Set(amt)
}

func (t *tokenContract) getAllowance(owner, spender common.Address) *big.Int {
	if t.allowance[owner] == nil || t.allowance[owner][spender] == nil {
		return big.NewInt(0)
	}
	return t.allowance[owner][spender]
}

// ERC-20 selectors (must match module_erc20.go).
var (
	tcSelBalanceOf    = crypto.Keccak256([]byte("balanceOf(address)"))[:4]
	tcSelTransfer     = crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
	tcSelTransferFrom = crypto.Keccak256([]byte("transferFrom(address,address,uint256)"))[:4]
)

var errTokenRevert = errors.New("token: reverted")

// run dispatches an ABI call. msgSender is the EVM caller of this sub-call — the
// precompile self (0x9999) for the vault, because the env does NOT proxy the caller.
// Returns ABI-encoded output (a 32-byte word for balanceOf and the bool result for
// transfer/transferFrom) and an error for a revert.
func (t *tokenContract) run(msgSender common.Address, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, errTokenRevert
	}
	sel := input[:4]
	args := input[4:]
	word := func(i int) common.Address {
		return common.BytesToAddress(args[i*32 : i*32+32])
	}
	uintWord := func(i int) *big.Int {
		return new(big.Int).SetBytes(args[i*32 : i*32+32])
	}
	out32 := func(v *big.Int) []byte {
		b := make([]byte, 32)
		v.FillBytes(b)
		return b
	}
	boolOut := func(ok bool) []byte {
		b := make([]byte, 32)
		if ok {
			b[31] = 1
		}
		return b
	}

	switch {
	case string(sel) == string(tcSelBalanceOf):
		if len(args) < 32 {
			return nil, errTokenRevert
		}
		return out32(t.bal(word(0))), nil

	case string(sel) == string(tcSelTransfer):
		if len(args) < 64 {
			return nil, errTokenRevert
		}
		to, amt := word(0), uintWord(1)
		if t.bal(msgSender).Cmp(amt) < 0 {
			return nil, errTokenRevert // insufficient balance reverts
		}
		t.balances[msgSender] = new(big.Int).Sub(t.bal(msgSender), amt)
		t.balances[to] = new(big.Int).Add(t.bal(to), amt)
		return boolOut(true), nil

	case string(sel) == string(tcSelTransferFrom):
		if len(args) < 96 {
			return nil, errTokenRevert
		}
		from, to, amt := word(0), word(1), uintWord(2)
		// OZ allowance check against msg.sender (the precompile self, 0x9999).
		al := t.getAllowance(from, msgSender)
		if al.Cmp(amt) < 0 {
			return nil, errTokenRevert // insufficient allowance reverts
		}
		if t.bal(from).Cmp(amt) < 0 {
			return nil, errTokenRevert // insufficient balance reverts
		}
		t.allowance[from][msgSender] = new(big.Int).Sub(al, amt)
		t.balances[from] = new(big.Int).Sub(t.bal(from), amt)
		t.balances[to] = new(big.Int).Add(t.bal(to), amt)
		return boolOut(true), nil
	}
	return nil, errTokenRevert
}

// ─────────────────────────────────────────────────────────────────────────────
// callSeamEnv is the callableEnv the precompile reaches via GetPrecompileEnv(). It is
// the production analog of evm/registry's precompileEnvBridge: Call routes to the
// named contract with the SELF address (self) as msg.sender (NO caller proxying), the
// exact semantics precompileEnvBridge.Call forwards from the geth env's default.
type callSeamEnv struct {
	self   common.Address // the precompile self (0x9999) — the sub-call's msg.sender
	tokens map[common.Address]*tokenContract
}

func (e *callSeamEnv) ReadOnly() bool { return false }

// Call has the EXACT callableEnv signature module_erc20.go type-asserts.
func (e *callSeamEnv) Call(addr common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	tok, ok := e.tokens[addr]
	if !ok {
		return nil, gas, errTokenRevert // call to a non-contract reverts
	}
	ret, err := tok.run(e.self, input)
	if err != nil {
		return nil, gas, err
	}
	return ret, gas, nil
}

var _ contract.PrecompileEnvironment = (*callSeamEnv)(nil)

// ─────────────────────────────────────────────────────────────────────────────
// callSeamStateDB satisfies contract.StateDB but DELIBERATELY does NOT implement
// erc20Vault, so stateDBERC20 cannot resolve the in-state ledger (branch a) and must
// fall through to the poolStateAdapter self (branch b), which uses the env's Call.
// This is the production shape: the chain's StateDB (stateDBBridge) has no token
// methods. Storage/native-balance use a plain MockStateDB; tokens live in the env.
type callSeamStateDB struct {
	inner *MockStateDB
}

func (s *callSeamStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	return s.inner.GetState(addr, key)
}
func (s *callSeamStateDB) SetState(addr common.Address, key, val common.Hash) common.Hash {
	old := s.inner.GetState(addr, key)
	s.inner.SetState(addr, key, val)
	return old
}
func (s *callSeamStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (s *callSeamStateDB) GetNonce(common.Address) uint64                             { return 0 }
func (s *callSeamStateDB) GetBalance(addr common.Address) *uint256.Int {
	return s.inner.GetBalance(addr)
}
func (s *callSeamStateDB) AddBalance(addr common.Address, amt *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	s.inner.AddBalance(addr, amt)
	return *s.inner.GetBalance(addr)
}
func (s *callSeamStateDB) SubBalance(addr common.Address, amt *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	s.inner.SubBalance(addr, amt)
	return *s.inner.GetBalance(addr)
}
func (s *callSeamStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int { return big.NewInt(0) }
func (s *callSeamStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)  {}
func (s *callSeamStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)  {}
func (s *callSeamStateDB) CreateAccount(addr common.Address)                          { s.inner.CreateAccount(addr) }
func (s *callSeamStateDB) Exist(addr common.Address) bool                             { return s.inner.Exist(addr) }
func (s *callSeamStateDB) AddLog(log *ethtypes.Log)                                   { s.inner.AddLog(log) }
func (s *callSeamStateDB) Logs() []*ethtypes.Log                                      { return s.inner.Logs() }
func (s *callSeamStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}
func (s *callSeamStateDB) TxHash() common.Hash      { return common.Hash{} }
func (s *callSeamStateDB) Snapshot() int            { return 0 }
func (s *callSeamStateDB) RevertToSnapshot(int)     {}

// Compile-time proof this StateDB satisfies the external contract.StateDB the bridge
// plumbs. Its NON-implementation of erc20Vault (the load-bearing fact that forces the
// Call seam, branch b of stateDBERC20) is asserted at runtime by assertNotERC20Vault.
var _ contract.StateDB = (*callSeamStateDB)(nil)

func assertNotERC20Vault(t *testing.T, s contract.StateDB) {
	t.Helper()
	if _, ok := s.(erc20Vault); ok {
		t.Fatal("test invariant broken: callSeamStateDB must NOT implement erc20Vault, " +
			"otherwise stateDBERC20 resolves the in-state ledger and the Call seam is not exercised")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// callSeamState is the AccessibleState whose GetPrecompileEnv() returns the live
// callableEnv — the thing that was nil before the wiring fix.
type callSeamState struct {
	sdb       *callSeamStateDB
	env       *callSeamEnv
	timestamp uint64
}

func (m *callSeamState) GetStateDB() contract.StateDB { return m.sdb }
func (m *callSeamState) GetBlockContext() contract.BlockContext {
	return &mockBlockCtx{number: big.NewInt(int64(m.sdb.inner.blockNumber)), timestamp: m.timestamp}
}
func (m *callSeamState) GetConsensusContext() context.Context { return context.Background() }
func (m *callSeamState) GetChainConfig() precompileconfig.ChainConfig { return nil }

// GetPrecompileEnv mirrors evm/registry's accessibleStateBridge.GetPrecompileEnv: it
// returns an UNTYPED nil when no env is wired (so the precompile's nil check in
// callable() fires), never a typed-nil interface. This is the production contract.
func (m *callSeamState) GetPrecompileEnv() contract.PrecompileEnvironment {
	if m.env == nil {
		return nil
	}
	return m.env
}

var _ contract.AccessibleState = (*callSeamState)(nil)

// vaultTokenBalance is the REAL token balance the 0x9999 vault holds in the token
// contract — the on-chain ground truth the conservation invariant pins the ledger to.
func vaultTokenBalance(env *callSeamEnv, token common.Address) *big.Int {
	return new(big.Int).Set(env.tokens[token].bal(poolManagerAddr9999))
}

// TestERC20Settle_CallSeam_DepositWithdrawConserves is the money-path proof: with the
// env wired (GetPrecompileEnv != nil), an ERC-20 leg settles through 0x9999 via the
// EVM Call seam — deposit (transferFrom into the vault) -> balanceOf (read claim) ->
// withdraw (transfer out of the vault) — and the vault-account conservation invariant
// holds at every step with zero mint/burn.
func TestERC20Settle_CallSeam_DepositWithdrawConserves(t *testing.T) {
	const (
		totalSupply = int64(1_000_000)
		depositAmt  = int64(250_000)
		withdrawAmt = int64(90_000)
	)
	token := common.HexToAddress("0x000000000000000000000000000000000000C0FE") // an ERC-20 (e.g. LUSD/LETH)
	depositor := common.HexToAddress("0x1111111111111111111111111111111111111111")

	tc := newTokenContract(token)
	tc.mint(depositor, big.NewInt(totalSupply))
	// The depositor grants the 0x9999 vault an allowance (approve(0x9999, ...)) — the
	// allowance transferFrom pulls against (msg.sender == self == 0x9999, NO proxying).
	tc.approve(depositor, poolManagerAddr9999, big.NewInt(depositAmt))

	env := &callSeamEnv{self: poolManagerAddr9999, tokens: map[common.Address]*tokenContract{token: tc}}
	state := &callSeamState{
		sdb:       &callSeamStateDB{inner: NewMockStateDB()},
		env:       env,
		timestamp: DexSettleActivationTime, // live-chain era (0x9999 logs active)
	}
	// Load-bearing: the StateDB must NOT be an erc20Vault, forcing the Call seam.
	assertNotERC20Vault(t, state.GetStateDB())

	// Sanity: the env actually exposes the Call surface the precompile type-asserts —
	// this is precisely what returned nil before the evm wiring fix.
	if _, ok := state.GetPrecompileEnv().(callableEnv); !ok {
		t.Fatal("GetPrecompileEnv() does not satisfy callableEnv: ERC-20 leg would refuse with ErrERC20VaultUnavailable")
	}

	c := &SettleContract{protocolFeeController: common.HexToAddress("0xFEE0000000000000000000000000000000000001")}
	aid := assetID(Currency{Address: token})

	// Conservation oracle: depositor + vault token balances == totalSupply, always; and
	// the vault's real token balance == settleVault[token] (the only pot deposits touch).
	checkConservation := func(step string) {
		t.Helper()
		dBal := tc.bal(depositor)
		vBal := vaultTokenBalance(env, token)
		sum := new(big.Int).Add(dBal, vBal)
		if sum.Cmp(big.NewInt(totalSupply)) != 0 {
			t.Fatalf("%s: token supply not conserved: depositor=%s + vault=%s = %s, want %d",
				step, dBal, vBal, sum, totalSupply)
		}
		ledger := loadSettleVault(newPoolStateAdapter(state), aid)
		if ledger.Cmp(vBal) != 0 {
			t.Fatalf("%s: vault-account invariant broken: settleVault[token]=%s != real vault token balance=%s",
				step, ledger, vBal)
		}
	}
	checkConservation("genesis")

	// ── DEPOSIT: transferFrom depositor -> 0x9999 through the Call seam ──────────────
	depData := make([]byte, 64)
	copy(depData[12:32], token.Bytes())
	big.NewInt(depositAmt).FillBytes(depData[32:64])
	out, _, err := c.Run(state, depositor, poolManagerAddr9999,
		prependSelector(SelectorDeposit, depData), 5_000_000, false)
	if err != nil {
		t.Fatalf("deposit through Call seam failed (env not wired?): %v", err)
	}
	if got := new(big.Int).SetBytes(out); got.Cmp(big.NewInt(depositAmt)) != 0 {
		t.Fatalf("deposit returned credited=%s, want %d (observed delta)", got, depositAmt)
	}
	if vBal := vaultTokenBalance(env, token); vBal.Cmp(big.NewInt(depositAmt)) != 0 {
		t.Fatalf("after deposit: vault token balance=%s, want %d — transferFrom did not reach the token via Call", vBal, depositAmt)
	}
	if claim := loadDepositorClaim(newPoolStateAdapter(state), depositor, aid); claim.Cmp(big.NewInt(depositAmt)) != 0 {
		t.Fatalf("after deposit: depositor claim=%s, want %d", claim, depositAmt)
	}
	checkConservation("after-deposit")

	// ── balanceOf: read the depositor's claim (read-only path) ───────────────────────
	balData := make([]byte, 64)
	copy(balData[12:32], depositor.Bytes())
	copy(balData[44:64], token.Bytes())
	balOut, _, err := c.Run(state, depositor, poolManagerAddr9999,
		prependSelector(SelectorBalanceOf, balData), 5_000_000, true)
	if err != nil {
		t.Fatalf("balanceOf failed: %v", err)
	}
	if got := new(big.Int).SetBytes(balOut); got.Cmp(big.NewInt(depositAmt)) != 0 {
		t.Fatalf("balanceOf=%s, want %d", got, depositAmt)
	}

	// ── WITHDRAW: transfer 0x9999 -> depositor through the Call seam ─────────────────
	wData := make([]byte, 64)
	copy(wData[12:32], token.Bytes())
	big.NewInt(withdrawAmt).FillBytes(wData[32:64])
	wOut, _, err := c.Run(state, depositor, poolManagerAddr9999,
		prependSelector(SelectorWithdraw, wData), 5_000_000, false)
	if err != nil {
		t.Fatalf("withdraw through Call seam failed: %v", err)
	}
	if got := new(big.Int).SetBytes(wOut); got.Cmp(big.NewInt(withdrawAmt)) != 0 {
		t.Fatalf("withdraw realized=%s, want %d", got, withdrawAmt)
	}
	wantVault := big.NewInt(depositAmt - withdrawAmt)
	if vBal := vaultTokenBalance(env, token); vBal.Cmp(wantVault) != 0 {
		t.Fatalf("after withdraw: vault token balance=%s, want %d — transfer did not reach the token via Call", vBal, wantVault)
	}
	if claim := loadDepositorClaim(newPoolStateAdapter(state), depositor, aid); claim.Cmp(wantVault) != 0 {
		t.Fatalf("after withdraw: depositor claim=%s, want %d", claim, wantVault)
	}
	// Depositor's on-chain token balance back up by the withdrawn amount.
	wantDepositor := big.NewInt(totalSupply - depositAmt + withdrawAmt)
	if dBal := tc.bal(depositor); dBal.Cmp(wantDepositor) != 0 {
		t.Fatalf("after withdraw: depositor token balance=%s, want %d", dBal, wantDepositor)
	}
	checkConservation("after-withdraw")
}

// TestERC20Settle_NoEnv_RefusesFailSecure proves the fail-secure posture is intact:
// when GetPrecompileEnv() returns nil (a chain that did NOT wire the Call surface, or
// a non-EVM caller) the ERC-20 deposit REFUSES with the vault-unavailable error rather
// than minting an unbacked claim. This is the behaviour the wiring fix REPLACES on a
// real chain — and must remain the safe default everywhere the env is absent.
func TestERC20Settle_NoEnv_RefusesFailSecure(t *testing.T) {
	token := common.HexToAddress("0x000000000000000000000000000000000000C0FE")
	depositor := common.HexToAddress("0x1111111111111111111111111111111111111111")

	state := &callSeamState{
		sdb:       &callSeamStateDB{inner: NewMockStateDB()},
		env:       nil, // NO env — GetPrecompileEnv() returns a typed-nil *callSeamEnv? guard below
		timestamp: DexSettleActivationTime,
	}
	// Guard against the typed-nil trap: GetPrecompileEnv must return an untyped nil so
	// the precompile's nil check fires. callSeamState returns m.env directly; a nil
	// *callSeamEnv stored in the interface would be non-nil. Force a true nil here.
	if state.env != nil {
		t.Fatal("setup")
	}

	c := &SettleContract{protocolFeeController: common.HexToAddress("0xFEE0000000000000000000000000000000000001")}
	depData := make([]byte, 64)
	copy(depData[12:32], token.Bytes())
	big.NewInt(1000).FillBytes(depData[32:64])
	_, _, err := c.Run(state, depositor, poolManagerAddr9999,
		prependSelector(SelectorDeposit, depData), 5_000_000, false)
	if err == nil {
		t.Fatal("ERC-20 deposit with NO env succeeded — fail-secure refusal missing (would mint unbacked claim)")
	}
	if !errors.Is(err, ErrERC20TransferFailed) && !errors.Is(err, ErrERC20VaultUnavailable) {
		t.Fatalf("expected vault-unavailable/transfer-failed refusal, got: %v", err)
	}
}
