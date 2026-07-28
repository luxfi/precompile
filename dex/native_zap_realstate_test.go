// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/holiman/uint256"

	"github.com/luxfi/crypto"
	dexcore "github.com/luxfi/dex/pkg/dex"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/state"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	"github.com/luxfi/geth/params"
	"github.com/luxfi/ids"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/luxfi/vm/chains/atomic"
)

// native_zap_realstate_test.go is the REAL *state.StateDB integration proof for the NATIVE-ZAP
// ERC-20 fund-strand fix — the test the MockStateDB suite STRUCTURALLY CANNOT be: the mock
// models neither geth's snapshot/journal nor (the actual root cause) EIP-158 empty-account
// reaping at Finalise(deleteEmptyObjects=true), so it kept the post-deposit writes (green) while
// the real host reaped them (live fund-strand). This drives the REAL dex SettleContract.Run
// against a REAL luxfi/geth *state.StateDB with a REAL vm.EVM Call seam (transferFrom on a REAL
// deployed ERC-20) and the REAL end-of-tx Finalise(true) — the production money path exactly.
//
// THE DISCRIMINATOR (RED on the unfixed code, GREEN after): a fresh 0x9999 vault is an EMPTY
// account; an ERC-20 deposit moves the TOKEN (the token contract's storage) but leaves 0x9999
// with zero native balance/nonce/code, so under EIP-158 the otherwise-empty 0x9999 — AND its
// seamReserve / dexcore-available storage — is DELETED at Finalise ⇒ seamReserve=0 while
// balanceOf(0x9999)=deposit (funds stranded, zero fill). The fix keeps 0x9999 NON-EMPTY (a nonce
// marker at the first 0x9999 write; module.go poolStateAdapter.SetState → ensureVaultAccount-
// Persists), so the storage survives Finalise. (See native_zap.go for the corrected diagnosis;
// the harness_probe matrix proved a NON-nested single write is reaped too — the nested call was
// a red herring.)

// ─────────────────────── REAL contract.StateDB over a geth *state.StateDB ───────────────────
// Embeds the geth StateDB (which already provides GetState/SetState/Add+SubBalance/Set+GetNonce/
// CreateAccount/Exist/AddLog/Logs/GetCodeSize/TxHash/Snapshot/RevertToSnapshot with the matching
// signatures) and adds only the few external-only methods. It deliberately does NOT implement
// erc20Vault, FORCING the dex onto the EVM Call seam (transferFrom on the real token) — the
// production path, not the in-state-vault test path.
type rsStateDB struct{ *state.StateDB }

func (s *rsStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int  { return new(big.Int) }
func (s *rsStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (s *rsStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int) {}
func (s *rsStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}

var _ contract.StateDB = (*rsStateDB)(nil)

// rsEnv wraps a REAL geth vm.PrecompileEnvironment, exposing the optional callableEnv (Call) the
// dex type-asserts — exactly as evm/registry's precompileEnvBridge does (no caller proxying: the
// sub-call's msg.sender is the settlement self, 0x9999/0x9996).
type rsEnv struct{ inner vm.PrecompileEnvironment }

func (e *rsEnv) ReadOnly() bool { return e.inner.ReadOnly() }
func (e *rsEnv) Call(addr common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	return e.inner.Call(addr, input, gas, value)
}

var _ contract.PrecompileEnvironment = (*rsEnv)(nil)

type rsBlockCtx struct {
	num *big.Int
	ts  uint64
}

func (b *rsBlockCtx) Number() *big.Int                                       { return b.num }
func (b *rsBlockCtx) Timestamp() uint64                                      { return b.ts }
func (b *rsBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

// rsState implements BOTH contract.AccessibleState and contract.AtomicState backed by the real
// geth StateDB + EVM env, so the value path (which type-asserts AtomicState for the runtime
// networkID/cChainID the resolver binds to) runs unchanged over the real host.
type rsState struct {
	sdb        *rsStateDB
	env        *rsEnv
	num        *big.Int
	ts         uint64
	networkID  uint32
	cChainID   ids.ID
	governance common.Address
}

func (s *rsState) GetStateDB() contract.StateDB                     { return s.sdb }
func (s *rsState) GetBlockContext() contract.BlockContext           { return &rsBlockCtx{num: s.num, ts: s.ts} }
func (s *rsState) GetConsensusContext() context.Context             { return context.Background() }
func (s *rsState) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (s *rsState) GetPrecompileEnv() contract.PrecompileEnvironment { return s.env }

// AtomicState — the sync swap uses only NetworkID/CChainID (resolverForRuntime); the rest return
// safe defaults (no cross-chain atomic op on the in-process sync path).
func (s *rsState) AtomicMemory() atomic.SharedMemory    { return nil }
func (s *rsState) NetworkID() uint32                    { return s.networkID }
func (s *rsState) ChainID() ids.ID                      { return s.cChainID }
func (s *rsState) CChainID() ids.ID                     { return s.cChainID }
func (s *rsState) GovernanceController() common.Address { return s.governance }
func (s *rsState) DChainID() ids.ID                     { return ids.Empty }
func (s *rsState) TxID() ids.ID                         { return ids.ID(s.sdb.TxHash()) }
func (s *rsState) CallIndex() uint32                    { return 0 }

var (
	_ contract.AccessibleState = (*rsState)(nil)
	_ contract.AtomicState     = (*rsState)(nil)
)

// rsHarness bundles the real EVM + state and the participant/token fixtures.
type rsHarness struct {
	t          *testing.T
	gdb        *state.StateDB
	evm        *vm.EVM
	deployer   common.Address
	maker      common.Address
	taker      common.Address
	base       common.Address // currency0 (sorted < quote)
	quote      common.Address // currency1
	networkID  uint32
	cChainID   ids.ID
	governance common.Address
	nextTx     uint64
}

const rsGas = 9_000_000

func newRSHarness(t *testing.T) *rsHarness {
	t.Helper()
	gdb, err := state.New(ethtypes.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	zero := common.Hash{}
	blockCtx := vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *uint256.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *uint256.Int) {},
		BlockNumber: big.NewInt(1), Time: 1, Random: &zero,
	}
	evm := vm.NewEVM(blockCtx, gdb, params.MergedTestChainConfig, vm.Config{})

	h := &rsHarness{
		t:          t,
		gdb:        gdb,
		evm:        evm,
		deployer:   common.HexToAddress("0xde0000000000000000000000000000000000d101"),
		maker:      common.HexToAddress("0xaa00000000000000000000000000000000000001"),
		taker:      common.HexToAddress("0xbb00000000000000000000000000000000000002"),
		networkID:  1,
		cChainID:   ids.ID{0xCC},
		governance: common.HexToAddress("0x60F0000000000000000000000000000000000A11"),
	}
	for _, a := range []common.Address{h.deployer, h.maker, h.taker} {
		gdb.CreateAccount(a)
		gdb.AddBalance(a, uint256.NewInt(1_000_000_000_000_000_000), tracing.BalanceChangeUnspecified)
	}

	// Deploy two REAL ERC-20s (TestToken; constructor mints the supply to the deployer), then
	// sort by address so currency0 < currency1 (the V4 invariant), and fund maker/taker.
	tokA := h.deployToken("AAA", 1_000_000)
	tokB := h.deployToken("BBB", 1_000_000)
	h.base, h.quote = tokA, tokB
	if h.base.Cmp(h.quote) > 0 {
		h.base, h.quote = h.quote, h.base
	}
	// maker holds the QUOTE (rests a bid that pays quote); taker holds the BASE (sells base).
	h.tokenTransfer(h.deployer, h.quote, h.maker, big.NewInt(500_000))
	h.tokenTransfer(h.deployer, h.base, h.taker, big.NewInt(500_000))

	// Install the PERMISSIONLESS resolver bound to this runtime identity. The deployed tokens
	// carry REAL code, so the value path's on-chain verifier (EXTCODESIZE) admits them with no
	// mock code-seeding. Restore the prior global on cleanup.
	prev := installedAssetResolver.Load()
	if err := InstallAssetResolver(newTestAssetResolver(h.networkID, h.cChainID), h.networkID, h.cChainID); err != nil {
		t.Fatalf("InstallAssetResolver: %v", err)
	}
	t.Cleanup(func() { installedAssetResolver.Store(prev) })

	h.commit() // settle deployment/funding into a clean base state.
	return h
}

// commit runs the production end-of-tx state commit (Finalise(true) — the EIP-158 empty-account
// reaping point — then IntermediateRoot(true)).
func (h *rsHarness) commit() {
	h.gdb.Finalise(true)
	h.gdb.IntermediateRoot(true)
}

func (h *rsHarness) newTxCtx() {
	h.nextTx++
	h.gdb.SetTxContext(common.BigToHash(new(big.Int).SetUint64(h.nextTx)), int(h.nextTx))
}

func (h *rsHarness) deployToken(symbol string, supply int64) common.Address {
	h.t.Helper()
	h.newTxCtx()
	bin, err := os.ReadFile("testdata/TestToken.bin")
	if err != nil {
		h.t.Fatalf("read TestToken.bin: %v", err)
	}
	initCode := append(common.FromHex(stripHexWS(string(bin))), rsEncodeCtor("Tok", symbol, big.NewInt(supply))...)
	_, addr, _, err := h.evm.Create(h.deployer, initCode, rsGas, uint256.NewInt(0))
	if err != nil {
		h.t.Fatalf("deploy %s: %v", symbol, err)
	}
	return addr
}

func (h *rsHarness) tokenTransfer(from, token, to common.Address, amount *big.Int) {
	h.t.Helper()
	h.newTxCtx()
	data := append(rsSel("transfer(address,uint256)"), common.LeftPadBytes(to.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(amount.Bytes(), 32)...)
	if _, _, err := h.evm.Call(from, token, data, rsGas, uint256.NewInt(0)); err != nil {
		h.t.Fatalf("token transfer: %v", err)
	}
}

func (h *rsHarness) approve9999(owner, token common.Address, amount *big.Int) {
	h.t.Helper()
	h.newTxCtx()
	data := append(rsSel("approve(address,uint256)"), common.LeftPadBytes(poolManagerAddr9999.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(amount.Bytes(), 32)...)
	if _, _, err := h.evm.Call(owner, token, data, rsGas, uint256.NewInt(0)); err != nil {
		h.t.Fatalf("approve(0x9999): %v", err)
	}
}

// callDex invokes the REAL dex precompile at `self` (0x9999) with `caller` as msg.sender, over a
// REAL vm.PrecompileEnvironment (the production Call seam). It snapshots before and reverts on
// error, exactly as geth's EVM.Call wraps a precompile CALL — so a refusal is observably atomic.
func (h *rsHarness) callDex(caller common.Address, calldata []byte) ([]byte, error) {
	h.newTxCtx()
	snap := h.gdb.Snapshot()
	env := vm.NewPrecompileEnvironment(h.evm, caller, poolManagerAddr9999, rsGas, false)
	st := &rsState{
		sdb: &rsStateDB{h.gdb}, env: &rsEnv{inner: env},
		num: big.NewInt(1), ts: 1,
		networkID: h.networkID, cChainID: h.cChainID, governance: h.governance,
	}
	out, _, err := (&SettleContract{}).Run(st, caller, poolManagerAddr9999, calldata, rsGas, false)
	if err != nil {
		h.gdb.RevertToSnapshot(snap)
	}
	return out, err
}

func (h *rsHarness) swapDeposit(caller, token common.Address, amount int64) {
	h.t.Helper()
	data := make([]byte, 64)
	copy(data[12:32], token.Bytes())
	big.NewInt(amount).FillBytes(data[32:64])
	if _, err := h.callDex(caller, prependSelector(SelectorSwapDeposit, data)); err != nil {
		h.t.Fatalf("swapDeposit(token=%s amount=%d): %v", token.Hex(), amount, err)
	}
}

func (h *rsHarness) swapWithdraw(caller, token common.Address, amount int64) uint64 {
	h.t.Helper()
	data := make([]byte, 64)
	copy(data[12:32], token.Bytes())
	big.NewInt(amount).FillBytes(data[32:64])
	out, err := h.callDex(caller, prependSelector(SelectorSwapWithdraw, data))
	if err != nil {
		h.t.Fatalf("swapWithdraw(token=%s amount=%d): %v", token.Hex(), amount, err)
	}
	return new(big.Int).SetBytes(out).Uint64()
}

func (h *rsHarness) market() PoolKey {
	return PoolKey{
		Currency0:   Currency{Address: h.base},
		Currency1:   Currency{Address: h.quote},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
}

func (h *rsHarness) swapPlace(caller common.Address, isBid bool, priceGrid, size uint64) uint64 {
	h.t.Helper()
	data := make([]byte, 256)
	copy(data[0:160], EncodePoolKeyABI(h.market()))
	if isBid {
		data[191] = 1
	}
	new(big.Int).SetUint64(priceGrid).FillBytes(data[192:224])
	new(big.Int).SetUint64(size).FillBytes(data[224:256])
	out, err := h.callDex(caller, prependSelector(SelectorSwapPlace, data))
	if err != nil {
		h.t.Fatalf("swapPlace(isBid=%v price=%d size=%d): %v", isBid, priceGrid, size, err)
	}
	return new(big.Int).SetBytes(out).Uint64()
}

// swapSell drives a real V4 SELL of `amountIn` base for quote through 0x9999, declaring a min-out
// floor via DM01 hookData (the sync path refuses an unprotected no-limit SELL).
func (h *rsHarness) swapSell(caller common.Address, amountIn int64, minOut uint64) ([]byte, error) {
	params := SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(-amountIn), SqrtPriceLimitX96: big.NewInt(0)}
	calldata := buildSwapCalldata(h.market(), params, EncodeMinOutHookData(minOut))
	return h.callDex(caller, prependSelector(SelectorSwap, calldata))
}

// seamReserve / available reads via the SAME poolStateAdapter the production money path uses.
func (h *rsHarness) seam(token common.Address) uint64 {
	kv := newPoolStateAdapter(&rsState{sdb: &rsStateDB{h.gdb}, num: big.NewInt(1), ts: 1})
	return loadSeamReserve(kv, assetID(Currency{Address: token})).Uint64()
}
func (h *rsHarness) avail(who, token common.Address) uint64 {
	store := newEVMStore(newPoolStateAdapter(&rsState{sdb: &rsStateDB{h.gdb}, num: big.NewInt(1), ts: 1}))
	v, _ := dexcore.GetAvailable(store, accountFromAddress(who), assetID(Currency{Address: token}))
	return v
}
func (h *rsHarness) ercBal(token, holder common.Address) uint64 {
	h.newTxCtx()
	data := append(rsSel("balanceOf(address)"), common.LeftPadBytes(holder.Bytes(), 32)...)
	ret, _, err := h.evm.Call(h.deployer, token, data, rsGas, uint256.NewInt(0))
	if err != nil {
		h.t.Fatalf("balanceOf: %v", err)
	}
	return new(big.Int).SetBytes(ret).Uint64()
}

// ──────────────────────────────────────── THE TEST ─────────────────────────────────────────

// TestNativeZAP_RealStateDB_ERC20DepositPlaceSwapWithdraw is the end-to-end money-path proof
// over a REAL *state.StateDB: an ERC-20-only market (so 0x9999 never gains a native balance —
// the empty-account reaping is fully exposed), driven swapDeposit → swapPlace → swap → withdraw,
// asserting seamReserve/available PERSIST across the production Finalise(true), the DEXFill log
// fires, and the deposit is WITHDRAWABLE. On the UNFIXED code 0x9999 is reaped at Finalise and
// the first assertion (seam persists) FAILS (==0, funds stranded, no fill); with the fix it PASSES.
func TestNativeZAP_RealStateDB_ERC20DepositPlaceSwapWithdraw(t *testing.T) {
	h := newRSHarness(t)
	const price = 50 // quote per base (grid units below)
	priceGrid := price * uint64(priceMultiplierConst)

	// ── MAKER: deposit QUOTE, rest a deep BID (buy base, pays quote). The maker's deposit is
	// the FIRST 0x9999 mutation, on an EMPTY 0x9999 — the exact live-bug shape.
	h.approve9999(h.maker, h.quote, big.NewInt(100_000))
	h.swapDeposit(h.maker, h.quote, 100_000)

	// THE DISCRIMINATOR: persist across the production end-of-tx commit.
	if got := h.seam(h.quote); got != 100_000 {
		t.Fatalf("PRE-COMMIT seamReserve[quote] = %d, want 100000 (dex must have written it)", got)
	}
	h.commit()
	if got := h.seam(h.quote); got != 100_000 {
		t.Fatalf("BUG: seamReserve[quote] = %d after Finalise(true), want 100000 — 0x9999 was reaped "+
			"(EIP-158 empty-account); the marker fix is missing/ineffective", got)
	}
	if got := h.avail(h.maker, h.quote); got != 100_000 {
		t.Fatalf("BUG: maker dexcore available[quote] = %d after Finalise, want 100000 (reaped)", got)
	}
	if got := h.ercBal(h.quote, poolManagerAddr9999); got != 100_000 {
		t.Fatalf("vault token balance = %d, want 100000 (the token must really be in the vault)", got)
	}

	h.swapPlace(h.maker, true, priceGrid, 1000) // BID 1000 base @ 50
	h.commit()
	takerBaseBefore := h.ercBal(h.base, h.taker)

	// ── TAKER: SELL 100 base for quote — the ATOMIC sync swap pulls the taker's REAL base into
	// the vault, matches the maker's resting bid, and pushes the realized quote to the taker. The
	// taker only approves the vault to pull its input (no pre-deposit on this path). minOut=4000
	// floors 100 base @ 50 = 5000 quote.
	h.approve9999(h.taker, h.base, big.NewInt(100))
	if _, err := h.swapSell(h.taker, 100, 4000); err != nil {
		t.Fatalf("swap (sell 100 base): %v", err)
	}

	// DEXFill must have fired at 0x9999 for THIS fill (the indexable settlement signal). Read the
	// logs BEFORE the commit resets the tx log buffer.
	logs := h.gdb.Logs()
	if findDEXFillLog(logs, h.market().ID(), h.taker) == nil {
		t.Fatalf("no DEXFill log emitted at 0x9999 for the fill (the indexer would not see it); logs=%d", len(logs))
	}
	h.commit()

	// The taker's realized proceeds settled to its REAL quote balance (the atomic swap pushes the
	// output to the taker); its base fell by exactly the 100 sold.
	if got := h.ercBal(h.quote, h.taker); got != 5000 {
		t.Fatalf("taker real QUOTE = %d after swap, want 5000 (100 base @ 50) — proceeds stranded?", got)
	}
	if got := takerBaseBefore - h.ercBal(h.base, h.taker); got != 100 {
		t.Fatalf("taker real BASE fell by %d, want 100 (the input pulled into the vault)", got)
	}

	// seamReserve[base] now holds the taker's 100 base, backing the maker's bought-base claim, and
	// it PERSISTS across the production commit (the swap's match writes 0x9999 storage too).
	if got := h.seam(h.base); got != 100 {
		t.Fatalf("BUG: seamReserve[base] = %d after swap+Finalise, want 100 (the taker input in the vault)", got)
	}

	// The maker BOUGHT 100 base; it is WITHDRAWABLE (funds are not stranded on either side).
	if got := h.avail(h.maker, h.base); got != 100 {
		t.Fatalf("maker dexcore available[base] = %d after swap, want 100 (bought base)", got)
	}
	if got := h.swapWithdraw(h.maker, h.base, 100); got != 100 {
		t.Fatalf("maker swapWithdraw(base, 100) realized %d, want 100", got)
	}
	h.commit()
	if got := h.ercBal(h.base, h.maker); got != 100 {
		t.Fatalf("maker real BASE balance = %d after withdraw, want 100 (funds withdrawable)", got)
	}

	t.Logf("REAL-StateDB e2e PASS: ERC-20 deposit→place→swap→withdraw; seamReserve/available "+
		"persisted across Finalise(true), DEXFill emitted, both sides realized their tokens")
}

// ───────────────────────────────── small ABI / hex helpers ─────────────────────────────────

func rsSel(sig string) []byte { return crypto.Keccak256([]byte(sig))[:4] }

func rsEncodeCtor(name, symbol string, supply *big.Int) []byte {
	word := func(v *big.Int) []byte { return common.LeftPadBytes(v.Bytes(), 32) }
	str := func(s string) []byte {
		out := append([]byte{}, common.LeftPadBytes(big.NewInt(int64(len(s))).Bytes(), 32)...)
		return append(out, common.RightPadBytes([]byte(s), 32)...)
	}
	head := append([]byte{}, word(big.NewInt(96))...)
	head = append(head, word(big.NewInt(160))...)
	head = append(head, word(supply)...)
	head = append(head, str(name)...)
	head = append(head, str(symbol)...)
	return head
}

func stripHexWS(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n', '\r', ' ', '\t':
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

// keep the ethtypes import used even if findDEXFillLog's signature shifts.
var _ = (*ethtypes.Log)(nil)
