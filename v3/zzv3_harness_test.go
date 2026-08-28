// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package v3

import (
	"context"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/dex"
	"github.com/luxfi/precompile/precompileconfig"
)

// Extra fixtures layered on harness_test.go's mockState. Three things the base
// harness cannot express, each needed to reach a real refusal path:
//
//   - a StateDB WITHOUT the erc20Vault capability      -> ErrVaultUnavailable
//   - a token that delivers less than it was asked for -> ErrDeltaMismatch
//   - a raw call surface that returns remainingGas     -> the gas assertions
//
// plus the native-currency pool (currency0 == the zero address), which the base
// fixtures never build and which is the whole pullExactNative/pushOutNative path.

// native is the zero address: the native-LUX "currency". It sorts strictly below
// every real token address, so it is always currency0 of a native pool.
var native = common.Address{}

// tokenC is a third ERC-20, used where a test needs a pool disjoint from stdPool.
var tokenC = common.HexToAddress("0x000000000000000000000000000000000000ccc4")

// nativePool is the 0.30%/spacing-60 pool over (native, tokenB).
var nativePool = poolCfg{c0: native, c1: tokenB, fee: uint32(dex.Fee030), tickSpacing: int32(dex.TickSpacing030)}

// ---------------------------------------------------------------------------
// rig: a precompile bound to an ARBITRARY contract.StateDB, exposing the raw
// (ret, remainingGas, err) triple. The base env pins its db to *mockState and
// drops remainingGas; both are needed here.
// ---------------------------------------------------------------------------

type rigAccessible struct {
	db  contract.StateDB
	blk *mockBlock
}

func (a *rigAccessible) GetStateDB() contract.StateDB                     { return a.db }
func (a *rigAccessible) GetBlockContext() contract.BlockContext           { return a.blk }
func (a *rigAccessible) GetConsensusContext() context.Context             { return context.Background() }
func (a *rigAccessible) GetChainConfig() precompileconfig.ChainConfig     { return nil }
func (a *rigAccessible) GetPrecompileEnv() contract.PrecompileEnvironment { return nil }

type rig struct {
	c  *V3Contract
	st *rigAccessible
}

func newRig(db contract.StateDB) *rig {
	return &rig{c: &V3Contract{}, st: &rigAccessible{db: db, blk: &mockBlock{ts: 1}}}
}

// call runs the precompile and returns everything, including remainingGas.
func (r *rig) call(caller common.Address, in []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	return r.c.Run(r.st, caller, v3Addr, in, gas, readOnly)
}

// callRaw is the same on the base env (whose db is *mockState), for the gas tests.
func (e *env) callRaw(caller common.Address, in []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	return e.c.Run(e.st, caller, v3Addr, in, gas, readOnly)
}

// ---------------------------------------------------------------------------
// ABI builders. One per selector, so a test can hand Run a byte string that is
// deliberately one byte short or one byte long.
// ---------------------------------------------------------------------------

func inInitialize(p poolCfg, sqrtPriceX96 *big.Int) []byte {
	in := append(selBytes(selInitialize), p.words()...)
	return append(in, uintArg(sqrtPriceX96)...)
}

func inMint(p poolCfg, lower, upper int32, amount *big.Int) []byte {
	in := append(selBytes(selMint), p.words()...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	return append(in, uintArg(amount)...)
}

func inBurn(p poolCfg, lower, upper int32, amount *big.Int) []byte {
	in := append(selBytes(selBurn), p.words()...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	return append(in, uintArg(amount)...)
}

func inCollect(p poolCfg, lower, upper int32, a0Req, a1Req *big.Int) []byte {
	in := append(selBytes(selCollect), p.words()...)
	in = append(in, tickWord(lower)...)
	in = append(in, tickWord(upper)...)
	in = append(in, uintArg(a0Req)...)
	return append(in, uintArg(a1Req)...)
}

func inSwap(p poolCfg, zeroForOne bool, amountSpecified, sqrtLimit *big.Int) []byte {
	in := append(selBytes(selSwap), p.words()...)
	in = append(in, boolArg(zeroForOne)...)
	in = append(in, intArg(amountSpecified)...)
	return append(in, uintArg(sqrtLimit)...)
}

func inSlot0(p poolCfg) []byte     { return append(selBytes(selSlot0), p.words()...) }
func inLiquidity(p poolCfg) []byte { return append(selBytes(selLiquidity), p.words()...) }

func inTicks(p poolCfg, tick int32) []byte {
	return append(append(selBytes(selTicks), p.words()...), tickWord(tick)...)
}

func inPositions(p poolCfg, owner common.Address, lower, upper int32) []byte {
	in := append(selBytes(selPositions), p.words()...)
	in = append(in, addressWord(owner)...)
	in = append(in, tickWord(lower)...)
	return append(in, tickWord(upper)...)
}

// rawWord makes a 32-byte word out of an arbitrary big.Int WITHOUT the codec's
// range discipline — the only way to hand parseTick a value that would truncate.
func rawWord(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

// short drops the last byte; long appends one. Every selector must refuse both.
func short(in []byte) []byte { return in[:len(in)-1] }
func long(in []byte) []byte  { return append(append([]byte{}, in...), 0x00) }

// ---------------------------------------------------------------------------
// nonVaultState: contract.StateDB with NO erc20Vault capability. Explicit
// forwarding (not embedding) is the point — embedding would promote the vault
// methods and the type would satisfy erc20Vault after all.
// ---------------------------------------------------------------------------

type nonVaultState struct{ m *mockState }

func newNonVaultState() *nonVaultState { return &nonVaultState{m: newMockState()} }

func (n *nonVaultState) GetState(a common.Address, k common.Hash) common.Hash {
	return n.m.GetState(a, k)
}

func (n *nonVaultState) SetState(a common.Address, k, v common.Hash) common.Hash {
	return n.m.SetState(a, k, v)
}
func (n *nonVaultState) SetNonce(a common.Address, v uint64, r tracing.NonceChangeReason) {
	n.m.SetNonce(a, v, r)
}
func (n *nonVaultState) GetNonce(a common.Address) uint64         { return n.m.GetNonce(a) }
func (n *nonVaultState) GetBalance(a common.Address) *uint256.Int { return n.m.GetBalance(a) }

func (n *nonVaultState) AddBalance(a common.Address, v *uint256.Int, r tracing.BalanceChangeReason) uint256.Int {
	return n.m.AddBalance(a, v, r)
}

func (n *nonVaultState) SubBalance(a common.Address, v *uint256.Int, r tracing.BalanceChangeReason) uint256.Int {
	return n.m.SubBalance(a, v, r)
}

func (n *nonVaultState) GetBalanceMultiCoin(a common.Address, c common.Hash) *big.Int {
	return n.m.GetBalanceMultiCoin(a, c)
}
func (n *nonVaultState) AddBalanceMultiCoin(a common.Address, c common.Hash, v *big.Int) {}
func (n *nonVaultState) SubBalanceMultiCoin(a common.Address, c common.Hash, v *big.Int) {}
func (n *nonVaultState) CreateAccount(a common.Address)                                  {}
func (n *nonVaultState) Exist(a common.Address) bool                                     { return true }
func (n *nonVaultState) AddLog(l *ethtypes.Log)                                          { n.m.AddLog(l) }
func (n *nonVaultState) Logs() []*ethtypes.Log                                           { return n.m.Logs() }
func (n *nonVaultState) TxHash() common.Hash                                             { return common.Hash{} }
func (n *nonVaultState) Snapshot() int                                                   { return 0 }
func (n *nonVaultState) RevertToSnapshot(int)                                            {}

func (n *nonVaultState) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}

// ---------------------------------------------------------------------------
// shortTransferState: a deflationary / fee-on-transfer ERC-20. transferFrom
// delivers `shortfall` LESS than asked, so the observed-delta check must refuse
// rather than credit the requested amount.
// ---------------------------------------------------------------------------

type shortTransferState struct {
	*mockState
	shortfall *big.Int
}

func (s *shortTransferState) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	return s.mockState.TransferTokenFrom(token, from, to, new(big.Int).Sub(amount, s.shortfall))
}

// ---------------------------------------------------------------------------
// Shared setup helpers.
// ---------------------------------------------------------------------------

// oneE18 and friends: the sizes every test in this lane trades in.
var (
	oneE18   = mustBig("1000000000000000000")
	e18x1000 = mustBig("1000000000000000000000")
)

// fundedEnv returns an env whose trader holds `amt` of tokenA and tokenB and
// whose stdPool is initialized at price 1.0 (tick 0).
func fundedEnv(amt *big.Int) *env {
	e := newEnv()
	e.db().fund(tokenA, trader, amt)
	e.db().fund(tokenB, trader, amt)
	if _, err := e.initialize(stdPool, dex.Q96, false); err != nil {
		panic(err)
	}
	return e
}

// mintAmounts is what modifyLiquidity will compute for a position — the same
// dex composition the precompile performs, so a caller can pre-fund a native
// pool with the EXACT value the observed-delta check will demand.
func mintAmounts(sqrtPrice *big.Int, lower, upper int32, L *big.Int) (a0, a1 *big.Int) {
	lo, err := dex.GetSqrtRatioAtTick(lower)
	if err != nil {
		panic(err)
	}
	hi, err := dex.GetSqrtRatioAtTick(upper)
	if err != nil {
		panic(err)
	}
	return dex.GetAmountsForLiquidity(sqrtPrice, lo, hi, L)
}

// poolIdOf derives the poolId the precompile will address state under.
func poolIdOf(p poolCfg) common.Hash {
	_, id, err := parsePoolKey(p.words())
	if err != nil {
		panic(err)
	}
	return id
}
