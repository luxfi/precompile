// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"

	"github.com/luxfi/geth/common"
)

// zzpool_harness_test.go holds the doubles the pool_manager.go / erc20_vault.go
// coverage lane shares. Everything here composes the EXISTING MockStateDB
// (pool_manager_test.go) rather than reimplementing a StateDB: the only thing the
// custody path needs on top of it is the OPTIONAL txIdentified capability (a tx
// hash) and the OPTIONAL erc20Vault capability (a per-token ledger keyed on the
// 0x9010 vault address, NOT the 0x9999 one contractStateDBWrapper models).

// zzpTxDB is MockStateDB + the txIdentified capability. Deposit/Withdraw/Swap/
// ModifyLiquidity all derive their DURABLE idempotency key through this seam, so
// a StateDB without it is the "unbound" refusal path and one with a settable hash
// is every bound path.
type zzpTxDB struct {
	*MockStateDB
	tx common.Hash
}

func zzpNewTxDB(tx common.Hash) *zzpTxDB {
	return &zzpTxDB{MockStateDB: NewMockStateDB(), tx: tx}
}

func (d *zzpTxDB) TxHash() common.Hash { return d.tx }

// zzpVaultDB is zzpTxDB + the erc20Vault capability, with an in-memory
// (token -> holder -> balance) ledger. The vault side is poolManagerAddr (0x9010),
// which is what erc20_vault.go moves value in and out of.
//
// failFrom / failTo make the token's transferFrom / transfer REVERT, which is how
// a real OZ-unsafe token surfaces (ErrERC20TransferFailed). shortBps models a
// fee-on-transfer token: the recipient receives amount*(1-shortBps/1e4), which is
// the observed-delta edge the deposit leg must credit instead of the request.
type zzpVaultDB struct {
	*zzpTxDB
	bal      map[common.Address]map[common.Address]*big.Int
	failFrom bool
	failTo   bool
	shortBps int64
	// swallow makes transferFrom succeed while delivering NOTHING — a token whose
	// transfer is a silent no-op. The observed-delta measurement is the only thing
	// that catches it (ErrERC20ZeroDelta).
	swallow bool
	// onTransferFrom / onTransferTo run INSIDE the token sub-call, which is where a
	// malicious token mounts its reentrancy. This is the real attack shape the
	// global custody guard exists to refuse.
	onTransferFrom func()
	onTransferTo   func()
}

func zzpNewVaultDB(tx common.Hash) *zzpVaultDB {
	return &zzpVaultDB{
		zzpTxDB: zzpNewTxDB(tx),
		bal:     make(map[common.Address]map[common.Address]*big.Int),
	}
}

func (d *zzpVaultDB) zzpSlot(token, holder common.Address) *big.Int {
	if d.bal[token] == nil {
		d.bal[token] = make(map[common.Address]*big.Int)
	}
	if d.bal[token][holder] == nil {
		d.bal[token][holder] = big.NewInt(0)
	}
	return d.bal[token][holder]
}

// zzpMint seeds a token balance (test setup only).
func (d *zzpVaultDB) zzpMint(token, holder common.Address, amount int64) {
	cur := d.zzpSlot(token, holder)
	d.bal[token][holder] = new(big.Int).Add(cur, big.NewInt(amount))
}

func (d *zzpVaultDB) TokenBalanceOf(token, owner common.Address) *big.Int {
	return new(big.Int).Set(d.zzpSlot(token, owner))
}

func (d *zzpVaultDB) TransferTokenFrom(token, from, to common.Address, amount *big.Int) error {
	if d.onTransferFrom != nil {
		d.onTransferFrom()
	}
	if d.failFrom {
		return ErrERC20TransferFailed
	}
	bal := d.zzpSlot(token, from)
	if bal.Cmp(amount) < 0 {
		return ErrERC20TransferFailed
	}
	d.bal[token][from] = new(big.Int).Sub(bal, amount)
	if d.swallow {
		return nil // debited the sender, delivered nothing: observed delta 0
	}
	received := new(big.Int).Set(amount)
	if d.shortBps > 0 {
		fee := new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(d.shortBps)), big.NewInt(10000))
		received.Sub(received, fee)
	}
	d.bal[token][to] = new(big.Int).Add(d.zzpSlot(token, to), received)
	return nil
}

func (d *zzpVaultDB) TransferTokenTo(token, to common.Address, amount *big.Int) error {
	if d.onTransferTo != nil {
		d.onTransferTo()
	}
	if d.failTo {
		return ErrERC20TransferFailed
	}
	bal := d.zzpSlot(token, poolManagerAddr)
	if bal.Cmp(amount) < 0 {
		return ErrERC20TransferFailed
	}
	d.bal[token][poolManagerAddr] = new(big.Int).Sub(bal, amount)
	d.bal[token][to] = new(big.Int).Add(d.zzpSlot(token, to), amount)
	return nil
}

// zzpLedger is the D-Chain side of custody as the PoolManager sees it: a per
// (account, asset) available balance plus a per-ref dedup index, which is exactly
// the shape custodyEngine documents. Deposits credit, withdraws debit CLAMPED to
// availability and return the realized amount — the clamp is what makes "a
// withdrawal can never exceed the deposited balance" a ledger property rather
// than a caller courtesy.
type zzpLedger struct {
	mockEngine
	avail  map[common.Address]map[common.Address]uint64
	opened map[[32]byte]bool
	refs   []([32]byte)
	// depositErr / withdrawErr / balanceErr force the backend failure branches.
	depositErr  error
	withdrawErr error
	balanceErr  error
	// overpay makes Withdraw return MORE than it debited — a backend mint. The
	// vault-underflow guard is the last line that stops it reaching the caller.
	overpay uint64
	// deposits / withdraws count backend calls so a replay that must NOT reach the
	// backend is observable, not merely "returned nil".
	deposits  int
	withdraws int
	// onDeposit / onWithdraw run INSIDE the backend leg — the second place a
	// reentrant custody call can originate.
	onDeposit  func()
	onWithdraw func()
	openErr    error
}

// zzpBadEngine is an Engine whose every operation fails, so the PoolManager's
// "the backend refused" branches are reachable without a live D-Chain.
type zzpBadEngine struct {
	mockEngine
	err error
}

func (e *zzpBadEngine) Initialize(*big.Int) (int24, error) { return 0, e.err }

func (e *zzpBadEngine) ModifyLiquidity(*PoolState, common.Address, ModifyLiquidityParams) (BalanceDelta, BalanceDelta, error) {
	return ZeroBalanceDelta(), ZeroBalanceDelta(), e.err
}

func (e *zzpBadEngine) Donate(*PoolState, *big.Int, *big.Int) (BalanceDelta, error) {
	return ZeroBalanceDelta(), e.err
}

func zzpNewLedger() *zzpLedger {
	return &zzpLedger{
		avail:  make(map[common.Address]map[common.Address]uint64),
		opened: make(map[[32]byte]bool),
	}
}

func (l *zzpLedger) zzpAvail(account common.Address, asset Currency) uint64 {
	if l.avail[account] == nil {
		return 0
	}
	return l.avail[account][asset.Address]
}

func (l *zzpLedger) zzpSet(account common.Address, asset Currency, v uint64) {
	if l.avail[account] == nil {
		l.avail[account] = make(map[common.Address]uint64)
	}
	l.avail[account][asset.Address] = v
}

// zzpTotal is the ledger-wide sum for one asset — the "value out" half of the
// custody conservation invariant.
func (l *zzpLedger) zzpTotal(asset Currency) *big.Int {
	sum := new(big.Int)
	for _, byAsset := range l.avail {
		sum.Add(sum, new(big.Int).SetUint64(byAsset[asset.Address]))
	}
	return sum
}

func (l *zzpLedger) OpenMarket(poolID [32]byte, base, quote Currency) error {
	if l.openErr != nil {
		return l.openErr
	}
	l.opened[poolID] = true
	return nil
}

func (l *zzpLedger) Deposit(account common.Address, asset Currency, amount uint64, ref [32]byte) error {
	l.deposits++
	if l.onDeposit != nil {
		l.onDeposit()
	}
	if l.depositErr != nil {
		return l.depositErr
	}
	l.refs = append(l.refs, ref)
	l.zzpSet(account, asset, l.zzpAvail(account, asset)+amount)
	return nil
}

func (l *zzpLedger) Withdraw(account common.Address, asset Currency, want uint64, ref [32]byte) (uint64, error) {
	l.withdraws++
	if l.onWithdraw != nil {
		l.onWithdraw()
	}
	if l.withdrawErr != nil {
		return 0, l.withdrawErr
	}
	l.refs = append(l.refs, ref)
	have := l.zzpAvail(account, asset)
	realized := want
	if realized > have {
		realized = have // CLAMP: the ledger can never pay out more than it holds
	}
	l.zzpSet(account, asset, have-realized)
	return realized + l.overpay, nil
}

func (l *zzpLedger) Balance(account common.Address, asset Currency) (uint64, error) {
	if l.balanceErr != nil {
		return 0, l.balanceErr
	}
	return l.zzpAvail(account, asset), nil
}

// zzpRouter is an Engine that ALSO implements poolRouter, so routePool's
// delegating branch and Initialize's server-tick override are reachable.
type zzpRouter struct {
	mockEngine
	routed   map[*PoolState][32]byte
	inits    int
	initTick int24
	initErr  error
}

func zzpNewRouter() *zzpRouter {
	return &zzpRouter{routed: make(map[*PoolState][32]byte)}
}

func (r *zzpRouter) InitializePool(ps *PoolState, poolID [32]byte, sqrtPriceX96 *big.Int, tickSpacing int32, lpFee uint32) (int24, error) {
	r.inits++
	if r.initErr != nil {
		return 0, r.initErr
	}
	r.routed[ps] = poolID
	return r.initTick, nil
}

func (r *zzpRouter) SetPoolID(ps *PoolState, poolID [32]byte) { r.routed[ps] = poolID }

// zzpAuth is an Engine that ALSO implements cancelAuthority, the seam
// ModifyLiquidity drives the durable cancel binding through.
type zzpAuth struct {
	mockEngine
	handles map[string]uint64
	seeded  map[string]uint64
	// nextID is the order id a successful place binds; bindPlace=false models a
	// backend that placed without exposing a handle.
	nextID    uint64
	bindPlace bool
}

func zzpNewAuth() *zzpAuth {
	return &zzpAuth{handles: make(map[string]uint64), seeded: make(map[string]uint64), nextID: 7, bindPlace: true}
}

func zzpHandleKey(maker common.Address, poolID [32]byte, salt [32]byte) string {
	return string(maker.Bytes()) + string(poolID[:]) + string(salt[:])
}

func (a *zzpAuth) OrderHandle(maker common.Address, poolID [32]byte, salt [32]byte) (uint64, bool) {
	if !a.bindPlace {
		return 0, false
	}
	return a.nextID, true
}

func (a *zzpAuth) SeedOrderHandle(maker common.Address, poolID [32]byte, salt [32]byte, orderID uint64) {
	a.seeded[zzpHandleKey(maker, poolID, salt)] = orderID
}

// zzpKey is the lane's standard pool key: native currency0 (so the custody path
// can move native value) and one ERC-20 currency1.
func zzpKey() PoolKey {
	return PoolKey{
		Currency0:   NativeCurrency,
		Currency1:   Currency{Address: common.HexToAddress("0x00000000000000000000000000000000000000C1")},
		Fee:         Fee030,
		TickSpacing: TickSpacing030,
		Hooks:       common.Address{},
	}
}

// zzpTokenAddr is the ERC-20 the vault tests move; zzpToken is its Currency.
var (
	zzpTokenAddr = common.HexToAddress("0x0000000000000000000000000000000000000C0C")
	zzpToken     = Currency{Address: zzpTokenAddr}
)

// zzpAlice / zzpBob are two distinct callers — every authorization assertion needs
// a second identity to prove a binding does not carry across principals.
var (
	zzpAlice = common.HexToAddress("0x00000000000000000000000000000000000A11CE")
	zzpBob   = common.HexToAddress("0x0000000000000000000000000000000000000B0B")
)

// zzpTx1 / zzpTx2 are two distinct EVM tx identities.
var (
	zzpTx1 = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	zzpTx2 = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
)
