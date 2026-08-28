// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// erc20_code_test.go pins what an empty return from a token sub-call means.
//
// The EVM answers a CALL to an address carrying no code with success and no
// return data. A non-compliant ERC-20 that returns nothing on success is
// indistinguishable from that, looking at the return alone — so SafeERC20 does
// not look at the return alone: it requires code at the target before it will
// read an empty return as success. The vault's push leg debits the depositor's
// claim before it moves the token, so accepting an empty return from an address
// with no code retires a claim against a transfer that never happened.

// codeStateDB is the callSeam StateDB plus the EXTCODESIZE surface a live geth
// StateDB carries, which is what poolStateAdapter.CodeSizeOf reads.
type codeStateDB struct {
	*callSeamStateDB
	size map[common.Address]int
}

func (s *codeStateDB) GetCodeSize(addr common.Address) int { return s.size[addr] }

// emptyReturnEnv answers a call to an address with no token exactly as the EVM
// answers a call to an address with no code: success, no return data. The
// callSeam env reverts instead, which is the one behaviour that hides this.
type emptyReturnEnv struct{ *callSeamEnv }

func (e *emptyReturnEnv) Call(addr common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	if _, ok := e.tokens[addr]; !ok {
		return nil, gas, nil
	}
	return e.callSeamEnv.Call(addr, input, gas, value)
}

// codeState is the AccessibleState over both halves.
type codeState struct {
	*callSeamState
	sdb *codeStateDB
	env *emptyReturnEnv
}

func (m *codeState) GetStateDB() contract.StateDB                     { return m.sdb }
func (m *codeState) GetPrecompileEnv() contract.PrecompileEnvironment { return m.env }

// codeHarness wires a vault whose token leg goes through the EVM Call surface,
// with a per-address code size the test controls.
func codeHarness(t *testing.T, tokens map[common.Address]*tokenContract) *codeState {
	t.Helper()
	inner := &callSeamStateDB{inner: NewMockStateDB()}
	st := &codeState{
		callSeamState: &callSeamState{sdb: inner, env: &callSeamEnv{self: poolManagerAddr9999, tokens: tokens}, timestamp: harnessBlockTime},
		sdb:           &codeStateDB{callSeamStateDB: inner, size: map[common.Address]int{}},
		env:           &emptyReturnEnv{&callSeamEnv{self: poolManagerAddr9999, tokens: tokens}},
	}
	// Load-bearing: the StateDB must NOT be an erc20Vault, or the in-state ledger
	// resolves and the Call seam under test is never reached.
	assertNotERC20Vault(t, st.GetStateDB())
	if _, ok := st.GetPrecompileEnv().(callableEnv); !ok {
		t.Fatal("the env must satisfy callableEnv or the token leg refuses for the wrong reason")
	}
	return st
}

// TestTokenTransferRefusesAnAddressWithNoCode is the defect: an empty return from
// an address carrying no code is the EVM's answer to a call into nothing, and
// reading it as a successful transfer retires value against a move that did not
// occur.
func TestTokenTransferRefusesAnAddressWithNoCode(t *testing.T) {
	token := common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	holder := common.HexToAddress("0x1111111111111111111111111111111111111111")
	st := codeHarness(t, map[common.Address]*tokenContract{})
	v := newPoolStateAdapter(st)

	if err := v.TransferTokenTo(token, holder, big.NewInt(100)); !errors.Is(err, ErrERC20NoCode) {
		t.Fatalf("push into an address with no code: want ErrERC20NoCode, got %v", err)
	}
	if err := v.TransferTokenFrom(token, holder, poolManagerAddr9999, big.NewInt(100)); !errors.Is(err, ErrERC20NoCode) {
		t.Fatalf("pull from an address with no code: want ErrERC20NoCode, got %v", err)
	}
}

// TestTokenTransferAcceptsAnEmptyReturnFromRealCode pins the other side: a token
// that HAS code and returns nothing on success is a real, common, non-compliant
// ERC-20, and it must keep working. The refusal above must be bought by the code
// check alone, never by tightening what a return may look like.
func TestTokenTransferAcceptsAnEmptyReturnFromRealCode(t *testing.T) {
	token := common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	holder := common.HexToAddress("0x1111111111111111111111111111111111111111")
	st := codeHarness(t, map[common.Address]*tokenContract{})
	st.sdb.size[token] = 1 // deployed, but the env still returns no data

	v := newPoolStateAdapter(st)
	if err := v.TransferTokenTo(token, holder, big.NewInt(100)); err != nil {
		t.Fatalf("push into a deployed token returning no data: %v", err)
	}
	if err := v.TransferTokenFrom(token, holder, poolManagerAddr9999, big.NewInt(100)); err != nil {
		t.Fatalf("pull from a deployed token returning no data: %v", err)
	}
}

// TestWithdrawKeepsTheClaimWhenTheTokenIsGone is the consequence at the surface
// that matters. withdraw debits the claim and the vault before it moves the
// token, so a push that cannot happen must fail the call rather than report
// success — otherwise the depositor's claim is retired and nothing arrives.
func TestWithdrawKeepsTheClaimWhenTheTokenIsGone(t *testing.T) {
	token := common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	depositor := common.HexToAddress("0x1111111111111111111111111111111111111111")
	st := codeHarness(t, map[common.Address]*tokenContract{})
	aid := assetID(Currency{Address: token})

	// A claim exists from an earlier deposit; the token address now carries no code.
	db := newPoolStateAdapter(st)
	storeDepositorClaim(db, depositor, aid, big.NewInt(1_000))
	storeSettleVault(db, aid, big.NewInt(1_000))

	data := make([]byte, 64)
	copy(data[12:32], token.Bytes())
	big.NewInt(1_000).FillBytes(data[32:64])
	c := &SettleContract{}
	if _, _, err := c.Run(st, depositor, poolManagerAddr9999, prependSelector(SelectorWithdraw, data), 5_000_000, false); err == nil {
		t.Fatal("withdraw against a token with no code reported success")
	}
	// The refusal reverts the frame in production; here the handler must at least
	// not have reported a delivery it could not make.
	if got := newPoolStateAdapter(st).GetBalance(depositor); got.Sign() != 0 {
		t.Fatalf("a refused withdraw moved native value: %s", got)
	}
}
