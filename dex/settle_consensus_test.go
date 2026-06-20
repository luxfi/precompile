// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
)

// settle_consensus_test.go — consensus-level tests for the 0x9999 money path:
//   - end-to-end SettleSwap (full verify->settle pipeline) with a real BLS cert;
//   - DETERMINISM (the EVM-layer red test: the receipt path produces an identical
//     result on every "validator", unlike a live matcher which would diverge);
//   - replay protection (a consumed receipt cannot settle twice);
//   - multi-layer halt (halted swap reverts with no partial state; withdraw still
//     works; resume restores);
//   - Block-STM access set (non-conflicting swaps touch disjoint slots; conflicts
//     share account/receipt; no global hot WRITE slot).

// buildSwapCalldata encodes a V4 swap call (UNCHANGED ABI) carrying the settlement
// envelope in hookData. Layout after the 4-byte selector (stripped by Run):
//
//	[0:160]   PoolKey  [160:192] zeroForOne  [192:224] amountSpecified
//	[224:256] sqrtPriceLimit     [256:288] hookData offset (=0x120=288)
//	[288:320] hookData length    [320:...]  hookData bytes (zero-padded to 32)
func buildSwapCalldata(key PoolKey, params SwapParams, hookData []byte) []byte {
	args := make([]byte, 288)
	copy(args[0:160], EncodePoolKeyABI(key))
	if params.ZeroForOne {
		args[191] = 1
	}
	// amountSpecified (we use exact-input negative magnitude or zero; sample uses 0).
	if params.AmountSpecified != nil {
		// two's complement not needed for our >=0 test amounts; store magnitude.
		params.AmountSpecified.FillBytes(args[192:224])
	}
	if params.SqrtPriceLimitX96 != nil {
		params.SqrtPriceLimitX96.FillBytes(args[224:256])
	}
	binary.BigEndian.PutUint64(args[280:288], 288) // offset word -> hookData at byte 288
	// length + data (zero-pad to a 32-byte boundary)
	lenWord := make([]byte, 32)
	binary.BigEndian.PutUint64(lenWord[24:32], uint64(len(hookData)))
	padded := make([]byte, (len(hookData)+31)/32*32)
	copy(padded, hookData)
	return append(append(args, lenWord...), padded...)
}

// settleHarness wires a 0x9999 contract, a mock state, a validator set in the
// registry, the configured chain identity, and a funded vault for the output asset.
type settleHarness struct {
	c          *SettleContract
	state      *mockAccessibleState
	vals       []testValidator
	vsID       [32]byte
	dChainID   [32]byte
	cChainID   [32]byte
	networkID  uint32
	key        PoolKey
	params     SwapParams
	caller     common.Address
}

func newSettleHarness(t *testing.T) *settleHarness {
	t.Helper()
	h := &settleHarness{
		c:         &SettleContract{protocolFeeController: common.HexToAddress("0xFEE0000000000000000000000000000000000001")},
		state:     &mockAccessibleState{stateDB: NewMockStateDB()},
		vals:      newTestValidators(t, 1, 1, 1),
		vsID:      [32]byte{0x01},
		dChainID:  [32]byte{0xDD},
		cChainID:  [32]byte{0xCC},
		networkID: 1,
		caller:    common.HexToAddress("0x1111111111111111111111111111111111111111"),
	}
	// V4 pool: currency0 = native (0x0), currency1 = token 0x..02. zeroForOne = swap
	// native in, token out. AmountSpecified = 0 (the receipt carries the amounts).
	h.key = PoolKey{
		Currency0:   Currency{Address: common.Address{}},
		Currency1:   Currency{Address: common.HexToAddress("0x0000000000000000000000000000000000000002")},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       common.Address{},
	}
	h.params = SwapParams{ZeroForOne: true, AmountSpecified: big.NewInt(0), SqrtPriceLimitX96: big.NewInt(0)}

	kv := newPoolStateAdapter(h.state)
	// Configure chain identity + validator set (as Configure would at genesis).
	SetSettleChainIdentity(kv, h.networkID, h.cChainID)
	vs := validatorSetFrom(h.dChainID, h.vsID, h.vals)
	if err := PutValidatorSet(kv, vs); err != nil {
		t.Fatalf("PutValidatorSet: %v", err)
	}
	return h
}

// outToken is the harness pool's currency1 (the swap output for ZeroForOne).
func (h *settleHarness) outToken() common.Address { return h.key.Currency1.Address }

// outAssetID is the injective AssetID of the output token.
func (h *settleHarness) outAssetID() [32]byte { return assetID(h.key.Currency1) }

// wrapper returns the harness's contract.StateDB as the erc20Vault-capable wrapper.
func (h *settleHarness) wrapper() *contractStateDBWrapper {
	return h.state.GetStateDB().(*contractStateDBWrapper)
}

// fund seeds: sender native (for amountIn), and the 0x9999 vault's OUTPUT token
// (for amountOut credit) + its tracked vault holdings. Native in, token out — the
// real V4 direction.
func (h *settleHarness) fund(t *testing.T, senderNative, vaultOutTokens int64) {
	t.Helper()
	db := h.state.stateDB
	db.AddBalance(h.caller, uint256.NewInt(uint64(senderNative)))
	// Mint the output token INTO the 0x9999 vault and track holdings.
	h.wrapper().mintTestToken(h.outToken(), poolManagerAddr9999, big.NewInt(vaultOutTokens))
	storeSettleVault(newPoolStateAdapter(h.state), h.outAssetID(), big.NewInt(vaultOutTokens))
}

// receiptFor builds a receipt bound to the harness's swap, with the given in/out
// asset IDs and amounts, then a valid 2-of-3 cert.
func (h *settleHarness) receiptFor(t *testing.T, inAsset, outAsset [32]byte, amountIn, amountOut int64, signers ...int) []byte {
	t.Helper()
	r := &DFillReceiptV1{
		Version:         1,
		NetworkID:       h.networkID,
		DChainID:        h.dChainID,
		CChainID:        h.cChainID,
		DHeight:         100,
		DBlockID:        [32]byte{0xB0},
		MarketID:        h.key.ID(),
		FillID:          [32]byte{0xF1},
		ReceiptID:       keccak32([]byte("receipt-1")),
		PoolKeyHash:     h.key.ID(),
		SwapParamsHash:  swapParamsHash(h.params),
		Sender:          h.caller,
		Recipient:       h.caller,
		TokenInAssetID:  inAsset,
		TokenOutAssetID: outAsset,
		AmountIn:        big.NewInt(amountIn),
		AmountOut:       big.NewInt(amountOut),
		FeeAmount:       big.NewInt(0),
		FeeAssetID:      inAsset,
		Deadline:        1 << 40,
		Nonce:           1,
		PrecompileAddr:  poolManagerAddr9999,
		CertType:        CertTypeBLSFastPath,
	}
	cert := buildCert(t, h.vsID, h.vals, r, r.ReceiptID, signers...)
	return EncodeSettlementHookData(r, cert, nil)
}

// TestSettle_E2E_NativeInTokenOut: full pipeline in the REAL V4 direction. Sender
// pays native in (currency0), receives the token out (currency1) from the vault.
// The swap debits native from the sender into the vault, credits the token from
// the vault to the recipient, and marks the receipt consumed.
func TestSettle_E2E_NativeInTokenOut(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	h.fund(t, 10_000, 10_000) // sender native + vault output token

	nativeID := [32]byte{}
	hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1)
	calldata := buildSwapCalldata(h.key, h.params, hookData)

	senderNativeBefore := db.GetBalance(h.caller).Uint64()
	recipTokenBefore := h.wrapper().TokenBalanceOf(h.outToken(), h.caller)
	out, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorSwap, calldata), 5_000_000, false)
	if err != nil {
		t.Fatalf("settle e2e failed: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("expected 32-byte BalanceDelta, got %d", len(out))
	}
	// Sender paid 1000 native in.
	if senderNativeBefore-db.GetBalance(h.caller).Uint64() != 1000 {
		t.Fatalf("sender should pay 1000 native, paid %d", senderNativeBefore-db.GetBalance(h.caller).Uint64())
	}
	// Recipient received 990 token out.
	recipTokenAfter := h.wrapper().TokenBalanceOf(h.outToken(), h.caller)
	if new(big.Int).Sub(recipTokenAfter, recipTokenBefore).Int64() != 990 {
		t.Fatalf("recipient should receive 990 token, got %s", new(big.Int).Sub(recipTokenAfter, recipTokenBefore))
	}
}

// TestSettle_NoMint_UnbackedOutputReverts: if the vault cannot back amountOut, the
// settle reverts (conservation; no mint) and no value moves.
func TestSettle_NoMint_UnbackedOutputReverts(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	h.fund(t, 10_000, 100) // vault holds only 100 of the output token

	nativeID := [32]byte{}
	hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1) // wants 990 out
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))

	senderBefore := db.GetBalance(h.caller).Uint64()
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrSettleUnbacked {
		t.Fatalf("unbacked output must revert ErrSettleUnbacked, got: %v", err)
	}
	if db.GetBalance(h.caller).Uint64() != senderBefore {
		t.Fatal("unbacked settle must not move value")
	}
}

// TestSettle_Replay: the same receipt cannot settle twice (consumedReceipt).
func TestSettle_Replay(t *testing.T) {
	h := newSettleHarness(t)
	h.fund(t, 10_000, 10_000)

	nativeID := [32]byte{}
	hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))

	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != nil {
		t.Fatalf("first settle failed: %v", err)
	}
	// Second identical settle must revert (receipt already consumed).
	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false)
	if err == nil {
		t.Fatal("replay of a consumed receipt must revert")
	}
}

// TestSettle_RestartDeterministic: settlement state is a pure function of the
// receipt + StateDB. Running the SAME receipt against two independent states (two
// "validators") yields identical consumed-flag + balances. This is the EVM-layer
// red test's positive half: the receipt path is deterministic (where a live
// matcher would diverge per validator).
func TestSettle_RestartDeterministic(t *testing.T) {
	run := func() (uint64, bool) {
		h := newSettleHarness(t)
		db := h.state.stateDB
		h.fund(t, 10_000, 10_000)
		nativeID := [32]byte{}
		hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1)
		calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
		_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false)
		if err != nil {
			t.Fatalf("settle: %v", err)
		}
		r, _ := DecodeFillReceipt(mustReceiptBytes(t, hookData))
		return db.GetBalance(h.caller).Uint64(), isReceiptConsumed(newPoolStateAdapter(h.state), r.ReceiptID)
	}
	b1, c1 := run()
	b2, c2 := run()
	if b1 != b2 || c1 != c2 || !c1 {
		t.Fatalf("settlement not deterministic across validators: (%d,%v) vs (%d,%v)", b1, c1, b2, c2)
	}
}

// TestSettle_HaltGlobal: a global halt reverts the swap with NO partial state, and
// withdraw still works (never strand funds). Resume restores settlement.
func TestSettle_HaltGlobal(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	h.fund(t, 10_000, 10_000)
	kv := newPoolStateAdapter(h.state)

	// Seed the vault with native and give the depositor a native deposit so they
	// have a withdrawable claim during the halt (never-strand-funds check). The
	// deposit's "EVM moved msg.value" model: the vault self-balance must cover it.
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(2000))
	depCalldata := prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 2000))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, depCalldata, 5_000_000, false); err != nil {
		t.Fatalf("deposit during setup failed: %v", err)
	}

	// Halt globally.
	SetHaltGlobal(kv, true)

	nativeID := [32]byte{}
	hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))

	senderBefore := db.GetBalance(h.caller).Uint64()
	_, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false)
	if err != ErrDEXHalted {
		t.Fatalf("halted swap must revert ErrDEXHalted, got: %v", err)
	}
	// No partial state: the handler returned BEFORE any debit (halt is step 1).
	if db.GetBalance(h.caller).Uint64() != senderBefore {
		t.Fatal("halted swap must not move value")
	}

	// Withdraw still works during the halt (never strand funds).
	wdCalldata := prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 2000))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, wdCalldata, 5_000_000, false); err != nil {
		t.Fatalf("withdraw during halt must work, got: %v", err)
	}

	// Resume restores settlement.
	SetHaltGlobal(kv, false)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != nil {
		t.Fatalf("after resume, settle must work, got: %v", err)
	}
}

// TestSettle_HaltScoped: market / asset / certType / validatorSet halts each block
// the matching swap and nothing else.
func TestSettle_HaltScoped(t *testing.T) {
	mkHarness := func() (*settleHarness, []byte) {
		h := newSettleHarness(t)
		h.fund(t, 10_000, 10_000)
		nativeID := [32]byte{}
		hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1)
		return h, prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	}

	// Market halt.
	h, calldata := mkHarness()
	SetHaltMarket(newPoolStateAdapter(h.state), h.key.ID(), true)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrMarketHalted {
		t.Fatalf("market halt must revert ErrMarketHalted, got: %v", err)
	}

	// Asset halt (native = all-zero asset).
	h, calldata = mkHarness()
	SetHaltAsset(newPoolStateAdapter(h.state), [32]byte{}, true)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrAssetHalted {
		t.Fatalf("asset halt must revert ErrAssetHalted, got: %v", err)
	}

	// CertType halt.
	h, calldata = mkHarness()
	SetHaltReceiptType(newPoolStateAdapter(h.state), CertTypeBLSFastPath, true)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrCertTypeDisabled {
		t.Fatalf("certType halt must revert ErrCertTypeDisabled, got: %v", err)
	}

	// ValidatorSet halt.
	h, calldata = mkHarness()
	SetHaltValidatorSet(newPoolStateAdapter(h.state), h.vsID, true)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrVSetHalted {
		t.Fatalf("validatorSet halt must revert ErrVSetHalted, got: %v", err)
	}
}

// TestSettle_RejectsForgedCert: the e2e path refuses a swap whose cert is forged
// (tampered aggregate). This is the negative half of the EVM-layer red test: an
// uncertified "fill" cannot settle.
func TestSettle_RejectsForgedCert(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	db.AddBalance(h.caller, uint256.NewInt(10_000))
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(10_000))
	storeSettleVault(newPoolStateAdapter(h.state), [32]byte{}, big.NewInt(10_000))

	nativeID := [32]byte{}
	// Build a valid envelope, then corrupt the cert's aggregate signature.
	r := &DFillReceiptV1{
		Version: 1, NetworkID: h.networkID, DChainID: h.dChainID, CChainID: h.cChainID,
		DHeight: 100, MarketID: h.key.ID(), ReceiptID: keccak32([]byte("forge")),
		PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(h.params),
		Sender: h.caller, Recipient: h.caller, TokenInAssetID: nativeID, TokenOutAssetID: nativeID,
		AmountIn: big.NewInt(1000), AmountOut: big.NewInt(990), FeeAmount: big.NewInt(0),
		Deadline: 1 << 40, PrecompileAddr: poolManagerAddr9999, CertType: CertTypeBLSFastPath,
	}
	cert := buildCert(t, h.vsID, h.vals, r, r.ReceiptID, 0, 1)
	cert.AggregateSignature[5] ^= 0xFF // forge
	hookData := EncodeSettlementHookData(r, cert, nil)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))

	senderBefore := db.GetBalance(h.caller).Uint64()
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err == nil {
		t.Fatal("forged cert must be refused")
	}
	if db.GetBalance(h.caller).Uint64() != senderBefore {
		t.Fatal("forged-cert swap must not move value")
	}
}

// TestSettle_BindingRejectsWrongChain: a receipt naming a different networkID is
// refused (cross-chain replay defense).
func TestSettle_BindingRejectsWrongChain(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	db.AddBalance(h.caller, uint256.NewInt(10_000))
	storeSettleVault(newPoolStateAdapter(h.state), [32]byte{}, big.NewInt(10_000))

	r := &DFillReceiptV1{
		Version: 1, NetworkID: 999 /* WRONG */, DChainID: h.dChainID, CChainID: h.cChainID,
		DHeight: 100, MarketID: h.key.ID(), ReceiptID: keccak32([]byte("wrongchain")),
		PoolKeyHash: h.key.ID(), SwapParamsHash: swapParamsHash(h.params),
		Sender: h.caller, Recipient: h.caller, AmountIn: big.NewInt(1000), AmountOut: big.NewInt(990),
		FeeAmount: big.NewInt(0), Deadline: 1 << 40, PrecompileAddr: poolManagerAddr9999, CertType: CertTypeBLSFastPath,
	}
	cert := buildCert(t, h.vsID, h.vals, r, r.ReceiptID, 0, 1)
	hookData := EncodeSettlementHookData(r, cert, nil)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, false); err != ErrReceiptWrongNetwork {
		t.Fatalf("wrong-network receipt must revert ErrReceiptWrongNetwork, got: %v", err)
	}
}

// TestSettle_0x9010_Forwarder: a swap hitting the deprecated 0x9010 forwards to
// the SAME 0x9999 settlement (one money path), and 0x9010 value-moving non-swap
// selectors revert PRECOMPILE_MOVED.
func TestSettle_0x9010_Forwarder(t *testing.T) {
	h := newSettleHarness(t)
	h.fund(t, 10_000, 10_000)

	nativeID := [32]byte{}
	hookData := h.receiptFor(t, nativeID, h.outAssetID(), 1000, 990, 0, 1)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))

	// Route through the 0x9010 DEXContract.runSwap forwarder.
	dc := &DEXContract{poolManager: NewPoolManager(&mockEngine{})}
	if _, _, err := dc.Run(h.state, h.caller, lxPoolAddr, calldata, 5_000_000, false); err != nil {
		t.Fatalf("0x9010 swap forwarder must settle, got: %v", err)
	}
	// The receipt is now consumed in the SHARED 0x9999 namespace.
	r, _ := DecodeFillReceipt(mustReceiptBytes(t, hookData))
	if !isReceiptConsumed(newPoolStateAdapter(h.state), r.ReceiptID) {
		t.Fatal("forwarded swap must consume the receipt in the 0x9999 namespace")
	}

	// A non-swap value-moving 0x9010 selector reverts PRECOMPILE_MOVED.
	depCalldata := prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 100))
	if _, _, err := dc.Run(h.state, h.caller, lxPoolAddr, depCalldata, 5_000_000, false); err != ErrPrecompileMoved {
		t.Fatalf("0x9010 deposit must revert PRECOMPILE_MOVED, got: %v", err)
	}
}

// TestPredictAccesses_NoGlobalHotWrites: the access set has ZERO global write
// slots — every write is keyed by account, asset, receipt, allowance, or pool
// (Block-STM rule). Two swaps that share NOTHING produce disjoint write sets;
// two that share the receipt or an account conflict.
func TestPredictAccesses_NoGlobalHotWrites(t *testing.T) {
	r1 := sampleReceipt()
	r1.ReceiptID = keccak32([]byte("r1"))
	// r2 shares NOTHING with r1: distinct receipt, accounts, pool, BOTH assets, and
	// fee asset (so even the sharded fee/volume buckets differ).
	r2 := sampleReceipt()
	r2.ReceiptID = keccak32([]byte("r2"))
	r2.Sender = common.HexToAddress("0x2222222222222222222222222222222222222222")
	r2.Recipient = r2.Sender
	r2.MarketID = [32]byte{0x2B}
	r2.PoolKeyHash = [32]byte{0x2B}
	r2.TokenInAssetID = [32]byte{31: 0x08}
	r2.TokenOutAssetID = [32]byte{31: 0x09}
	r2.FeeAssetID = [32]byte{31: 0x08}

	a1 := PredictAccesses(r1, 1)
	a2 := PredictAccesses(r2, 1)

	// No write key is a constant/global: every write must contain either the
	// receiptID, an account address, an asset id, or a pool id.
	for _, w := range a1.Writes {
		if isGlobalHotKey(w) {
			t.Fatalf("write key %x is a global hot slot (forbidden under Block-STM)", w)
		}
	}
	// Disjoint swaps => disjoint write sets.
	if intersects(a1.Writes, a2.Writes) {
		t.Fatal("non-conflicting swaps must have disjoint write sets")
	}

	// Same-receipt swaps conflict on the consumedReceipt write.
	a1b := PredictAccesses(r1, 1)
	if !intersects(a1.Writes, a1b.Writes) {
		t.Fatal("two swaps for the same receipt must conflict (shared consumedReceipt write)")
	}
}

// --- test helpers ---

func prependSelector(sel uint32, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[0:4], sel)
	copy(out[4:], data)
	return out
}

func encodeDepositCalldata(asset common.Address, amount uint64) []byte {
	b := make([]byte, 64)
	copy(b[12:32], asset.Bytes())
	binary.BigEndian.PutUint64(b[56:64], amount)
	return b
}

func mustReceiptBytes(t *testing.T, hookData []byte) []byte {
	t.Helper()
	r, _, _, err := DecodeSettlementHookData(hookData)
	if err != nil {
		t.Fatalf("decode hookData: %v", err)
	}
	return r.Encode()
}

// isGlobalHotKey reports whether a derived storage key is one of the known global
// halt/config slots that are READ-only on the swap path (never written by a swap).
// A swap WRITE must never equal one of these.
func isGlobalHotKey(k common.Hash) bool {
	globals := []common.Hash{haltGlobalKey, cfgNetworkIDKey, cfgCChainIDKey}
	for _, g := range globals {
		if k == g {
			return true
		}
	}
	return false
}

func intersects(a, b []common.Hash) bool {
	set := make(map[common.Hash]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}

// compile-time: ensure the harness's contract satisfies the precompile interface.
var _ contract.StatefulPrecompiledContract = (*SettleContract)(nil)
