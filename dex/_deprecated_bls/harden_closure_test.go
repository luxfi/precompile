// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/geth/common"
	ethtypes "github.com/luxfi/geth/core/types"
)

// noVaultStateDB is a minimal StateDB that does NOT implement the erc20Vault
// capability — used to exercise the ErrSettleERC20Vault / (nil,false) defensive
// branches that the production poolStateAdapter never triggers.
type noVaultStateDB struct{}

func (noVaultStateDB) GetState(common.Address, common.Hash) common.Hash  { return common.Hash{} }
func (noVaultStateDB) SetState(common.Address, common.Hash, common.Hash) {}
func (noVaultStateDB) GetBalance(common.Address) *uint256.Int            { return uint256.NewInt(0) }
func (noVaultStateDB) AddBalance(common.Address, *uint256.Int)           {}
func (noVaultStateDB) SubBalance(common.Address, *uint256.Int)           {}
func (noVaultStateDB) Exist(common.Address) bool                         { return false }
func (noVaultStateDB) CreateAccount(common.Address)                      {}
func (noVaultStateDB) GetBlockNumber() uint64                            { return 0 }
func (noVaultStateDB) AddLog(*ethtypes.Log)                              {}

// harden_closure_test.go — final coverage closure for the consensus money paths:
// genesis Configure, halt-setter guards, donate/extsload edge branches, the analytics
// accrual paths, and the cert/registry decode edge cases.

// ── settleConfigurator.Configure (genesis seam) ──────────────────────────────

func TestCov_SettleConfigure_GenesisSeed(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.GetStateDB()
	vals := newTestValidators(t, 1, 1, 1)
	vs := validatorSetFrom([32]byte{0xDD}, [32]byte{0xA0}, vals)
	cfg := &SettleConfig{
		ProtocolFeeController: common.HexToAddress("0xFEE0000000000000000000000000000000000009"),
		NetworkID:             7,
		CChainID:              [32]byte{0xC7},
		ValidatorSets:         []ValidatorSet{*vs},
	}
	cfgr := &settleConfigurator{}
	if err := cfgr.Configure(nil, cfg, db, nil); err != nil {
		t.Fatalf("genesis Configure: %v", err)
	}
	// Chain identity persisted.
	gotNet, gotCID := loadSettleChainIdentity(newPoolStateAdapter(h.state))
	if gotNet != 7 || gotCID != ([32]byte{0xC7}) {
		t.Fatalf("Configure must persist chain identity, got net=%d cid=%x", gotNet, gotCID)
	}
	// Validator set seeded + resolvable.
	if _, err := ResolveValidatorSet(newPoolStateAdapter(h.state), [32]byte{0xDD}, [32]byte{0xA0}, CertTypeBLSFastPath, 100); err != nil {
		t.Fatalf("genesis-seeded set must resolve, got: %v", err)
	}
}

func TestCov_SettleConfigure_Refusals(t *testing.T) {
	cfgr := &settleConfigurator{}
	db := (&mockAccessibleState{stateDB: NewMockStateDB()}).GetStateDB()
	// wrong config type.
	if err := cfgr.Configure(nil, &QuoterConfig{}, db, nil); err == nil {
		t.Fatal("Configure with the wrong config type must error")
	}
	// missing controller.
	if err := cfgr.Configure(nil, &SettleConfig{}, db, nil); err != ErrDEXNoProtocolFeeController {
		t.Fatalf("Configure without a controller must revert, got: %v", err)
	}
	// genesis set with a missing PoP is rejected (the seeded set fails the PoP gate).
	vals := newTestValidators(t, 1, 1)
	vs := validatorSetFrom([32]byte{0xDD}, [32]byte{0xA1}, vals)
	vs.Validators[0].PoP = nil // strip a PoP.
	cfg := &SettleConfig{ProtocolFeeController: common.HexToAddress("0x1"), ValidatorSets: []ValidatorSet{*vs}}
	if err := cfgr.Configure(nil, cfg, db, nil); err != ErrVerifierBadPoP {
		t.Fatalf("genesis set with a missing PoP must be rejected, got: %v", err)
	}
}

// ── halt-setter guards (gas-OOG, short input, scoped setters) ────────────────

func TestCov_HaltSetters_Guards(t *testing.T) {
	h := newSettleHarness(t)
	controller := h.c.protocolFeeController

	// gas-OOG on each setter (suppliedGas < gasHaltAdmin) returns out-of-gas.
	for _, sel := range []uint32{SelectorSetHaltGlobal, SelectorSetHaltMarket, SelectorSetHaltAsset, SelectorSetHaltValidatorSet, SelectorSetHaltReceiptType} {
		if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(sel, make([]byte, 64)), 10, false); err == nil {
			t.Fatalf("under-gassed halt setter %x must revert", sel)
		}
	}
	// short input on setHaltGlobal (<32) / scoped (<64) / receiptType (<64).
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltGlobal, make([]byte, 4)), 5_000_000, false); err == nil {
		t.Fatal("short setHaltGlobal input must revert")
	}
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltMarket, make([]byte, 32)), 5_000_000, false); err == nil {
		t.Fatal("short setHaltMarket input must revert")
	}
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltReceiptType, make([]byte, 32)), 5_000_000, false); err == nil {
		t.Fatal("short setHaltReceiptType input must revert")
	}
	// clearing a halt (on=false) also exercises the setHalt(false) branch.
	mid := make([]byte, 64)
	mid[63] = 0 // off
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorSetHaltMarket, mid), 5_000_000, false); err != nil {
		t.Fatalf("clear setHaltMarket: %v", err)
	}
}

func TestCov_RegisterValidatorSet_GasOOG(t *testing.T) {
	h := newSettleHarness(t)
	controller := h.c.protocolFeeController
	vals := newTestValidators(t, 1, 1, 1)
	payload := encodeValidatorSetWire(t, h.dChainID, [32]byte{0x7A}, CertTypeBLSFastPath, 0, 2, 3, vals, true)
	// Base gas too low.
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, payload), 10, false); err == nil {
		t.Fatal("under-gassed register (base) must revert")
	}
	// Enough for base but not for the per-validator PoP charge.
	if _, _, err := h.c.Run(h.state, controller, poolManagerAddr9999, prependSelector(SelectorRegisterValidatorSet, payload), gasRegisterValidatorSetBase+1, false); err == nil {
		t.Fatal("under-gassed register (per-validator) must revert")
	}
}

// ── donate / extsload edge branches ──────────────────────────────────────────

func TestCov_Donate_ReadOnlyAndGas(t *testing.T) {
	h := newSettleHarness(t)
	// readOnly donate => ErrUnsupported.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDonate, make([]byte, 32)), 5_000_000, true); err != ErrUnsupported {
		t.Fatalf("readOnly donate must revert ErrUnsupported, got: %v", err)
	}
	// gas-OOG donate.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDonate, make([]byte, 32)), 10, false); err == nil {
		t.Fatal("under-gassed donate must revert")
	}
}

func TestCov_Extsload_EdgeBranches(t *testing.T) {
	h := newSettleHarness(t)
	h.registerMarket(t)
	// extsload single: gas-OOG + short input.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsload, make([]byte, 32)), 10, true); err == nil {
		t.Fatal("under-gassed extsload must revert")
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsload, make([]byte, 4)), 5_000_000, true); err == nil {
		t.Fatal("short extsload input must revert")
	}
	// extsloadArray: gas-OOG (offset+length present but gas too low for n words).
	arr := make([]byte, 64)
	arr[31] = 0x20 // offset
	arr[63] = 0x02 // length 2 (but no data words => length OOB => revert)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, arr), 5_000_000, true); err == nil {
		t.Fatal("extsloadArray length beyond data must revert")
	}
	// extsloadArray: too-short top-level input.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, make([]byte, 10)), 5_000_000, true); err == nil {
		t.Fatal("short extsloadArray input must revert")
	}
	// extsloadArray happy path with n words + tight gas to hit the cost branch.
	slot := marketSlot(h.key.ID(), marketPriceSuffix)
	good := make([]byte, 0, 96)
	good = append(good, leftPad32([]byte{0x20})...)
	good = append(good, leftPad32([]byte{0x01})...)
	good = append(good, slot[:]...)
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, good), GasPoolLookup, true); err == nil {
		t.Fatal("extsloadArray with gas only for the base lookup (not the words) must revert")
	}
}

// ── analytics accrual (fee/volume zero + positive) ───────────────────────────

func TestCov_AccrueFeeAndVolume(t *testing.T) {
	h := newSettleHarness(t)
	db := newPoolStateAdapter(h.state)
	asset := [32]byte{0x11}
	pool := [32]byte{0x22}
	// zero/nil amount is a no-op (early return).
	accrueFee(db, asset, big.NewInt(0), 1)
	accrueFee(db, asset, nil, 1)
	accrueVolume(db, pool, big.NewInt(0), 1)
	accrueVolume(db, pool, nil, 1)
	if db.GetState(poolManagerAddr9999, feeBucketKey(asset, 1)) != (common.Hash{}) {
		t.Fatal("zero fee must not write a bucket")
	}
	// positive accrual accumulates in the sharded bucket.
	accrueFee(db, asset, big.NewInt(100), 1)
	accrueFee(db, asset, big.NewInt(50), 1)
	if new(big.Int).SetBytes(db.GetState(poolManagerAddr9999, feeBucketKey(asset, 1)).Bytes()).Cmp(big.NewInt(150)) != 0 {
		t.Fatal("fee bucket must accumulate to 150")
	}
	accrueVolume(db, pool, big.NewInt(1000), 5)
	if new(big.Int).SetBytes(db.GetState(poolManagerAddr9999, volBucketKey(pool, 5)).Bytes()).Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("volume bucket must accumulate to 1000")
	}
	// A swap with a non-zero fee exercises accrueFee on the live path.
	h.fund(t, 10_000, 10_000)
	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.FeeAmount = big.NewInt(7)
		r.FeeAssetID = [32]byte{}
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err != nil {
		t.Fatalf("swap with fee: %v", err)
	}
}

// ── cert/registry decode edge cases ──────────────────────────────────────────

func TestCov_DecodeBLSCert_Malformed(t *testing.T) {
	// too short.
	if _, err := DecodeBLSCert(make([]byte, 10)); err != ErrCertTooShort {
		t.Fatalf("short cert must be ErrCertTooShort, got: %v", err)
	}
	// bad version.
	b := make([]byte, blsCertFixedHeaderLen)
	b[0] = 0xFF
	if _, err := DecodeBLSCert(b); err != ErrCertVersion {
		t.Fatalf("bad version must be ErrCertVersion, got: %v", err)
	}
	// bitmap length overruns the buffer.
	b2 := make([]byte, blsCertFixedHeaderLen)
	b2[0] = blsCertVersion
	// set bitmapLen field (last 4 bytes of the fixed header) to a huge value.
	off := blsCertFixedHeaderLen - 4
	b2[off], b2[off+1], b2[off+2], b2[off+3] = 0xFF, 0xFF, 0xFF, 0xFF
	if _, err := DecodeBLSCert(b2); err != ErrCertTooShort {
		t.Fatalf("bitmap overrun must be ErrCertTooShort, got: %v", err)
	}
	// well-formed round-trip with a 1-byte bitmap.
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	c := buildCert(t, [32]byte{0x01}, vals, r, r.ReceiptID, 0, 1)
	got, err := DecodeBLSCert(c.Encode())
	if err != nil || string(got.SignerBitmap) != string(c.SignerBitmap) {
		t.Fatalf("round-trip mismatch: %v", err)
	}
}

func TestCov_VerifyBLSCert_HeaderRejections(t *testing.T) {
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	vset := validatorSetFrom(r.DChainID, [32]byte{0x01}, vals)
	good := buildCert(t, [32]byte{0x01}, vals, r, r.ReceiptID, 0, 1)

	// wrong version.
	bad := *good
	bad.Version = 9
	if err := VerifyBLSCert(&bad, r, r.ReceiptID, vset); err != ErrCertVersion {
		t.Fatalf("bad version must be ErrCertVersion, got: %v", err)
	}
	// wrong certType.
	bad = *good
	bad.CertType = CertTypeZK
	if err := VerifyBLSCert(&bad, r, r.ReceiptID, vset); err != ErrCertType {
		t.Fatalf("bad certType must be ErrCertType, got: %v", err)
	}
	// empty bitmap (no signers).
	bad = *good
	bad.SignerBitmap = make([]byte, 1) // all-zero, popcount 0.
	if err := VerifyBLSCert(&bad, r, r.ReceiptID, vset); err != ErrCertNoSigners {
		t.Fatalf("empty bitmap must be ErrCertNoSigners, got: %v", err)
	}
	// wrong bitmap length.
	bad = *good
	bad.SignerBitmap = make([]byte, 5) // n=3 => wants 1 byte.
	bad.SignerBitmap[0] = 0x80
	if err := VerifyBLSCert(&bad, r, r.ReceiptID, vset); err != ErrCertBitmapLen {
		t.Fatalf("wrong bitmap length must be ErrCertBitmapLen, got: %v", err)
	}
	// unparseable aggregate signature (all-zero is not a valid G2 point).
	bad = *good
	bad.AggregateSignature = [96]byte{}
	if err := VerifyBLSCert(&bad, r, r.ReceiptID, vset); err == nil {
		t.Fatal("all-zero aggregate signature must fail verification")
	}
}

func TestCov_BitSet_OutOfRange(t *testing.T) {
	bm := []byte{0x80} // bit 0 set.
	if !bitSet(bm, 0) {
		t.Fatal("bit 0 must be set")
	}
	if bitSet(bm, 99) { // byteIdx 12 >= len(bm)=1 => false.
		t.Fatal("out-of-range bit must read false")
	}
}

func TestCov_SigFrom_Invalid(t *testing.T) {
	// An all-zero 96-byte blob is not a valid signature; sigFrom returns nil.
	if sigFrom([96]byte{}) != nil {
		t.Fatal("all-zero signature must decode to nil")
	}
	// A real signature decodes to non-nil.
	sk, _ := bls.NewSecretKey()
	sig, _ := sk.Sign([]byte("x"))
	var b [96]byte
	copy(b[:], bls.SignatureToBytes(sig))
	if sigFrom(b) == nil {
		t.Fatal("a valid signature must decode to non-nil")
	}
}

// ── ResolveValidatorSet tamper / corruption branches ─────────────────────────

func TestCov_ResolveValidatorSet_TamperGuards(t *testing.T) {
	db := NewMockStateDB()
	vals := newTestValidators(t, 5, 3, 2) // total 10
	dC := [32]byte{0xDD}
	vsID := [32]byte{0xB0}
	vs := validatorSetFrom(dC, vsID, vals)
	if err := PutValidatorSet(db, vs); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Corrupt the stored total in the meta slot so total != storedTotal.
	meta := db.GetState(poolManagerAddr9999, vrMetaKey(dC, vsID))
	meta[14] = 0xFF // bump storedTotal high byte.
	db.SetState(poolManagerAddr9999, vrMetaKey(dC, vsID), meta)
	if _, err := ResolveValidatorSet(db, dC, vsID, CertTypeBLSFastPath, 100); err != ErrVerifierBadEntry {
		t.Fatalf("tampered total must revert ErrVerifierBadEntry, got: %v", err)
	}

	// Corrupt a stored pubkey so PublicKeyFromCompressedBytes fails.
	db2 := NewMockStateDB()
	vs2 := validatorSetFrom(dC, [32]byte{0xB1}, newTestValidators(t, 1, 1))
	if err := PutValidatorSet(db2, vs2); err != nil {
		t.Fatalf("put2: %v", err)
	}
	db2.SetState(poolManagerAddr9999, vrValKey(vrPkAPrefix, dC, [32]byte{0xB1}, 0), common.Hash{0x01}) // garbage pubkey bytes.
	if _, err := ResolveValidatorSet(db2, dC, [32]byte{0xB1}, CertTypeBLSFastPath, 100); err != ErrVerifierBadKey {
		t.Fatalf("corrupt pubkey must revert ErrVerifierBadKey, got: %v", err)
	}
}

// TestCov_PutValidatorSet_Guards: empty set, oversized count, nil pubkey, short PoP.
func TestCov_PutValidatorSet_Guards(t *testing.T) {
	db := NewMockStateDB()
	// empty set.
	if err := PutValidatorSet(db, &ValidatorSet{DChainID: [32]byte{0xDD}, ValidatorSetID: [32]byte{0x01}}); err != ErrVerifierBadEntry {
		t.Fatalf("empty set must revert ErrVerifierBadEntry, got: %v", err)
	}
	// nil pubkey.
	if err := PutValidatorSet(db, &ValidatorSet{
		DChainID: [32]byte{0xDD}, ValidatorSetID: [32]byte{0x02},
		Validators: []Validator{{PublicKey: nil, Weight: 1}}, TotalWeight: 1,
	}); err != ErrVerifierBadKey {
		t.Fatalf("nil pubkey must revert ErrVerifierBadKey, got: %v", err)
	}
	// valid key but short PoP.
	v := newTestValidators(t, 1)[0]
	if err := PutValidatorSet(db, &ValidatorSet{
		DChainID: [32]byte{0xDD}, ValidatorSetID: [32]byte{0x03},
		Validators: []Validator{{PublicKey: v.pk, Weight: 1, PoP: make([]byte, 10)}}, TotalWeight: 1,
	}); err != ErrVerifierBadPoP {
		t.Fatalf("short PoP must revert ErrVerifierBadPoP, got: %v", err)
	}
}

// ── verifyCert resolve-failure branch ────────────────────────────────────────

func TestCov_VerifyCert_UnknownSet(t *testing.T) {
	h := newSettleHarness(t)
	r := sampleReceipt()
	r.DChainID = [32]byte{0xEE} // no registry entry for this dChainID.
	cert := &BLSCert{Version: blsCertVersion, CertType: CertTypeBLSFastPath, ValidatorSetID: [32]byte{0x99}, SignerBitmap: []byte{0x80}}
	if err := verifyCert(newPoolStateAdapter(h.state), r, r.ReceiptID, cert); err != ErrVerifierNotFound {
		t.Fatalf("verifyCert on an unknown set must revert ErrVerifierNotFound, got: %v", err)
	}
}

// ── custody / initialize / market guards ─────────────────────────────────────

func TestCov_Custody_GuardBranches(t *testing.T) {
	h := newSettleHarness(t)
	// withdraw: readOnly, gas-OOG, short input.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 1)), 5_000_000, true); err == nil {
		t.Fatal("readOnly withdraw must revert")
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 1)), 10, false); err == nil {
		t.Fatal("under-gassed withdraw must revert")
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorWithdraw, make([]byte, 10)), 5_000_000, false); err == nil {
		t.Fatal("short withdraw input must revert")
	}
	// deposit: gas-OOG.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 1)), 10, false); err == nil {
		t.Fatal("under-gassed deposit must revert")
	}
	// balanceOf: gas-OOG + short input.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorBalanceOf, make([]byte, 64)), 10, true); err == nil {
		t.Fatal("under-gassed balanceOf must revert")
	}
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorBalanceOf, make([]byte, 10)), 5_000_000, true); err == nil {
		t.Fatal("short balanceOf input must revert")
	}
}

func TestCov_Initialize_GuardBranches(t *testing.T) {
	h := newSettleHarness(t)
	// readOnly.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 5_000_000, true); err == nil {
		t.Fatal("readOnly initialize must revert")
	}
	// gas-OOG.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(h.key, new(big.Int).Set(Q96)), 10, false); err == nil {
		t.Fatal("under-gassed initialize must revert")
	}
	// short input.
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorInitialize, make([]byte, 10)), 5_000_000, false); err == nil {
		t.Fatal("short initialize input must revert")
	}
	// bad tickSpacing (0).
	badTS := h.key
	badTS.Fee = 200
	badTS.TickSpacing = 0
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, initCalldata(badTS, new(big.Int).Set(Q96)), 5_000_000, false); err != ErrInitTickSpacing {
		t.Fatalf("zero tickSpacing must revert ErrInitTickSpacing, got: %v", err)
	}
}

func TestCov_MarketExists(t *testing.T) {
	h := newSettleHarness(t)
	if MarketExists(newPoolStateAdapter(h.state), h.key) {
		t.Fatal("market must not exist before initialize")
	}
	h.registerMarket(t)
	if !MarketExists(newPoolStateAdapter(h.state), h.key) {
		t.Fatal("market must exist after initialize")
	}
}

// TestCov_Settle_FeeOnTransferInLegShort: a fee-on-transfer tokenIn delivers less
// than amountIn to the vault; settle() must refuse (ErrSettleObservedShort) rather
// than credit tokenOut against an under-funded tokenIn (conservation).
func TestCov_Settle_FeeOnTransferInLegShort(t *testing.T) {
	h := newERC20Harness(t)
	h.state.stateDB.feeOnTransferBps = 100 // 1% fee on transfer.
	w := h.wrapper()
	w.mintTestToken(h.key.Currency0.Address, h.caller, big.NewInt(5000))
	w.mintTestToken(h.key.Currency1.Address, poolManagerAddr9999, big.NewInt(5000))
	storeSettleVault(newPoolStateAdapter(h.state), assetID(h.key.Currency1), big.NewInt(5000))
	hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.TokenInAssetID = assetID(h.key.Currency0)
		r.TokenOutAssetID = assetID(h.key.Currency1)
		r.AmountIn = big.NewInt(1000) // vault receives only 990 (1% fee).
		r.AmountOut = big.NewInt(900)
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err != ErrSettleObservedShort {
		t.Fatalf("fee-on-transfer tokenIn must revert ErrSettleObservedShort, got: %v", err)
	}
}

// TestCov_Custody_ERC20FeeOnTransferDeposit: a fee-on-transfer deposit credits only
// the OBSERVED delta (fee-on-transfer safe), not the requested amount.
func TestCov_Custody_ERC20FeeOnTransferDeposit(t *testing.T) {
	h := newSettleHarness(t)
	h.state.stateDB.feeOnTransferBps = 200 // 2% fee.
	tok := common.HexToAddress("0x00000000000000000000000000000000000000E5")
	w := h.wrapper()
	w.mintTestToken(tok, h.caller, big.NewInt(5000))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(tok, 1000)), 5_000_000, false); err != nil {
		t.Fatalf("fee-on-transfer ERC-20 deposit: %v", err)
	}
	// Credited the observed delta (1000 - 2% = 980), not 1000.
	if got := loadDepositorClaim(newPoolStateAdapter(h.state), h.caller, assetID(Currency{Address: tok})); got.Cmp(big.NewInt(980)) != 0 {
		t.Fatalf("fee-on-transfer deposit must credit the observed 980, got %s", got)
	}
}

// TestCov_StateDBERC20_NonVault: stateDBERC20 resolves (nil, false) for a StateDB
// that does not implement the erc20Vault capability (the defensive branch). The
// positive path (poolStateAdapter forwarding to an erc20Vault underlying) is
// exercised by every ERC-20 settle/custody test.
func TestCov_StateDBERC20_NonVault(t *testing.T) {
	if _, ok := stateDBERC20(noVaultStateDB{}); ok {
		t.Fatal("a non-erc20Vault StateDB must resolve (nil, false)")
	}
}

// TestCov_Settle_ERC20VaultUnavailable: settle() with an ERC-20 tokenIn against a
// StateDB that lacks the erc20Vault capability reverts ErrSettleERC20Vault (the
// defensive no-mint branch), never faking a credit.
func TestCov_Settle_ERC20VaultUnavailable(t *testing.T) {
	r := &DFillReceiptV1{
		TokenInAssetID:  assetID(Currency{Address: common.HexToAddress("0xAA")}), // ERC-20 in.
		TokenOutAssetID: [32]byte{},
		AmountIn:        big.NewInt(100),
		AmountOut:       big.NewInt(0),
		Sender:          common.HexToAddress("0x1"),
		Recipient:       common.HexToAddress("0x1"),
	}
	if err := settle(noVaultStateDB{}, r); err != ErrSettleERC20Vault {
		t.Fatalf("ERC-20 settle without a vault must revert ErrSettleERC20Vault, got: %v", err)
	}
}

// TestCov_StateView_TimestampBoilerplate covers the trivial Timestamp accessor.
func TestCov_StateView_TimestampBoilerplate(t *testing.T) {
	if (&StateViewConfig{}).Timestamp() != nil {
		t.Fatal("nil-upgrade StateViewConfig.Timestamp must be nil")
	}
	if (&PositionManagerConfig{}).Timestamp() != nil {
		t.Fatal("nil-upgrade PositionManagerConfig.Timestamp must be nil")
	}
	if (&SettleConfig{}).Timestamp() != nil {
		t.Fatal("nil-upgrade SettleConfig.Timestamp must be nil")
	}
}
