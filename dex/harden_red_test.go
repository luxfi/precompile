// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/geth/common"
)

// harden_red_test.go — one targeted adversarial test per CONFIRMED finding,
// proving the exploit is now BLOCKED. Each test drives the REAL handler path
// (SettleContract.Run / VerifyBLSCert / PutValidatorSet) so it exercises exactly
// the code an attacker reaches, not a reconstruction.

// ── shared adversarial helpers ───────────────────────────────────────────────

// buildReceiptCert builds a DFillReceiptV1 bound to the harness swap with the given
// in/out asset IDs + amounts, then a cert signed (over the FULL value-bound message)
// by the given signer indices. Returns the encoded settlement hookData.
func (h *settleHarness) buildReceiptCert(t testing.TB, mutate func(*DFillReceiptV1), signers ...int) ([]byte, *DFillReceiptV1, *BLSCert) {
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
		ReceiptID:       keccak32([]byte("hardrcpt-1")),
		PoolKeyHash:     h.key.ID(),
		SwapParamsHash:  swapParamsHash(h.params),
		Sender:          h.caller,
		Recipient:       h.caller,
		TokenInAssetID:  [32]byte{},
		TokenOutAssetID: h.outAssetID(),
		AmountIn:        big.NewInt(1000),
		AmountOut:       big.NewInt(990),
		FeeAmount:       big.NewInt(0),
		FeeAssetID:      [32]byte{},
		Deadline:        1 << 40,
		Nonce:           1,
		PrecompileAddr:  poolManagerAddr9999,
		CertType:        CertTypeBLSFastPath,
	}
	if mutate != nil {
		mutate(r)
	}
	cert := buildCert(t, h.vsID, h.vals, r, r.ReceiptID, signers...)
	return EncodeSettlementHookData(r, cert, nil), r, cert
}

// runSwap drives the full 0x9999 swap path with the given hookData and caller.
func (h *settleHarness) runSwap(t testing.TB, caller common.Address, hookData []byte) ([]byte, error) {
	t.Helper()
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	out, _, err := h.c.Run(h.state, caller, poolManagerAddr9999, calldata, 50_000_000, false)
	return out, err
}

// ── FINDING bls-quorum-attacker-controlled ───────────────────────────────────

// TestRED_AttackerLowersQuorum: a single-signer cert can no longer claim a tiny
// quorum fraction — the quorum is registry-pinned and floored at 2/3 BFT, and the
// cert carries no quorum field at all. A 1-of-3 (33%) signer set is refused.
func TestRED_AttackerLowersQuorum(t *testing.T) {
	vsID := [32]byte{0x21}
	vals := newTestValidators(t, 1, 1, 1) // total 3
	r := sampleReceipt()
	root := r.ReceiptID
	vset := validatorSetFrom(r.DChainID, vsID, vals)

	// A single signer (weight 1 / total 3 = 33%). There is NO quorum field to lower.
	cert := buildCert(t, vsID, vals, r, root, 0)
	if err := VerifyBLSCert(cert, r, root, vset); err != ErrCertQuorumNotMet {
		t.Fatalf("single-signer cert must fail the registry quorum, got: %v", err)
	}
}

// TestRED_QuorumBoundary: pins the >=2/3 BFT boundary (matches Lux warp VerifyWeight
// semantics). With weights {1,1,1}: 2 signers (exactly 2/3) ACCEPT, 1 signer (1/3)
// REJECT. With weights {1,1,2} (total 4): signers {0,1}=2/4=50% REJECT, {0,1,2}=4/4
// ACCEPT — proving the floor is genuinely weight-proportional, not count-based.
func TestRED_QuorumBoundary(t *testing.T) {
	t.Run("equal-weights-exactly-two-thirds", func(t *testing.T) {
		vals := newTestValidators(t, 1, 1, 1)
		r := sampleReceipt()
		vset := validatorSetFrom(r.DChainID, [32]byte{0x22}, vals)
		// exactly 2/3 => accept (>= boundary).
		if err := VerifyBLSCert(buildCert(t, [32]byte{0x22}, vals, r, r.ReceiptID, 0, 1), r, r.ReceiptID, vset); err != nil {
			t.Fatalf("exactly 2/3 must verify (>= boundary), got: %v", err)
		}
		// 1/3 => reject.
		if err := VerifyBLSCert(buildCert(t, [32]byte{0x22}, vals, r, r.ReceiptID, 0), r, r.ReceiptID, vset); err != ErrCertQuorumNotMet {
			t.Fatalf("1/3 must be rejected, got: %v", err)
		}
	})
	t.Run("weighted-below-two-thirds-rejected", func(t *testing.T) {
		vals := newTestValidators(t, 1, 1, 2) // total 4
		r := sampleReceipt()
		vset := validatorSetFrom(r.DChainID, [32]byte{0x23}, vals)
		// signers {0,1} hold 2/4 = 50% < 2/3 => reject even though that is 2 of 3 nodes.
		if err := VerifyBLSCert(buildCert(t, [32]byte{0x23}, vals, r, r.ReceiptID, 0, 1), r, r.ReceiptID, vset); err != ErrCertQuorumNotMet {
			t.Fatalf("50%% weight must be rejected (weight, not count), got: %v", err)
		}
		// all 3 (4/4) => accept.
		if err := VerifyBLSCert(buildCert(t, [32]byte{0x23}, vals, r, r.ReceiptID, 0, 1, 2), r, r.ReceiptID, vset); err != nil {
			t.Fatalf("full-weight cert must verify, got: %v", err)
		}
	})
}

// TestRED_RegistryQuorumStricterThanBFT: governance can pin a quorum ABOVE 2/3
// (e.g. 90%); a cert holding only 2/3 weight then fails the registry quorum even
// though it clears the BFT floor — the registry value binds when stricter.
func TestRED_RegistryQuorumStricterThanBFT(t *testing.T) {
	vals := newTestValidators(t, 1, 1, 1)
	r := sampleReceipt()
	vset := validatorSetFrom(r.DChainID, [32]byte{0x24}, vals)
	vset.QuorumNum, vset.QuorumDen = 9, 10 // 90% registry quorum.
	// 2 of 3 = 67% < 90% => rejected by the registry quorum.
	if err := VerifyBLSCert(buildCert(t, [32]byte{0x24}, vals, r, r.ReceiptID, 0, 1), r, r.ReceiptID, vset); err != ErrCertQuorumNotMet {
		t.Fatalf("67%% must fail a 90%% registry quorum, got: %v", err)
	}
}

// TestRED_SettleSwap_SubBFTCertDrainsVault: end-to-end — a single-signer (33%) cert
// against a funded vault must REVERT and move zero value (the headline drain).
func TestRED_SettleSwap_SubBFTCertDrainsVault(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	h.fund(t, 10_000, 10_000)

	// Build a receipt + a cert signed by ONLY validator 0 (1/3 weight).
	hookData, _, _ := h.buildReceiptCert(t, nil, 0)
	senderBefore := db.GetBalance(h.caller).Uint64()
	vaultBefore := h.wrapper().TokenBalanceOf(h.outToken(), poolManagerAddr9999)

	if _, err := h.runSwap(t, h.caller, hookData); err != ErrCertQuorumNotMet {
		t.Fatalf("sub-BFT cert must revert ErrCertQuorumNotMet end-to-end, got: %v", err)
	}
	if db.GetBalance(h.caller).Uint64() != senderBefore {
		t.Fatal("sub-BFT settle must not debit the sender")
	}
	if h.wrapper().TokenBalanceOf(h.outToken(), poolManagerAddr9999).Cmp(vaultBefore) != 0 {
		t.Fatal("sub-BFT settle must not drain the vault")
	}
}

// ── FINDING bls-zero-total-weight-vacuous-quorum ─────────────────────────────

// TestRED_WeightMeetsQuorum_Table directly tables the quorum + BFT primitives
// including the zero-total degenerate case (must be false, never vacuously true).
func TestRED_WeightMeetsQuorum_Table(t *testing.T) {
	cases := []struct {
		sw, tw   uint64
		num, den uint32
		want     bool
	}{
		{0, 0, 2, 3, false},              // degenerate: 0>=0 must NOT vacuously pass (fix).
		{0, 10, 2, 3, false},             // no signers.
		{7, 10, 2, 3, true},              // 70% >= 2/3.
		{6, 10, 2, 3, false},             // 60% < 2/3.
		{20, 30, 2, 3, true},             // exactly 2/3 (>=).
		{1<<63 + 1, 1 << 63, 1, 1, true}, // high-bit products: sw*1 >= tw*1.
		{1 << 62, 1 << 63, 1, 1, false},  // 50% with overflow-scale weights.
	}
	for _, c := range cases {
		if got := weightMeetsQuorum(c.sw, c.tw, c.num, c.den); got != c.want {
			t.Fatalf("weightMeetsQuorum(%d,%d,%d,%d)=%v want %v", c.sw, c.tw, c.num, c.den, got, c.want)
		}
	}
	// BFT floor: zero total never clears; exactly 2/3 clears (>=); below does not.
	if meetsBFTFloor(0, 0) {
		t.Fatal("meetsBFTFloor(0,0) must be false")
	}
	if !meetsBFTFloor(2, 3) {
		t.Fatal("meetsBFTFloor(2,3) must be true (>= 2/3)")
	}
	if meetsBFTFloor(1, 3) {
		t.Fatal("meetsBFTFloor(1,3) must be false")
	}
}

// TestRED_PutValidatorSet_RejectsZeroTotalWeight: a set whose weights sum to zero is
// refused at the writer (so a degenerate set never reaches the verifier).
func TestRED_PutValidatorSet_RejectsZeroTotalWeight(t *testing.T) {
	db := NewMockStateDB()
	vals := newTestValidators(t, 0, 0, 0) // all weight 0
	vs := validatorSetFrom([32]byte{0xDD}, [32]byte{0x31}, vals)
	if err := PutValidatorSet(db, vs); err != ErrVerifierBadEntry {
		t.Fatalf("zero-total-weight set must be rejected, got: %v", err)
	}
}

// TestRED_ZeroTotalWeightSet_VerifyRejected: even if a zero-total set somehow exists
// in memory, VerifyBLSCert rejects it (the quorum primitive fails closed) despite a
// genuine single-signer signature.
func TestRED_ZeroTotalWeightSet_VerifyRejected(t *testing.T) {
	vals := newTestValidators(t, 0, 0, 0)
	r := sampleReceipt()
	vset := validatorSetFrom(r.DChainID, [32]byte{0x32}, vals) // TotalWeight == 0
	cert := buildCert(t, [32]byte{0x32}, vals, r, r.ReceiptID, 0)
	if err := VerifyBLSCert(cert, r, r.ReceiptID, vset); err != ErrCertQuorumNotMet {
		t.Fatalf("zero-total-weight set must fail quorum, got: %v", err)
	}
}

// ── FINDING bls-no-proof-of-possession / rogue-key ───────────────────────────

// TestRED_RogueKeyRegistrationRejected: a rogue key (no valid PoP) cannot be
// registered. This forecloses the rogue-key forgery at the source — the set is
// never written, so the downstream aggregate-forgery is unreachable.
func TestRED_RogueKeyRegistrationRejected(t *testing.T) {
	db := NewMockStateDB()
	honest := newTestValidators(t, 1, 1)
	attacker, _ := bls.NewSecretKey()

	// Rogue member carrying NO PoP.
	vs := &ValidatorSet{
		DChainID: [32]byte{0xDD}, ValidatorSetID: [32]byte{0x41},
		CertType: CertTypeBLSFastPath, Status: VerifierActive, QuorumNum: 2, QuorumDen: 3,
	}
	for _, v := range honest {
		vs.Validators = append(vs.Validators, Validator{PublicKey: v.pk, Weight: v.weight, PoP: makePoP(t, v)})
		vs.TotalWeight += v.weight
	}
	vs.Validators = append(vs.Validators, Validator{PublicKey: attacker.PublicKey(), Weight: 1, PoP: nil})
	vs.TotalWeight += 1
	if err := PutValidatorSet(db, vs); err != ErrVerifierBadPoP {
		t.Fatalf("rogue key with no PoP must be rejected, got: %v", err)
	}
	// The set was NOT written: resolving it is not-found.
	if _, err := ResolveValidatorSet(db, [32]byte{0xDD}, [32]byte{0x41}, CertTypeBLSFastPath, 100); err != ErrVerifierNotFound {
		t.Fatalf("a rejected set must not be written, got: %v", err)
	}
}

// TestRED_PoPForWrongKeyRejected: a member whose PoP is over a DIFFERENT key (a PoP
// lifted from another validator) is rejected — the PoP binds to its own key.
func TestRED_PoPForWrongKeyRejected(t *testing.T) {
	db := NewMockStateDB()
	a := newTestValidators(t, 1)[0]
	b := newTestValidators(t, 1)[0]
	// a's key with b's PoP (over b's key) — mismatch.
	vs := &ValidatorSet{
		DChainID: [32]byte{0xDD}, ValidatorSetID: [32]byte{0x42},
		CertType: CertTypeBLSFastPath, Status: VerifierActive, QuorumNum: 1, QuorumDen: 1,
		Validators:  []Validator{{PublicKey: a.pk, Weight: 1, PoP: makePoP(t, b)}},
		TotalWeight: 1,
	}
	if err := PutValidatorSet(db, vs); err != ErrVerifierBadPoP {
		t.Fatalf("PoP over a different key must be rejected, got: %v", err)
	}
}

// ── FINDING dex-cert-no-value-bind (CRITICAL) ────────────────────────────────

// TestRED_CertDoesNotBindValueFields: the headline drain. Take a VALID receipt+cert,
// then forge a NEW receipt copying the signed roots/id verbatim but with attacker
// amounts/parties, and REUSE the cert byte-for-byte. The signed message now binds
// the full value, so the recomputed message differs and the cert no longer verifies.
func TestRED_CertDoesNotBindValueFields(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	h.fund(t, 10_000, 500_000) // vault funded with a big output balance to "drain".

	// A legitimate receipt + 2-of-3 cert (the public cert an attacker would harvest).
	_, legit, cert := h.buildReceiptCert(t, nil, 0, 1)

	// Forge a new receipt: keep EVERY signed root/id field identical, but set attacker
	// amounts (amountIn=1, amountOut=huge). Reuse the cert byte-for-byte.
	forged := *legit
	forged.AmountIn = big.NewInt(1)
	forged.AmountOut = big.NewInt(500_000)
	forgedHook := EncodeSettlementHookData(&forged, cert, nil)

	senderBefore := db.GetBalance(h.caller).Uint64()
	vaultBefore := h.wrapper().TokenBalanceOf(h.outToken(), poolManagerAddr9999)
	if _, err := h.runSwap(t, h.caller, forgedHook); err != ErrCertMsgMismatch {
		t.Fatalf("value-tampered receipt with a reused cert must revert ErrCertMsgMismatch, got: %v", err)
	}
	if db.GetBalance(h.caller).Uint64() != senderBefore {
		t.Fatal("value-tamper attack must move no native")
	}
	if h.wrapper().TokenBalanceOf(h.outToken(), poolManagerAddr9999).Cmp(vaultBefore) != 0 {
		t.Fatal("value-tamper attack must not drain the vault")
	}
}

// TestRED_CertValueBind_AnyFieldTamperReverts: mutate EACH value field in turn while
// reusing the original cert; every mutation must break the message binding. A
// correctly re-signed receipt for the same mutation settles (proving it is the
// SIGNATURE, not some other gate, that rejects the reused cert).
func TestRED_CertValueBind_AnyFieldTamperReverts(t *testing.T) {
	attacker := common.HexToAddress("0xA77ac4e7000000000000000000000000000000FF")
	mutators := map[string]func(*DFillReceiptV1){
		"AmountOut":     func(r *DFillReceiptV1) { r.AmountOut = big.NewInt(2000) },
		"AmountIn":      func(r *DFillReceiptV1) { r.AmountIn = big.NewInt(1) },
		"FeeAmount":     func(r *DFillReceiptV1) { r.FeeAmount = big.NewInt(777) },
		"FillID":        func(r *DFillReceiptV1) { r.FillID = [32]byte{0xAB} },
		"Nonce":         func(r *DFillReceiptV1) { r.Nonce = 999 },
		"MarketIDField": func(r *DFillReceiptV1) { r.MarketID = [32]byte{0xCD} },
	}
	for name, mut := range mutators {
		name, mut := name, mut
		t.Run(name, func(t *testing.T) {
			vals := newTestValidators(t, 1, 1, 1)
			vsID := [32]byte{0x51}
			r := sampleReceipt()
			vset := validatorSetFrom(r.DChainID, vsID, vals)
			cert := buildCert(t, vsID, vals, r, r.ReceiptID, 0, 1) // valid over r.

			// Tamper one value field; the reused cert must no longer verify.
			tampered := *r
			tampered.Sender, tampered.Recipient = r.Sender, r.Recipient
			mut(&tampered)
			if err := VerifyBLSCert(cert, &tampered, tampered.ReceiptID, vset); err != ErrCertMsgMismatch {
				t.Fatalf("%s tamper with reused cert must be ErrCertMsgMismatch, got: %v", name, err)
			}
			// A re-signed cert over the tampered receipt DOES verify (it is the binding).
			recert := buildCert(t, vsID, vals, &tampered, tampered.ReceiptID, 0, 1)
			_ = attacker
			if err := VerifyBLSCert(recert, &tampered, tampered.ReceiptID, vset); err != nil {
				t.Fatalf("%s correctly re-signed must verify, got: %v", name, err)
			}
		})
	}
}

// TestRED_SignedMessageBindsEveryField: the property that a single-field change in
// ANY value-bearing field changes signedMessage (catches an underbinding regression).
func TestRED_SignedMessageBindsEveryField(t *testing.T) {
	base := sampleReceipt()
	root := base.ReceiptID
	want := signedMessage(base, root)
	check := func(name string, mut func(*DFillReceiptV1)) {
		r := *base
		r.AmountIn = new(big.Int).Set(base.AmountIn)
		r.AmountOut = new(big.Int).Set(base.AmountOut)
		r.FeeAmount = new(big.Int).Set(base.FeeAmount)
		mut(&r)
		if signedMessage(&r, root) == want {
			t.Fatalf("signedMessage did NOT change when %s changed (underbinding)", name)
		}
	}
	check("Sender", func(r *DFillReceiptV1) { r.Sender = common.HexToAddress("0xdead") })
	check("Recipient", func(r *DFillReceiptV1) { r.Recipient = common.HexToAddress("0xbeef") })
	check("AmountIn", func(r *DFillReceiptV1) { r.AmountIn = big.NewInt(1) })
	check("AmountOut", func(r *DFillReceiptV1) { r.AmountOut = big.NewInt(1) })
	check("FeeAmount", func(r *DFillReceiptV1) { r.FeeAmount = big.NewInt(1) })
	check("FeeAssetID", func(r *DFillReceiptV1) { r.FeeAssetID = [32]byte{0x9} })
	check("TokenIn", func(r *DFillReceiptV1) { r.TokenInAssetID = [32]byte{0x9} })
	check("TokenOut", func(r *DFillReceiptV1) { r.TokenOutAssetID = [32]byte{0x9} })
	check("PoolKeyHash", func(r *DFillReceiptV1) { r.PoolKeyHash = [32]byte{0x9} })
	check("SwapParamsHash", func(r *DFillReceiptV1) { r.SwapParamsHash = [32]byte{0x9} })
	check("MarketID", func(r *DFillReceiptV1) { r.MarketID = [32]byte{0x9} })
	check("FillID", func(r *DFillReceiptV1) { r.FillID = [32]byte{0x9} })
	check("Deadline", func(r *DFillReceiptV1) { r.Deadline = 123456 })
	check("Nonce", func(r *DFillReceiptV1) { r.Nonce = 424242 }) // base Nonce is 7.
	check("CChainID", func(r *DFillReceiptV1) { r.CChainID = [32]byte{0x9} })
	check("PrecompileAddr", func(r *DFillReceiptV1) { r.PrecompileAddr = common.HexToAddress("0x9") })
}

// ── FINDING halt-market-scope-decoupled (HIGH) ───────────────────────────────

// TestRED_HaltMarket_BoundToPool: governance halts a market by its pool id; a
// receipt whose free-form MarketID differs from its PoolKeyHash can NO LONGER dodge
// the halt (checkHalt keys on PoolKeyHash). The legitimate user's swap is blocked
// regardless of what MarketID the (compromised) market puts in its receipts.
func TestRED_HaltMarket_BoundToPool(t *testing.T) {
	for _, mid := range [][32]byte{{0xAB}, {}, {0x99, 0x88}} {
		mid := mid
		t.Run("marketID-override", func(t *testing.T) {
			h := newSettleHarness(t)
			h.fund(t, 10_000, 10_000)
			// Receipt with MarketID != PoolKeyHash (the attacker-controlled free field).
			hookData, _, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) { r.MarketID = mid }, 0, 1)
			// Halt the pool by its real id.
			SetHaltMarket(newPoolStateAdapter(h.state), h.key.ID(), true)
			if _, err := h.runSwap(t, h.caller, hookData); err != ErrMarketHalted {
				t.Fatalf("market halt must block the swap regardless of MarketID, got: %v", err)
			}
		})
	}
}

// TestRED_HaltMarket_UnrelatedPoolNotBlocked: halting a DIFFERENT pool does not block
// this swap (the halt is correctly pool-scoped, not global).
func TestRED_HaltMarket_UnrelatedPoolNotBlocked(t *testing.T) {
	h := newSettleHarness(t)
	h.fund(t, 10_000, 10_000)
	hookData, _, _ := h.buildReceiptCert(t, nil, 0, 1)
	SetHaltMarket(newPoolStateAdapter(h.state), [32]byte{0xFE, 0xED}, true) // unrelated pool.
	if _, err := h.runSwap(t, h.caller, hookData); err != nil {
		t.Fatalf("halting an unrelated pool must not block this swap, got: %v", err)
	}
}

// ── FINDING native-deposit-absolute-balance-mint (CRITICAL) ──────────────────

// TestRED_NativeDeposit_ZeroValueOnPrefundedVault: the exact drain PoC. With the
// vault pre-funded (by an honest depositor's native), an attacker calling
// deposit(native, V) with msg.value==0 (modelled by NOT crediting the vault for
// this call) is REJECTED — no unbacked claim is minted.
func TestRED_NativeDeposit_ZeroValueOnPrefundedVault(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	attacker := common.HexToAddress("0xA77ac4000000000000000000000000000000ace0")
	nativeID := [32]byte{}

	// Honest depositor H funds 5000 native into the vault THROUGH a real deposit
	// (EVM moved value first => vault balance increments, settleVault tracks it).
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(5000)) // EVM transfer for H's deposit.
	hCalldata := prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 5000))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, hCalldata, 5_000_000, false); err != nil {
		t.Fatalf("honest deposit setup failed: %v", err)
	}
	claimBefore := loadDepositorClaim(newPoolStateAdapter(h.state), attacker, nativeID)
	vaultBefore := loadSettleVault(newPoolStateAdapter(h.state), nativeID)

	// Attacker deposits with msg.value==0 (vault NOT credited for this call). The
	// observed delta is 0, so the deposit must revert ErrSettleDepositShort.
	aCalldata := prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 5000))
	if _, _, err := h.c.Run(h.state, attacker, poolManagerAddr9999, aCalldata, 5_000_000, false); err != ErrSettleDepositShort {
		t.Fatalf("zero-value deposit on a prefunded vault must revert ErrSettleDepositShort, got: %v", err)
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), attacker, nativeID).Sign() != 0 {
		t.Fatal("attacker must not mint a claim from a zero-value deposit")
	}
	_ = claimBefore
	if loadSettleVault(newPoolStateAdapter(h.state), nativeID).Cmp(vaultBefore) != 0 {
		t.Fatal("zero-value deposit must not change settleVault")
	}
}

// TestRED_NativeDeposit_DrainViaZeroValueThenWithdraw: the full two-tx PoC. Even
// against a vault holding others' native, deposit(value=0)+withdraw nets the
// attacker zero (the deposit reverts, so there is nothing to withdraw).
func TestRED_NativeDeposit_DrainViaZeroValueThenWithdraw(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	attacker := common.HexToAddress("0xA77ac4000000000000000000000000000000ace1")

	// Honest depositor seeds the vault.
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(7000))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 7000)), 5_000_000, false); err != nil {
		t.Fatalf("honest deposit: %v", err)
	}

	vaultBalBefore := db.GetBalance(poolManagerAddr9999).Uint64()
	attackerBalBefore := db.GetBalance(attacker).Uint64()

	// tx1: deposit(value=0) MUST revert (no claim minted).
	if _, _, err := h.c.Run(h.state, attacker, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 7000)), 5_000_000, false); err != ErrSettleDepositShort {
		t.Fatalf("zero-value deposit must revert, got: %v", err)
	}
	// tx2: withdraw with a zero claim yields 0.
	out, _, err := h.c.Run(h.state, attacker, poolManagerAddr9999, prependSelector(SelectorWithdraw, encodeDepositCalldata(common.Address{}, 7000)), 5_000_000, false)
	if err != nil {
		t.Fatalf("withdraw must not error (just returns 0): %v", err)
	}
	if new(big.Int).SetBytes(out).Sign() != 0 {
		t.Fatal("attacker withdraw must realize 0")
	}
	if db.GetBalance(attacker).Uint64() != attackerBalBefore {
		t.Fatal("attacker native balance must be unchanged (no drain)")
	}
	if db.GetBalance(poolManagerAddr9999).Uint64() != vaultBalBefore {
		t.Fatal("vault native balance must be unchanged (no drain)")
	}
}

// TestRED_NativeDeposit_ValueShortRejected: deposit(native, X) where only Y<X was
// delivered (vault credited Y) is rejected; a deposit delivering exactly X credits X.
func TestRED_NativeDeposit_ValueShortRejected(t *testing.T) {
	h := newSettleHarness(t)
	db := h.state.stateDB
	nativeID := [32]byte{}

	// Deliver 900 but assert amount 1000 => short => revert.
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(900))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 1000)), 5_000_000, false); err != ErrSettleDepositShort {
		t.Fatalf("under-delivered native deposit must revert, got: %v", err)
	}
	// Now deliver the missing 100 (total 1000) and deposit 1000 => credits exactly 1000.
	db.AddBalance(poolManagerAddr9999, uint256.NewInt(100))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorDeposit, encodeDepositCalldata(common.Address{}, 1000)), 5_000_000, false); err != nil {
		t.Fatalf("exact-value deposit must succeed, got: %v", err)
	}
	if loadDepositorClaim(newPoolStateAdapter(h.state), h.caller, nativeID).Cmp(big.NewInt(1000)) != 0 {
		t.Fatal("exact-value deposit must credit exactly the delivered amount")
	}
}

// ── FINDING extsloadarray-offset-overflow-panic (HIGH) ───────────────────────

// TestRED_SettleExtsloadArray_OffsetOverflowNoPanic: the 0x9999 extsloadArray no
// longer panics on an overflowing offset (validator-liveness DoS). Every offset in
// the exploitable window reverts cleanly with a bounds error.
func TestRED_SettleExtsloadArray_OffsetOverflowNoPanic(t *testing.T) {
	h := newSettleHarness(t)
	mk := func(low uint64) []byte {
		a := make([]byte, 64)
		for i := 0; i < 8; i++ {
			a[31-i] = byte(low >> (8 * uint(i)))
		}
		return a
	}
	cases := map[string]uint64{
		"MaxInt64":    0x7FFFFFFFFFFFFFFF, // the headline: int(off)+32 overflowed to negative.
		"MaxInt64-31": 0x7FFFFFFFFFFFFFE0,
		"2^63":        0x8000000000000000, // negative-int path under the old cast.
		"MaxUint64":   0xFFFFFFFFFFFFFFFF,
		"len+9":       uint64(64 - 4 + 9), // just beyond input after selector strip.
	}
	for name, off := range cases {
		name, off := name, off
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DoS: extsloadArray panicked on offset %q: %v", name, r)
				}
			}()
			calldata := prependSelector(SelectorExtsloadArray, mk(off))
			if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 5_000_000, true); err == nil {
				t.Fatalf("offset %q must revert with a bounds error, got nil", name)
			}
		})
	}
}

// FuzzSettleExtsloadArray: no input to the 0x9999 extsloadArray may panic.
func FuzzSettleExtsloadArray(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 96))
	f.Fuzz(func(t *testing.T, raw []byte) {
		h := newSettleHarness(t)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("extsloadArray panicked on %x: %v", raw, r)
			}
		}()
		_, _, _ = h.c.Run(h.state, h.caller, poolManagerAddr9999, prependSelector(SelectorExtsloadArray, raw), 5_000_000, true)
	})
}

// ── FINDING gas-swap-flat-vs-on-bls-cost (HIGH) ──────────────────────────────

// TestRED_Gas_SwapScalesWithValidatorSet: swap gas grows with the validator-set
// size, and a swap funded only with the OLD flat 50k gas runs out for a large set.
func TestRED_Gas_SwapScalesWithValidatorSet(t *testing.T) {
	gasFor := func(n int) uint64 {
		h := newSettleHarnessN(t, n)
		h.fund(t, 1_000_000, 1_000_000)
		// sign with all n (clears the BFT floor).
		signers := make([]int, n)
		for i := range signers {
			signers[i] = i
		}
		hookData, _, _ := h.buildReceiptCert(t, nil, signers...)
		calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
		_, remaining, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000_000, false)
		if err != nil {
			t.Fatalf("n=%d settle failed: %v", n, err)
		}
		return 50_000_000 - remaining
	}
	g3 := gasFor(3)
	g32 := gasFor(32)
	if g32 <= g3 {
		t.Fatalf("gas must grow with set size: n=3 charged %d, n=32 charged %d", g3, g32)
	}
	// The growth must reflect ~ (32-3) extra validators * per-validator gas.
	if g32-g3 < uint64(32-3)*GasResolvePerValidator {
		t.Fatalf("gas growth %d below the per-validator floor for 29 extra validators", g32-g3)
	}

	// A large set funded with only the old flat 50k must run OUT of gas.
	h := newSettleHarnessN(t, 64)
	h.fund(t, 1_000_000, 1_000_000)
	signers := make([]int, 64)
	for i := range signers {
		signers[i] = i
	}
	hookData, _, _ := h.buildReceiptCert(t, nil, signers...)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	if _, _, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000, false); err == nil {
		t.Fatal("a 64-validator settle funded with the old flat 50k gas must run out of gas")
	}
}

// TestRED_Gas_ForgedCertPaysFullVerifyGas: a forged-signature cert over a large
// registered set still consumes the N/S-proportional gas before reverting (it
// cannot under-pay by failing late at the pairing).
func TestRED_Gas_ForgedCertPaysFullVerifyGas(t *testing.T) {
	n := 16
	h := newSettleHarnessN(t, n)
	h.fund(t, 1_000_000, 1_000_000)
	signers := make([]int, n)
	for i := range signers {
		signers[i] = i
	}
	hookData, r, cert := h.buildReceiptCert(t, nil, signers...)
	cert.AggregateSignature[3] ^= 0xFF // forge.
	hookData = EncodeSettlementHookData(r, cert, nil)
	calldata := prependSelector(SelectorSwap, buildSwapCalldata(h.key, h.params, hookData))
	_, remaining, err := h.c.Run(h.state, h.caller, poolManagerAddr9999, calldata, 50_000_000, false)
	if err != ErrCertVerifyFailed {
		t.Fatalf("forged cert must revert ErrCertVerifyFailed, got: %v", err)
	}
	charged := 50_000_000 - remaining
	floor := GasSwapBase + uint64(n)*GasResolvePerValidator + uint64(n)*GasAggPerSigner + GasBLSPairing
	if charged < floor {
		t.Fatalf("forged cert charged %d, below the full verify floor %d", charged, floor)
	}
}

// ── FINDING packbalancedelta-int128-truncation (LOW) ─────────────────────────

// TestRED_SettleSwap_AmountExceedsInt128Reverts: a certified receipt whose amountOut
// exceeds int128 reverts before moving value, rather than returning a wrapped/sign-
// flipped delta. The receipt stays unconsumed.
func TestRED_SettleSwap_AmountExceedsInt128Reverts(t *testing.T) {
	h := newSettleHarness(t)
	h.fund(t, 10_000, 10_000)
	huge := new(big.Int).Lsh(big.NewInt(1), 127) // 2^127 > MaxInt128.

	// Default native-in / token-out direction (binds correctly); amountOut = 2^127.
	// The int128 guard (step 6a) reverts BEFORE settle, so the vault need not back it.
	hookData, r, _ := h.buildReceiptCert(t, func(r *DFillReceiptV1) {
		r.AmountIn = big.NewInt(1000)
		r.AmountOut = huge
	}, 0, 1)
	if _, err := h.runSwap(t, h.caller, hookData); err != ErrSettleDeltaOverflow {
		t.Fatalf("amountOut > int128 must revert ErrSettleDeltaOverflow, got: %v", err)
	}
	if isReceiptConsumed(newPoolStateAdapter(h.state), r.ReceiptID) {
		t.Fatal("an int128-overflow settle must leave the receipt UNCONSUMED")
	}
}

// TestRED_FitsSignedInt128_Boundary tables the int128 range guard.
func TestRED_FitsSignedInt128_Boundary(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1)) // 2^127-1
	min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))                // -2^127
	cases := []struct {
		v    *big.Int
		want bool
	}{
		{nil, true},
		{big.NewInt(0), true},
		{max, true},
		{min, true},
		{new(big.Int).Add(max, big.NewInt(1)), false}, // 2^127
		{new(big.Int).Sub(min, big.NewInt(1)), false}, // -2^127-1
		{new(big.Int).Lsh(big.NewInt(1), 200), false}, // way over
	}
	for i, c := range cases {
		if got := FitsSignedInt128(c.v); got != c.want {
			t.Fatalf("case %d: FitsSignedInt128(%v)=%v want %v", i, c.v, got, c.want)
		}
	}
}

// TestRED_PackBalanceDelta_NoSilentSignFlip: a value just over int128 must NOT
// round-trip to a sign-flipped negative through Pack/Unpack — the guard catches it
// (the lenient packer would otherwise corrupt a credit into a debit).
func TestRED_PackBalanceDelta_RoundTripWithinRange(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(990), max, min} {
		if !FitsSignedInt128(v) {
			t.Fatalf("%v should fit int128", v)
		}
		packed := PackBalanceDelta(v, big.NewInt(0))
		a0, _ := UnpackBalanceDelta(packed)
		if a0.Cmp(v) != 0 {
			t.Fatalf("in-range %v must round-trip, got %v", v, a0)
		}
	}
	// 2^128+5 does NOT fit; the guard must reject it (so SettleSwap reverts upstream).
	overflow := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(5))
	if FitsSignedInt128(overflow) {
		t.Fatal("2^128+5 must not be reported as fitting int128 (would sign-flip)")
	}
}
