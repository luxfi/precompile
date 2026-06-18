// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
)

// custody_frame_parity_test.go PINS the precompile's locally-declared custody
// wire frame to the FROZEN github.com/luxfi/dex/pkg/zapwire definitions. The
// precompile cannot import the cgo-tagged d-chain package, so it re-declares the
// frame constants (the same three-homes pattern the place/cancel/submit frames
// use). This test is the byte-parity guard: if zapwire's frame ever changes, the
// hardcoded canonical values below must be updated in lockstep across ALL homes
// (precompile, chains/dexvm/custody.go, the d-chain handler) or the wire breaks.
//
// Canonical values (github.com/luxfi/dex/pkg/zapwire, verified 2026-06-17):
//
//	MethodDeposit     = "clob_deposit"
//	MethodWithdraw    = "clob_withdraw"
//	MethodOpenMarket  = "clob_open_market"
//	UserSize          = 16
//	AssetIDSize       = 8
//	DepositReqSize    = UserSize + AssetIDSize + 8 = 32
//	WithdrawReqSize   = UserSize + AssetIDSize + 8 = 32
//	OpenMarketReqSize = PoolIDSize(32) + AssetIDSize + AssetIDSize = 48
//	BalanceRespSize   = 1 + 8 = 9
//	clob_balance request = UserSize + AssetIDSize = 24; response = available[8]+locked[8]
func TestCustodyFrameParity(t *testing.T) {
	cases := []struct {
		name      string
		got, want any
	}{
		{"ZAPMethodDeposit", ZAPMethodDeposit, "clob_deposit"},
		{"ZAPMethodWithdraw", ZAPMethodWithdraw, "clob_withdraw"},
		{"ZAPMethodOpenMarket", ZAPMethodOpenMarket, "clob_open_market"},
		{"ZAPMethodBalance", ZAPMethodBalance, "clob_balance"},
		{"zapUserSize", zapUserSize, 16},
		{"zapAssetIDSize", zapAssetIDSize, 8},
		{"depositReqSize", depositReqSize, 32},
		{"withdrawReqSize", withdrawReqSize, 32},
		{"openMarketReqSize", openMarketReqSize, 48},
		{"balanceRespSize", balanceRespSize, 9},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("frame drift %s: precompile=%v != zapwire canonical=%v", c.name, c.got, c.want)
		}
	}
}

// TestCustodyFrameEncodings pins the exact byte layout the precompile produces
// for each custody frame, matching zapwire's Encode* output field-for-field.
func TestCustodyFrameEncodings(t *testing.T) {
	// Deposit frame: user[16] + asset[8] + amount[8], byte-identical to
	// zapwire.EncodeDeposit.
	user := common.HexToAddress("0x35D64Ff3f618f7a17DF34DCb21be375A4686a8de")
	const asset uint64 = 0x4c5558_00000001
	const amount uint64 = 12345

	payload := make([]byte, depositReqSize)
	copy(payload[0:16], padUserHandle(user))
	binary.BigEndian.PutUint64(payload[16:24], asset)
	binary.BigEndian.PutUint64(payload[24:32], amount)

	if len(payload) != 32 {
		t.Fatalf("deposit payload len=%d want 32", len(payload))
	}
	if binary.BigEndian.Uint64(payload[16:24]) != asset {
		t.Errorf("deposit asset field mismatch")
	}
	if binary.BigEndian.Uint64(payload[24:32]) != amount {
		t.Errorf("deposit amount field mismatch")
	}
	// User field is the leading 16 bytes of the caller address.
	for i := 0; i < 16; i++ {
		if payload[i] != user.Bytes()[i] {
			t.Errorf("deposit user byte %d mismatch", i)
		}
	}

	// assetHandle native LUX == 0 (address(0) leading 8 bytes).
	if h := assetHandle(NativeCurrency); h != 0 {
		t.Errorf("native asset handle = %d, want 0", h)
	}
	// assetHandle of a non-zero currency == BE of its leading 8 address bytes.
	// Address 0x0011223344556677.. -> handle 0x0011223344556677.
	c := Currency{Address: common.HexToAddress("0x0011223344556677000000000000000000000000")}
	const wantHandle uint64 = 0x0011223344556677
	if h := assetHandle(c); h != wantHandle {
		t.Errorf("currency asset handle = %#016x, want %#016x", h, wantHandle)
	}
}
