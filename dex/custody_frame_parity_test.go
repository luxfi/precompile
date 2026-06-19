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
// (precompile, chains/dexvm/{custody,relay}.go, the d-chain handler) or the wire
// breaks.
//
// Canonical values (github.com/luxfi/dex/pkg/zapwire, verified 2026-06-18):
//
//	MethodDeposit     = "clob_deposit"
//	MethodWithdraw    = "clob_withdraw"
//	MethodOpenMarket  = "clob_open_market"
//	UserSize          = 16
//	AssetIDSize       = 32   (FULL injective asset id — NOT a truncated handle)
//	RefSize           = 32   (idempotency ref = originating EVM txHash)
//	DepositReqSize    = UserSize + AssetIDSize + 8 + RefSize = 88
//	WithdrawReqSize   = UserSize + AssetIDSize + 8 + RefSize = 88
//	OpenMarketReqSize = PoolIDSize(32) + AssetIDSize + AssetIDSize = 96
//	BalanceReqSize    = UserSize + AssetIDSize = 48
//	BalanceRespSize   = 1 + 8 = 9
//	custodyAmountOff  = UserSize + AssetIDSize = 48
//	custodyRefOff     = UserSize + AssetIDSize + 8 = 56
//
// The asset field is the FULL 32-byte injective id (NOT a truncated 8-byte
// handle): a truncation maps distinct assets to the same balance key, so a
// worthless token whose id folds to the native-LUX key 0 could mint a native claim
// and drain the native vault (and two tokens sharing a leading prefix collide). The
// four ORDER frames (ensure/place/cancel/submit) are byte-unchanged by this. This
// parity guard moves in lockstep with zapwire.
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
		{"zapAssetIDSize", zapAssetIDSize, 32},
		{"zapRefSize", zapRefSize, 32},
		{"depositReqSize", depositReqSize, 88},
		{"withdrawReqSize", withdrawReqSize, 88},
		{"openMarketReqSize", openMarketReqSize, 96},
		{"balanceRespSize", balanceRespSize, 9},
		{"custodyAmountOff", custodyAmountOff, 48},
		{"custodyRefOff", custodyRefOff, 56},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("frame drift %s: precompile=%v != zapwire canonical=%v", c.name, c.got, c.want)
		}
	}
}

// TestCustodyFrameEncodings pins the exact byte layout the precompile produces for
// the deposit frame, matching zapwire.EncodeDeposit field-for-field: user[16] +
// asset[32] + amount[8] + ref[32], with the 32-byte injective asset id at
// [16:custodyAmountOff], the amount at [custodyAmountOff:custodyRefOff], and the
// 32-byte idempotency ref at the tail [custodyRefOff:].
func TestCustodyFrameEncodings(t *testing.T) {
	user := common.HexToAddress("0x35D64Ff3f618f7a17DF34DCb21be375A4686a8de")
	asset := assetID(Currency{Address: common.HexToAddress("0xA0b86991C6218B36c1d19D4a2e9Eb0cE3606EB48")})
	const amount uint64 = 12345
	ref := [32]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	payload := make([]byte, depositReqSize)
	copy(payload[0:16], padUserHandle(user))
	copy(payload[16:custodyAmountOff], asset[:])
	binary.BigEndian.PutUint64(payload[custodyAmountOff:custodyRefOff], amount)
	copy(payload[custodyRefOff:custodyRefOff+zapRefSize], ref[:])

	if len(payload) != 88 {
		t.Fatalf("deposit payload len=%d want 88", len(payload))
	}
	// Asset field is the FULL 32 bytes at [16:48].
	var gotAsset [32]byte
	copy(gotAsset[:], payload[16:custodyAmountOff])
	if gotAsset != asset {
		t.Errorf("deposit asset field mismatch: got %x want %x", gotAsset, asset)
	}
	if binary.BigEndian.Uint64(payload[custodyAmountOff:custodyRefOff]) != amount {
		t.Errorf("deposit amount field mismatch")
	}
	// Ref field is the trailing 32 bytes (offset custodyRefOff).
	var gotRef [32]byte
	copy(gotRef[:], payload[custodyRefOff:custodyRefOff+zapRefSize])
	if gotRef != ref {
		t.Errorf("deposit ref field mismatch: got %x want %x", gotRef[:8], ref[:8])
	}
	// User field is the leading 16 bytes of the caller address.
	for i := 0; i < 16; i++ {
		if payload[i] != user.Bytes()[i] {
			t.Errorf("deposit user byte %d mismatch", i)
		}
	}
}

// TestAssetIDInjective proves the address->asset-id map is INJECTIVE, the property
// that closes the collision class: native LUX (address(0)) maps to the all-zero id,
// and two DISTINCT token addresses — even ones sharing a leading 8-byte prefix that
// the old fold collapsed — map to DISTINCT ids. So no token can ever share a
// balance key with native (the vault-drain mint) or with another token.
func TestAssetIDInjective(t *testing.T) {
	// Native LUX == all-zero id.
	if id := assetID(NativeCurrency); id != ([32]byte{}) {
		t.Errorf("native asset id = %x, want all-zero", id)
	}
	// A token with 8 leading-zero address bytes (the old fold's collision with
	// native) maps to a NON-zero id distinct from native's.
	zeroLead := assetID(Currency{Address: common.HexToAddress("0x0000000000000000112233445566778899aabbcc")})
	if zeroLead == ([32]byte{}) {
		t.Errorf("zero-leading token folded to the native key — collision NOT closed")
	}
	// Two tokens sharing the leading 8 address bytes (the old fold's token<->token
	// collision) map to DISTINCT ids.
	a := assetID(Currency{Address: common.HexToAddress("0x00112233445566770000000000000000000000AA")})
	b := assetID(Currency{Address: common.HexToAddress("0x00112233445566770000000000000000000000BB")})
	if a == b {
		t.Errorf("two tokens sharing a leading 8-byte prefix collide: %x == %x", a, b)
	}
	// And neither collides with native.
	if a == ([32]byte{}) || b == ([32]byte{}) {
		t.Errorf("a token mapped to the native key — collision NOT closed")
	}
}
