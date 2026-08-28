// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package fhe

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// zzwidth_test.go pins the width a plaintext may have when it enters the
// ciphertext domain.
//
// The container and the loader disagree. A euint256 really is 256 bits wide —
// tfheRandom fills every one of them — but the only loader
// BitwisePublicEncryptor exposes is EncryptUint64, whose bit loop reads
// `value >> i` off a uint64. In Go that is zero for every i above 63, with no
// error and no panic. So bits 64..255 of a plaintext were not rounded off, they
// were ENCRYPTED AS ZERO, and afterwards nothing distinguishes that ciphertext
// from one whose plaintext really was zero.
//
// tfheTrivialEncrypt now refuses instead, which surfaces as the zero handle the
// package already returns when no keys are installed — the same fail-closed
// shape, not a second one.

func zzwPow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

// TestZzwPlaintextStopsAtTheLoaderWidth walks the boundary from both sides. The
// largest loadable plaintext must still encrypt and decrypt to itself; the
// smallest unloadable one must be refused rather than encrypted as its low word.
func TestZzwPlaintextStopsAtTheLoaderWidth(t *testing.T) {
	if err := initTFHE(); err != nil {
		t.Fatalf("keys: %v", err)
	}

	max := new(big.Int).Sub(zzwPow2(64), big.NewInt(1)) // 2^64-1
	ct := tfheTrivialEncrypt(max, TypeEuint64)
	if ct == nil {
		t.Fatal("the largest loadable plaintext was refused")
	}
	if got := tfheDecrypt(ct, TypeEuint64); got.Cmp(max) != 0 {
		t.Fatalf("2^64-1 encrypted then decrypted to %s", got)
	}

	for _, tc := range []struct {
		name string
		v    *big.Int
	}{
		{"one past the loader", zzwPow2(64)},
		{"2^200, which used to encrypt as zero", zzwPow2(200)},
		{"2^256-1", new(big.Int).Sub(zzwPow2(256), big.NewInt(1))},
	} {
		for _, ty := range []uint8{TypeEuint64, TypeEuint128, TypeEuint256, TypeEaddress} {
			if got := tfheTrivialEncrypt(tc.v, ty); got != nil {
				t.Fatalf("%s: type %d admitted a plaintext of %d bits", tc.name, ty, tc.v.BitLen())
			}
		}
	}
}

// The mechanism, stated as arithmetic so it stays legible without a 256-bit
// encryption in the test: the loader is handed a uint64, and every bit the
// plaintext had above 63 is absent from it before any encryption happens.
func TestZzwTheDiscardedBitsWereEncryptedAsZero(t *testing.T) {
	v := zzwPow2(200)
	if v.Bit(200) != 1 {
		t.Fatal("fixture: 2^200 has bit 200 set")
	}
	loaded := v.Uint64() // what EncryptUint64 receives
	if loaded != 0 {
		t.Fatalf("the plaintext handed to the loader was %d, want 0 — the substitution "+
			"this refusal exists to prevent has changed", loaded)
	}
	// And its bit loop, `(value >> i) & 1` over a uint64, reads zero for every
	// bit the container has and the loader does not.
	for i := 64; i < 256; i++ {
		if (loaded>>(i%64))&1 != 0 {
			t.Fatalf("bit %d of the loaded value is set; it cannot be", i)
		}
	}
}

// TestZzwEncryptedAddressesNoLongerConflate is the consequence that made this
// worth refusing rather than documenting. asEaddress declares a 160-bit type and
// loaded 64 bits, so two addresses sharing their last EIGHT bytes became the
// SAME plaintext — and a homomorphic equality over encrypted addresses answered
// true for two different accounts. Measured at 16045690984833335023 for both,
// in a 160-bit container, before the refusal.
func TestZzwEncryptedAddressesNoLongerConflate(t *testing.T) {
	if err := initTFHE(); err != nil {
		t.Fatalf("keys: %v", err)
	}
	a := common.HexToAddress("0xAAAAAAAAAAAA0000CAFEBABEDEADBEEFDEADBEEF")
	b := common.HexToAddress("0xBBBBBBBBBBBB1111CAFEBABEDEADBEEFDEADBEEF")
	if a == b {
		t.Fatal("fixture: the two addresses must differ")
	}
	av, bv := new(big.Int).SetBytes(a.Bytes()), new(big.Int).SetBytes(b.Bytes())
	if av.Uint64() != bv.Uint64() {
		t.Fatalf("fixture: the two addresses must share their low 64 bits (%d vs %d)",
			av.Uint64(), bv.Uint64())
	}
	if tfheTrivialEncrypt(av, TypeEaddress) != nil || tfheTrivialEncrypt(bv, TypeEaddress) != nil {
		t.Fatal("an address wider than 64 bits was admitted, so two distinct addresses " +
			"can still share one encrypted value")
	}

	// An address that does fit still encrypts, so this is a width bound and not a
	// blanket refusal of asEaddress.
	small := common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")
	ct := tfheTrivialEncrypt(new(big.Int).SetBytes(small.Bytes()), TypeEaddress)
	if ct == nil {
		t.Fatal("an address inside the loader width was refused")
	}
	if got := tfheDecrypt(ct, TypeEaddress); got.Cmp(big.NewInt(0xDEADBEEF)) != 0 {
		t.Fatalf("decrypted to %s, want 0xDEADBEEF", got)
	}
}

// TestZzwScalarStopsAtTheLoaderWidth covers the other door a 256-bit calldata
// word takes into the ciphertext domain. The scalar ops read data[32:64] whole
// and every evaluator below takes a uint64, whose bit loop is zero above bit 63
// — so scalarAdd(ct, 2^64+7) used to add 7.
//
// scalarAdd is enough to exercise it: the bound is one check ahead of the switch,
// not five copies inside it, so there is one thing to test.
func TestZzwScalarStopsAtTheLoaderWidth(t *testing.T) {
	if err := initTFHE(); err != nil {
		t.Fatalf("keys: %v", err)
	}
	db := newTestStateDB()
	caller := common.Address{0x01}
	h := encryptValue(db, 5, TypeEuint8, caller)
	if h == (common.Hash{}) {
		t.Fatal("fixture: the operand did not encrypt")
	}

	wide := new(big.Int).Add(zzwPow2(64), big.NewInt(7))
	if wide.Uint64() != 7 {
		t.Fatalf("fixture: (2^64+7).Uint64() = %d, want 7", wide.Uint64())
	}
	if got := performFHEScalarOperation(db, "scalarAdd", h, wide, caller); got != (common.Hash{}) {
		t.Fatalf("a scalar of 2^64+7 was admitted, handle %s", got.Hex())
	}

	// The largest scalar the loader can carry still computes, so this is a width
	// bound and not a refusal of scalar ops.
	max := new(big.Int).Sub(zzwPow2(64), big.NewInt(1))
	if got := performFHEScalarOperation(db, "scalarAdd", h, max, caller); got == (common.Hash{}) {
		t.Fatal("the largest loadable scalar was refused")
	}
	if got := performFHEScalarOperation(db, "scalarAdd", h, big.NewInt(7), caller); got == (common.Hash{}) {
		t.Fatal("an ordinary scalar was refused")
	}
}

// A refused encryption yields the zero handle, and the zero handle is not a
// ciphertext — so the refusal is visible at first use rather than becoming a
// confidently wrong answer. This is the same shape the package already uses when
// no keys are installed, which is why the refusal needed no new failure mode.
func TestZzwRefusedEncryptionYieldsNoUsableHandle(t *testing.T) {
	if err := initTFHE(); err != nil {
		t.Fatalf("keys: %v", err)
	}
	db := newTestStateDB()
	h := encryptBigIntValue(db, zzwPow2(200), TypeEuint256, common.Address{0x01})
	if h != (common.Hash{}) {
		t.Fatalf("a refused encryption returned handle %s, want the zero handle", h.Hex())
	}
	if ct, ty, ok := getCiphertext(db, h); ok {
		t.Fatalf("the zero handle resolved to a %d-byte ciphertext of type %d", len(ct), ty)
	}
}
