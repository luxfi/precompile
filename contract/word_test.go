// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"errors"
	"math/big"
	"testing"
)

// pow2 is 2^n.
func pow2(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

// TestUnsignedAdmitsExactlyItsWidth walks every width and asserts the boundary
// from both sides. The largest representable value must be admitted and the
// smallest unrepresentable one refused; a check that is off by one in either
// direction fails here rather than in whatever consensus rule depends on it.
func TestUnsignedAdmitsExactlyItsWidth(t *testing.T) {
	for bits := uint(0); bits <= 64; bits++ {
		max := new(big.Int).Sub(pow2(bits), big.NewInt(1)) // 2^bits - 1
		got, err := Unsigned(max, bits)
		if err != nil {
			t.Fatalf("Unsigned(2^%d-1, %d) refused the largest representable value: %v", bits, bits, err)
		}
		if got != max.Uint64() {
			t.Fatalf("Unsigned(2^%d-1, %d) = %d, want %d", bits, bits, got, max.Uint64())
		}
		if _, err := Unsigned(pow2(bits), bits); !errors.Is(err, ErrRange) {
			t.Fatalf("Unsigned(2^%d, %d) admitted a value one past the width: %v", bits, bits, err)
		}
		if got, err := Unsigned(big.NewInt(0), bits); err != nil || got != 0 {
			t.Fatalf("Unsigned(0, %d) = (%d, %v), want (0, nil)", bits, got, err)
		}
	}
}

// TestUnsignedRefusesWhatTheBareConversionSubstitutes names the values the
// conversion this replaces turns into something else, and where each
// substitution happens. There are two distinct steps and they are worth keeping
// apart:
//
//   - Uint64 itself substitutes only past 2^64. Below that it is faithful.
//   - The Go conversion that FOLLOWS it — uint24(x), which is uint32(x) because
//     uint24 is an alias — substitutes past 2^32, on a value Uint64 handed over
//     intact.
//
// So `uint24(w.Uint64())` on a 256-bit word has two independent truncations in
// series, and a reader checking only the first concludes the site is safe.
// Refusing at the declared width covers both, because it happens before either.
func TestUnsignedRefusesWhatTheBareConversionSubstitutes(t *testing.T) {
	for _, tc := range []struct {
		name string
		x    *big.Int
		bits uint
		// what `uint32(x.Uint64())` yields — the full narrowing as written at
		// the call sites this replaces.
		narrowed uint32
	}{
		{"2^32+6 as a 24-bit tick", new(big.Int).Add(pow2(32), big.NewInt(6)), 24, 6},
		{"2^24+3000 as a 24-bit fee", new(big.Int).Add(pow2(24), big.NewInt(3000)), 24, 1<<24 + 3000},
		{"2^64+6 as a 64-bit amount", new(big.Int).Add(pow2(64), big.NewInt(6)), 64, 6},
		{"2^255 as a 64-bit amount", pow2(255), 64, 0},
		{"2^256-1 as a 24-bit fee", new(big.Int).Sub(pow2(256), big.NewInt(1)), 24, 1<<32 - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := uint32(tc.x.Uint64()); got != tc.narrowed {
				t.Fatalf("fixture: uint32(%s.Uint64()) = %d, want %d — the substitution this "+
					"refusal exists to prevent has changed", tc.x, got, tc.narrowed)
			}
			if _, err := Unsigned(tc.x, tc.bits); !errors.Is(err, ErrRange) {
				t.Fatalf("Unsigned(%s, %d) admitted it: %v", tc.x, tc.bits, err)
			}
		})
	}
}

// The signed half of the same point, at the exact word the dex decoder used to
// turn into an ordinary in-range tick.
func TestSignedRefusesWhatTheBareConversionSubstitutes(t *testing.T) {
	x := new(big.Int).Add(pow2(32), big.NewInt(6)) // 2^32 + 6
	if got := x.Int64(); got != 1<<32+6 {
		t.Fatalf("fixture: Int64 is not the truncating step here, it returned %d", got)
	}
	if got := int32(x.Int64()); got != 6 {
		t.Fatalf("fixture: int32(2^32+6) = %d, want 6", got)
	}
	if _, err := Signed(x, 24); !errors.Is(err, ErrRange) {
		t.Fatalf("Signed admitted 2^32+6 as an int24: %v", err)
	}
	// And the value that is in int32 but not in int24 — the range where the
	// conversion is faithful and the field still cannot hold it.
	if _, err := Signed(new(big.Int).Add(pow2(24), big.NewInt(60)), 24); !errors.Is(err, ErrRange) {
		t.Fatalf("Signed admitted 2^24+60 as an int24: %v", err)
	}
}

// A negative value has no unsigned reading, and Uint64 answers with its
// magnitude's low word — so -(2^64+6) arrives as 6, a positive number.
func TestUnsignedRefusesNegative(t *testing.T) {
	neg := new(big.Int).Neg(new(big.Int).Add(pow2(64), big.NewInt(6)))
	if got := neg.Uint64(); got != 6 {
		t.Fatalf("fixture: (-(2^64+6)).Uint64() = %d, want 6", got)
	}
	if _, err := Unsigned(neg, 64); !errors.Is(err, ErrRange) {
		t.Fatalf("Unsigned admitted a negative value: %v", err)
	}
	if _, err := Unsigned(big.NewInt(-1), 64); !errors.Is(err, ErrRange) {
		t.Fatalf("Unsigned(-1, 64) admitted it: %v", err)
	}
}

// A width the return type cannot hold refuses rather than returning a value that
// does not mean what the caller asked for.
func TestUnsignedRefusesWidthPastUint64(t *testing.T) {
	for _, bits := range []uint{65, 128, 160, 256} {
		if _, err := Unsigned(big.NewInt(1), bits); !errors.Is(err, ErrRange) {
			t.Fatalf("Unsigned(1, %d) did not fail closed: %v", bits, err)
		}
	}
}

// TestSignedAdmitsExactlyItsWidth walks both ends of the two's-complement span.
// The asymmetry is the point: -2^(bits-1) is representable and +2^(bits-1) is
// not, and the two share a bit length, so a check written on BitLen alone gets
// exactly one of these wrong.
func TestSignedAdmitsExactlyItsWidth(t *testing.T) {
	for bits := uint(1); bits <= 64; bits++ {
		hi := pow2(bits - 1)
		max := new(big.Int).Sub(hi, big.NewInt(1)) // 2^(bits-1) - 1
		lo := new(big.Int).Neg(hi)                 // -2^(bits-1)

		if got, err := Signed(max, bits); err != nil || got != max.Int64() {
			t.Fatalf("Signed(2^%d-1, %d) = (%d, %v), want the largest representable value",
				bits-1, bits, got, err)
		}
		if got, err := Signed(lo, bits); err != nil || got != lo.Int64() {
			t.Fatalf("Signed(-2^%d, %d) = (%d, %v), want the smallest representable value",
				bits-1, bits, got, err)
		}
		if _, err := Signed(hi, bits); !errors.Is(err, ErrRange) {
			t.Fatalf("Signed(2^%d, %d) admitted a value one past the top: %v", bits-1, bits, err)
		}
		if _, err := Signed(new(big.Int).Sub(lo, big.NewInt(1)), bits); !errors.Is(err, ErrRange) {
			t.Fatalf("Signed(-2^%d-1, %d) admitted a value one past the bottom: %v", bits-1, bits, err)
		}
		if got, err := Signed(big.NewInt(0), bits); err != nil || got != 0 {
			t.Fatalf("Signed(0, %d) = (%d, %v), want (0, nil)", bits, got, err)
		}
	}
}

func TestSignedRefusesWidthItCannotHold(t *testing.T) {
	for _, bits := range []uint{0, 65, 128, 256} {
		if _, err := Signed(big.NewInt(0), bits); !errors.Is(err, ErrRange) {
			t.Fatalf("Signed(0, %d) did not fail closed: %v", bits, err)
		}
	}
}

// Signed does not mutate its argument. The bound is built by shifting a package
// level `one`, and reusing that allocation for the negation is the kind of thing
// that silently corrupts a shared constant.
func TestSignedLeavesItsInputAndTheShiftBaseAlone(t *testing.T) {
	x := new(big.Int).Lsh(big.NewInt(1), 200)
	want := new(big.Int).Set(x)
	for range 4 {
		if _, err := Signed(x, 24); !errors.Is(err, ErrRange) {
			t.Fatalf("Signed refused for the wrong reason: %v", err)
		}
		if _, err := Unsigned(x, 24); !errors.Is(err, ErrRange) {
			t.Fatalf("Unsigned refused for the wrong reason: %v", err)
		}
	}
	if x.Cmp(want) != 0 {
		t.Fatalf("the argument was mutated: %s, want %s", x, want)
	}
	if one.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("the shift base was mutated to %s", one)
	}
}

// Both errors are ErrInvalidInput, so a precompile that already refuses on that
// sentinel keeps refusing without knowing this type exists.
func TestRangeIsAnInvalidInput(t *testing.T) {
	if !errors.Is(ErrRange, ErrInvalidInput) {
		t.Fatal("ErrRange does not wrap ErrInvalidInput")
	}
}
