// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestZeroVerdictRefuses is the property the type exists for: the default,
// the fall-through, the forgotten branch and the unset struct field all deny.
//
// This is what (bool, error) could not give and what an error-only signature
// gives backwards — under error-only the zero value is nil, which admits.
func TestZeroVerdictRefuses(t *testing.T) {
	var v Verdict
	require.False(t, v.OK())
	require.ErrorIs(t, v.Err(), ErrNoVerifier)
	require.Equal(t, byte(0), v.Word()[31])

	// A struct that forgot to set its verdict field denies too.
	var holder struct{ V Verdict }
	require.False(t, holder.V.OK())
	require.ErrorIs(t, holder.V.Err(), ErrNoVerifier)
}

// TestVerdictStatesAreDistinct pins the collision (bool, error) could not
// express: "nothing checked this" and "this did not check out" are different
// facts with different errors.
func TestVerdictStatesAreDistinct(t *testing.T) {
	ran := func(b bool) bool { return b } // never a literal; see the gate

	accepted := Checked(ran(true))
	require.True(t, accepted.OK())
	require.NoError(t, accepted.Err())
	require.Equal(t, byte(1), accepted.Word()[31])

	rejected := Checked(ran(false))
	require.False(t, rejected.OK())
	require.ErrorIs(t, rejected.Err(), ErrRejected)
	require.NotErrorIs(t, rejected.Err(), ErrNoVerifier,
		"a verifier that ran and refused is not a missing verifier")
	require.Equal(t, byte(0), rejected.Word()[31])

	missing := Refused(ErrNoVerifier)
	require.False(t, missing.OK())
	require.ErrorIs(t, missing.Err(), ErrNoVerifier)
	require.NotErrorIs(t, missing.Err(), ErrRejected,
		"a missing verifier is not a failed verification")
	require.Equal(t, byte(0), missing.Word()[31])
}

// TestRefusedNamesItsReason pins that a refusal carries which one it was, so a
// caller can tell an incomplete key from a disabled op from an unwired FFI.
func TestRefusedNamesItsReason(t *testing.T) {
	incomplete := errors.New("verifying key carries no IPA commitment key")
	v := Refused(incomplete)
	require.ErrorIs(t, v.Err(), incomplete)
	require.False(t, v.OK())
}

// TestRefusedCannotImpersonateRejection is the collision guard from the other
// side. Refused(nil) and Refused(ErrRejected) would both let "nothing ran"
// answer as "ran and failed", which is the exact state the type removes.
func TestRefusedCannotImpersonateRejection(t *testing.T) {
	require.ErrorIs(t, Refused(nil).Err(), ErrNoVerifier)
	require.ErrorIs(t, Refused(ErrRejected).Err(), ErrNoVerifier)

	wrapped := errors.Join(ErrRejected, errors.New("context"))
	require.ErrorIs(t, Refused(wrapped).Err(), ErrNoVerifier,
		"a reason that wraps ErrRejected is still not a rejection")
}

// TestVerdictWordIsFreshEachCall pins that a caller may scribble on a result
// without corrupting the next one. A shared word would let one consumer flip
// another's verification outcome.
func TestVerdictWordIsFreshEachCall(t *testing.T) {
	ran := func(b bool) bool { return b }
	v := Checked(ran(true))
	first := v.Word()
	require.Len(t, first, 32)
	for i := range first {
		first[i] = 0xAA
	}
	require.Equal(t, byte(1), v.Word()[31])
	require.Equal(t, byte(0), v.Word()[0])
}

// TestVerdictCannotBeSplit is the structural half of "callers that ignore the
// result should be visible".
//
// Under (bool, error) a caller could write `_, err := verify(...)` and keep the
// error while dropping the verdict — which is how three tests came to miss
// three verifiers that answered valid without verifying. A Verdict is one
// value carrying both, so there is nothing to take while leaving the rest:
// `_, err := f()` does not compile against a single-value signature. This
// asserts the two readers agree, which is what makes carrying one safe.
func TestVerdictCannotBeSplit(t *testing.T) {
	ran := func(b bool) bool { return b }
	for _, v := range []Verdict{Checked(ran(true)), Checked(ran(false)), Refused(nil), {}} {
		require.Equal(t, v.Err() == nil, v.OK(), "OK and Err must never disagree")
		require.Equal(t, v.OK(), v.Word()[31] == 1, "Word must never disagree either")
	}
}

// --- the gates, tested against source that violates them -------------------
//
// A gate that has never failed is not known to be a gate. These parse
// synthetic files and assert the detection logic fires, so the two repo-wide
// gates are themselves under test rather than merely passing vacuously.

func parseExprs(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	require.NoError(t, err)
	return f
}

func TestGateCatchesALiteralPositive(t *testing.T) {
	const src = `package p
func a() Verdict { return Checked(true) }
func b() Verdict { return contract.Checked(false) }
func c() Verdict { return Checked(!true) }
func d() Verdict { return Checked((true)) }
func e(x bool) Verdict { return Checked(x) }
func f(a, b []byte) Verdict { return contract.Checked(bytesEqual(a, b)) }
`
	var caught, allowed int
	ast.Inspect(parseExprs(t, src), func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		c, ok := calls(e, "Checked")
		if !ok || len(c.Args) != 1 {
			return true
		}
		if isConstBool(c.Args[0]) {
			caught++
		} else {
			allowed++
		}
		return true
	})
	require.Equal(t, 4, caught, "bare, qualified, negated and parenthesised literals must all be caught")
	require.Equal(t, 2, allowed, "a computed predicate must pass")
}

func TestGateCatchesADiscardedVerdict(t *testing.T) {
	const src = `package p
func a() { _ = verifyThing(x) }
func b() { verifyThing(x) }
func c() { _ = Checked(y) }
func d() { v := verifyThing(x); use(v) }
func e() { _ = harmless(x) }
func f() { _, _ = contract.Refused(nil), 1 }
`
	var caught int
	ast.Inspect(parseExprs(t, src), func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				if id, ok := lhs.(*ast.Ident); !ok || id.Name != "_" {
					return true
				}
			}
			for _, rhs := range s.Rhs {
				if verdictShaped(rhs) {
					caught++
				}
			}
		case *ast.ExprStmt:
			if verdictShaped(s.X) {
				caught++
			}
		}
		return true
	})
	require.Equal(t, 4, caught,
		"discarded verify calls, discarded constructors and bare-statement calls must all be caught")
}

func TestGateIgnoresUnrelatedCode(t *testing.T) {
	require.False(t, isConstBool(&ast.Ident{Name: "ok"}))
	require.False(t, isConstBool(&ast.BasicLit{Kind: token.INT, Value: "1"}))
	require.False(t, isConstBool(&ast.UnaryExpr{Op: token.SUB, X: &ast.Ident{Name: "true"}}))

	_, ok := calls(&ast.Ident{Name: "Checked"}, "Checked")
	require.False(t, ok, "a bare identifier is not a call")
	_, ok = calls(&ast.CallExpr{Fun: &ast.SelectorExpr{
		X: &ast.Ident{Name: "other"}, Sel: &ast.Ident{Name: "Checked"},
	}}, "Checked")
	require.False(t, ok, "another package's Checked is not ours")
	_, ok = calls(&ast.CallExpr{Fun: &ast.ArrayType{}}, "Checked")
	require.False(t, ok)

	require.False(t, verdictShaped(&ast.Ident{Name: "x"}))
	require.False(t, verdictShaped(&ast.CallExpr{Fun: &ast.ArrayType{}}))
	require.False(t, verdictShaped(&ast.CallExpr{Fun: &ast.Ident{Name: "hash"}}))
}
