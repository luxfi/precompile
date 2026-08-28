// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moduleRoot walks up from this package to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// walkSource visits every non-test .go file in the module, skipping vendored
// and nested-module trees.
func walkSource(t *testing.T, visit func(path string, fset *token.FileSet, f *ast.File)) {
	t.Helper()
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable directory is not this test's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				return fs.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return fs.SkipDir // a nested module is not this module
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // unparseable source belongs to whoever is editing it
		}
		visit(path, fset, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// isConstBool reports whether e is a compile-time true/false, including a
// parenthesised or negated one.
func isConstBool(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "true" || x.Name == "false"
	case *ast.ParenExpr:
		return isConstBool(x.X)
	case *ast.UnaryExpr:
		return x.Op == token.NOT && isConstBool(x.X)
	}
	return false
}

// calls reports whether e is a call to the named function, either bare
// (inside package contract) or qualified as contract.Name.
func calls(e ast.Expr, name string) (*ast.CallExpr, bool) {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return c, fn.Name == name
	case *ast.SelectorExpr:
		id, ok := fn.X.(*ast.Ident)
		return c, ok && id.Name == "contract" && fn.Sel.Name == name
	}
	return nil, false
}

// TestCheckedIsNeverALiteral is the enforcement half of the Verdict argument.
//
// The type makes a positive impossible to write as a struct literal from
// another package, and makes the zero value a refusal. What it cannot stop is
// Checked(true) — no Go type can. This walks every non-test file in the module
// and fails if any call to Checked passes a constant.
//
// That is what closes the measured defect. `return true, nil` is one of the
// most common lines in Go and reads as ordinary success; Checked(true) is a
// single greppable shape that fails the build. A positive verdict now has to
// come from an expression that computed something.
func TestCheckedIsNeverALiteral(t *testing.T) {
	var bad []string
	walkSource(t, func(path string, fset *token.FileSet, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			e, isExpr := n.(ast.Expr)
			if !isExpr {
				return true
			}
			c, ok := calls(e, "Checked")
			if !ok || len(c.Args) != 1 {
				return true
			}
			if isConstBool(c.Args[0]) {
				bad = append(bad, fset.Position(c.Pos()).String())
			}
			return true
		})
	})
	if len(bad) > 0 {
		t.Fatalf("Checked was passed a constant — a verdict claimed without a computation:\n  %s",
			strings.Join(bad, "\n  "))
	}
}

// TestVerdictIsNeverDiscarded pins the other half: a caller must not obtain a
// Verdict and throw it away.
//
// The single-value signature already does most of this. Under (bool, error) a
// caller could write `_, err := verify(...)` and keep the error while dropping
// the verdict — which is exactly how three tests came to miss three verifiers
// that answered valid without verifying. A Verdict cannot be split that way:
// the verdict and the reason are one value, so there is nothing to take while
// leaving the rest.
//
// What remains possible is dropping the whole thing: `_ = verify(...)`, or the
// call as a bare statement. This refuses both, in files that deal in Verdicts.
func TestVerdictIsNeverDiscarded(t *testing.T) {
	var bad []string
	walkSource(t, func(path string, fset *token.FileSet, f *ast.File) {
		src, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(src), "Verdict") {
			return // only files that traffic in verdicts
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				// `_ = f()` / `_, _ = f()` with a Verdict-shaped callee.
				allBlank := true
				for _, lhs := range s.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok || id.Name != "_" {
						allBlank = false
					}
				}
				if !allBlank {
					return true
				}
				for _, rhs := range s.Rhs {
					if verdictShaped(rhs) {
						bad = append(bad, fset.Position(s.Pos()).String())
					}
				}
			case *ast.ExprStmt:
				if verdictShaped(s.X) {
					bad = append(bad, fset.Position(s.Pos()).String())
				}
			}
			return true
		})
	})
	if len(bad) > 0 {
		t.Fatalf("a verdict was obtained and discarded:\n  %s", strings.Join(bad, "\n  "))
	}
}

// verdictShaped reports whether e is a call that yields a Verdict: either a
// constructor, or a function whose name says it verifies.
func verdictShaped(e ast.Expr) bool {
	if _, ok := calls(e, "Checked"); ok {
		return true
	}
	if _, ok := calls(e, "Refused"); ok {
		return true
	}
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	var name string
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		name = fn.Name
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	default:
		return false
	}
	return strings.Contains(strings.ToLower(name), "verify")
}
