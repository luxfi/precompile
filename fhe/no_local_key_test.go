// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Structural launch-safety gate for the FHE gateway precompile.
//
// The original 0x0700 precompile derived its FHE secret key from a FIXED
// in-source seed and returned real plaintext from a local decrypt — so the
// "secret" key was public and anyone could decrypt anyone's ciphertexts (the
// permissionless-launch confidentiality blocker). The fix made the precompile a
// THRESHOLD GATEWAY: it holds only PUBLIC key material, and decryption is an
// ACL-gated, fail-closed F-Chain threshold ceremony where no single party holds
// the secret key.
//
// The behavioural posture is pinned by security_test.go. THIS file pins the
// SOURCE-LEVEL posture so the class of regression cannot silently return: no
// production file may carry an in-source keygen seed, a secret key, a decryptor,
// or any full-keypair/secret-sampling primitive; and the decrypt/seal handlers
// must structurally enforce the ACL. These tests scan source (no cgo needed) so
// they run in every build, including CGO_ENABLED=0 CI.

package fhe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenLocalKeyIdents are identifier/selector names that, if they appear in
// a PRODUCTION file, mean the precompile is forming or holding FHE secret
// material locally — defeating the threshold model. Matched EXACTLY against
// AST identifier and selector names (never substrings, so method names like
// handleDecrypt are not affected; never comments, which legitimately explain the
// absence of a secret key).
var forbiddenLocalKeyIdents = map[string]string{
	"NewKeyGeneratorFromSeed": "in-source deterministic keygen seed (public secret key — the original blocker)",
	"fheKeygenSeed":           "in-source keygen seed constant",
	"GenKeyPair":              "generates the full master (sk, pk) in one process",
	"GenSecretKey":            "samples a full secret key locally",
	"GenSecretKeyNew":         "samples a full secret key locally",
	"GenBootstrapKey":         "requires the full secret key to build the bootstrap key",
	"NewDecryptor":            "a decryptor holds the secret key — the precompile must not decrypt locally",
	"NewBitwiseDecryptor":     "a decryptor holds the secret key — the precompile must not decrypt locally",
	"SecretKey":               "references an FHE secret-key type/field",
	"SKLWE":                   "references the LWE secret-key component",
	"SKBR":                    "references the blind-rotation secret-key component",
	"DecryptUint64":           "a local decrypt call",
}

// productionFiles returns the package's non-test .go files.
func productionFiles(t *testing.T) []string {
	t.Helper()
	all, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var prod []string
	for _, f := range all {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		prod = append(prod, f)
	}
	if len(prod) == 0 {
		t.Fatal("no production files found to scan")
	}
	return prod
}

// TestPrecompile_NoLocalSecretKey_Structural fails if any production file
// references a secret-key/decryptor/keygen-seed construct. This is the
// source-level guard against re-complecting a local decrypt into the gateway.
func TestPrecompile_NoLocalSecretKey_Structural(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range productionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			var name string
			switch x := n.(type) {
			case *ast.Ident:
				name = x.Name
			case *ast.SelectorExpr:
				name = x.Sel.Name
			default:
				return true
			}
			if why, bad := forbiddenLocalKeyIdents[name]; bad {
				pos := fset.Position(n.Pos())
				t.Errorf("%s:%d references forbidden local-key construct %q (%s)",
					path, pos.Line, name, why)
			}
			return true
		})
	}
}

// TestPrecompile_NoLocalSecretKey_NegativeControl proves the scanner has teeth:
// a synthetic source containing a forbidden construct is flagged.
func TestPrecompile_NoLocalSecretKey_NegativeControl(t *testing.T) {
	src := `package fhe
func leak() {
	kg, _ := NewKeyGeneratorFromSeed(params, fheKeygenSeed[:]) // must be caught
	_ = kg
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	flagged := false
	ast.Inspect(f, func(n ast.Node) bool {
		var name string
		switch x := n.(type) {
		case *ast.Ident:
			name = x.Name
		case *ast.SelectorExpr:
			name = x.Sel.Name
		default:
			return true
		}
		if _, bad := forbiddenLocalKeyIdents[name]; bad {
			flagged = true
			return false
		}
		return true
	})
	if !flagged {
		t.Fatal("negative control: scanner failed to flag an injected local-key construct")
	}
}

// aclGatedHandlers must structurally call isAuthorized before any reveal-shaped
// path. These are the only two handlers that gate access to confidential output.
var aclGatedHandlers = []string{"handleDecrypt", "handleSealOutput"}

// TestPrecompile_DecryptSeal_ACLGated_Structural asserts that handleDecrypt and
// handleSealOutput each call isAuthorized (the ACL is load-bearing, not vestigial
// — closing the "caller plumbed but unused" slop) and never call a local-decrypt
// primitive.
func TestPrecompile_DecryptSeal_ACLGated_Structural(t *testing.T) {
	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, path := range productionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			want := false
			for _, h := range aclGatedHandlers {
				if fn.Name.Name == h {
					want = true
				}
			}
			if !want {
				continue
			}
			found[fn.Name.Name] = true
			if !bodyCalls(fn.Body, "isAuthorized") {
				t.Errorf("%s does not call isAuthorized — the ACL gate is missing (confidential output is ungated)",
					fn.Name.Name)
			}
			for bad := range forbiddenLocalKeyIdents {
				if bodyCalls(fn.Body, bad) {
					t.Errorf("%s calls forbidden local-key primitive %q — it must fail closed, not decrypt locally",
						fn.Name.Name, bad)
				}
			}
		}
	}
	for _, h := range aclGatedHandlers {
		if !found[h] {
			t.Errorf("expected to scan handler %q but it was not found (renamed/removed?)", h)
		}
	}
}

// TestPrecompile_ACLGate_NegativeControl proves the ACL-presence check has teeth:
// a synthetic handler without isAuthorized is detected as ungated.
func TestPrecompile_ACLGate_NegativeControl(t *testing.T) {
	src := `package fhe
func handleDecryptBad() {
	// returns plaintext with no ACL check — must be detected as ungated
	_ = "plaintext"
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "handleDecryptBad" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("synthetic handler not parsed")
	}
	if bodyCalls(body, "isAuthorized") {
		t.Fatal("negative control: ungated handler wrongly reported as ACL-gated")
	}
}

// bodyCalls reports whether body contains a call (bare or selector) to target.
func bodyCalls(body *ast.BlockStmt, target string) bool {
	hit := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hit {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == target {
				hit = true
			}
		case *ast.SelectorExpr:
			if fn.Sel.Name == target {
				hit = true
			}
		}
		return !hit
	})
	return hit
}
