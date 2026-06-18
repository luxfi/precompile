// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !starkfri_p3q

// verify_nocgo.go — safe-refuse fallback.
//
// This file is compiled whenever the real verifier binding
// (verify_cgo.go) is NOT — i.e. when cgo is disabled OR the
// `starkfri_p3q` build tag is absent. It intentionally does NOT call
// RegisterVerifier, so the package's default state stands: no verifier
// registered ⇒ Verify()/Run() return ErrVerifierNotRegistered ⇒ there
// is no forgery oracle (safe-refuse).
//
// To get the REAL strict-PQ STARK/FRI verifier:
//
//	make -C ../../p3q staticlib            # build libp3q_c_abi.a
//	go build -tags starkfri_p3q ./...      # compile with the binding
//
// See verify_cgo.go for the binding and the wire-format bridge.
//
// This file carries no symbols; it exists only to document the build
// matrix and to make the two-file build-tag partition explicit (so a
// reader greps one place to learn how the verifier is wired).
package starkfri
