// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !hqc_circl && !hqc_pqclean

package hqc

import (
	"errors"
	"testing"

	"github.com/luxfi/crypto/hqc"
	"github.com/luxfi/geth/common"
)

// TestRun_BackendStubSurfacesError — under the default no-backend
// build, hqc.Encapsulate returns hqc.ErrBackendNotWired. The precompile
// must propagate it as-is rather than swallowing into a generic error.
//
// Build-tag-gated so it does not run under hqc_pqclean / hqc_circl
// where a real backend supplies bytes instead of an error.
func TestRun_BackendStubSurfacesError(t *testing.T) {
	in := make([]byte, 2+SeedSize+2249)
	in[0] = 0x01
	in[1] = 0x00 // HQC-128
	// pkBytes left zero — backend stub returns ErrBackendNotWired before
	// any structural validation, which is the expected behaviour on a
	// host without a wired HQC backend (cgo PQClean or CIRCL HQC).
	_, _, err := HQCPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, 1_000_000, true)
	if !errors.Is(err, hqc.ErrBackendNotWired) {
		t.Errorf("backend-not-wired path: want hqc.ErrBackendNotWired, got %v", err)
	}
}
