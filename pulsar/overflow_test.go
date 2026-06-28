// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/geth/common"
)

// TestVerify_MlenOverflowRejected proves the consensus-halt fix: an attacker
// who sets the message-length field near MaxUint64 must get a clean
// ErrInvalidInputLength, NOT a slice-out-of-range panic. A panic in geth's
// precompile dispatch has no recover() — it would halt every validator on the
// tx. Before the fix, mlen+sigSize wrapped uint64, the guard passed, and
// body[:mlen] panicked.
func TestVerify_MlenOverflowRejected(t *testing.T) {
	p := PulsarVerifyPrecompile

	input := []byte{ModePulsar44}
	input = append(input, make([]byte, Pulsar44PublicKeySize)...)
	lenField := make([]byte, 32)
	binary.BigEndian.PutUint64(lenField[24:], ^uint64(0)-8)
	input = append(input, lenField...)
	input = append(input, make([]byte, 64)...)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CONSENSUS-HALT: overflow mlen panicked instead of rejecting: %v", r)
		}
	}()
	_, _, err := p.Run(nil, common.Address{}, common.Address{}, input, 100_000_000, true)
	if err == nil {
		t.Fatal("expected ErrInvalidInputLength for overflow mlen, got nil")
	}
}
