// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dex

import (
	"fmt"
	"testing"
)

func TestZzstProbe(t *testing.T) {
	t.Logf("dbPrefixMeta len=%d cap=%d", len(dbPrefixMeta), cap(dbPrefixMeta))
	t.Logf("dbPrefixPool len=%d cap=%d", len(dbPrefixPool), cap(dbPrefixPool))
	t.Logf("dbPrefixPosition len=%d cap=%d", len(dbPrefixPosition), cap(dbPrefixPosition))
	t.Logf("dbPrefixTick len=%d cap=%d", len(dbPrefixTick), cap(dbPrefixTick))
	t.Logf("dbPrefixBitmap len=%d cap=%d", len(dbPrefixBitmap), cap(dbPrefixBitmap))
	t.Logf("coreKVPrefix len=%d cap=%d", len(coreKVPrefix), cap(coreKVPrefix))

	// Sscanf %x into *[32]byte?
	var id [32]byte
	n, err := fmt.Sscanf("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "%x", &id)
	t.Logf("Sscanf n=%d err=%v id=%x", n, err, id)

	var id2 [32]byte
	n2, err2 := fmt.Sscanf("zzzz", "%x", &id2)
	t.Logf("Sscanf bad n=%d err=%v id=%x", n2, err2, id2)

	// PoolKey ID collision for fee >= 2^24?
	k1 := PoolKey{Fee: 1, TickSpacing: 1}
	k2 := PoolKey{Fee: 1 + (1 << 24), TickSpacing: 1}
	t.Logf("fee collision: %v  id1=%x id2=%x", k1.ID() == k2.ID(), k1.ID(), k2.ID())

	k3 := PoolKey{Fee: 3000, TickSpacing: 60}
	k4 := PoolKey{Fee: 3000, TickSpacing: 60 + (1 << 24)}
	t.Logf("tickSpacing collision: %v", k3.ID() == k4.ID())

	k5 := PoolKey{Fee: 3000, TickSpacing: -1}
	k6 := PoolKey{Fee: 3000, TickSpacing: -1 - (1 << 24)}
	t.Logf("negative tickSpacing collision: %v", k5.ID() == k6.ID())

	// evmStore.Get with corrupt length word.
	sdb := NewMockStateDB()
	st := newEVMStore(sdb)
	key := []byte("k")
	var big [32]byte
	for i := 24; i < 32; i++ {
		big[i] = 0xff
	}
	sdb.SetState(poolManagerAddr9999, st.valueSlot(key, 0), big)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Get(corrupt 0xffff.. len) PANICKED: %v", r)
			}
		}()
		v, err := st.Get(key)
		t.Logf("Get(corrupt) len=%d err=%v", len(v), err)
	}()
}
