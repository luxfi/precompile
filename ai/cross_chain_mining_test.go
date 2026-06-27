// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"encoding/binary"
	"math/big"
	"testing"
)

func makeWorkProof(privacy uint16, mins uint32) []byte {
	p := make([]byte, WorkProofMinSize)
	p[31] = 0xAA                                     // deviceId (last byte)
	p[63] = 0xBB                                     // nonce (last byte)
	binary.BigEndian.PutUint64(p[64:72], 1718000000) // timestamp
	binary.BigEndian.PutUint16(p[72:74], privacy)
	binary.BigEndian.PutUint32(p[74:78], mins)
	return p
}

func TestMintWorkAndDoubleSpend(t *testing.T) {
	st := NewMockStateDB()
	proof := makeWorkProof(3, 60) // confidential, 60 compute-minutes
	chainId := uint64(200202)

	want, err := CalculateReward(proof, chainId)
	if err != nil {
		t.Fatalf("CalculateReward: %v", err)
	}

	reward, err := mintWork(st, proof, chainId)
	if err != nil {
		t.Fatalf("mintWork: %v", err)
	}
	if reward.Sign() <= 0 || reward.Cmp(want) != 0 {
		t.Fatalf("reward = %s, want %s", reward, want)
	}

	// Same work, same chain → double-spend rejected.
	if _, err := mintWork(st, proof, chainId); err != ErrWorkAlreadySpent {
		t.Fatalf("double-spend: got %v, want ErrWorkAlreadySpent", err)
	}

	// Same work on a DIFFERENT chain is a distinct workId (chainId-bound) → allowed.
	if _, err := mintWork(st, proof, chainId+1); err != nil {
		t.Fatalf("cross-chain work should be distinct: %v", err)
	}
}

func TestMintDataAndDoubleSpend(t *testing.T) {
	st := NewMockStateDB()
	desc := make([]byte, 42)
	desc[31] = 0xCD                               // dataHash (last byte)
	binary.BigEndian.PutUint64(desc[32:40], 1000) // dataSize units
	binary.BigEndian.PutUint16(desc[40:42], 3)    // privacy: confidential
	chainId := uint64(200202)

	reward, err := mintData(st, desc, chainId)
	if err != nil {
		t.Fatalf("mintData: %v", err)
	}
	want := new(big.Int).Set(baseRewardPerMinute)
	want.Mul(want, big.NewInt(1000))
	want.Mul(want, big.NewInt(int64(privacyMultipliers[3])))
	want.Div(want, big.NewInt(10000))
	if reward.Sign() <= 0 || reward.Cmp(want) != 0 {
		t.Fatalf("data reward = %s, want %s", reward, want)
	}

	// Same dataset → double-claim rejected.
	if _, err := mintData(st, desc, chainId); err != ErrWorkAlreadySpent {
		t.Fatalf("double-claim data: got %v, want ErrWorkAlreadySpent", err)
	}
}

func TestParseTriple(t *testing.T) {
	a, b, c := []byte("workproof-blob"), []byte("pubkey"), []byte("signature-bytes")
	var in []byte
	put := func(blob []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(blob)))
		in = append(in, l[:]...)
		in = append(in, blob...)
	}
	put(a)
	put(b)
	put(c)
	var cid [8]byte
	binary.BigEndian.PutUint64(cid[:], 200202)
	in = append(in, cid[:]...)

	ga, gb, gc, gcid, err := parseTriple(in)
	if err != nil {
		t.Fatalf("parseTriple: %v", err)
	}
	if string(ga) != string(a) || string(gb) != string(b) || string(gc) != string(c) || gcid != 200202 {
		t.Fatalf("parseTriple mismatch: %q %q %q %d", ga, gb, gc, gcid)
	}
	if _, _, _, _, err := parseTriple(in[:len(in)-2]); err == nil {
		t.Fatal("expected truncated parseTriple to error")
	}
}
