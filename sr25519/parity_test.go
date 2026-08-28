// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sr25519

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/modules"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// This package ships TWO verifiers behind one name: sr25519-donna under cgo and
// ChainSafe/go-schnorrkel without it. Whichever the node links decides whether a
// block is valid, so a single input on which they disagree is a chain split.
//
// The build tags make it impossible to link both into one binary, so parity
// cannot be checked by calling them side by side. What this file does instead:
// every expectation below is a CONSTANT -- either a published vector or a
// property that must hold of any correct Schnorrkel verifier -- never a value
// read back from the verifier under test. Both builds are held to the same
// constants, so agreement follows from both passing:
//
//	go test ./sr25519/...
//	CGO_ENABLED=0 go test ./sr25519/...
//
// TestParity_CorpusDigest closes the gap the individual cases leave, by pinning
// a digest over the verdicts for a large deterministic corpus. Any divergence
// anywhere in that corpus changes the digest and fails one of the two builds.

func hexed(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}

func verdict(tb testing.TB, in []byte) bool {
	tb.Helper()
	out, _, err := SR25519VerifyPrecompile.Run(
		nil, common.Address{}, ContractAddress, in, SR25519VerifyPrecompile.RequiredGas(in), true)
	require.NoError(tb, err)
	require.Len(tb, out, 32)
	return out[31] == 1
}

// TestParity_BackendIsNamed makes the run self-describing: a reader of CI output
// can tell which verifier was exercised, and a build that linked neither would
// not compile.
func TestParity_BackendIsNamed(t *testing.T) {
	require.NotEmpty(t, backend)
	t.Logf("sr25519 verifier under test: %s", backend)
}

// TestParity_AcceptsTheKnownGoodVector is the one input both backends must
// accept. Alice's key and signature are the well-known Substrate development
// vector, produced with the "substrate" signing context.
func TestParity_AcceptsTheKnownGoodVector(t *testing.T) {
	require.True(t, verdict(t, buildInput(alicePubKey, aliceSignature, aliceMessage)),
		"%s must accept the published Alice vector", backend)

	// verifySR25519 and Run must agree; Run adds only gas and framing.
	require.True(t, verifySR25519(alicePubKey, aliceSignature, aliceMessage))
}

// TestParity_StructuredRefusals holds both backends to the same verdict on the
// inputs where two Ristretto/Schnorrkel implementations most plausibly differ:
// canonicality of the compressed public key, the identity encoding, the
// signature's scalar half, and the sign bit Schnorrkel packs into it.
func TestParity_StructuredRefusals(t *testing.T) {
	// Ristretto255 encodings that no correct decoder accepts: field elements at
	// or above p, and the all-ones word.
	nonCanonical := []string{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p+1
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // all ones
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p-1, s = -1
		"00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0100000000000000000000000000000000000000000000000000000000000000", // negative field element
	}
	for _, enc := range nonCanonical {
		t.Run("pubkey/"+enc[:12], func(t *testing.T) {
			require.False(t, verdict(t, buildInput(hexed(t, enc), aliceSignature, aliceMessage)),
				"%s must not accept a non-canonical Ristretto public key", backend)
		})
		t.Run("sigR/"+enc[:12], func(t *testing.T) {
			sig := append(append([]byte{}, hexed(t, enc)...), aliceSignature[32:]...)
			require.False(t, verdict(t, buildInput(alicePubKey, sig, aliceMessage)))
		})
	}

	// The Ristretto identity is a canonical encoding but carries no key.
	identity := make([]byte, PublicKeySize)
	require.False(t, verdict(t, buildInput(identity, aliceSignature, aliceMessage)),
		"the identity element must not verify as a public key")

	// Schnorrkel sets the high bit of the last signature byte; clearing it, and
	// every other single-bit mutation, must break the signature.
	for _, at := range []int{0, 1, 31, 32, 33, 62, 63} {
		for _, bit := range []byte{0x01, 0x80} {
			sig := append([]byte{}, aliceSignature...)
			sig[at] ^= bit
			require.False(t, verdict(t, buildInput(alicePubKey, sig, aliceMessage)),
				"signature byte %d bit %#x must matter", at, bit)
		}
	}

	// The scalar half must be reduced. Adding the Ristretto group order L to s
	// gives a second encoding of the same scalar; a verifier that reduces rather
	// than refuses would accept it, which is signature malleability.
	//
	// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
	l := hexed(t, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	malleated := append([]byte{}, aliceSignature...)
	carry := 0
	for i := range 32 {
		sum := int(malleated[32+i]&0x7F) + int(l[i]) + carry
		if i == 31 {
			sum = int(malleated[63]&0x7F) + int(l[31]) + carry
		}
		malleated[32+i] = byte(sum)
		carry = sum >> 8
	}
	malleated[63] |= 0x80 // restore Schnorrkel's marker bit
	require.NotEqual(t, aliceSignature, malleated, "the mutation must change the encoding")
	require.False(t, verdict(t, buildInput(alicePubKey, malleated, aliceMessage)),
		"s must be canonical: s + L must not verify")

	// Every field is bound: key, signature and message each break it alone.
	require.False(t, verdict(t, buildInput(
		hexed(t, "8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"),
		aliceSignature, aliceMessage)), "a different public key must not verify")
	require.False(t, verdict(t, buildInput(alicePubKey, aliceSignature,
		append(append([]byte{}, aliceMessage...), '!'))), "an extended message must not verify")
	require.False(t, verdict(t, buildInput(alicePubKey, aliceSignature,
		aliceMessage[:len(aliceMessage)-1])), "a truncated message must not verify")
	require.False(t, verdict(t, buildInput(alicePubKey, make([]byte, SignatureSize), aliceMessage)),
		"the zero signature must not verify")
	require.False(t, verdict(t, make([]byte, MinInputSize)), "an all-zero call must not verify")

	ones := make([]byte, MinInputSize)
	for i := range ones {
		ones[i] = 0xFF
	}
	require.False(t, verdict(t, ones), "an all-ones call must not verify")
}

// parityCorpus builds a deterministic set of calls from a SHA-256 chain: no
// clock, no randomness, no map order. Both builds see byte-identical inputs.
func parityCorpus() [][]byte {
	const n = 512
	corpus := make([][]byte, 0, n)
	seed := sha256.Sum256([]byte("lux/precompile/sr25519 parity corpus v1"))
	block := seed

	next := func() [32]byte {
		block = sha256.Sum256(block[:])
		return block
	}

	for i := range n {
		// Message length walks 1..17 bytes so the per-byte gas arm varies too.
		msgLen := 1 + i%17
		in := make([]byte, 0, PublicKeySize+SignatureSize+msgLen)

		switch i % 4 {
		case 0:
			// Fully pseudorandom.
			a, b := next(), next()
			in = append(in, a[:]...)
			in = append(in, b[:]...)
			c := next()
			in = append(in, c[:]...)
		case 1:
			// Alice's real key with a pseudorandom signature.
			a, b := next(), next()
			in = append(in, alicePubKey...)
			in = append(in, a[:]...)
			in = append(in, b[:]...)
		case 2:
			// Alice's real signature under a pseudorandom key.
			a := next()
			in = append(in, a[:]...)
			in = append(in, aliceSignature...)
		case 3:
			// Alice's real key and signature over a different message.
			in = append(in, alicePubKey...)
			in = append(in, aliceSignature...)
		}

		// Pad or trim to exactly pubkey+sig+msgLen with a deterministic tail.
		want := PublicKeySize + SignatureSize + msgLen
		for len(in) < want {
			t := next()
			in = append(in, t[:]...)
		}
		corpus = append(corpus, in[:want])
	}
	return corpus
}

// TestParity_CorpusDigest is the cross-backend check the per-case tests cannot
// give on their own. It hashes the verdict for all 512 deterministic calls into
// one digest and compares it to a pinned constant. The two builds cannot be
// linked together, so this digest is how their agreement is stated: if
// sr25519-donna and go-schnorrkel differ on ANY input in the corpus, the digest
// differs and one of the two runs fails.
//
// The pinned value was produced by running this test under both builds and
// confirming they matched. Regenerating it because it "went red" defeats the
// entire purpose -- a mismatch means the backends disagree, which is a
// consensus split, not a stale constant.
func TestParity_CorpusDigest(t *testing.T) {
	corpus := parityCorpus()
	require.Len(t, corpus, 512)

	h := sha256.New()
	accepted := 0
	for i, in := range corpus {
		// The corpus itself is hashed in, so a change to the generator shows up
		// as a mismatch rather than silently comparing different inputs.
		var hdr [8]byte
		binary.BigEndian.PutUint32(hdr[:4], uint32(i))
		binary.BigEndian.PutUint32(hdr[4:], uint32(len(in)))
		h.Write(hdr[:])
		h.Write(in)

		v := verdict(t, in)
		if v {
			accepted++
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}

	require.Zero(t, accepted,
		"no pseudorandom call may verify; %s accepted %d of %d", backend, accepted, len(corpus))
	require.Equal(t,
		"cbe358fc9189609bf42d61e5baa0472f3483f37b0324848d68720c3d22c80412",
		hex.EncodeToString(h.Sum(nil)),
		"%s disagrees with the pinned cross-backend verdict corpus", backend)
}

// TestParity_GasIsBackendIndependent: the price is computed from the input
// length alone, so both builds must charge identically for identical calldata.
func TestParity_GasIsBackendIndependent(t *testing.T) {
	for _, n := range []int{0, 1, 96, 97, 128, 1024, 65536} {
		in := make([]byte, n)
		want := SR25519VerifyBaseGas
		if n > PublicKeySize+SignatureSize {
			want += uint64(n-PublicKeySize-SignatureSize) * SR25519VerifyPerByteGas
		}
		require.Equal(t, want, SR25519VerifyPrecompile.RequiredGas(in), "len=%d", n)
	}
	require.Equal(t, SR25519VerifyBaseGas, SR25519VerifyPrecompile.RequiredGas(nil))

	// Price rises by exactly the per-byte rate for each extra message byte.
	prev := SR25519VerifyPrecompile.RequiredGas(make([]byte, MinInputSize))
	for n := MinInputSize + 1; n <= MinInputSize+64; n++ {
		got := SR25519VerifyPrecompile.RequiredGas(make([]byte, n))
		require.Equal(t, SR25519VerifyPerByteGas, got-prev, "len=%d", n)
		prev = got
	}

	// The base fee is charged even for calls too short to verify, so a truncated
	// call is not a free probe.
	require.Equal(t, SR25519VerifyBaseGas, SR25519VerifyPrecompile.RequiredGas(make([]byte, 96)))
}

// TestParity_GasDeduction covers exact, surplus and insufficient supply.
func TestParity_GasDeduction(t *testing.T) {
	in := buildInput(alicePubKey, aliceSignature, aliceMessage)
	price := SR25519VerifyPrecompile.RequiredGas(in)

	out, left, err := SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress, in, price+37, true)
	require.NoError(t, err)
	require.Equal(t, byte(1), out[31])
	require.Equal(t, uint64(37), left)

	_, left, err = SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress, in, price, true)
	require.NoError(t, err)
	require.Zero(t, left)

	out, left, err = SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress, in, price-1, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
	require.Nil(t, out)
	require.Zero(t, left)

	_, _, err = SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress, in, 0, true)
	require.ErrorIs(t, err, contract.ErrOutOfGas)

	// A short call is refused with an error, and the base fee is still deducted.
	out, left, err = SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress,
		make([]byte, MinInputSize-1), SR25519VerifyBaseGas+5, true)
	require.ErrorIs(t, err, ErrInputTooShort)
	require.Equal(t, failResult, out)
	require.Equal(t, uint64(5), left)
}

// TestParity_LengthBoundary: one byte below MinInputSize is refused, exactly
// MinInputSize is answered.
func TestParity_LengthBoundary(t *testing.T) {
	for n := 0; n < MinInputSize; n++ {
		in := make([]byte, n)
		out, _, err := SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress,
			in, SR25519VerifyPrecompile.RequiredGas(in)+1000, true)
		require.ErrorIs(t, err, ErrInputTooShort, "len=%d", n)
		require.Equal(t, failResult, out)
	}

	in := make([]byte, MinInputSize)
	out, _, err := SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress,
		in, SR25519VerifyPrecompile.RequiredGas(in), true)
	require.NoError(t, err, "the minimum length is answered, not refused")
	require.Equal(t, byte(0), out[31])
}

// TestParity_HelperGuards covers verifySR25519's own preconditions. Run cannot
// reach them -- it slices fixed widths from an already length-checked input --
// but the helper is package surface and the guards are what keep a future
// caller from indexing past the end.
func TestParity_HelperGuards(t *testing.T) {
	good := make([]byte, PublicKeySize)
	sig := make([]byte, SignatureSize)

	for _, n := range []int{0, 1, 31, 33, 64} {
		require.False(t, verifySR25519(make([]byte, n), sig, []byte("m")), "pubkey len=%d", n)
	}
	for _, n := range []int{0, 1, 63, 65, 128} {
		require.False(t, verifySR25519(good, make([]byte, n), []byte("m")), "sig len=%d", n)
	}
	require.False(t, verifySR25519(good, sig, nil))
	require.False(t, verifySR25519(good, sig, []byte{}))
	require.False(t, verifySR25519(nil, nil, nil))
}

// TestParity_Deterministic: no clock, no randomness, no map iteration. Repeated
// calls in any order return the same bytes.
func TestParity_Deterministic(t *testing.T) {
	cases := [][]byte{
		buildInput(alicePubKey, aliceSignature, aliceMessage),
		buildInput(alicePubKey, aliceSignature, []byte("other")),
		make([]byte, MinInputSize),
	}
	first := make([]bool, len(cases))
	for i, in := range cases {
		first[i] = verdict(t, in)
	}
	for range 16 {
		for i := len(cases) - 1; i >= 0; i-- {
			require.Equal(t, first[i], verdict(t, cases[i]), "case %d is not deterministic", i)
		}
	}
	require.True(t, first[0])
	require.False(t, first[1])
	require.False(t, first[2])
}

// TestParity_ReadOnlyAndCallerAreIrrelevant: the precompile touches no state.
func TestParity_ReadOnlyAndCallerAreIrrelevant(t *testing.T) {
	in := buildInput(alicePubKey, aliceSignature, aliceMessage)
	gas := SR25519VerifyPrecompile.RequiredGas(in)

	ro, _, err := SR25519VerifyPrecompile.Run(nil, common.Address{}, ContractAddress, in, gas, true)
	require.NoError(t, err)
	rw, _, err := SR25519VerifyPrecompile.Run(nil, common.HexToAddress("0xbeef"), common.Address{}, in, gas, false)
	require.NoError(t, err)
	require.Equal(t, ro, rw)
}

// --- module wiring ------------------------------------------------------

func TestParity_ModuleWiring(t *testing.T) {
	// This package builds its registry entry inline in init() rather than
	// exporting it, so the registration is restated here.
	entry := modules.Module{
		ConfigKey:    ConfigKey,
		Address:      ContractAddress,
		Contract:     SR25519VerifyPrecompile,
		Configurator: &configurator{},
	}
	require.Equal(t, "sr25519Verify", entry.ConfigKey)
	require.Equal(t,
		common.HexToAddress("0x0A00000000000000000000000000000000000001"),
		ContractAddress)
	require.Equal(t, ContractAddress, SR25519VerifyPrecompile.Address())

	require.IsType(t, &Config{}, (&configurator{}).MakeConfig())
	require.NoError(t, (&configurator{}).Configure(nil, nil, nil, nil))
	require.False(t, (&Config{}).Equal(&struct{ precompileconfig.Config }{}))

	// Registering the same address twice is refused, which is the condition
	// init() panics on. The panic itself runs before any test can observe it.
	require.Error(t, modules.RegisterModule(entry))
}
