// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vrf

import (
	"encoding/hex"
	"testing"

	edwards "filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

// RFC 9381 Appendix B.3 -- ECVRF-EDWARDS25519-SHA512-TAI.
//
// These are the only oracle in this package that does not come from the
// implementation itself: a prove/verify round trip agrees with itself even
// when every domain separator, the suite octet and the point encoding are all
// wrong together. Each field below is transcribed from the RFC.
var rfc9381TAI = []struct {
	name  string
	sk    string // secret key (Ed25519 seed)
	pk    string // public key, point_to_string(Y)
	alpha string // alpha_string
	h     string // ECVRF_encode_to_curve(PK, alpha)
	pi    string // pi_string
	beta  string // beta_string
}{
	{
		name:  "example16_empty_alpha",
		sk:    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		pk:    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		alpha: "",
		h:     "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
		pi:    "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
		beta:  "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
	},
	{
		name:  "example17_one_byte_alpha",
		sk:    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		pk:    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		alpha: "72",
		h:     "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
		pi:    "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
		beta:  "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
	},
	{
		name:  "example18_two_byte_alpha",
		sk:    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		pk:    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		alpha: "af82",
		h:     "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
		pi:    "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
		beta:  "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
	},
}

// TestRFC9381_Verify runs each published proof through the precompile and
// requires the published beta_string back.
func TestRFC9381_Verify(t *testing.T) {
	for _, v := range rfc9381TAI {
		t.Run(v.name, func(t *testing.T) {
			input := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mustHex(v.pi))
			got, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			require.NoError(t, err)
			require.Equal(t, v.beta, hex.EncodeToString(got))
		})
	}
}

// TestRFC9381_ProofToHash pins ECVRF_proof_to_hash on its own, so a break in
// the cofactor multiplication or the 0x03 domain separator is attributable.
func TestRFC9381_ProofToHash(t *testing.T) {
	for _, v := range rfc9381TAI {
		t.Run(v.name, func(t *testing.T) {
			input := append([]byte{OpProofToHash}, mustHex(v.pi)...)
			got, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			require.NoError(t, err)
			require.Equal(t, v.beta, hex.EncodeToString(got))
		})
	}
}

// TestRFC9381_EncodeToCurve pins ECVRF_encode_to_curve. This is the value the
// suite octet, both domain separators, the sign bit of the candidate y and the
// cofactor multiplication all feed into, so it localises a break that
// TestRFC9381_Verify would only report as "invalid".
func TestRFC9381_EncodeToCurve(t *testing.T) {
	for _, v := range rfc9381TAI {
		t.Run(v.name, func(t *testing.T) {
			H := encodeToCurve(mustHex(v.pk), mustHex(v.alpha))
			require.NotNil(t, H)
			require.Equal(t, v.h, hex.EncodeToString(H.Bytes()))
		})
	}
}

// TestRFC9381_Prove requires the test prover to reproduce the published
// pi_string bit for bit. The prover shares encodeToCurve and
// challengeGeneration with the verifier, so this pins the challenge
// derivation and the proof encoding as well.
func TestRFC9381_Prove(t *testing.T) {
	for _, v := range rfc9381TAI {
		t.Run(v.name, func(t *testing.T) {
			Y, err := new(edwards.Point).SetBytes(mustHex(v.pk))
			require.NoError(t, err)

			_, derived := expandSecretKey(mustHex(v.sk))
			require.Equal(t, v.pk, hex.EncodeToString(derived.Bytes()),
				"public key derived from SK must match the published PK")

			pi := testProve(mustHex(v.sk), Y, mustHex(v.alpha))
			require.Equal(t, v.pi, hex.EncodeToString(pi))
		})
	}
}

// TestRFC9381_ProofIsBoundToAlpha flips one bit of alpha_string and requires
// the published proof to stop verifying. A verifier that ignored alpha would
// pass every test above.
func TestRFC9381_ProofIsBoundToAlpha(t *testing.T) {
	for _, v := range rfc9381TAI {
		t.Run(v.name, func(t *testing.T) {
			alpha := append(mustHex(v.alpha), 0x00)
			input := buildVerifyInput(mustHex(v.pk), alpha, mustHex(v.pi))
			got, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
			require.NoError(t, err)
			require.Nil(t, got)
		})
	}
}

// TestRFC9381_ProofIsBoundToKey verifies each proof against the other two
// published public keys and requires refusal.
func TestRFC9381_ProofIsBoundToKey(t *testing.T) {
	for i, v := range rfc9381TAI {
		for j, other := range rfc9381TAI {
			if i == j {
				continue
			}
			t.Run(v.name+"_under_"+other.name, func(t *testing.T) {
				input := buildVerifyInput(mustHex(other.pk), mustHex(v.alpha), mustHex(v.pi))
				got, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
				require.NoError(t, err)
				require.Nil(t, got)
			})
		}
	}
}

// TestRFC9381_EveryProofBitIsLoadBearing flips one bit in every byte of each
// published proof and requires all 80 mutants to be refused. A verifier that
// skipped the c == c' comparison, or that only compared a prefix of the
// scalars, survives a single hand-picked corruption but not this.
func TestRFC9381_EveryProofBitIsLoadBearing(t *testing.T) {
	for _, v := range rfc9381TAI {
		t.Run(v.name, func(t *testing.T) {
			pi := mustHex(v.pi)
			for i := range pi {
				mutant := make([]byte, len(pi))
				copy(mutant, pi)
				mutant[i] ^= 0x01

				input := buildVerifyInput(mustHex(v.pk), mustHex(v.alpha), mutant)
				got, _, err := VRFPrecompile.Run(nil, ContractAddress, ContractAddress, input, testGas, true)
				require.NoError(t, err)
				require.Nilf(t, got, "flipping bit 0 of proof byte %d still verified", i)
			}
		})
	}
}
