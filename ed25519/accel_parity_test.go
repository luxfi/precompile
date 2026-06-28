// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ed25519

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestEd25519_VerdictMatchesCanonicalOracle proves the precompile's verdict is
// exactly ed25519.Verify (the canonical CPU oracle, now the single source of
// truth) across valid / tampered / wrong-key / wrong-message vectors. The
// deleted accel branch trusted a GPU Ed25519 kernel whose edge-case behavior
// (cofactor handling, non-canonical S, small-order points) was not proven
// byte-identical to this oracle -- a latent CPU/GPU split on attacker inputs.
func TestEd25519_VerdictMatchesCanonicalOracle(t *testing.T) {
	precompileVerdict := func(msg, sig, pub []byte) bool {
		input := make([]byte, 0, InputLength)
		input = append(input, msg...)
		input = append(input, sig...)
		input = append(input, pub...)
		res, _, err := Ed25519VerifyPrecompile.Run(
			nil, common.Address{}, ContractAddress, input, testGas, true,
		)
		require.NoError(t, err)
		return res != nil && len(res) == 32 && res[31] == 1
	}

	for i := 0; i < 64; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		msg := sha256.Sum256([]byte{byte(i)})
		sig := ed25519.Sign(priv, msg[:])

		// Build the four vector families and assert the precompile verdict
		// equals the canonical oracle's verdict for each.
		otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
		wrongMsg := sha256.Sum256([]byte{byte(i), 0xFF})
		tampered := append([]byte(nil), sig...)
		tampered[0] ^= 0x01

		vectors := []struct {
			name          string
			msg, sig, pub []byte
		}{
			{"valid", msg[:], sig, pub},
			{"tampered-sig", msg[:], tampered, pub},
			{"wrong-key", msg[:], sig, otherPub},
			{"wrong-msg", wrongMsg[:], sig, pub},
		}
		for _, v := range vectors {
			want := ed25519.Verify(v.pub, v.msg, v.sig)
			got := precompileVerdict(v.msg, v.sig, v.pub)
			require.Equal(t, want, got,
				"verdict must match canonical ed25519.Verify oracle (vector=%s, iter=%d)", v.name, i)
		}
	}
}
