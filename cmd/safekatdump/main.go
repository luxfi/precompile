// safekatdump generates real known-answer test (KAT) vectors and the
// EXACT precompile input bytes for the Corona (0x012206), Pulsar (0x012204),
// Magnetar (0x012207) and CGGMP21 (0x0800..0003) verify precompiles, so the
// safe-{corona,pulsar,magnetar,cggmp21} Foundry tests can assert that their
// Solidity calldata framing matches the on-chain precompile wire format
// byte-for-byte.
//
// Output is JSON to stdout: one object per scheme with the precompile
// address, the verify context, the component fields, and the full framed
// `input` blob (== what the precompile's Run() parses).
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	csign "github.com/luxfi/corona/sign"
	cthr "github.com/luxfi/corona/threshold"
	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/crypto/slhdsa"
	"github.com/luxfi/lattice/v7/ring"
)

type katOut struct {
	Scheme    string `json:"scheme"`
	Address   string `json:"address"`
	Context   string `json:"context"`
	Mode      string `json:"mode,omitempty"`
	Threshold uint32 `json:"threshold,omitempty"`
	Parties   uint32 `json:"parties,omitempty"`
	PubKeyHex string `json:"pubkey,omitempty"`
	SigHex    string `json:"sig"`
	MsgHex    string `json:"msg,omitempty"`
	MsgHash   string `json:"msgHash,omitempty"`
	InputHex  string `json:"input"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

// ---- Pulsar (0x012204): byte-equal to single-party ML-DSA-65 -------------
// Wire: mode(1) || pk || msgLen:uint256(32) || msg || sig
func pulsarKAT() katOut {
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	must(err)
	ctx := []byte("lux-evm-precompile-pulsar-v1")
	// The Safe message is always the 32-byte Safe-tx hash.
	msg := sha256.Sum256([]byte("safe-pulsar KAT message"))
	sigBytes, err := priv.SignCtx(rand.Reader, msg[:], ctx)
	must(err)
	pub := priv.PublicKey.Bytes()

	var input bytes.Buffer
	input.WriteByte(0x65) // ML-DSA-65 mode
	input.Write(pub)
	var ml [32]byte
	binary.BigEndian.PutUint64(ml[24:], uint64(len(msg)))
	input.Write(ml[:])
	input.Write(msg[:])
	input.Write(sigBytes)

	return katOut{
		Scheme:    "pulsar",
		Address:   "0x0000000000000000000000000000000000012204",
		Context:   string(ctx),
		Mode:      "0x65",
		PubKeyHex: hex.EncodeToString(pub),
		SigHex:    hex.EncodeToString(sigBytes),
		MsgHash:   hex.EncodeToString(msg[:]),
		InputHex:  hex.EncodeToString(input.Bytes()),
	}
}

// ---- Magnetar (0x012207): byte-equal to single-party SLH-DSA-SHA2-128s ----
// Wire: mode(1) || pkLen:uint16 || pk || msgLen:uint16 || msg || sig
func magnetarKAT() katOut {
	priv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	must(err)
	ctx := []byte("lux-evm-precompile-magnetar-v1")
	msg := sha256.Sum256([]byte("safe-magnetar KAT message"))
	sigBytes, err := priv.SignCtx(rand.Reader, msg[:], ctx)
	must(err)
	pub := priv.PublicKey.Bytes()

	var input bytes.Buffer
	input.WriteByte(0x00) // SHA2-128s mode
	var pl [2]byte
	binary.BigEndian.PutUint16(pl[:], uint16(len(pub)))
	input.Write(pl[:])
	input.Write(pub)
	var mlh [2]byte
	binary.BigEndian.PutUint16(mlh[:], uint16(len(msg)))
	input.Write(mlh[:])
	input.Write(msg[:])
	input.Write(sigBytes)

	return katOut{
		Scheme:    "magnetar",
		Address:   "0x0000000000000000000000000000000000012207",
		Context:   string(ctx),
		Mode:      "0x00",
		PubKeyHex: hex.EncodeToString(pub),
		SigHex:    hex.EncodeToString(sigBytes),
		MsgHash:   hex.EncodeToString(msg[:]),
		InputHex:  hex.EncodeToString(input.Bytes()),
	}
}

// ---- Corona (0x012206): real 2-round LWE threshold signature -------------
// Wire: t:uint32 || n:uint32 || msgHash:32 || serializedSig
// serializedSig (per precompile contract.go deserializeSignature):
//   c || z[N] || Delta[M] || A[M][N] || bTilde[M], each poly = N()*8 bytes BE.
func coronaKAT(t, n uint32) katOut {
	shares, groupKey, err := cthr.GenerateKeys(int(t), int(n), rand.Reader)
	must(err)

	prfKey := make([]byte, csign.KeySize)
	_, _ = rand.Read(prfKey)

	signers := make([]int, n)
	for i := range signers {
		signers[i] = i
	}
	sessionID := 1

	tsigners := make([]*cthr.Signer, n)
	for i, sh := range shares {
		tsigners[i] = cthr.NewSigner(sh)
	}

	// 32-byte message hash exactly as the precompile receives it.
	var msgHash [32]byte
	copy(msgHash[:], []byte("corona-kat-msg"))
	signMessage := fmt.Sprintf("lux-evm-precompile-corona-v1|%x", msgHash[:])

	round1 := make(map[int]*cthr.Round1Data)
	for i, s := range tsigners {
		r1, err := s.Round1(sessionID, prfKey, signers)
		must(err)
		round1[i] = r1
	}
	round2 := make(map[int]*cthr.Round2Data)
	for i, s := range tsigners {
		r2, err := s.Round2(sessionID, signMessage, prfKey, signers, round1)
		must(err)
		round2[i] = r2
	}
	sig, err := tsigners[0].Finalize(round2)
	must(err)

	if !cthr.Verify(groupKey, signMessage, sig) {
		must(fmt.Errorf("corona sanity verify failed pre-serialization"))
	}

	sigBytes, err := coronaSerialize(groupKey.Params, sig, groupKey)
	must(err)

	var input bytes.Buffer
	var tn [8]byte
	binary.BigEndian.PutUint32(tn[0:4], t)
	binary.BigEndian.PutUint32(tn[4:8], n)
	input.Write(tn[:])
	input.Write(msgHash[:])
	input.Write(sigBytes)

	return katOut{
		Scheme:    "corona",
		Address:   "0x0000000000000000000000000000000000012206",
		Context:   "lux-evm-precompile-corona-v1",
		Threshold: t,
		Parties:   n,
		SigHex:    hex.EncodeToString(sigBytes),
		MsgHash:   hex.EncodeToString(msgHash[:]),
		InputHex:  hex.EncodeToString(input.Bytes()),
	}
}

// coronaSerialize replicates precompile/corona/contract_test.go serializeSignature
// EXACTLY (8-byte big-endian coefficients, component order
// c || z[N] || Delta[M] || A[M][N] || bTilde[M]).
func coronaSerialize(params *cthr.Params, sig *cthr.Signature, groupKey *cthr.GroupKey) ([]byte, error) {
	var buf bytes.Buffer
	r := params.R
	rXi := params.RXi
	rNu := params.RNu

	cCopy := *sig.C.CopyNew()
	r.IMForm(cCopy, cCopy)
	r.INTT(cCopy, cCopy)
	if err := serializePoly(&buf, r, cCopy); err != nil {
		return nil, err
	}
	for i := 0; i < csign.N; i++ {
		zCopy := *sig.Z[i].CopyNew()
		r.IMForm(zCopy, zCopy)
		r.INTT(zCopy, zCopy)
		if err := serializePoly(&buf, r, zCopy); err != nil {
			return nil, err
		}
	}
	for i := 0; i < csign.M; i++ {
		if err := serializePoly(&buf, rNu, sig.Delta[i]); err != nil {
			return nil, err
		}
	}
	for i := 0; i < csign.M; i++ {
		for j := 0; j < csign.N; j++ {
			aCopy := *groupKey.A[i][j].CopyNew()
			r.IMForm(aCopy, aCopy)
			r.INTT(aCopy, aCopy)
			if err := serializePoly(&buf, r, aCopy); err != nil {
				return nil, err
			}
		}
	}
	for i := 0; i < csign.M; i++ {
		if err := serializePoly(&buf, rXi, groupKey.BTilde[i]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func serializePoly(buf *bytes.Buffer, r *ring.Ring, poly ring.Poly) error {
	coeffs := make([]*big.Int, r.N())
	r.PolyToBigint(poly, 1, coeffs)
	for _, coeff := range coeffs {
		cb := make([]byte, 8)
		coeff.FillBytes(cb)
		if _, err := buf.Write(cb); err != nil {
			return err
		}
	}
	return nil
}

// ---- CGGMP21 (0x0800..0003): threshold ECDSA, byte-equal to single-party --
// secp256k1 ECDSA. The precompile parses a standard ECDSA signature and
// asserts the recovered pubkey equals the supplied aggregated pubkey, so a
// real KAT is just a genuine secp256k1 signature whose key is the group key.
// Wire: t:uint32(4) || n:uint32(4) || pubkey(65: 0x04||x||y) || msgHash(32) ||
//       sig(65: r||s||v).
func cggmp21KAT(t, n uint32) katOut {
	priv, err := crypto.GenerateKey()
	must(err)

	// 32-byte message hash exactly as the precompile receives it.
	msg := sha256.Sum256([]byte("safe-cggmp21 KAT message"))

	// crypto.Sign produces [R || S || V] with V in {0,1}, the exact 65-byte
	// layout the precompile parses at input[105:170].
	sigBytes, err := crypto.Sign(msg[:], priv)
	must(err)

	// Uncompressed group public key: 0x04 || x || y (65 bytes).
	pub := crypto.FromECDSAPub(&priv.PublicKey)
	if len(pub) != 65 {
		must(fmt.Errorf("cggmp21: unexpected pubkey length %d", len(pub)))
	}

	var input bytes.Buffer
	var tn [8]byte
	binary.BigEndian.PutUint32(tn[0:4], t)
	binary.BigEndian.PutUint32(tn[4:8], n)
	input.Write(tn[:])
	input.Write(pub)
	input.Write(msg[:])
	input.Write(sigBytes)

	return katOut{
		Scheme:    "cggmp21",
		Address:   "0x0800000000000000000000000000000000000003",
		Context:   "",
		Threshold: t,
		Parties:   n,
		PubKeyHex: hex.EncodeToString(pub),
		SigHex:    hex.EncodeToString(sigBytes),
		MsgHash:   hex.EncodeToString(msg[:]),
		InputHex:  hex.EncodeToString(input.Bytes()),
	}
}

func main() {
	out := []katOut{
		pulsarKAT(),
		magnetarKAT(),
		coronaKAT(2, 3),
		cggmp21KAT(2, 3),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}
