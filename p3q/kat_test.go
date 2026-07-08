// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package p3q

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// Known-answer test (KAT) vector for the P3Q verifier core.
//
// This is a FIXED, real FIPS 204 ML-DSA-44 signature produced by
// luxfi/crypto/mldsa (cloudflare/circl mldsa44) over the 32-byte message
// katMsg under the P3Q domain-separation context PrecompileCtx
// ("lux-evm-precompile-p3q-v1"). Unlike the round-trip tests that mint a
// fresh key each run, these bytes are frozen: the verifier MUST accept
// them, and any tampering MUST be rejected. This pins the exact
// accept/reject behaviour of the FIPS 204 verify path so a future change
// to the mldsa dependency, the wire encoder, or the context binding that
// silently altered verification would be caught.
//
// Vector provenance: generated once via mldsa.GenerateKey(MLDSA44) +
// SignCtx(msg, PrecompileCtx); see git history for the generator. Sizes:
// pk = 1312 B (MLDSA44PublicKeySize), sig = 2420 B (MLDSA44SignatureSize),
// msg = 32 B.
const (
	katPKHex  = "f3ed473005d0232f3190df128cef92bea2add465c19a4df73e695c5577923caa981b6080a0fa0efd81bf19b211ec6981f41944cb6ecbf6d8644c9f8caedc455b9c3dfb78afa64e494165e2bd6f3fa3b30bf20676e7040a8d83e80855073425ced2643f93e6c709d9dfa957be4c043cf53390dce5029af4adcee65e5eafdaaea43c6ddc386b267e09f7485a30ca09dfee85706477038594feb0e4ee020c475ae0b85d93f0b2f87647757fe1d531f0733e891012a189253a5465873478a542d13b3d9ec1afd43890296096d08558aa09c1be4e417edbc161eae6f19a8d10af0b20cfb44dac12b763fc7e92c427ed34bff3891aa03f3307e52e33157f388d6dff24d472f8fb5f180ad585d087f4efc2fdef58a87a042e2734db7340a3c92327e37b809cac0c7ae0d3503f989eba11af1678c39b1da54856e25096b9856cec2b9cc62a2e04e48c6adbd9791d9bfd0a304ad9f5f35067a30830001292b8ec430cea33f36042c7e19ec2699a09cb9e9b6f42ee1204dfaa0285b80479086fb9dad2f269939b3d43c0933186280e0021d3389de88867cbc132bb1b454d15fd79ab3d5892a1de7ca8f01627f7f70c8bb32d1986bcce6be2efc43aeea62bbb11437be5413ebd4664bd084863952bd9e2f863a3f58551f06853b83079385f960c2be34d1d06aecd55225dd72f5bfbeb5547a9d799fc9f5a3c07a8cd998d013ab699967b847c7c641bc7721fbbf09d05091f0e7d4f2d9b94044ae04e3816d3de9f7eec692e1cb211c68da2c20f281fe5bcd0beaf08a60d7a2dad18407ac5ffb08e8681d9e99d235125246524d51c7981205615c8640a133988a66648839cb6056f5a7f4df01903b0d8da9e8393109be35f70ab2f42b5abe4a2fdc0a42bb473cb641b54e4a0cc5e4b84db273c2591a4a1a97a6dd4cf2a19c61b50bb488964819617c58667d02d54e5aaa88b08aa93705f1239986d9d19378d824e65d65a95c38014c3994d7cdebb5f1101e615e9ce7fb1ea6e6903d2eb72bc53d031f962436c59d3e6457fd1a7cb420cfc38ee11d07e6e714e6a3573226910b2214f605fc8b5341425a16023a17416bade48e69512b30af0714c736f0f37f757d271976bb4e877933b1a120b339ced273434234c30d6e5b4d71c6ba74dfd8b3a2e297550b282e31472164981df0c5399235f734cbe04b926de2323f52e02de341667839a62d64fd2bbf3082cb1e80d6d4bfd1b5d975ceb3c015e975c3104c7d0afbad4d65136ee721fb49fc6a2f5d77dac6fdd56b7e6667a75cde736dd647b4bcd75d7127f40d9175c207be67d6562d0b88a5564ca8fc28f217d63670e06d96c206554853bd3cc50de4564aed03a3afce91d2265dc269d37a768c040c4bf6eca7b1185079031eee31d00ef9d2c06dd10af5395c9395c6c25fb00af5ea8661664b23835ff728a7e655898a65da912013e98b9d84bcc83fa949da7cd2c0065c86ac7da89591f9194bffbe2d00fe4bdef5a7533693fd258931fa7648ac4ea0dae94c2ec4df12d25e3d4f339f2fdd12c7ad92c656001630fc02026884696b61b3319ad3527ea745211035cce4670ca597649d8bc7951cfea40383537dd2ec41c569fd0f17892f9bc9e770e727f66a119e169a57204f6daaa715162e21d60e81d0365b59a09504d594b3a37eefd9dde815e48a3fec3a229ec8ee838176c4d043711f7d0534d9def975e49b4058f8e095e09e52547a0197d79c093288416e5bb63a67476e4e0c8d7367f4832fda7a1f84e96e7437e92972841fb4db5d727ee5c9dddb9e9cf95bdc5ce79476fcbda89b247775807303abfd7911f2046f5ab08bab2f45eeeb5da0ba0e7acdee683fb0088"
	katSIGHex = "6326d4ac7e9ebaee79b444fbb19b55ab219fe2bddb7f3e77823c6bac3815796409ec143cd6b6916f8baaf0833f4ca30f214e919003ac95b124b00bbffd87f96e2b49f7d81a740526e2a07d30f883b7c44d7105524b06f5c07c442a965065b1bbba24b5c98f877a4b8a45536267508e5b239868779af14765da4c525e47cf86d3012c4ccb305bfd16244b65f93356a71b8c61778f0a6b87d53fe33aeac1677e15ef33738cb08290e4b4883b4e6ce30e06e6a2588dead8ed93dd45f0ba31a6241979dc3a7f9c317da89efc25f20245b09468f09eff3543163a5918206dc3fc9e23c34a55d1839d04d229bddd21c0ccb1df9183bf11a1a6733481041f0145f764ea1e867c5350331568acfdd6e525e502a177c0d8bed6dbcf649e7b4ed1fe5ae3a6eed89320c3b3349c09ead45d238ff1786c1da139408abd55c3f8a9d2bdc52d65b942b1fde945084394f0ec1525704503183f6f05d84796c1778c3b209a4eca2f170028f043358da12582a4d3f737fcff38f9b4a75b5f7491270ffb3fb93bf475e4d55ee8842b0f64a765e21f62549cf2aaedd759eb60b60fb4c3a043a2261d0a3d887aa2ce4b3d5df3031f1db0f1bc6cab42bc81e075fd60070085ce8089f2f6ab742f91ab5190f5a7f93ad02e7f215f345a06660a3ab635dfd94a3c62fb232c0033f57ab6746f39cb977eee269aa1a025fa615f52ec14eb52a9869963b95323a02d8654e74c69c02d4d6a35d97e44cb6e1028aeccc49ddc2f33cebb46ee030ab6dbfc8e3d00cdf68560aed44a1e8a98afcc55efd54bbc9d51da652e651fa543ab1fd74543115622f0b9ba66fa9fbb3c558e11adfee698176325cef2544ea136a26d7dcc22fcb4da84bf2fc318f90c85bbfdc548f1568fa2e4be3e27bf487558b6c059000199d4d574a3a6740850db687916b609769702a418f9446192f3b1c982ed0feabe13de5c3c7dbe94593e905e496ca99f465d899e809bf4fdafbadbd4dacb62f5c414ac3348e75cbbe8820f188a958af5e7eadac14ccb653d300902a202c98152f9ea257b4a82543b4a251e69be2464b845bd507546129553401fe623f36519b6ce47baebab9e4aa969781c70353620082611e5141e81f1c0f22633fa0e206ad0ca021860a03aac0508ab1151d511575dfdfdf690cf243540344b2f65bb2c4fc3b9a17c3a71b88c832c31f1fe3d5f708e36a743baa5863188327eca0abe7d7fd54f35ff342a3e4a830f415d2981caa38cb73716450303b3de1d803ae0275af69b46331f421936cc7a827c66cd35396dbdaa83faa3ba17db47ab577b9e6fb8cdc4f5307f0186136fd955009b54d9fc240bb15357f6ffe29c2c27b35803bcdaf0a51b72bca04f6d437cc15e4408f425015e27f7ca01c771c8cd47780be3aaf77b0736cf438679e1599026298ac48c3f94b825ebfc8d76c63d44247a01accbedeae69de1a6982a7cdc596f2697b20f6340bf2af90f54b67c559d6d0895af9db2d6c1759750a26632a3310ea3b1896036a5b795d8974c6976c27e0f5c8e43c1129c3655a8dd67d411fffa58cb4ee935aa200c6f783c728655598997f7d6936c12495fbb5d9d92f6628260c37edf1ce7f98874dfa05a3d96631e671454a8afc573b4fe5d33434f5e31e1d51671839f94b0ba89c69705887fc6a6a025dc536e9598fa5175195252ab9d3c1b91e666d7ab284c5dcf81b81e091b489a3cb97eacd2c358766da45a59729c69ce441ae80da9189713d3a33979e0ffe3075bcaf7ab8b03a174e4f542f1503228c3f847e63f0f389c9225ca556c6f81dc17ecd4b3fa0be24da2c2ce52a5be491b1f8251d103b0849f7dda33ef0cdcf3877ecd135a66175597aa29c709a88bed029b95effa97b14b7fad78d7cce6ddeae7a770f08c2d9718ec534ee0945789927bc76b7997471b86e5d65387c12b6731c13042c988cb14a2cd88bdbf074a2b48b5f770ef8acc9f9229bd3b35e00289c64c48c516a45354469bb23a33abb87ed0e8e2d761adcb2bba2d9deb64134803833b5cf15bbd980dc0d322b34ca4f9ebefab7340a436424bdcf2e6a1b7bf0b03aace6f0a6154f709170771fe021c2be11093011298d669054da0a84e9016d6ee3dc215960544b08706f77675e0d51eab0b878796f561c828be75ca67a06d9808b954be83865ea1b7ee141863ed6752efff60de5abf612e577e131ef44c25d601f589e22445ece07a133fb2409aaeff49c074548a805b3533b09959253e441517a9be1ff3d00f75e870858c97baec68a67ca3ceeeda6a9471875244b104e1a0a2292cda684681a0cd5140678e46fe731eaf0f4f1cb2e53ff5ecf9bd51eb3a747bfcc05d7ff528faae4bb6c05c4511eedaf7efd1ef1dfefb94ea466b83ef2467c9e5bd451905eca62e4cdc14066f432674cd8d224b1f6fa6ad2ea5b4268339118ad5b5acb0b28bbd9a7f71f1df4365e6d4a763b8419fddf4d9c536a67051eab385f43f346f01b1e4f151b43177f9e8f91046627aef81d2303c0ff9935a834f6f0a829eb166f3b5ef396270b4b03f0a402c2668fb60d23e8d004f8c3d2500239c13b4a0d6a8a6fb3939395e8ed67ca241f1a13d3e952d302e31264adab8174f3f4182a61b147804a4037143c6bdf98da8100d9659a0fe6d0115b1ba4422c5319854eb8414949d0d365a45f1b5b99bac4c0c6ceec062b98511be7aeb4683772efc96f3f03c309278b3b100af3946a030b8ee50c192c6495dce88d060275f9dca6bbf5856f796c62566b2af618809c8689aa8123c0ccc637d2fc7b354504e3239adff3c1b3c2f3f7280eb76fc3c585670085c8a1273fc4c79cc72c4341e95af1cc170539c952800690f5588af90387921cd8a1e545b01c44a9766d8413a86257515211eb8b977ddd3987ae9b852aa658b087485f724f9e81bd267a07644a8dd85869b3ef7bab554a17a58441a854847e6cbeec0abe327484690e7a24c02baa5d9d5102008b4041c557f747821ca3dab02964e712f1f859532a03a6055671a226368a082b06e34f165717798814acc988a5ec58f589081a11561f0c2eba0bedc89bf71552890a26e84af3e45d39b0dc8e6df66aa37565c090347126f524424fd64de537320764557849a3f4b7dfe0ca1a8fd84baaec499bf66cd684f69577aac9f7818f3a4431d6f3619fef3adf9c55c7c8b79e2c0b5caf7e11c9c62acf1ecf390b269a7f503082032d74d2e61f6214ebae8bfb458d71b987d6128062164ad22ec80b6a6e396b4735a60c438dd11285ebee04fd753c0ce4e25dd1a8783bc11ecc5eb80ce15e3bc4cdbbf010d141930446b90bad1d8e30e4144459a9dacb2cc04292a2e3a405660aeb7ccdde8fcfd06112531365c7291999ca9b3b5bec8e6f1f6ff000000000000000000000000000000000000000000000000000c152437"
	katMSGHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestP3Q_KAT_Accept is the positive KAT: the frozen ML-DSA-44 vector
// MUST verify true through both the on-chain precompile path and the
// standalone Verify entry point.
func TestP3Q_KAT_Accept(t *testing.T) {
	pk := mustHex(t, katPKHex)
	sig := mustHex(t, katSIGHex)
	msg := mustHex(t, katMSGHex)
	require.Len(t, pk, MLDSA44PublicKeySize)
	require.Len(t, sig, MLDSA44SignatureSize)
	require.Len(t, msg, MessageHashSize)

	// Standalone entry point.
	require.NoError(t, Verify(ModeMLDSA44, pk, sig, msg),
		"frozen KAT vector must verify via standalone Verify")

	// On-chain precompile path.
	input := EncodeInput(ModeMLDSA44, sig, pk, msg)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiTrueClone(), out, "frozen KAT vector must verify true on-chain")
}

// TestP3Q_KAT_TamperSig is the negative KAT: flipping a single bit
// anywhere in the frozen signature MUST cause rejection. We sweep several
// byte positions (challenge, z, and hint regions) to exercise the
// FIPS 204 decode + equality checks rather than one lucky offset.
func TestP3Q_KAT_TamperSig(t *testing.T) {
	pk := mustHex(t, katPKHex)
	msg := mustHex(t, katMSGHex)
	for _, pos := range []int{0, 1, 32, 100, 1200, MLDSA44SignatureSize - 1} {
		sig := mustHex(t, katSIGHex)
		sig[pos] ^= 0x01
		input := EncodeInput(ModeMLDSA44, sig, pk, msg)
		gas := P3QVerifyPrecompile.RequiredGas(input) * 2
		out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
		require.NoError(t, err, "pos=%d", pos)
		require.Equal(t, abiFalse(), out, "single-bit sig tamper at pos=%d must reject", pos)
	}
}

// TestP3Q_KAT_TamperMsg is the negative KAT for the message binding: the
// frozen signature MUST NOT verify against any message other than the one
// it was minted over.
func TestP3Q_KAT_TamperMsg(t *testing.T) {
	pk := mustHex(t, katPKHex)
	sig := mustHex(t, katSIGHex)
	msg := mustHex(t, katMSGHex)
	msg[0] ^= 0x01
	input := EncodeInput(ModeMLDSA44, sig, pk, msg)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "KAT sig must not verify against a mutated message")
}

// TestP3Q_KAT_WrongLength is the negative KAT for the exact-size wire
// check: a signature that is one byte short of MLDSA44SignatureSize MUST
// be rejected before ever reaching the FIPS 204 verifier.
func TestP3Q_KAT_WrongLength(t *testing.T) {
	pk := mustHex(t, katPKHex)
	msg := mustHex(t, katMSGHex)
	short := mustHex(t, katSIGHex)[:MLDSA44SignatureSize-1] // 2419 bytes
	input := EncodeInput(ModeMLDSA44, short, pk, msg)
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "wrong-length signature must be rejected")

	// Standalone Verify surfaces the size mismatch as a typed error.
	require.Error(t, Verify(ModeMLDSA44, pk, short, msg))
}

// TestP3Q_KAT_WrongMode confirms the frozen ML-DSA-44 vector does NOT
// verify when the wire mode claims ML-DSA-65 (the sizes no longer match,
// so the precompile rejects on the length check).
func TestP3Q_KAT_WrongMode(t *testing.T) {
	pk := mustHex(t, katPKHex)
	sig := mustHex(t, katSIGHex)
	msg := mustHex(t, katMSGHex)
	input := EncodeInput(ModeMLDSA65, sig, pk, msg) // wrong mode byte
	gas := P3QVerifyPrecompile.RequiredGas(input) * 2
	out, _, err := P3QVerifyPrecompile.Run(nil, common.Address{}, ContractP3QVerifyAddress, input, gas, true)
	require.NoError(t, err)
	require.Equal(t, abiFalse(), out, "ML-DSA-44 vector under ML-DSA-65 mode must reject")
}
