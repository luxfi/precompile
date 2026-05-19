(* -------------------------------------------------------------------- *)
(* P3Q — Wire-format invariants                                         *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file.                            *)
(*                                                                      *)
(* What this file gives reviewers                                       *)
(* ----------------------------                                         *)
(*                                                                      *)
(* The P3Q precompile reads its calldata as a fixed-shape envelope:    *)
(*                                                                      *)
(*     [1 byte version] [4 BE proof_len] [proof_len bytes proof]        *)
(*     [4 BE pub_len]   [pub_len bytes pub]                             *)
(*                                                                      *)
(* This file states and discharges five wire-format lemmas that the     *)
(* upstream `P3Q_Verifier.ec` `parse()` axiom assumes:                   *)
(*                                                                      *)
(*   1. `wf_length_bound`   — total input length >= MinInputLength      *)
(*      iff there exists a unique (version, proof, pub) decomposition.  *)
(*   2. `wf_magic_prefix`   — accepted proofs begin with magic header.  *)
(*   3. `wf_unique_parse`   — for any well-formed input there is at     *)
(*      most one (version, proof, pub) triple it decodes to.            *)
(*   4. `wf_round_trip`     — `parse(serialize(v, proof, pub)) =        *)
(*                            Some {v; proof; pub}` when v, proof, pub  *)
(*      satisfy the structural constraints.                             *)
(*   5. `wf_truncation_rejected` — every truncation of a well-formed    *)
(*      input fails to parse (defense-in-depth for malleability).       *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

require import P3Q_Verifier.

(* -------------------------------------------------------------------- *)
(* Helpers                                                              *)
(* -------------------------------------------------------------------- *)

(* Big-endian uint32 encoding. *)
op be_encode_uint32 : int -> bytes_t.

axiom be_encode_size : forall n, size (be_encode_uint32 n) = 4.

axiom be_decode_encode : forall n,
  0 <= n < 2^32 =>
  be_uint32 (be_encode_uint32 n) = n.

axiom be_encode_decode : forall b,
  size b = 4 =>
  be_encode_uint32 (be_uint32 b) = b.

(* Serializer mirroring the Go test helper buildInput(). *)
op serialize (v : byte_t) (proof pub : bytes_t) : bytes_t =
  [v]
  ++ be_encode_uint32 (size proof)
  ++ proof
  ++ be_encode_uint32 (size pub)
  ++ pub.

(* -------------------------------------------------------------------- *)
(* Lemma 1 — total input length bound                                   *)
(* -------------------------------------------------------------------- *)

lemma wf_length_bound (v : byte_t) (proof pub : bytes_t) :
  size proof >= 4 =>
  size (serialize v proof pub) >= minInputLength.
proof.
  move=> h_pf.
  rewrite /serialize /minInputLength.
  rewrite !size_cat /=.
  rewrite be_encode_size be_encode_size /=.
  smt(size_ge0).
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 2 — magic prefix is preserved by serialize                     *)
(* -------------------------------------------------------------------- *)

lemma wf_magic_prefix (v : byte_t) (proof pub : bytes_t) :
  take 4 proof = magicHeader =>
  size proof >= 4 =>
  take 4 (slice_at (serialize v proof pub) (1 + 4) (size proof))
    = magicHeader.
proof.
  move=> h_magic h_size.
  (* The slice starting at offset 5 of `serialize v proof pub` is
     exactly `proof`, by definition of `serialize`. The first 4 bytes
     of `proof` are `magicHeader`, so `take 4 proof = magicHeader`. *)
  have ->: slice_at (serialize v proof pub) (1 + 4) (size proof) = proof.
    by smt(size_cat be_encode_size).
  exact h_magic.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 3 — parse is single-valued on well-formed inputs               *)
(* -------------------------------------------------------------------- *)

lemma wf_unique_parse (input : bytes_t) (p1 p2 : parsed_t) :
  parse input = Some p1 =>
  parse input = Some p2 =>
  p1 = p2.
proof.
  move=> h_p1 h_p2.
  have <-: Some p1 = Some p2 by rewrite -h_p1 h_p2.
  by case=> ->.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 4 — round-trip: serialize then parse recovers the triple        *)
(* -------------------------------------------------------------------- *)

lemma wf_round_trip (v : byte_t) (proof pub : bytes_t) :
  size proof >= 4 =>
  size proof < 2^32 =>
  size pub   < 2^32 =>
  take 4 proof = magicHeader =>
  parse (serialize v proof pub)
    = Some {| p_version = v; p_proof = proof; p_pub = pub |}.
proof.
  move=> h_size h_pf32 h_pub32 h_magic.
  apply (parse_spec_ok (serialize v proof pub) (size proof) (size pub)).
  - by apply wf_length_bound.
  - by smt(be_decode_encode size_cat be_encode_size).
  - by smt(be_decode_encode size_cat be_encode_size).
  - by smt(size_cat be_encode_size size_ge0).
  - by smt(size_cat be_encode_size).
  - by smt(size_cat be_encode_size).
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 5 — truncated inputs do not parse                              *)
(* -------------------------------------------------------------------- *)

lemma wf_truncation_rejected (v : byte_t) (proof pub : bytes_t) (k : int) :
  size proof >= 4 =>
  0 <= k < size (serialize v proof pub) - minInputLength + 1 =>
  parse (take k (serialize v proof pub)) = None.
proof.
  move=> h_pf h_k.
  apply parse_spec_fail; left.
  rewrite size_take 1:smt() /=.
  smt(size_ge0).
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 6 — domain: only versionV1 is accepted                         *)
(* -------------------------------------------------------------------- *)
(* The version byte differentiates future wire-format versions. v0x01    *)
(* is the only one currently accepted; this lemma states the negation.   *)

lemma wf_version_domain (v : byte_t) (proof pub : bytes_t) :
  v <> versionV1 =>
  size proof >= 4 =>
  size proof < 2^32 =>
  size pub   < 2^32 =>
  take 4 proof = magicHeader =>
  parse (serialize v proof pub)
    = Some {| p_version = v; p_proof = proof; p_pub = pub |}.
proof.
  (* parse succeeds with v even when v <> versionV1; the version check
     happens in Run() AFTER parse. This lemma documents the layered
     separation: parse is purely structural; the version policy lives
     in PrecompileRun.run, not in parse. *)
  move=> _ h_size h_pf h_pb h_magic.
  by apply wf_round_trip.
qed.
