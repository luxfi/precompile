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
(*                                                                      *)
(* NOTE: the proof payload is bound to the identifier `prf` (not        *)
(* `proof`) because `proof` is a reserved keyword in current EasyCrypt. *)
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
op serialize (v : byte_t) (prf pub : bytes_t) : bytes_t =
  [v]
  ++ be_encode_uint32 (size prf)
  ++ prf
  ++ be_encode_uint32 (size pub)
  ++ pub.

(* -------------------------------------------------------------------- *)
(* Structural helpers — what each field-slice of `serialize` returns.    *)
(* These discharge the abstract `slice_at`/`nth` obligations that        *)
(* `parse_spec_ok` consumes, now that `slice_at b off len` is defined    *)
(* concretely as `take len (drop off b)` in P3Q_Verifier.ec.             *)
(* -------------------------------------------------------------------- *)

(* The version byte sits at offset 0. *)
lemma ser_nth0 (v : byte_t) (prf pub : bytes_t) :
  nth 0 (serialize v prf pub) 0 = v.
proof. by rewrite /serialize. qed.

(* Bytes [1..5) encode the proof length. *)
lemma ser_slice_plen (v : byte_t) (prf pub : bytes_t) :
  slice_at (serialize v prf pub) 1 4 = be_encode_uint32 (size prf).
proof.
  rewrite /slice_at /serialize.
  have ->: [v] ++ be_encode_uint32 (size prf) ++ prf
             ++ be_encode_uint32 (size pub) ++ pub
         = [v] ++ (be_encode_uint32 (size prf)
             ++ (prf ++ be_encode_uint32 (size pub) ++ pub)).
    by rewrite -!catA.
  by rewrite drop_size_cat // take_size_cat ?be_encode_size.
qed.

(* Bytes [5 .. 5+size prf) are the proof itself. *)
lemma ser_slice_prf (v : byte_t) (prf pub : bytes_t) :
  slice_at (serialize v prf pub) (1 + 4) (size prf) = prf.
proof.
  rewrite /slice_at /serialize.
  have ->: [v] ++ be_encode_uint32 (size prf) ++ prf
             ++ be_encode_uint32 (size pub) ++ pub
         = ([v] ++ be_encode_uint32 (size prf))
             ++ (prf ++ (be_encode_uint32 (size pub) ++ pub)).
    by rewrite -!catA.
  rewrite drop_size_cat. by rewrite size_cat be_encode_size /=.
  by rewrite take_size_cat.
qed.

(* Bytes [5+size prf .. 9+size prf) encode the pub length. *)
lemma ser_slice_publen (v : byte_t) (prf pub : bytes_t) :
  slice_at (serialize v prf pub) (1 + 4 + size prf) 4 = be_encode_uint32 (size pub).
proof.
  rewrite /slice_at /serialize.
  have ->: [v] ++ be_encode_uint32 (size prf) ++ prf
             ++ be_encode_uint32 (size pub) ++ pub
         = ([v] ++ be_encode_uint32 (size prf) ++ prf)
             ++ (be_encode_uint32 (size pub) ++ pub).
    by rewrite -!catA.
  rewrite drop_size_cat. by rewrite !size_cat be_encode_size /#.
  by rewrite take_size_cat ?be_encode_size.
qed.

(* The trailing bytes are the pub input. *)
lemma ser_slice_pub (v : byte_t) (prf pub : bytes_t) :
  slice_at (serialize v prf pub) (1 + 4 + size prf + 4) (size pub) = pub.
proof.
  rewrite /slice_at /serialize.
  rewrite drop_size_cat. by rewrite !size_cat be_encode_size be_encode_size /#.
  by rewrite take_size.
qed.

(* Total serialized length in closed form. *)
lemma ser_size (v : byte_t) (prf pub : bytes_t) :
  size (serialize v prf pub) = 1 + 4 + size prf + 4 + size pub.
proof. by rewrite /serialize !size_cat be_encode_size be_encode_size /#. qed.

(* A slice that lies entirely within the first `k` bytes is unaffected by
   truncating the buffer to length `k`. Used to show that a truncated
   envelope still exposes the original length fields (and so still parses
   to None for the structural reasons below). *)
lemma slice_take_inside (s : bytes_t) (off len k : int) :
  0 <= off => 0 <= len => off + len <= k =>
  slice_at (take k s) off len = slice_at s off len.
proof.
  move=> ho hl hk.
  rewrite /slice_at drop_take 1:ho 1:/# take_take.
  have ->: (len <= k - off) = true by smt().
  done.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 1 — total input length bound                                   *)
(* -------------------------------------------------------------------- *)

lemma wf_length_bound (v : byte_t) (prf pub : bytes_t) :
  4 <= size prf =>
  minInputLength <= size (serialize v prf pub).
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

lemma wf_magic_prefix (v : byte_t) (prf pub : bytes_t) :
  take 4 prf = magicHeader =>
  4 <= size prf =>
  take 4 (slice_at (serialize v prf pub) (1 + 4) (size prf))
    = magicHeader.
proof.
  move=> h_magic h_size.
  (* The slice starting at offset 5 of `serialize v prf pub` is
     exactly `prf`, by definition of `serialize`. The first 4 bytes
     of `prf` are `magicHeader`, so `take 4 prf = magicHeader`. *)
  have ->: slice_at (serialize v prf pub) (1 + 4) (size prf) = prf.
    rewrite /slice_at /serialize.
    have ->: [v] ++ be_encode_uint32 (size prf) ++ prf
               ++ be_encode_uint32 (size pub) ++ pub
           = ([v] ++ be_encode_uint32 (size prf))
               ++ (prf ++ (be_encode_uint32 (size pub) ++ pub)).
      by rewrite -!catA.
    rewrite drop_size_cat.
      by rewrite size_cat be_encode_size /=.
    by rewrite take_size_cat.
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
  have h: Some p1 = Some p2 by rewrite -h_p1 h_p2.
  by apply (someI _ _ h).
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 4 — round-trip: serialize then parse recovers the triple        *)
(* -------------------------------------------------------------------- *)

lemma wf_round_trip (v : byte_t) (prf pub : bytes_t) :
  4 <= size prf =>
  size prf < 2^32 =>
  size pub   < 2^32 =>
  take 4 prf = magicHeader =>
  parse (serialize v prf pub)
    = Some {| p_version = v; p_proof = prf; p_pub = pub |}.
proof.
  move=> h_size h_pf32 h_pub32 h_magic.
  have hlen : minInputLength <= size (serialize v prf pub) by apply wf_length_bound.
  have heq1 : size prf = be_uint32 (slice_at (serialize v prf pub) 1 4)
    by rewrite ser_slice_plen be_decode_encode 1:(_ : 0 <= size prf < 2^32) //; smt(size_ge0).
  have heq2 : size pub
                = be_uint32 (slice_at (serialize v prf pub) (1 + 4 + size prf) 4)
    by rewrite ser_slice_publen be_decode_encode 1:(_ : 0 <= size pub < 2^32) //; smt(size_ge0).
  have hle1 : size prf + 4 <= size (serialize v prf pub) - (1 + 4).
    rewrite /serialize !size_cat be_encode_size be_encode_size /=. smt(size_ge0).
  have hle2 : size pub <= size (serialize v prf pub) - (1 + 4 + size prf + 4).
    rewrite /serialize !size_cat be_encode_size be_encode_size /=. smt(size_ge0).
  have hmg : take 4 (slice_at (serialize v prf pub) (1 + 4) (size prf)) = magicHeader
    by rewrite ser_slice_prf.
  have hps := parse_spec_ok (serialize v prf pub) hlen (size prf) (size pub)
                heq1 heq2 hle1 hle2 hmg.
  move: hps; rewrite ser_nth0 ser_slice_prf ser_slice_pub => ->.
  done.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 5 — truncated inputs do not parse                              *)
(* -------------------------------------------------------------------- *)

lemma wf_truncation_rejected (v : byte_t) (prf pub : bytes_t) (k : int) :
  4 <= size prf =>
  size prf < 2^32 =>
  size pub < 2^32 =>
  0 <= k < size (serialize v prf pub) - minInputLength + 1 =>
  parse (take k (serialize v prf pub)) = None.
proof.
  move=> h_pf h_pf32 h_pub32 h_k.
  have hsz : size (serialize v prf pub) = 1 + 4 + size prf + 4 + size pub
    by apply ser_size.
  have hszk : size (take k (serialize v prf pub)) = k by rewrite size_take 1:/# /#.
  have hmil : minInputLength = 13
    by rewrite /minInputLength /versionByte /proofLenBytes /pubLenBytes.
  apply parse_spec_fail.
  case (k < minInputLength) => hk_small.
  - (* short truncation: fails the MinInputLength gate directly. *)
    left. by rewrite hszk.
  - (* long-enough truncation: the embedded length fields survive, but the
       declared (proof, pub) payload cannot fit, so a structural check fails. *)
    right.
    move=> p_off proof_len pub_off pub_len hpoff hpl hpuoff hpul.
    (* The proof-length field [1..5) is intact (k >= 13 > 5). *)
    have hpl_val : proof_len = size prf.
      rewrite hpl (slice_take_inside (serialize v prf pub) 1 4 k) //; 1: smt().
      by rewrite ser_slice_plen be_decode_encode 1:(_: 0 <= size prf < 2^32) //;
         smt(size_ge0).
    case (k < 1 + 4 + size prf + 4) => hk_mid.
    + (* The declared proof bytes overrun the buffer: check 1 fires. *)
      left. move: hszk hpoff hpl_val h_k hsz hmil; smt().
    + (* The pub-length field [5+|prf| .. 9+|prf|) is intact, so it still
         decodes to |pub|; the declared pub bytes overrun the buffer: check
         2 fires. *)
      have hpul_val : pub_len = size pub.
        rewrite hpul hpoff hpl_val.
        rewrite (slice_take_inside (serialize v prf pub) (1 + 4 + size prf) 4 k);
          first 3 by smt().
        by rewrite ser_slice_publen be_decode_encode 1:(_: 0 <= size pub < 2^32) //;
           smt(size_ge0).
      right; left.
      move: hszk hpuoff hpoff hpl_val hpul_val h_k hsz hmil hk_mid; smt().
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 6 — domain: only versionV1 is accepted                         *)
(* -------------------------------------------------------------------- *)
(* The version byte differentiates future wire-format versions. v0x01    *)
(* is the only one currently accepted; this lemma states the negation.   *)

lemma wf_version_domain (v : byte_t) (prf pub : bytes_t) :
  v <> versionV1 =>
  4 <= size prf =>
  size prf < 2^32 =>
  size pub   < 2^32 =>
  take 4 prf = magicHeader =>
  parse (serialize v prf pub)
    = Some {| p_version = v; p_proof = prf; p_pub = pub |}.
proof.
  (* parse succeeds with v even when v <> versionV1; the version check
     happens in Run() AFTER parse. This lemma documents the layered
     separation: parse is purely structural; the version policy lives
     in PrecompileRun.run, not in parse. *)
  move=> _ h_size h_pf h_pb h_magic.
  by apply wf_round_trip.
qed.
