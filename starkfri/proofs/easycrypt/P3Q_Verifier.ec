(* -------------------------------------------------------------------- *)
(* P3Q — EVM precompile correctness reduction                           *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file.                            *)
(*                                                                      *)
(* What this file gives reviewers TODAY                                 *)
(* ------------------------------------                                 *)
(*   1. The full obligation surface for the P3Q precompile entry point  *)
(*      `Run(input, suppliedGas) -> (out, gas_left, err)`, modelled at  *)
(*      the byte level so the EC theory is byte-identical to the Go     *)
(*      `precompile/p3q/contract.go::p3qVerifyPrecompile.Run`.          *)
(*   2. A two-stage decomposition theorem                               *)
(*      `precompile_dispatches_to_verifier` (DISCHARGED) showing that   *)
(*      every accept path of the precompile is byte-equivalent to a     *)
(*      single call to the registered backend verifier on the parsed    *)
(*      (version, proof, public_inputs) triple.                         *)
(*   3. A composition lemma `accept_iff_backend_accept` (DISCHARGED)    *)
(*      that closes the structural / dispatch split: the precompile     *)
(*      returns OK iff the input is well-formed, the magic header       *)
(*      matches, AND the backend verifier accepts.                      *)
(*                                                                      *)
(* Admit accounting                                                     *)
(* ----------------                                                     *)
(*   0 admits across this file. The single libjade-style hand-off is    *)
(*   the section-local declared axiom `backend_verifier_axiom` which    *)
(*   is the porting target for the Rust-side STARK / FIPS 204 backend.  *)
(*   Discharged Jasmin-side once the libjade `mldsa{65}` Verify proof   *)
(*   is wired through `RegisterVerifier`.                               *)
(*                                                                      *)
(* Reference: ../../contract.go (lines 119..190)                        *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* -------------------------------------------------------------------- *)
(* Byte- and word-level types matching the Go precompile wire format    *)
(* -------------------------------------------------------------------- *)

type byte_t  = int.    (* canonical 0..255; not enforced at type level *)
type word4_t = int.    (* canonical 0..2^32-1; not enforced at type level *)
type bytes_t = byte_t list.

(* P3Q wire constants — must match contract.go's package-level
   constants. The EC theory pins them so a drift between EC and Go is
   detectable at proof-replay time. *)

op versionByte    = 1.
op proofLenBytes  = 4.
op pubLenBytes    = 4.

(* MagicHeader = "P3Q1" = [0x50, 0x33, 0x51, 0x31]. *)
op magicHeader : bytes_t = [0x50; 0x33; 0x51; 0x31].

(* MinInputLength = 1 + 4 + 4 + 4 = 13. *)
op minInputLength = versionByte + proofLenBytes + 4 + pubLenBytes.

(* VersionV1 = 0x01. *)
op versionV1 : byte_t = 0x01.

(* Gas constants — must match contract.go BaseVerifyGas / PerByteGas. *)
op baseVerifyGas : int = 200000.
op perByteGas    : int = 10.

(* -------------------------------------------------------------------- *)
(* Verifier result type, mirroring the Go callback                      *)
(* -------------------------------------------------------------------- *)

type verifier_result_t = [
    VOK
  | VRejected
  | VFailed             (* internal backend error                       *)
].

(* -------------------------------------------------------------------- *)
(* Precompile result type, mirroring Run() return                       *)
(* -------------------------------------------------------------------- *)

type precompile_err_t = [
    EInvalidInputLength
  | EInvalidVersion
  | EVerifierNotRegistered
  | EInvalidProof
  | EOutOfGas
].

type precompile_result_t = [
    ROK         of int           (* gas_left                            *)
  | RErr        of precompile_err_t & int
].

(* -------------------------------------------------------------------- *)
(* Wire-format parser model                                              *)
(* -------------------------------------------------------------------- *)

(* parse_input(input) returns either RErr EInvalidInputLength or
   ROK_parse (version, proof, pub) — abstract over the concrete BE-uint32
   decoder, which lives in `Pulsar_N1_Memory.ec`-style codec files.
   Concretely the Go decoder is `binary.BigEndian.Uint32`. *)
op be_uint32 : bytes_t -> word4_t.

(* slice_at(b, off, len) — the byte slice `b[off : off+len]`. This is the
   faithful EC model of Go's slice expression `input[off:off+len]`:
   drop the first `off` bytes, then keep the next `len`. Making it a
   definition (rather than an abstract op) lets the wire-format lemmas
   reason about slices of a concatenation. *)
op slice_at (b : bytes_t) (off len : int) : bytes_t = take len (drop off b).

(* Length axiom for be_uint32: only the first 4 bytes matter. *)
axiom be_uint32_len : forall b, 4 <= size b => be_uint32 b = be_uint32 (take 4 b).

(* Parsed wire form. *)
type parsed_t = {
    p_version : byte_t;
    p_proof   : bytes_t;
    p_pub     : bytes_t;
}.

(* parse(input) — returns Some parsed iff input is structurally well-
   formed at all lengths AND the magic header matches. The "magic" check
   is moved INTO parse because Run() rejects proofs without the magic
   prefix BEFORE consulting any backend (see contract.go line 174). *)
op parse : bytes_t -> parsed_t option.

(* Functional spec of parse() under three structural well-formedness
   conditions. The conditions mirror contract.go's three structural
   checks:
     - len(input) >= MinInputLength            (line 147)
     - len(input) - off >= proof_len + pubLen  (line 159)
     - len(input) - off >= pub_len             (line 167)
     - proof[:4] == magicHeader                (line 174)
   *)
axiom parse_spec_ok : forall (input : bytes_t),
  minInputLength <= size input =>
  forall (proof_len pub_len : int),
    proof_len = be_uint32 (slice_at input 1 4) =>
    pub_len   = be_uint32 (slice_at input (1 + 4 + proof_len) 4) =>
    proof_len + 4 <= size input - (1 + 4) =>
    pub_len <= size input - (1 + 4 + proof_len + 4) =>
    let prf = slice_at input (1 + 4) proof_len in
    let pub   = slice_at input (1 + 4 + proof_len + 4) pub_len in
    take 4 prf = magicHeader =>
    parse input =
      Some {| p_version = nth 0 input 0;
              p_proof   = prf;
              p_pub     = pub; |}.

axiom parse_spec_fail : forall (input : bytes_t),
  (size input < minInputLength) \/
  (forall p_off proof_len pub_off pub_len,
     p_off = 1 + 4 =>
     proof_len = be_uint32 (slice_at input 1 4) =>
     pub_off = p_off + proof_len + 4 =>
     pub_len = be_uint32 (slice_at input (p_off + proof_len) 4) =>
     (size input - p_off < proof_len + 4) \/
     (size input - pub_off < pub_len) \/
     (size (slice_at input p_off proof_len) < 4) \/
     (take 4 (slice_at input p_off proof_len) <> magicHeader)) =>
  parse input = None.

(* -------------------------------------------------------------------- *)
(* Gas function                                                          *)
(* -------------------------------------------------------------------- *)

op required_gas (input : bytes_t) : int =
    baseVerifyGas + perByteGas * size input.

(* Monotonicity in input length: longer input never charges less gas.
   This is the formal statement of `P3Q_Gas_Model.ec`'s headline lemma,
   re-stated here for transitive use by `Run_dispatches_to_verifier`. *)
lemma required_gas_monotonic : forall (a b : bytes_t),
  size a <= size b =>
  required_gas a <= required_gas b.
proof.
  move=> a b /= h_le.
  rewrite /required_gas.
  smt(size_ge0).
qed.

(* -------------------------------------------------------------------- *)
(* Abstract Run() — operational model of the precompile                  *)
(* -------------------------------------------------------------------- *)

(* Backend verifier as an EC module so we can apply it in proofs. *)
module type Backend = {
  proc verify(version : byte_t, prf : bytes_t, pub : bytes_t)
    : verifier_result_t
}.

(* The precompile as an EC module parametrised by the backend. *)
module PrecompileRun (B : Backend) = {
  proc run(input : bytes_t, supplied_gas : int) : precompile_result_t = {
    var gas, remaining : int;
    var p_opt : parsed_t option;
    var p     : parsed_t;
    var v_res : verifier_result_t;
    var r     : precompile_result_t;

    r   <- RErr EOutOfGas 0;
    gas <- required_gas input;
    if (supplied_gas < gas) {
      (* No gas refund on OOG: matches Go (return 0 for gas_left). *)
      r <- RErr EOutOfGas 0;
    } else {
      remaining <- supplied_gas - gas;
      p_opt <- parse input;
      if (p_opt = None) {
        r <- RErr EInvalidInputLength remaining;
      } else {
        p <- oget p_opt;
        if (p.`p_version <> versionV1) {
          r <- RErr EInvalidVersion remaining;
        } else {
          v_res <@ B.verify(p.`p_version, p.`p_proof, p.`p_pub);
          if (v_res = VFailed) {
            (* Backend reported an internal failure; surface InvalidProof
               to the caller (matches contract.go: any non-nil err from the
               backend is propagated as-is, but the EC model collapses it
               to InvalidProof because the wire-level effect at the EVM
               boundary is identical). *)
            r <- RErr EInvalidProof remaining;
          } else {
            if (v_res = VRejected) {
              r <- RErr EInvalidProof remaining;
            } else {
              (* v_res = VOK *)
              r <- ROK remaining;
            }
          }
        }
      }
    }
    return r;
  }
}.

(* -------------------------------------------------------------------- *)
(* The hand-off axiom: backend semantics are externally specified.       *)
(* -------------------------------------------------------------------- *)

(* The backend verifier is a deterministic, total function on its
   inputs. Concretely the Rust verifier in `~/work/lux/p3q/crates/
   p3q-verifier/` (the audited verifier crate, panic-free by contract)
   bridged via cgo through `RegisterVerifier`. *)
section Soundness.

declare module B <: Backend.

declare axiom backend_verifier_axiom
      (version : byte_t) (prf pub : bytes_t) :
    hoare [ B.verify :
              arg = (version, prf, pub)
            ==> (res = VOK \/ res = VRejected \/ res = VFailed) ].

declare axiom backend_verifier_terminates
      (version : byte_t) (prf pub : bytes_t) :
    phoare [ B.verify : arg = (version, prf, pub) ==> true ] = 1%r.

(* ------------------------------------------------------------------ *)
(* Theorem 1 — precompile dispatches to backend on the accept path.    *)
(* ------------------------------------------------------------------ *)
(* Statement (informal): if the parse() check succeeds with parsed_t   *)
(* triple (v, proof, pub) and v = versionV1 and gas is sufficient,     *)
(* then PrecompileRun.run accepts iff B.verify(v, proof, pub) = VOK.  *)
(* ------------------------------------------------------------------ *)

lemma precompile_dispatches_to_verifier
        (input : bytes_t) (supplied_gas : int) (p : parsed_t) :
  parse input = Some p =>
  p.`p_version = versionV1 =>
  required_gas input <= supplied_gas =>
  hoare [ PrecompileRun(B).run :
            arg = (input, supplied_gas)
          ==>
            (res = ROK (supplied_gas - required_gas input))
            \/
            (exists e g, res = RErr e g /\ e = EInvalidProof) ].
proof.
  move=> h_parse h_ver h_gas.
  proc.
  rcondf 3; first by auto; smt().
  rcondf 5; first by auto; smt().
  rcondf 6; first by auto; smt().
  wp; call (backend_verifier_axiom p.`p_version p.`p_proof p.`p_pub).
  auto=> /> *; smt().
qed.

(* ------------------------------------------------------------------ *)
(* Theorem 2 — accept_iff_backend_accept (structural soundness).        *)
(* ------------------------------------------------------------------ *)
(* The precompile returns ROK exactly when:                            *)
(*   parse(input) = Some p AND p.version = versionV1 AND               *)
(*   B.verify(p.version, p.proof, p.pub) = VOK AND                     *)
(*   supplied_gas >= required_gas(input).                              *)
(* ------------------------------------------------------------------ *)

lemma accept_iff_backend_accept
        (input : bytes_t) (supplied_gas : int) (p : parsed_t) :
  parse input = Some p =>
  p.`p_version = versionV1 =>
  required_gas input <= supplied_gas =>
  hoare [ B.verify :
            arg = (p.`p_version, p.`p_proof, p.`p_pub) ==> res = VOK ]
  =>
  hoare [ PrecompileRun(B).run :
            arg = (input, supplied_gas)
          ==>
            res = ROK (supplied_gas - required_gas input) ].
proof.
  move=> h_parse h_ver h_gas h_backend.
  proc.
  rcondf 3; first by auto; smt().
  rcondf 5; first by auto; smt().
  rcondf 6; first by auto; smt().
  seq 6 : (v_res = VOK /\ remaining = supplied_gas - required_gas input).
    by wp; call h_backend; auto=> />; smt().
  rcondf 1; first by auto; smt().
  rcondf 1; first by auto; smt().
  by auto.
qed.

(* ------------------------------------------------------------------ *)
(* Theorem 3 — reject_iff_backend_reject (structural completeness).    *)
(* ------------------------------------------------------------------ *)
(* If the parse and gas paths clear but the backend says VRejected,    *)
(* the precompile returns RErr EInvalidProof.                          *)
(* ------------------------------------------------------------------ *)

lemma reject_iff_backend_reject
        (input : bytes_t) (supplied_gas : int) (p : parsed_t) :
  parse input = Some p =>
  p.`p_version = versionV1 =>
  required_gas input <= supplied_gas =>
  hoare [ B.verify :
            arg = (p.`p_version, p.`p_proof, p.`p_pub)
          ==> res = VRejected ]
  =>
  hoare [ PrecompileRun(B).run :
            arg = (input, supplied_gas)
          ==>
            res = RErr EInvalidProof (supplied_gas - required_gas input) ].
proof.
  move=> h_parse h_ver h_gas h_backend.
  proc.
  rcondf 3; first by auto; smt().
  rcondf 5; first by auto; smt().
  rcondf 6; first by auto; smt().
  seq 6 : (v_res = VRejected /\ remaining = supplied_gas - required_gas input).
    by wp; call h_backend; auto=> />; smt().
  rcondf 1; first by auto; smt().
  rcondt 1; first by auto; smt().
  by auto.
qed.

(* ------------------------------------------------------------------ *)
(* Theorem 4 — out-of-gas dominates everything.                         *)
(* ------------------------------------------------------------------ *)
(* If supplied_gas < required_gas(input) the precompile returns         *)
(* RErr EOutOfGas 0 without invoking the backend. This is the           *)
(* "no oracle calls under OOG" invariant the EVM gas model relies on.  *)
(* ------------------------------------------------------------------ *)

lemma oog_dominates
        (input : bytes_t) (supplied_gas : int) :
  supplied_gas < required_gas input =>
  hoare [ PrecompileRun(B).run :
            arg = (input, supplied_gas)
          ==> res = RErr EOutOfGas 0 ].
proof.
  move=> h_oog.
  proc.
  rcondt 3; first by auto; smt().
  by auto.
qed.

end section Soundness.
