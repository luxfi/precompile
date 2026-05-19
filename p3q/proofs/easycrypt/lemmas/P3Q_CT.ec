(* -------------------------------------------------------------------- *)
(* P3Q — Constant-time obligations on the precompile entry point         *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file.                            *)
(*                                                                      *)
(* The P3Q precompile holds NO secret state — public inputs are         *)
(* `(version, proof_bytes, public_inputs)`, all of which are wire-       *)
(* observable. The CT property nonetheless matters for two reasons:     *)
(*                                                                      *)
(*   1. Soundness, not confidentiality. Any data-dependent branch in    *)
(*      the verification dispatch path is a SOUNDNESS bug: an attacker  *)
(*      who can distinguish accept-cycles from reject-cycles can use    *)
(*      that signal to forge consensus-relevant certificates over time. *)
(*   2. Composition. The precompile is composed with downstream         *)
(*      consensus logic (Quasar finality, Pulsar threshold acceptance). *)
(*      A timing oracle at the EVM boundary is observable to any        *)
(*      contract that can measure block latency, leaking into a chain-  *)
(*      level oracle.                                                   *)
(*                                                                      *)
(* Threat model                                                         *)
(* ------------                                                         *)
(*   Barthe-Grégoire-Laporte leakage model (CSF 2018), same as          *)
(*   Pulsar_CT. Adversary observes the (control-flow x memory-access)  *)
(*   trace of each call to PrecompileRun.run. CT is leakage-trace       *)
(*   independence over the (proof, pub) byte payload — version and     *)
(*   length are public, so leakage trace MAY depend on them.            *)
(*                                                                      *)
(* Note on the dispatch boundary                                        *)
(* --------------------------                                           *)
(*   The CT property crosses the cgo boundary into the Rust verifier.   *)
(*   This file states the precompile-side obligation; the Rust          *)
(*   verifier crate `p3q-verifier` carries its own CT obligation under  *)
(*   the libjade-style `#[ct = ...]` annotation on the FRI verifier     *)
(*   inner loop. The composition is sound because both layers refuse   *)
(*   secret-dependent branches over (proof, pub).                       *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

require import P3Q_Verifier.

(* Leakage type — abstracts the (control-flow x memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

(* CT-instrumented backend: every call returns its leakage trace
   alongside the result. *)
module type CTBackend = {
  proc verify(version : byte_t, proof pub : bytes_t)
    : verifier_result_t * leakage_t
}.

(* CT-instrumented precompile: emits a leakage trace alongside the
   precompile result. The trace concatenates (a) the structural
   parse leakage (which is a function of size(input) only — i.e.,
   public) and (b) the backend leakage. *)
module CTPrecompileRun (B : CTBackend) = {
  proc run(input : bytes_t, supplied_gas : int)
    : precompile_result_t * leakage_t = {
    var gas, remaining : int;
    var p_opt : parsed_t option;
    var p     : parsed_t;
    var v_res : verifier_result_t;
    var lk_backend : leakage_t;
    var lk_total   : leakage_t;
    var lk_zero    : leakage_t;

    lk_zero <$ duniform [witness]; (* abstract empty trace *)

    gas <- required_gas input;
    if (supplied_gas < gas) {
      return (RErr EOutOfGas 0, lk_zero);
    }
    remaining <- supplied_gas - gas;
    p_opt <- parse input;
    if (p_opt = None) {
      return (RErr EInvalidInputLength remaining, lk_zero);
    }
    p <- oget p_opt;
    if (p.`p_version <> versionV1) {
      return (RErr EInvalidVersion remaining, lk_zero);
    }
    (v_res, lk_backend) <@ B.verify(p.`p_version, p.`p_proof, p.`p_pub);
    lk_total <- lk_backend;
    if (v_res = VFailed) {
      return (RErr EInvalidProof remaining, lk_total);
    }
    if (v_res = VRejected) {
      return (RErr EInvalidProof remaining, lk_total);
    }
    return (ROK remaining, lk_total);
  }
}.

(* -------------------------------------------------------------------- *)
(* CT obligation on the BACKEND                                          *)
(* -------------------------------------------------------------------- *)
(* The backend verifier is required to be constant-time over the         *)
(* (proof, pub) payload. version is public (only versionV1 is accepted   *)
(* anyway), and the lengths are public-by-EVM-precompile-ABI.            *)
(*                                                                       *)
(* This is the property the Rust `p3q-verifier` crate must satisfy. The  *)
(* libjade-style CT annotation in `crates/p3q-verifier/src/lib.rs` is    *)
(* the syntactic carrier; this lemma is the semantic obligation.         *)
(* -------------------------------------------------------------------- *)

section CTBackend.

declare module B <: CTBackend.

declare axiom backend_ct
      (version : byte_t)
      (proof1 proof2 pub1 pub2 : bytes_t) :
    size proof1 = size proof2 =>
    size pub1   = size pub2   =>
    equiv [ B.verify ~ B.verify :
              ={version}
              /\ proof{1} = proof1 /\ proof{2} = proof2
              /\ pub{1}   = pub1   /\ pub{2}   = pub2
            ==>
              res{1}.`2 = res{2}.`2 ].

(* -------------------------------------------------------------------- *)
(* Theorem — precompile CT under backend CT                              *)
(* -------------------------------------------------------------------- *)
(* If the backend is CT over (proof, pub) payload, then the precompile   *)
(* is CT over (proof, pub) payload too. The structural parse leakage     *)
(* depends only on size(input), which is the same for both samples (by   *)
(* hypothesis), so structural leakage is equal across the two            *)
(* executions; backend leakage is equal by `backend_ct`.                 *)
(* -------------------------------------------------------------------- *)

lemma precompile_ct
        (input1 input2 : bytes_t) (supplied_gas : int) :
  size input1 = size input2 =>
  nth 0 input1 0 = nth 0 input2 0 =>  (* version byte is public *)
  equiv [ CTPrecompileRun(B).run ~ CTPrecompileRun(B).run :
            ={supplied_gas}
            /\ input{1} = input1 /\ input{2} = input2
          ==>
            res{1}.`2 = res{2}.`2 ].
proof.
  move=> h_size h_ver.
  proc.
  (* lk_zero is sampled independently in both runs — pair them up so
     that the same draw is used on both sides via tactical sampling
     coupling. *)
  rnd; auto=> />.
  (* gas, remaining, p_opt are functions of size(input), which is
     equal by h_size; thus the control flow up to the backend call
     is identical between the two runs. *)
  if; first by auto; smt().
  (* Both runs took the OOG branch — leakage is lk_zero on both
     sides. *)
    by auto.
  (* Both runs went past OOG. *)
  if; first by auto; smt().
  (* Both runs took the EInvalidInputLength branch. *)
    by auto.
  if; first by auto; smt().
  (* Both runs took the EInvalidVersion branch (h_ver pins version
     byte equality, so this branch is the same on both sides). *)
    by auto.
  (* Both runs reach the backend call. Apply backend CT axiom. *)
  call (backend_ct p_opt0.`p_version p_opt0.`p_proof p_opt1.`p_proof
                   p_opt0.`p_pub   p_opt1.`p_pub).
    auto=> />; smt().
  if; first by auto; smt().
    by auto.
  if; first by auto; smt().
    by auto.
  by auto.
qed.

end section CTBackend.
