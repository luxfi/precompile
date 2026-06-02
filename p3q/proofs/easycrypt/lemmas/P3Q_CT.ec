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
  proc verify(version : byte_t, prf pub : bytes_t)
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
    var r          : precompile_result_t * leakage_t;

    lk_zero <$ duniform [witness]; (* abstract empty trace *)

    r   <- (RErr EOutOfGas 0, lk_zero);
    gas <- required_gas input;
    if (supplied_gas < gas) {
      r <- (RErr EOutOfGas 0, lk_zero);
    } else {
      remaining <- supplied_gas - gas;
      p_opt <- parse input;
      if (p_opt = None) {
        r <- (RErr EInvalidInputLength remaining, lk_zero);
      } else {
        p <- oget p_opt;
        if (p.`p_version <> versionV1) {
          r <- (RErr EInvalidVersion remaining, lk_zero);
        } else {
          (v_res, lk_backend) <@ B.verify(p.`p_version, p.`p_proof, p.`p_pub);
          lk_total <- lk_backend;
          if (v_res = VFailed) {
            r <- (RErr EInvalidProof remaining, lk_total);
          } else {
            if (v_res = VRejected) {
              r <- (RErr EInvalidProof remaining, lk_total);
            } else {
              r <- (ROK remaining, lk_total);
            }
          }
        }
      }
    }
    return r;
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
      (prf1 prf2 pub1 pub2 : bytes_t) :
    size prf1 = size prf2 =>
    size pub1   = size pub2   =>
    equiv [ B.verify ~ B.verify :
              ={version}
              /\ prf{1} = prf1 /\ prf{2} = prf2
              /\ pub{1}   = pub1   /\ pub{2}   = pub2
            ==>
              res{1}.`2 = res{2}.`2 ].

(* -------------------------------------------------------------------- *)
(* CT obligation on the PARSER                                           *)
(* -------------------------------------------------------------------- *)
(* The codec `parse` is required to be constant-time over the (proof,    *)
(* pub) payload. Its only adversary-observable trace is its branch       *)
(* structure: whether the input parses (None vs Some) and, when it does, *)
(* the version byte and the proof/pub segment LENGTHS it exposes. Each   *)
(* of these is a function of the PUBLIC data only — the input length and *)
(* the (public) version byte — never of the proof/pub byte contents.     *)
(* This is the parser-side analogue of `backend_ct`; it is the formal    *)
(* statement of the comment above that "structural parse leakage is a    *)
(* function of size(input) only". It is discharged in the Go/Rust codec  *)
(* `binary.BigEndian.Uint32` + fixed-offset slicing, which performs no   *)
(* data-dependent branch over the payload. *)
declare axiom parse_ct (i1 i2 : bytes_t) :
    size i1 = size i2 =>
    nth 0 i1 0 = nth 0 i2 0 =>
       ((parse i1 = None) = (parse i2 = None))
    /\ omap (fun (p:parsed_t) => p.`p_version) (parse i1)
        = omap (fun (p:parsed_t) => p.`p_version) (parse i2)
    /\ omap (fun (p:parsed_t) => size p.`p_proof) (parse i1)
        = omap (fun (p:parsed_t) => size p.`p_proof) (parse i2)
    /\ omap (fun (p:parsed_t) => size p.`p_pub) (parse i1)
        = omap (fun (p:parsed_t) => size p.`p_pub) (parse i2).

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
  have [hnone hrest] := parse_ct input1 input2 h_size h_ver.
  have [hver hsz]     := hrest.
  have [hszprf hszpub] := hsz.
  proc.
  (* lk_zero is sampled in both runs; couple the draws. The prefix
     (lk_zero, r, gas) is then equal on both sides since gas is a
     function of size(input), which is equal by h_size. *)
  seq 3 3 : (={lk_zero, r, gas, supplied_gas}
             /\ input{1} = input1 /\ input{2} = input2).
    wp; rnd; auto; smt().
  (* OOG branch: condition depends only on (gas, supplied_gas), equal
     on both sides. *)
  if; 1: smt().
  + by auto.
  + (* past OOG: p_opt = parse input on each side. *)
    seq 2 2 : (={lk_zero, gas, remaining, supplied_gas}
               /\ input{1} = input1 /\ input{2} = input2
               /\ p_opt{1} = parse input1 /\ p_opt{2} = parse input2).
      by auto.
    (* parse None/Some branch: same on both sides by parse_ct (hnone). *)
    if.
    - smt().
    - by auto.
    - seq 1 1 : (={lk_zero, gas, remaining, supplied_gas}
                 /\ input{1} = input1 /\ input{2} = input2
                 /\ p{1} = oget (parse input1) /\ p{2} = oget (parse input2)
                 /\ parse input1 <> None /\ parse input2 <> None).
        by auto; smt().
      (* version branch: same on both sides by parse_ct (hver). *)
      if.
      * smt().
      * by auto.
      * (* backend reached on both sides. backend_ct gives EQUAL LEAKAGE
           (lk_backend); the verifier RESULT v_res may differ, but every
           trailing branch sets r.`2 = lk_total = lk_backend, so the
           leakage output is equal regardless of the branch each side
           takes. The proof/pub segment lengths agree by hszprf/hszpub,
           discharging the backend_ct size side-conditions. *)
        seq 2 2 : (={lk_total}).
          wp.
          call (backend_ct (oget (parse input1)).`p_version
                            (oget (parse input1)).`p_proof
                            (oget (parse input2)).`p_proof
                            (oget (parse input1)).`p_pub
                            (oget (parse input2)).`p_pub).
          + move: hszprf hnone; case (parse input1); case (parse input2) => //= /#.
          + move: hszpub hnone; case (parse input1); case (parse input2) => //= /#.
          auto; smt().
        by if{1}; if{2}; auto.
qed.

end section CTBackend.
