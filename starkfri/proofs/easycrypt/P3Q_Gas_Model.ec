(* -------------------------------------------------------------------- *)
(* P3Q — Gas model: monotonicity + no early-exit timing leak             *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file.                            *)
(*                                                                      *)
(* Properties proved                                                    *)
(* ----------------                                                     *)
(*                                                                      *)
(*   1. `gas_monotonic`           — len(a) <= len(b) => gas(a) <= gas(b)*)
(*   2. `gas_charged_upfront`     — Run() returns RErr EOutOfGas 0      *)
(*                                  whenever supplied_gas <             *)
(*                                  required_gas(input), BEFORE any     *)
(*                                  parse or backend dispatch.          *)
(*   3. `gas_linear`              — required_gas(input) = base + k *    *)
(*                                  len(input), so gas charge is a      *)
(*                                  pure function of public byte-count. *)
(*   4. `gas_no_secret_leak`      — gas charged depends ONLY on         *)
(*                                  len(input), not on proof contents,  *)
(*                                  pub-input contents, or the backend  *)
(*                                  verifier result. This is the EVM    *)
(*                                  side-channel posture: gas billing    *)
(*                                  cannot reveal backend acceptance.   *)
(*                                                                      *)
(* Layer separation                                                     *)
(* ----------------                                                     *)
(* Gas charging is decomplected from verification policy: gas is        *)
(* computed in `required_gas(input)`, debited once at the top of Run(),  *)
(* and the remainder is plumbed through all return paths. Failure modes *)
(* (`EInvalidInputLength`, `EInvalidVersion`, `EVerifierNotRegistered`, *)
(* `EInvalidProof`) all return the SAME `remaining`, so the gas-cost    *)
(* trace observable to the caller is independent of which failure mode  *)
(* fired. The only failure that bills differently is `EOutOfGas`,       *)
(* which is by definition observable before billing.                    *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

require import P3Q_Verifier.

(* -------------------------------------------------------------------- *)
(* Lemma 1 — gas is monotonic in input length                            *)
(* -------------------------------------------------------------------- *)

lemma gas_monotonic (a b : bytes_t) :
  size a <= size b =>
  required_gas a <= required_gas b.
proof.
  move=> h.
  rewrite /required_gas.
  smt(size_ge0).
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 2 — gas is purely linear in input length                        *)
(* -------------------------------------------------------------------- *)

lemma gas_linear (a : bytes_t) :
  required_gas a = baseVerifyGas + perByteGas * size a.
proof.
  by rewrite /required_gas.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 3 — gas formula in closed form for empty input                  *)
(* -------------------------------------------------------------------- *)

lemma gas_empty :
  required_gas [] = baseVerifyGas.
proof.
  by rewrite /required_gas /=.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 4 — gas charged upfront: OOG fires before any side effect       *)
(* -------------------------------------------------------------------- *)
(* This is the EVM gas-billing invariant: a precompile MUST debit gas    *)
(* before performing any state-dependent or oracle-dependent work, or    *)
(* a caller could trick the precompile into invoking the backend for     *)
(* free. Lemma proved via the OOG branch dominance in P3Q_Verifier.ec.   *)
(* -------------------------------------------------------------------- *)

section GasUpfront.

declare module B <: Backend.

lemma gas_charged_upfront (input : bytes_t) (supplied_gas : int) :
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

(* -------------------------------------------------------------------- *)
(* Lemma 5 — gas trace is independent of proof / pub contents            *)
(* -------------------------------------------------------------------- *)
(* For two inputs of the same length, required_gas is identical. The     *)
(* practical consequence: a caller cannot infer anything about proof or *)
(* pub-input contents from the gas charge. Combined with the constant-  *)
(* time backend (see Pulsar_CT.ec analogue), the gas-billing layer       *)
(* leaks nothing beyond input length, which the caller already knows.   *)
(* -------------------------------------------------------------------- *)

lemma gas_no_secret_leak (a b : bytes_t) :
  size a = size b =>
  required_gas a = required_gas b.
proof.
  move=> h.
  by rewrite /required_gas h.
qed.

(* -------------------------------------------------------------------- *)
(* Lemma 6 — uniform remaining-gas on all error paths                    *)
(* -------------------------------------------------------------------- *)
(* All non-OOG error paths return the same `supplied_gas - gas` value as *)
(* the success path. This is the "uniform-billing" invariant: a caller   *)
(* observing gas-remaining cannot distinguish EInvalidInputLength,       *)
(* EInvalidVersion, EVerifierNotRegistered, EInvalidProof, or ROK.       *)
(* -------------------------------------------------------------------- *)

lemma uniform_billing
        (input : bytes_t) (supplied_gas : int) :
  required_gas input <= supplied_gas =>
  hoare [ PrecompileRun(B).run :
            arg = (input, supplied_gas)
          ==>
            (res = ROK (supplied_gas - required_gas input))
            \/
            (exists e, res = RErr e (supplied_gas - required_gas input)) ].
proof.
  move=> h_gas.
  proc.
  rcondf 3; first by auto; smt().
  seq 4 : (remaining = supplied_gas - required_gas input); first by auto; smt().
  if; first by auto=> />; smt().
  seq 1 : (remaining = supplied_gas - required_gas input); first by auto.
  if; first by auto=> />; smt().
  seq 1 : (remaining = supplied_gas - required_gas input).
    by call (_: true); auto.
  if; first by auto=> />; smt().
  if; auto=> />; smt().
qed.

end section GasUpfront.
