// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package contract

import "errors"

// ErrRejected is the outcome of a verifier that ran and did not accept.
// ErrNoVerifier is the outcome of a path that could not verify at all — no
// verifier is wired, a key carries none of the material the equation needs,
// an operation is disabled. The two are different facts and a caller that
// treats them alike has misread one of them.
var (
	ErrRejected   = errors.New("verification failed")
	ErrNoVerifier = errors.New("no verifier: nothing checked this")
)

// Verdict is the outcome of one cryptographic check.
//
// It replaces (bool, error) on verification paths, for a reason that was
// measured rather than assumed. Three verifiers in this repository answered
// "valid" without verifying anything: one folded its IPA rounds, assigned the
// result to _, and returned true; one returned a length check as a verdict, so
// every byte string was a valid range proof; one returned true for every
// statement. Three existing tests missed all of it because they discarded the
// verdict into _.
//
// (bool, error) has four representable states and three meanings:
//
//	(true,  nil) verified, accepted
//	(false, nil) verified and rejected — OR nothing ran        ← the collision
//	(false, err) an error
//	(true,  err) nonsense, and nothing stops it being written
//
// The collision is the defect. "I did not verify" has no spelling of its own,
// so it borrows the spelling of "I verified and it failed", and a caller
// cannot tell a missing verifier from a bad proof. The missing thing is a bit
// recording whether a verifier ran. Verdict carries it, and its zero value has
// that bit clear — so a fall-through, an unset struct field, a forgotten
// branch and a `var v Verdict` all refuse. Fail-secure is the default rather
// than something each author has to remember.
//
// Why not error alone, with a sentinel for "no verifier". It is the more
// obvious answer and it is worse. `return nil` is the most ordinary line in
// Go: it is what a function tail looks like when nothing went wrong, and under
// an error-only signature it MEANS accepted. The accept becomes the default
// shape of a forgotten path. The halo2 bug written error-only is
// `_ = foldedCommitment; return nil` — the same bug, now indistinguishable
// from ordinary success. Fail-secure needs the default to deny, and for error
// the default is nil, which admits. So error-only inverts exactly the property
// this type exists to hold. (bool, error)'s zero (false, nil) is at least a
// refusal; its problems are the collision above and that `true` is a keyword
// anyone can type. Verdict fixes both: the collision structurally, and the
// keyword by having no exported field — a positive cannot be written as a
// literal from another package, only obtained from Checked.
//
// What that does NOT do: Checked(true) is still writable, and no Go type can
// stop it. What it does instead is make every claim of a positive an
// enumerable call site — `grep -rn 'contract.Checked'` lists all of them for a
// reviewer — and TestCheckedIsNeverALiteral in this package fails the build if
// any of them passes a constant. The lie is not impossible; it is impossible
// to write by accident, and impossible to leave in the tree.
//
// Verdict is for security verdicts only. A lookup's (T, bool) reports presence
// and stays as it is: ring's scalar(b) ([]*big.Int, bool) refuses a scalar
// outside [1, N-1] at parse time and every caller checks it. The difference is
// what a wrong true costs — a missing map entry, or an accepted forgery.
type Verdict struct {
	ran    bool
	passed bool
	why    error
}

// Checked records the outcome of a check that ran.
//
// passed must be the verifier's own closing predicate — the expression that
// compares computed evidence against the claim. Never a literal: a literal is
// a claim about work, not the work. TestCheckedIsNeverALiteral enforces that
// across every package in this module.
func Checked(passed bool) Verdict { return Verdict{ran: true, passed: passed} }

// Refused records that no verifier ran, and why. A nil or ErrRejected reason
// is replaced by ErrNoVerifier: "nothing checked this" must never be able to
// masquerade as "this was checked and failed", which is the collision the type
// exists to remove.
func Refused(why error) Verdict {
	if why == nil || errors.Is(why, ErrRejected) {
		why = ErrNoVerifier
	}
	return Verdict{why: why}
}

// OK reports acceptance, and only acceptance. The zero Verdict is not OK.
func (v Verdict) OK() bool { return v.ran && v.passed }

// Err is nil on acceptance, ErrRejected when a verifier ran and refused, and
// the refusal reason when none ran. errors.Is(v.Err(), ErrNoVerifier)
// distinguishes "nothing checked this" from "this did not check out".
func (v Verdict) Err() error {
	switch {
	case v.OK():
		return nil
	case v.ran:
		return ErrRejected
	case v.why != nil:
		return v.why
	default:
		return ErrNoVerifier
	}
}

// Word is the 32-byte EVM-ABI encoding of the verdict as a bool: the last byte
// is 1 on acceptance and 0 otherwise. Fresh on every call, so a caller may
// mutate what it gets without touching the next caller's result.
//
// A refusal encodes as false. A precompile whose contract is "report the
// outcome, never revert" must still say something, and false is the only
// honest thing to say about a check that did not happen. A precompile that can
// revert should return Err instead, which keeps the distinction.
func (v Verdict) Word() []byte {
	w := make([]byte, 32)
	if v.OK() {
		w[31] = 1
	}
	return w
}
