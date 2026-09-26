"""Fail-closed adjudication of a verifier verdict.

PROVENANCE
    This is a sanitized representative implementation demonstrating the control
    pattern used in the private system. It is not a copy of the private module.
    It was written for this showcase, is self-contained, and runs on the Python
    standard library alone.

WHAT THIS DEMONSTRATES

An AI verifier returns a structured verdict: which criteria it considers
established, on what evidence, with what verdict. The tempting implementation
reads that document and reports what it says.

That implementation has a specific defect, and it is not subtle once named:
the verdict is written by the party being judged's counterpart, and every
question that matters is answered *inside* the document. Which criteria were
required? The verdict says. Was the verifier eligible? The verdict says. Does
the cited evidence exist? The verdict says.

So this adjudicator takes five questions away from the verdict and answers them
from inputs the verdict cannot reach:

    required criteria       <- the trusted Criteria Lock, not the verdict
    evidence admissibility  <- the trusted Criteria Lock, per criterion
    verifier eligibility    <- trusted policy supplied out of band
    evidence existence      <- a registry of records produced independently
    the decision itself     <- computed here, from the above

What the verifier keeps is the part no machine can do: reading a diff and
judging whether a claim outruns its evidence. That judgement is admitted where
the lock allows it and nowhere else.

Every unresolved condition returns BLOCKED. There is no path where a missing
input, an unknown evidence class, or an unreadable field produces PASS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SHA1_RE = re.compile(r"\A[0-9a-f]{40}\Z")

# A verdict names one of these. Nothing else is a verdict.
PASS, ABSTAIN, VETO = "PASS", "ABSTAIN", "VETO"
KNOWN_VERDICTS = frozenset({PASS, ABSTAIN, VETO})

# A verdict that says PASS and "not verified" in the same document is not a
# verdict. Each stated verdict implies exactly one governance status, and the
# two fields are checked against each other rather than read independently.
IMPLIED_STATUS = {
    PASS: "VERIFIED_NOT_AUTHORIZED",
    ABSTAIN: "NOT_VERIFIED",
    VETO: "BLOCKED_VETO",
}

# Criterion states that can never support a PASS, whatever the verdict says.
NON_ESTABLISHING = frozenset({
    "DISPROVEN", "INSUFFICIENT_EVIDENCE", "CONFLICTING_EVIDENCE",
    "STALE", "NOT_APPLICABLE",
})

# Evidence classes, ordered by what they can carry.
#
# The first two assert something *observed*, so they may only enter through the
# trusted registry -- a model cannot bring them into existence by describing
# them. INDEPENDENT_EVALUATION is verifier-originated and needs no record,
# because a semantic judgement is exactly what no machine produces. AGENT_ASSERTION
# is a claim source and establishes nothing on its own.
OBSERVED_CLASSES = frozenset({"PRIMARY_STATE", "DETERMINISTIC_DERIVATION"})
VERIFIER_ORIGINATED = frozenset({"INDEPENDENT_EVALUATION"})
NEVER_ESTABLISHING = frozenset({"AGENT_ASSERTION"})
KNOWN_CLASSES = OBSERVED_CLASSES | VERIFIER_ORIGINATED | NEVER_ESTABLISHING

# Eligibility is a ladder. Anything the verifier discloses about itself may move
# it DOWN; nothing it says may move it up.
ELIGIBILITY_RANK = {"INELIGIBLE": 0, "LIMITED": 1, "ELIGIBLE": 2}


@dataclass(frozen=True)
class TrustedEvidenceRecord:
    """An observation the trusted layer produced, bound to an exact candidate.

    `proposition` is what the observation is *about*, declared by its producer.
    Without it a real, deterministic, correctly-bound record establishing
    "file X has digest D" can be cited under a criterion about the test suite --
    nothing forged, reference resolves, class admissible, and the record simply
    has nothing to do with the claim.
    """
    evidence_id: str
    evidence_class: str
    proposition: str
    candidate_sha: str
    establishes: bool


@dataclass(frozen=True)
class LockedCriterion:
    criterion_id: str
    required: bool
    admissible_evidence: frozenset[str]
    # Which propositions may establish this criterion. Empty means the criterion
    # is satisfied by verifier judgement alone, which the lock must say explicitly.
    admissible_propositions: frozenset[str]


@dataclass
class Decision:
    decision: str                       # PASS | BLOCKED
    reasons: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.decision == PASS


def _blocked(*reasons: str) -> Decision:
    return Decision("BLOCKED", list(reasons))


def adjudicate(
    verdict: dict[str, Any],
    *,
    criteria_lock: dict[str, LockedCriterion],
    evidence_registry: dict[str, TrustedEvidenceRecord],
    trusted_eligibility: str,
    candidate_sha: str,
) -> Decision:
    """Decide whether `verdict` may be treated as an authoritative PASS.

    `criteria_lock`, `evidence_registry`, `trusted_eligibility` and
    `candidate_sha` all arrive from outside the verdict. That is the whole design:
    the document being judged supplies none of the standards it is judged against.
    """
    reasons: list[str] = []

    # ---- 0. The candidate must be an exact identity, before anything else.
    #
    # "the PR", "latest", "current code" are not identities. A verdict about an
    # unresolved label cannot be stale, because it was never about anything.
    if not SHA1_RE.match(candidate_sha or ""):
        return _blocked(f"CANDIDATE_NOT_EXACT: {candidate_sha!r} is not a 40-hex commit")
    stated = verdict.get("candidate_sha")
    if stated != candidate_sha:
        return _blocked(
            f"CANDIDATE_MISMATCH: verdict judged {stated!r}, "
            f"the effect would apply to {candidate_sha!r}")

    # ---- 1. The verdict must be a verdict.
    stated_verdict = verdict.get("verdict")
    if stated_verdict not in KNOWN_VERDICTS:
        return _blocked(f"VERDICT_UNKNOWN: {stated_verdict!r}")
    if stated_verdict != PASS:
        # ABSTAIN is not PASS. VETO is not "PASS with notes".
        return _blocked(f"VERDICT_NOT_PASS: {stated_verdict}")

    implied = IMPLIED_STATUS[stated_verdict]
    if verdict.get("final_governance_status") != implied:
        return _blocked(
            f"VERDICT_SELF_CONTRADICTORY: {stated_verdict} implies {implied}, "
            f"document says {verdict.get('final_governance_status')!r}")

    # ---- 2. Eligibility comes from trusted policy, never from self-disclosure.
    if trusted_eligibility not in ELIGIBILITY_RANK:
        return _blocked(f"ELIGIBILITY_UNKNOWN: {trusted_eligibility!r}")
    effective = ELIGIBILITY_RANK[trusted_eligibility]
    disclosed = verdict.get("verifier_eligibility")
    if disclosed in ELIGIBILITY_RANK:
        # Monotonic lowering: a verifier disclosing a conflict is believed;
        # a verifier declaring itself clean is not.
        effective = min(effective, ELIGIBILITY_RANK[disclosed])
    if effective < ELIGIBILITY_RANK["ELIGIBLE"]:
        return _blocked("VERIFIER_NOT_ELIGIBLE: authoritative PASS is prohibited")

    # ---- 3. A disclosed contradiction has consequences.
    #
    # This field existed before anything read it, so a suppressed contradiction
    # and a disclosed one produced the same PASS -- which taught the verifier that
    # disclosure cost something and bought nothing.
    contradicted = set(verdict.get("contradictory_evidence") or ())
    results = verdict.get("criteria_results") or {}
    if not isinstance(results, dict):
        return _blocked("CRITERIA_RESULTS_MALFORMED: not an object")

    # ---- 4. The required set comes from the lock. The verdict does not get a vote.
    #
    # Deriving it from `results` would let a verdict pass by omitting the criteria
    # it could not establish.
    for criterion_id, locked in sorted(criteria_lock.items()):
        if not locked.required:
            continue
        entry = results.get(criterion_id)
        if entry is None:
            reasons.append(f"CRITERION_NOT_ADDRESSED: {criterion_id} is required by the lock")
            continue
        reasons.extend(_check_criterion(
            criterion_id, entry, locked, evidence_registry, candidate_sha, contradicted))

    # ---- 5. Fail closed. An empty reason list is the only way through.
    return Decision(PASS) if not reasons else Decision("BLOCKED", reasons)


def _check_criterion(
    criterion_id: str,
    entry: Any,
    locked: LockedCriterion,
    registry: dict[str, TrustedEvidenceRecord],
    candidate_sha: str,
    contradicted: set[str],
) -> list[str]:
    reasons: list[str] = []
    if not isinstance(entry, dict):
        return [f"CRITERION_MALFORMED: {criterion_id}"]

    if criterion_id in contradicted:
        reasons.append(
            f"CONTRADICTION_DISCLOSED: {criterion_id} appears in contradictory_evidence "
            f"and cannot support a PASS")

    status = entry.get("status")
    if status in NON_ESTABLISHING:
        reasons.append(f"CRITERION_NOT_ESTABLISHED: {criterion_id} is {status}")
    elif status != "ESTABLISHED":
        reasons.append(f"CRITERION_STATUS_UNKNOWN: {criterion_id} is {status!r}")

    cited = entry.get("evidence_ids")
    if not isinstance(cited, list) or not cited:
        # A required criterion with no evidence is the vacuity case: nothing to
        # examine must never read as nothing wrong.
        return reasons + [f"EVIDENCE_ABSENT: {criterion_id} cites no evidence"]

    established_by_admissible = False
    for evidence_id in cited:
        record = registry.get(evidence_id)
        if record is None:
            # The reference resolving is the whole point. A model can invent an
            # id; it cannot invent a record the trusted layer independently made.
            reasons.append(f"EVIDENCE_UNRESOLVED: {criterion_id} cites {evidence_id!r}, "
                           f"which is not in the trusted registry")
            continue
        if record.evidence_class not in KNOWN_CLASSES:
            reasons.append(f"EVIDENCE_CLASS_UNKNOWN: {record.evidence_class!r}")
            continue
        if record.evidence_class in NEVER_ESTABLISHING:
            reasons.append(
                f"EVIDENCE_CLASS_PROHIBITED: {evidence_id} is "
                f"{record.evidence_class} and establishes nothing")
            continue
        if record.evidence_class not in locked.admissible_evidence:
            reasons.append(
                f"EVIDENCE_CLASS_INADMISSIBLE: {criterion_id} does not admit "
                f"{record.evidence_class}")
            continue
        if record.candidate_sha != candidate_sha:
            # Evidence from candidate A cannot establish candidate B.
            # "Small change" is not an exception.
            reasons.append(
                f"EVIDENCE_STALE: {evidence_id} is bound to {record.candidate_sha[:12]}, "
                f"candidate is {candidate_sha[:12]}")
            continue
        if locked.admissible_propositions and \
                record.proposition not in locked.admissible_propositions:
            reasons.append(
                f"PROPOSITION_NOT_BOUND: {evidence_id} is about "
                f"{record.proposition!r}, which does not establish {criterion_id}")
            continue
        if not record.establishes:
            reasons.append(
                f"EVIDENCE_DOES_NOT_ESTABLISH: {evidence_id} reports establishes=false")
            continue
        established_by_admissible = True

    if not established_by_admissible:
        reasons.append(
            f"NO_ADMISSIBLE_ESTABLISHING_EVIDENCE: {criterion_id}")
    return reasons
