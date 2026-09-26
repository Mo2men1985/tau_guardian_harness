"""Fail-closed adjudication over locked criteria and trusted evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .common import ABSTAIN, KNOWN_DECISIONS, PASS, VETO, MergeGateError, require_id, sha256_json
from .criteria import CriteriaLock, Criterion
from .evidence import EvidenceRegistry
from .submission import AuditSubmission, CriterionEvidence
from .target import AuditTarget


@dataclass(frozen=True)
class CriterionDecision:
    criterion_id: str
    decision: str
    reason_codes: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        require_id(self.criterion_id, "criterion_id")
        if self.decision not in KNOWN_DECISIONS:
            raise MergeGateError(f"DECISION_UNKNOWN: {self.decision!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion_id": self.criterion_id,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class DecisionResult:
    decision: str
    reason_codes: tuple[str, ...]
    criteria: tuple[CriterionDecision, ...]

    def __post_init__(self) -> None:
        if self.decision not in KNOWN_DECISIONS:
            raise MergeGateError(f"DECISION_UNKNOWN: {self.decision!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "criteria": [
                item.to_dict()
                for item in sorted(self.criteria, key=lambda value: value.criterion_id)
            ],
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


def _evaluate(
    criterion: Criterion,
    cited: CriterionEvidence | None,
    registry: EvidenceRegistry,
    candidate_sha: str,
) -> CriterionDecision:
    if cited is None or not cited.evidence_ids:
        return CriterionDecision(
            criterion_id=criterion.criterion_id,
            decision=ABSTAIN,
            reason_codes=("CRITERION_EVIDENCE_MISSING",),
        )

    reasons: list[str] = []
    positive = 0
    negative = 0
    uncertain = False

    for evidence_id in cited.evidence_ids:
        record = registry.get(evidence_id)
        if record is None:
            reasons.append(f"EVIDENCE_UNRESOLVED:{evidence_id}")
            uncertain = True
            continue
        if record.candidate_sha != candidate_sha:
            reasons.append(f"EVIDENCE_STALE:{evidence_id}")
            uncertain = True
            continue
        if record.evidence_class not in criterion.admissible_evidence_classes:
            reasons.append(f"EVIDENCE_CLASS_INADMISSIBLE:{evidence_id}")
            uncertain = True
            continue
        if record.proposition not in criterion.admissible_propositions:
            reasons.append(f"PROPOSITION_NOT_BOUND:{evidence_id}")
            uncertain = True
            continue
        if not record.complete:
            reasons.append(f"EVIDENCE_INCOMPLETE:{evidence_id}")
            uncertain = True
            continue
        if record.establishes is True:
            positive += 1
        else:
            negative += 1
            reasons.append(f"ADVERSE_EVIDENCE:{evidence_id}")

    if positive and negative:
        reasons.append("CONFLICTING_EVIDENCE")
        return CriterionDecision(
            criterion.criterion_id,
            ABSTAIN,
            tuple(sorted(set(reasons))),
            cited.evidence_ids,
        )
    if negative:
        return CriterionDecision(
            criterion.criterion_id,
            VETO,
            tuple(sorted(set(reasons))),
            cited.evidence_ids,
        )
    if uncertain:
        return CriterionDecision(
            criterion.criterion_id,
            ABSTAIN,
            tuple(sorted(set(reasons))),
            cited.evidence_ids,
        )
    if positive < criterion.required_establishing_records:
        return CriterionDecision(
            criterion.criterion_id,
            ABSTAIN,
            ("ESTABLISHING_EVIDENCE_COUNT_INSUFFICIENT",),
            cited.evidence_ids,
        )
    return CriterionDecision(
        criterion.criterion_id,
        PASS,
        ("CRITERION_ESTABLISHED",),
        cited.evidence_ids,
    )


def adjudicate(
    *,
    target: AuditTarget,
    criteria_lock: CriteriaLock,
    evidence_registry: EvidenceRegistry,
    submission: AuditSubmission,
) -> DecisionResult:
    """Compute the decision without trusting the submission to define standards."""
    locked_ids = {item.criterion_id for item in criteria_lock.criteria}
    unknown = sorted(
        item.criterion_id for item in submission.criteria if item.criterion_id not in locked_ids
    )

    decisions = tuple(
        _evaluate(
            criterion,
            submission.get(criterion.criterion_id),
            evidence_registry,
            target.candidate_sha,
        )
        for criterion in criteria_lock.criteria
    )
    required = tuple(
        result
        for result in decisions
        if criteria_lock.get(result.criterion_id) is not None
        and criteria_lock.get(result.criterion_id).required
    )

    reasons: list[str] = [f"SUBMISSION_UNKNOWN_CRITERION:{item}" for item in unknown]
    if any(item.decision == VETO for item in required):
        overall = VETO
        reasons.append("REQUIRED_CRITERION_VETO")
    elif unknown or any(item.decision == ABSTAIN for item in required):
        overall = ABSTAIN
        reasons.append("REQUIRED_CRITERION_UNRESOLVED")
    else:
        overall = PASS
        reasons.append("ALL_REQUIRED_CRITERIA_ESTABLISHED")

    return DecisionResult(overall, tuple(sorted(set(reasons))), decisions)
