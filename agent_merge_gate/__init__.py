"""Agent Merge Gate core package."""

from .adjudication import adjudicate
from .bundle import build_bundle, build_run_manifest
from .models import (
    ABSTAIN,
    PASS,
    VETO,
    AuditSubmission,
    AuditTarget,
    CriteriaLock,
    Criterion,
    CriterionDecision,
    CriterionEvidence,
    DecisionResult,
    EvidenceRecord,
    EvidenceRegistry,
    MergeGateError,
)

__all__ = [
    "ABSTAIN",
    "PASS",
    "VETO",
    "AuditSubmission",
    "AuditTarget",
    "CriteriaLock",
    "Criterion",
    "CriterionDecision",
    "CriterionEvidence",
    "DecisionResult",
    "EvidenceRecord",
    "EvidenceRegistry",
    "MergeGateError",
    "adjudicate",
    "build_bundle",
    "build_run_manifest",
]
