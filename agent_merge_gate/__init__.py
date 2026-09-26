"""Public API for the Agent Merge Gate Phase 1 core."""

from .adjudication import CriterionDecision, DecisionResult, adjudicate
from .bundle import EvidenceBundle, RunManifest, build_bundle, build_run_manifest
from .common import (
    ABSTAIN,
    AGENT,
    AGENT_ASSERTION,
    DETERMINISTIC,
    INDEPENDENT_REVIEW,
    INDEPENDENT_REVIEWER,
    PASS,
    PRIMARY_STATE,
    TRUSTED_SYSTEM,
    VETO,
    MergeGateError,
)
from .criteria import CriteriaLock, Criterion
from .evidence import EvidenceRecord, EvidenceRegistry
from .submission import AuditSubmission, CriterionEvidence
from .target import AuditTarget

__all__ = [
    "ABSTAIN",
    "AGENT",
    "AGENT_ASSERTION",
    "DETERMINISTIC",
    "INDEPENDENT_REVIEW",
    "INDEPENDENT_REVIEWER",
    "PASS",
    "PRIMARY_STATE",
    "TRUSTED_SYSTEM",
    "VETO",
    "AuditSubmission",
    "AuditTarget",
    "CriteriaLock",
    "Criterion",
    "CriterionDecision",
    "CriterionEvidence",
    "DecisionResult",
    "EvidenceBundle",
    "EvidenceRecord",
    "EvidenceRegistry",
    "MergeGateError",
    "RunManifest",
    "adjudicate",
    "build_bundle",
    "build_run_manifest",
]
