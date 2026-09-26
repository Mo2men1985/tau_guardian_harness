"""Immutable run manifests and evidence bundles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adjudication import DecisionResult, adjudicate
from .common import MergeGateError, require_id, require_sha256, sha256_json
from .criteria import CriteriaLock
from .evidence import EvidenceRegistry
from .submission import AuditSubmission
from .target import AuditTarget


@dataclass(frozen=True)
class RunManifest:
    schema_version: str
    target: AuditTarget
    criteria_lock_sha256: str
    evidence_registry_sha256: str
    submission_sha256: str
    policy_version: str

    def __post_init__(self) -> None:
        require_id(self.schema_version, "schema_version")
        require_id(self.policy_version, "policy_version")
        require_sha256(self.criteria_lock_sha256, "criteria_lock_sha256")
        require_sha256(self.evidence_registry_sha256, "evidence_registry_sha256")
        require_sha256(self.submission_sha256, "submission_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target.to_dict(),
            "criteria_lock_sha256": self.criteria_lock_sha256,
            "evidence_registry_sha256": self.evidence_registry_sha256,
            "submission_sha256": self.submission_sha256,
            "policy_version": self.policy_version,
        }

    @property
    def manifest_id(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class EvidenceBundle:
    schema_version: str
    manifest: RunManifest
    decision: DecisionResult
    criteria_lock: CriteriaLock
    evidence_registry: EvidenceRegistry
    submission: AuditSubmission

    def __post_init__(self) -> None:
        require_id(self.schema_version, "schema_version")
        if self.manifest.criteria_lock_sha256 != self.criteria_lock.digest:
            raise MergeGateError("BUNDLE_CRITERIA_LOCK_HASH_MISMATCH")
        if self.manifest.evidence_registry_sha256 != self.evidence_registry.digest:
            raise MergeGateError("BUNDLE_EVIDENCE_REGISTRY_HASH_MISMATCH")
        if self.manifest.submission_sha256 != self.submission.digest:
            raise MergeGateError("BUNDLE_SUBMISSION_HASH_MISMATCH")
        if self.manifest.policy_version != self.criteria_lock.policy_version:
            raise MergeGateError("BUNDLE_POLICY_VERSION_MISMATCH")
        expected = adjudicate(
            target=self.manifest.target,
            criteria_lock=self.criteria_lock,
            evidence_registry=self.evidence_registry,
            submission=self.submission,
        )
        if self.decision.digest != expected.digest:
            raise MergeGateError("BUNDLE_DECISION_MISMATCH")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest.manifest_id,
            "manifest": self.manifest.to_dict(),
            "decision": self.decision.to_dict(),
            "criteria_lock": self.criteria_lock.to_dict(),
            "evidence_registry": self.evidence_registry.to_dict(),
            "submission": self.submission.to_dict(),
        }

    @property
    def bundle_sha256(self) -> str:
        return sha256_json(self.to_dict())


def build_run_manifest(
    *,
    target: AuditTarget,
    criteria_lock: CriteriaLock,
    evidence_registry: EvidenceRegistry,
    submission: AuditSubmission,
    schema_version: str = "merge-gate-run-v1",
) -> RunManifest:
    return RunManifest(
        schema_version=schema_version,
        target=target,
        criteria_lock_sha256=criteria_lock.digest,
        evidence_registry_sha256=evidence_registry.digest,
        submission_sha256=submission.digest,
        policy_version=criteria_lock.policy_version,
    )


def build_bundle(
    *,
    target: AuditTarget,
    criteria_lock: CriteriaLock,
    evidence_registry: EvidenceRegistry,
    submission: AuditSubmission,
    schema_version: str = "merge-gate-bundle-v1",
) -> EvidenceBundle:
    manifest = build_run_manifest(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=evidence_registry,
        submission=submission,
    )
    decision = adjudicate(
        target=target,
        criteria_lock=criteria_lock,
        evidence_registry=evidence_registry,
        submission=submission,
    )
    return EvidenceBundle(
        schema_version=schema_version,
        manifest=manifest,
        decision=decision,
        criteria_lock=criteria_lock,
        evidence_registry=evidence_registry,
        submission=submission,
    )
