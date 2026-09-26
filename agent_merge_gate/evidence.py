"""Trusted evidence records and registry integrity."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .common import (
    AGENT,
    AGENT_ASSERTION,
    DETERMINISTIC,
    INDEPENDENT_REVIEW,
    INDEPENDENT_REVIEWER,
    KNOWN_EVIDENCE_CLASSES,
    KNOWN_PRODUCER_KINDS,
    MergeGateError,
    PRIMARY_STATE,
    TRUSTED_SYSTEM,
    canonical_json,
    require_exact_sha,
    require_id,
    require_sha256,
    sha256_json,
)


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    evidence_class: str
    proposition: str
    candidate_sha: str
    producer_kind: str
    producer: str
    complete: bool
    establishes: bool | None
    artifact_sha256: str | None = None
    detail_json: str = "{}"

    def __post_init__(self) -> None:
        require_id(self.evidence_id, "evidence_id")
        require_id(self.proposition, "proposition")
        require_exact_sha(self.candidate_sha, "candidate_sha")
        if self.evidence_class not in KNOWN_EVIDENCE_CLASSES:
            raise MergeGateError(f"EVIDENCE_CLASS_UNKNOWN: {self.evidence_class!r}")
        if self.producer_kind not in KNOWN_PRODUCER_KINDS:
            raise MergeGateError(f"PRODUCER_KIND_UNKNOWN: {self.producer_kind!r}")
        if not isinstance(self.producer, str) or not self.producer.strip():
            raise MergeGateError("PRODUCER_MISSING")

        if self.evidence_class in {PRIMARY_STATE, DETERMINISTIC}:
            if self.producer_kind != TRUSTED_SYSTEM:
                raise MergeGateError(f"TRUSTED_ORIGIN_REQUIRED: {self.evidence_id}")
        elif self.evidence_class == INDEPENDENT_REVIEW:
            if self.producer_kind != INDEPENT_REVIEWER:
                raise MergeGateError(f"INDEPENDENT_ORIGIN_REQUIRED: {self.evidence_id}")
        elif self.evidence_class == AGENT_ASSERTION:
            if self.producer_kind != AGENT:
                raise MergeGateError(f"AGENT_ORIGIN_REQUIRED: {self.evidence_id}")

        if self.complete and self.establishes is None:
            raise MergeGateError(f"COMPLETE_EVIDENCE_WITHOUT_OUTCOME: {self.evidence_id}")
        if not self.complete and self.establishes is not None:
            raise MergeGateError(f"INCOMPLETE_EVIDENCE_HAS_OUTCOME: {self.evidence_id}")
        if self.artifact_sha256 is not None:
            require_sha256(self.artifact_sha256, "artifact_sha256")
        try:
            detail = json.loads(self.detail_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise MergeGateError(f"DETAIL_JSON_INVALID: {self.evidence_id}") from exc
        if not isinstance(detail, dict):
            raise MergeGateError(f"DETAIL_JSON_NOT_OBJECT: {self.evidence_id}")
        object.__setattr__(self, "detail_json", canonical_json(detail))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_class": self.evidence_class,
            "proposition": self.proposition,
            "candidate_sha": self.candidate_sha,
            "producer_kind": self.producer_kind,
            "producer": self.producer,
            "complete": self.complete,
            "establishes": self.establishes,
            "artifact_sha256": self.artifact_sha256,
            "detail": json.loads(self.detail_json),
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class EvidenceRegistry:
    records: tuple[EvidenceRecord, ...]

    def __post_init__(self) -> None:
        ids = [item.evidence_id for item in self.records]
        if len(ids) != len(set(ids)):
            raise MergeGateError("EVIDENCE_ID_COLLISION")

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return next((item for item in self.records if item.evidence_id == evidence_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [
                item.to_dict()
                for item in sorted(self.records, key=lambda value: value.evidence_id)
            ]
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())
