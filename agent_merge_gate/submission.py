"""Untrusted evidence citations proposed for locked criteria."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .common import MergeGateError, require_id, sha256_json


@dataclass(frozen=True)
class CriterionEvidence:
    criterion_id: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_id(self.criterion_id, "criterion_id")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise MergeGateError(f"DUPLICATE_EVIDENCE_REFERENCE: {self.criterion_id}")
        for evidence_id in self.evidence_ids:
            require_id(evidence_id, "evidence_id")

    def to_dict(self) -> dict[str, Any]:
        return {"criterion_id": self.criterion_id, "evidence_ids": list(self.evidence_ids)}


@dataclass(frozen=True)
class AuditSubmission:
    criteria: tuple[CriterionEvidence, ...]

    def __post_init__(self) -> None:
        ids = [item.criterion_id for item in self.criteria]
        if len(ids) != len(set(ids)):
            raise MergeGateError("SUBMISSION_CRITERION_COLLISION")

    def get(self, criterion_id: str) -> CriterionEvidence | None:
        return next((item for item in self.criteria if item.criterion_id == criterion_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "criteria": [
                item.to_dict()
                for item in sorted(self.criteria, key=lambda value: value.criterion_id)
            ]
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())
