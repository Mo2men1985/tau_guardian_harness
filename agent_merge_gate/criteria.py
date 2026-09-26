"""Trusted acceptance criteria and admissibility rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .common import (
    AGENT_ASSERTION,
    KNOWN_EVIDENCE_CLASSES,
    MergeGateError,
    require_id,
    sha256_json,
)


@dataclass(frozen=True)
class Criterion:
    criterion_id: str
    required: bool
    admissible_evidence_classes: frozenset[str]
    admissible_propositions: frozenset[str]
    required_establishing_records: int = 1

    def __post_init__(self) -> None:
        require_id(self.criterion_id, "criterion_id")
        unknown = set(self.admissible_evidence_classes) - KNOWN_EVIDENCE_CLASSES
        if unknown:
            raise MergeGateError(f"EVIDENCE_CLASS_UNKNOWN: {sorted(unknown)}")
        if AGENT_ASSERTION in self.admissible_evidence_classes:
            raise MergeGateError(f"AGENT_ASSERTION_NOT_ADMISSIBLE: {self.criterion_id}")
        if not self.admissible_evidence_classes:
            raise MergeGateError(f"ADMISSIBLE_EVIDENCE_EMPTY: {self.criterion_id}")
        if not self.admissible_propositions:
            raise MergeGateError(f"ADMISSIBLE_PROPOSITIONS_EMPTY: {self.criterion_id}")
        if self.required_establishing_records < 1:
            raise MergeGateError(f"REQUIRED_EVIDENCE_COUNT_INVALID: {self.criterion_id}")
        for proposition in self.admissible_propositions:
            require_id(proposition, "proposition")

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion_id": self.criterion_id,
            "required": self.required,
            "admissible_evidence_classes": sorted(self.admissible_evidence_classes),
            "admissible_propositions": sorted(self.admissible_propositions),
            "required_establishing_records": self.required_establishing_records,
        }


@dataclass(frozen=True)
class CriteriaLock:
    policy_version: str
    criteria: tuple[Criterion, ...]

    def __post_init__(self) -> None:
        require_id(self.policy_version, "policy_version")
        if not self.criteria:
            raise MergeGateError("CRITERIA_LOCK_EMPTY")
        ids = [item.criterion_id for item in self.criteria]
        if len(ids) != len(set(ids)):
            raise MergeGateError("CRITERION_ID_COLLISION")

    def get(self, criterion_id: str) -> Criterion | None:
        return next((item for item in self.criteria if item.criterion_id == criterion_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "criteria": [
                item.to_dict()
                for item in sorted(self.criteria, key=lambda value: value.criterion_id)
            ],
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())
