"""Exact repository state under audit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .common import require_exact_sha, require_repository, require_sha256, sha256_json


@dataclass(frozen=True)
class AuditTarget:
    repository: str
    base_sha: str
    candidate_sha: str
    diff_sha256: str

    def __post_init__(self) -> None:
        require_repository(self.repository)
        require_exact_sha(self.base_sha, "base_sha")
        require_exact_sha(self.candidate_sha, "candidate_sha")
        require_sha256(self.diff_sha256, "diff_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "diff_sha256": self.diff_sha256,
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())
