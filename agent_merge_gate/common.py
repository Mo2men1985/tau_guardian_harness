"""Shared constants and canonical hashing for Agent Merge Gate."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

PASS = "PASS"
ABSTAIN = "ABSTAIN"
VETO = "VETO"
KNOWN_DECISIONS = frozenset({PASS, ABSTAIN, VETO})

PRIMARY_STATE = "PRIMARY_STATE"
DETERMINISTIC = "DETERMINISTIC_DERIVATION"
INDEPENDENT_REVIEW = "INDEPENDENT_REVIEW"
AGENT_ASSERTION = "AGENT_ASSERTION"
KNOWN_EVIDENCE_CLASSES = frozenset(
    {PRIMARY_STATE, DETERMINISTIC, INDEPENDENT_REVIEW, AGENT_ASSERTION}
)

TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
INDEPENDENT_REVIEWER = "INDEPENDENT_REVIEWER"
AGENT = "AGENT"
KNOWN_PRODUCER_KINDS = frozenset({TRUSTED_SYSTEM, INDEPENDENT_REVIEWER, AGENT})

_SHA_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class MergeGateError(ValueError):
    """Trusted-core input is structurally invalid."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def require_id(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise MergeGateError(f"{field_name.upper()}_INVALID: {value!r}")


def require_exact_sha(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise MergeGateError(
            f"{field_name.upper()}_NOT_EXACT: expected a 40- or 64-hex commit"
        )


def require_sha256(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise MergeGateError(f"{field_name.upper()}_INVALID: expected 64-hex SHA-256")


def require_repository(value: str) -> None:
    if not isinstance(value, str) or not _REPO_RE.fullmatch(value):
        raise MergeGateError("REPOSITORY_INVALID: expected owner/name")
