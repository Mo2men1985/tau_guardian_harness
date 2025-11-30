"""Reference audit log writer implementation for tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class InMemoryAuditRepo:
    """Simple in-memory audit repository used in unit tests."""

    events: List[Dict[str, str]] = field(default_factory=list)

    def add_event(self, event: Dict[str, str]) -> None:
        self.events.append(event)


def write_audit_log(repo: InMemoryAuditRepo, user_id: str, action: str) -> None:
    """Record both the user action and an audit trail entry."""

    repo.add_event({"type": "USER_ACTION", "user_id": user_id, "action": action})
    repo.add_event({"type": "AUDIT_TRAIL", "user_id": user_id, "action": action})
