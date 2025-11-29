from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Iterator


@dataclass
class InMemoryAuditRepo:
    """Very small in-memory audit log with a transaction helper."""
    events: List[Dict[str, str]] = field(default_factory=list)

    def save_event(self, event_type: str, message: str) -> None:
        self.events.append({"type": event_type, "message": message})

    def transaction(self) -> "_Transaction":
        return _Transaction(self)


@dataclass
class _Transaction:
    repo: InMemoryAuditRepo

    def __enter__(self) -> InMemoryAuditRepo:
        # In a real system this is where you would begin a DB transaction.
        return self.repo

    def __exit__(self, exc_type, exc, tb) -> None:
        # And here you would commit/rollback.
        return False  # propagate exceptions


def write_audit_log(repo: InMemoryAuditRepo, user_id: str, action: str) -> None:
    """Write multiple audit events inside a transaction context."""
    message = f"user={user_id} action={action}"
    with repo.transaction() as tx:
        tx.save_event("USER_ACTION", message)
        tx.save_event("AUDIT_TRAIL", message)
