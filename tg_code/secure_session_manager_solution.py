"""In-memory secure session manager."""

from __future__ import annotations

import secrets
from typing import Dict, Optional

_sessions: Dict[str, str] = {}


def _new_session_id() -> str:
    # 24 bytes -> 32+ chars when urlsafe encoded
    return secrets.token_urlsafe(24)


def create_session(user_id: str) -> str:
    session_id = _new_session_id()
    _sessions[session_id] = user_id
    return session_id


def get_user_for_session(session_id: str) -> Optional[str]:
    return _sessions.get(session_id)


def invalidate_session(session_id: str) -> None:
    _sessions.pop(session_id, None)


def rotate_session(session_id: str) -> str:
    user = _sessions.get(session_id)
    if user is None:
        raise KeyError("session_not_found")

    invalidate_session(session_id)
    new_session_id = _new_session_id()
    _sessions[new_session_id] = user
    return new_session_id
