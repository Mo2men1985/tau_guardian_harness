"""Simple login handler with hashing and basic validation."""

from __future__ import annotations

import hashlib
from typing import Dict


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def login_handler(repo: any, username: str, password: str) -> Dict[str, object]:
    user = repo.get_user(username)
    if not user or user.get("password_hash") != _hash_password(password):
        return {"ok": False, "error": "invalid_credentials"}

    if not user.get("is_active", True):
        return {"ok": False, "error": "inactive_user"}

    return {"ok": True, "user_id": user["username"]}
