from __future__ import annotations

from typing import Any, Dict, Protocol
import hmac
import hashlib


class UserRepo(Protocol):
    def get_user(self, username: str) -> Dict[str, Any]:
        ...


def _hash_password(raw: str) -> str:
    """Deterministic password hashing helper for tests.

    This is **not** meant as a real password hashing scheme, but it ensures
    we never store or compare raw passwords directly.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def login_handler(user_repo: UserRepo, username: str, password: str) -> Dict[str, Any]:
    """Authenticate a user against a repository of password hashes.

    - Returns structured error codes instead of raising.
    - Uses constant-time comparison for password hashes.
    - Does not expose raw credentials.
    """
    user = user_repo.get_user(username)
    if not user:
        return {"ok": False, "error": "invalid_credentials"}

    if not user.get("is_active", True):
        return {"ok": False, "error": "inactive_user"}

    stored_hash = user.get("password_hash")
    if not stored_hash:
        return {"ok": False, "error": "invalid_credentials"}

    candidate_hash = _hash_password(password)
    if not hmac.compare_digest(stored_hash, candidate_hash):
        return {"ok": False, "error": "invalid_credentials"}

    return {"ok": True, "user_id": user["username"]}
