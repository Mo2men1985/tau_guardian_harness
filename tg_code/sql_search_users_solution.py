"""Build a parameterized search query for users."""

from __future__ import annotations

from typing import Tuple


def build_user_search_query(prefix: str) -> Tuple[str, tuple]:
    query = "SELECT id, username FROM users WHERE username LIKE ?"
    params = (f"{prefix}%",)
    return query, params
