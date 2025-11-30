"""Sliding window rate limiter reference implementation."""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict

_window_seconds = 10
_limit = 3
_requests: Dict[str, Deque[int]] = {}


def allow_request(user_id: str, ts: int) -> bool:
    dq = _requests.setdefault(user_id, deque())

    # Drop timestamps outside the window
    while dq and dq[0] <= ts - _window_seconds:
        dq.popleft()

    if len(dq) >= _limit:
        return False

    dq.append(ts)
    return True
