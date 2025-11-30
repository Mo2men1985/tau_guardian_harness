from collections import deque
from typing import Deque, Dict

_requests: Dict[str, Deque[int]] = {}


def allow_request(user_id: str, ts: int) -> bool:
    window = 10
    limit = 3

    dq = _requests.setdefault(user_id, deque())

    # Remove timestamps that are outside the rolling window [ts - window + 1, ts]
    cutoff = ts - window + 1
    while dq and dq[0] < cutoff:
        dq.popleft()

    if len(dq) < limit:
        dq.append(ts)
        return True

    return False


