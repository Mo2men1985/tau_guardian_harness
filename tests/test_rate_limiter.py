import os
import sys
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import importlib
import tg_code.rate_limiter_solution as rl


def test_under_limit_allows_requests():
    assert rl.allow_request("u1", 0) is True
    assert rl.allow_request("u1", 1) is True
    assert rl.allow_request("u1", 2) is True


def test_exceeding_limit_blocks_request():
    importlib.reload(rl)
    assert rl.allow_request("u1", 0) is True
    assert rl.allow_request("u1", 1) is True
    assert rl.allow_request("u1", 2) is True
    assert rl.allow_request("u1", 3) is False


def test_old_requests_expire():
    importlib.reload(rl)
    assert rl.allow_request("u1", 0) is True
    assert rl.allow_request("u1", 5) is True
    assert rl.allow_request("u1", 9) is True
    assert rl.allow_request("u1", 11) is True  # request at 0 should have expired
