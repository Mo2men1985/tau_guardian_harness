import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.password_reset_token_solution import generate_reset_token


def test_token_is_deterministic():
    t1 = generate_reset_token("user1", 1700000000, "s3cr3t-key")
    t2 = generate_reset_token("user1", 1700000000, "s3cr3t-key")
    assert t1 == t2


def test_token_changes_with_inputs():
    base = generate_reset_token("user1", 1700000000, "s3cr3t-key")
    assert base != generate_reset_token("user2", 1700000000, "s3cr3t-key")
    assert base != generate_reset_token("user1", 1700000001, "s3cr3t-key")
    assert base != generate_reset_token("user1", 1700000000, "other-key")


def test_token_looks_url_safe():
    token = generate_reset_token("user3", 1700000000, "another-key")
    assert isinstance(token, str)
    # Simple heuristic: URL-safe base64 should not contain '+' or '/'.
    assert "+" not in token
    assert "/" not in token
    assert len(token) >= 16
