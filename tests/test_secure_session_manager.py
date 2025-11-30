import os
import sys
import importlib

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import tg_code.secure_session_manager_solution as sm  # noqa: E402


def _reset_module() -> None:
    # Reload the module to reset the in-memory session store between tests.
    importlib.reload(sm)


def test_create_and_lookup_session() -> None:
    _reset_module()
    session_id = sm.create_session("user-1")
    assert isinstance(session_id, str)
    # Session ids should be reasonably long and unpredictable.
    assert len(session_id) >= 32
    assert sm.get_user_for_session(session_id) == "user-1"


def test_sessions_are_unique() -> None:
    _reset_module()
    s1 = sm.create_session("u1")
    s2 = sm.create_session("u2")
    assert s1 != s2
    # Both sessions should be independently resolvable.
    assert sm.get_user_for_session(s1) == "u1"
    assert sm.get_user_for_session(s2) == "u2"


def test_invalidate_session() -> None:
    _reset_module()
    session_id = sm.create_session("u3")
    assert sm.get_user_for_session(session_id) == "u3"
    sm.invalidate_session(session_id)
    assert sm.get_user_for_session(session_id) is None


def test_rotate_session_changes_id_and_preserves_user() -> None:
    _reset_module()
    session_id = sm.create_session("u4")
    new_session_id = sm.rotate_session(session_id)
    assert new_session_id != session_id
    assert sm.get_user_for_session(new_session_id) == "u4"
    # Old id should no longer resolve.
    assert sm.get_user_for_session(session_id) is None

