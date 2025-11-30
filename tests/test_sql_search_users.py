import os
import sys
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.sql_search_users_solution import build_user_search_query


def test_builds_parameterized_query():
    query, params = build_user_search_query("al")
    assert "SELECT" in query.upper()
    assert "FROM users".upper() in query.upper()
    assert "username LIKE ?" in query
    assert isinstance(params, tuple)
    assert params == ("al%",)


def test_prefix_not_in_query_text():
    # The raw prefix should not be embedded in the SQL string itself (only in params).
    query, params = build_user_search_query("Bob")
    assert "Bob" not in query
    assert params == ("Bob%",)

