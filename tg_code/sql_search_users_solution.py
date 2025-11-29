from typing import Tuple

def build_user_search_query(prefix: str) -> Tuple[str, tuple]:
    """Build a parameterized query for searching users by username prefix.

    The query uses a single positional placeholder and a parameters tuple.
    No user-controlled data is interpolated directly into the SQL string.
    """
    query = "SELECT id, username FROM users WHERE username LIKE ?"
    # The user-controlled prefix is only used in the bound parameter, not in the SQL text.
    param = prefix + "%"
    return query, (param,)
