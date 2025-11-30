"""Simple HTML template renderer with escaping."""

from __future__ import annotations

import html


def render_user_profile(username: str, bio: str) -> str:
    safe_username = html.escape(username)
    safe_bio = html.escape(bio)
    return f'<div class="profile"><h1>{safe_username}</h1><p>{safe_bio}</p></div>'
