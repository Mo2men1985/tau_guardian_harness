import html


def render_user_profile(username: str, bio: str) -> str:
    """Render a simple HTML snippet for a user profile, with escaping.

    Both username and bio are HTML-escaped to avoid injection.
    """
    safe_username = html.escape(username, quote=True)
    safe_bio = html.escape(bio, quote=True)
    return f'<div class="profile"><h1>{safe_username}</h1><p>{safe_bio}</p></div>'
