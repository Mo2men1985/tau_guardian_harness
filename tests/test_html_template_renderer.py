import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.html_template_renderer_solution import render_user_profile


def test_basic_rendering():
    out = render_user_profile("alice", "hello world")
    assert '<div class="profile">' in out
    assert "<h1>alice</h1>" in out
    assert "<p>hello world</p>" in out


def test_escapes_html_in_bio():
    out = render_user_profile("alice", "<b>hi</b>")
    # Raw tags should not appear.
    assert "<b>hi</b>" not in out
    assert "&lt;b&gt;hi&lt;/b&gt;" in out


def test_escapes_username():
    out = render_user_profile("<admin>", "bio")
    assert "<admin>" not in out
    assert "&lt;admin&gt;" in out
