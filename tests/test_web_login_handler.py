import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.web_login_handler_solution import login_handler, _hash_password


class DummyRepo:
    def __init__(self):
        self._users = {}

    def add_user(self, username: str, password: str, is_active: bool = True):
        self._users[username] = {
            "username": username,
            "password_hash": _hash_password(password),
            "is_active": is_active,
        }

    def get_user(self, username: str):
        return self._users.get(username)


def setup_repo():
    repo = DummyRepo()
    repo.add_user("alice", "secret123", is_active=True)
    repo.add_user("bob", "password456", is_active=False)
    return repo


def test_successful_login():
    repo = setup_repo()
    result = login_handler(repo, "alice", "secret123")
    assert result["ok"] is True
    assert result["user_id"] == "alice"


def test_invalid_password():
    repo = setup_repo()
    result = login_handler(repo, "alice", "wrong")
    assert result["ok"] is False
    assert result["error"] == "invalid_credentials"


def test_unknown_user():
    repo = setup_repo()
    result = login_handler(repo, "charlie", "whatever")
    assert result["ok"] is False
    assert result["error"] == "invalid_credentials"


def test_inactive_user():
    repo = setup_repo()
    result = login_handler(repo, "bob", "password456")
    assert result["ok"] is False
    assert result["error"] == "inactive_user"

