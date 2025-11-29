import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.jwt_auth_middleware_solution import jwt_auth_middleware, generate_test_token


def echo_user_handler(request, context):
    return context.get("user_id")


def test_valid_token_allows_access():
    secret = "top-secret-key"
    token = generate_test_token("alice", secret)
    wrapped = jwt_auth_middleware(echo_user_handler, secret)

    request = {"headers": {"Authorization": f"Bearer {token}"}}
    result = wrapped(request, {})
    assert result == "alice"


def test_missing_header_raises():
    secret = "top-secret-key"
    wrapped = jwt_auth_middleware(echo_user_handler, secret)
    request = {"headers": {}}
    try:
        wrapped(request, {})
    except PermissionError as e:
        assert "missing_authorization" in str(e)
    else:
        assert False, "Expected PermissionError"


def test_invalid_token_rejected():
    secret = "top-secret-key"
    # Token for another user or with wrong signature
    bad_token = "alice.bad-signature"
    wrapped = jwt_auth_middleware(echo_user_handler, secret)
    request = {"headers": {"Authorization": f"Bearer {bad_token}"}}
    try:
        wrapped(request, {})
    except PermissionError as e:
        assert "invalid_token" in str(e)
    else:
        assert False, "Expected PermissionError"
