from __future__ import annotations

from typing import Any, Callable, Dict
import hmac
import hashlib


def _sign_user(user_id: str, secret_key: str) -> str:
    msg = user_id.encode("utf-8")
    key_bytes = secret_key.encode("utf-8")
    digest = hmac.new(key_bytes, msg, hashlib.sha256).hexdigest()
    return digest


def generate_test_token(user_id: str, secret_key: str) -> str:
    """Helper used by tests to build a valid token string."""
    signature = _sign_user(user_id, secret_key)
    return f"{user_id}.{signature}"


def _decode_and_verify_token(raw: str, secret_key: str) -> Dict[str, Any]:
    try:
        user_id, sig = raw.split(".", 1)
    except ValueError:
        raise PermissionError("invalid_token")

    expected = _sign_user(user_id, secret_key)
    if not hmac.compare_digest(expected, sig):
        raise PermissionError("invalid_token")

    return {"user_id": user_id}


def jwt_auth_middleware(handler: Callable[[Dict[str, Any], Dict[str, Any]], Any], secret_key: str):
    """Return a handler that enforces a simple Bearer token scheme.

    On success it injects `user_id` into the context dict before calling the handler.
    """
    def wrapped(request: Dict[str, Any], context: Dict[str, Any]):
        headers = request.get("headers", {})
        auth_header = headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise PermissionError("missing_authorization")

        raw = auth_header.split(" ", 1)[1].strip()
        claims = _decode_and_verify_token(raw, secret_key)
        new_context = dict(context)
        new_context["user_id"] = claims["user_id"]
        return handler(request, new_context)

    return wrapped
