"""Minimal JWT-like middleware for tests."""

from __future__ import annotations

import base64
import hmac
import hashlib
from typing import Any, Callable, Dict


Handler = Callable[[Dict[str, Any], Dict[str, Any]], Any]


def _sign(user_id: str, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("utf-8")


def generate_test_token(user_id: str, secret: str) -> str:
    return f"{user_id}.{_sign(user_id, secret)}"


def jwt_auth_middleware(handler: Handler, secret: str) -> Handler:
    def wrapper(request: Dict[str, Any], context: Dict[str, Any]):
        headers = request.get("headers") or {}
        auth_header = headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise PermissionError("missing_authorization")

        token = auth_header[len("Bearer ") :]
        if "." not in token:
            raise PermissionError("invalid_token")

        user_id, sig = token.split(".", 1)
        expected = _sign(user_id, secret)
        if not hmac.compare_digest(sig, expected):
            raise PermissionError("invalid_token")

        context = dict(context or {})
        context["user_id"] = user_id
        return handler(request, context)

    return wrapper
