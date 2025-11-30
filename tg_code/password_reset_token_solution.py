"""Deterministic, URL-safe password reset token generator."""

from __future__ import annotations

import base64
import hmac
import hashlib


def generate_reset_token(user_id: str, timestamp: int, secret_key: str) -> str:
    message = f"{user_id}:{timestamp}".encode("utf-8")
    mac = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")
    return token
