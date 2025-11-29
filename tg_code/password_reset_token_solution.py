import hmac
import hashlib
import base64


def generate_reset_token(user_id: str, issued_at: int, secret_key: str) -> str:
    """Generate a deterministic, URL-safe password reset token.

    The token is an HMAC-SHA256 digest of `user_id:issued_at` using `secret_key`
    as the key, encoded with URL-safe base64 without padding.
    """
    msg = f"{user_id}:{issued_at}".encode("utf-8")
    key_bytes = secret_key.encode("utf-8")
    digest = hmac.new(key_bytes, msg, hashlib.sha256).digest()
    token_bytes = base64.urlsafe_b64encode(digest).rstrip(b"=")
    return token_bytes.decode("ascii")
