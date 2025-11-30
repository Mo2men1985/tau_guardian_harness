"""Reference file upload validator."""

from __future__ import annotations

import os
from typing import Dict

# Allow modest uploads (5 MB).
MAX_SIZE_BYTES = 5 * 1024 * 1024

_ALLOWED_TYPES: Dict[str, str] = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "pdf": "application/pdf",
}


def validate_upload(filename: str, content_type: str, size_bytes: int) -> bool:
    if size_bytes <= 0 or size_bytes > MAX_SIZE_BYTES:
        return False

    _, ext = os.path.splitext(filename)
    ext = ext.lstrip(".").lower()
    expected_type = _ALLOWED_TYPES.get(ext)
    if not expected_type:
        return False

    if expected_type != content_type.lower():
        return False

    return True
