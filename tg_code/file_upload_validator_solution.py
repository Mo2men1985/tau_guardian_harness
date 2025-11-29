import os


MAX_SIZE_BYTES = 5 * 1024 * 1024

_EXTENSION_TO_CONTENT_TYPE = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".pdf": "application/pdf",
}


def validate_upload(filename: str, content_type: str, size_bytes: int) -> bool:
    """Validate a file upload using simple metadata checks."""
    if size_bytes <= 0 or size_bytes > MAX_SIZE_BYTES:
        return False

    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in _EXTENSION_TO_CONTENT_TYPE:
        return False

    expected_ct = _EXTENSION_TO_CONTENT_TYPE[ext]
    if content_type.lower() != expected_ct.lower():
        return False

    return True
