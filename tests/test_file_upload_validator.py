import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.file_upload_validator_solution import validate_upload, MAX_SIZE_BYTES


def test_accepts_valid_png():
    assert validate_upload("avatar.png", "image/png", 1024) is True


def test_rejects_unknown_extension():
    assert validate_upload("archive.zip", "application/zip", 1024) is False


def test_rejects_mismatched_content_type():
    assert validate_upload("avatar.jpg", "image/png", 1024) is False


def test_rejects_too_large_files():
    assert validate_upload("big.pdf", "application/pdf", MAX_SIZE_BYTES + 1) is False


def test_rejects_zero_size():
    assert validate_upload("empty.pdf", "application/pdf", 0) is False

