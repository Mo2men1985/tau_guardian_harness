import textwrap

from tg_swebench_cli import normalize_patch_text


def test_normalize_patch_text_strips_fences_and_prose() -> None:
    raw = textwrap.dedent(
        """
        Some intro text that should be removed.
        ```diff
        diff --git a/foo.py b/foo.py
        --- a/foo.py
        +++ b/foo.py
        +print("hello")
        ```
        trailing words
        """
    )

    normalized = normalize_patch_text(raw)

    assert normalized.startswith("diff --git a/foo.py b/foo.py")
    assert normalized.endswith("\n")
    assert "```" not in normalized
    assert "Some intro text" not in normalized
