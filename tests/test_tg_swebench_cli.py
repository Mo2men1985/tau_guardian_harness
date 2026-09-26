from tg_swebench_cli import normalize_patch_text


def test_normalize_patch_preserves_context_prefix_and_python_indentation():
    raw = """intro\n```diff\ndiff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n def f():\n-    return 1\n+    return 2\n```\ntrailing\n"""
    normalized = normalize_patch_text(raw)
    assert "\n def f():\n" in normalized
    assert "\n-    return 1\n" in normalized
    assert "\n+    return 2\n" in normalized
    assert "```" not in normalized
