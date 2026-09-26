import re
from pathlib import Path

FORBIDDEN = [
    re.compile(r"\bCRI\b"),
    re.compile(r"\bSAD\b"),
    re.compile("τ"),
    re.compile(r"\btau\b", re.IGNORECASE),
    re.compile(r"tau_", re.IGNORECASE),
]
TEXT_SUFFIXES = {".py", ".md", ".txt", ".json", ".jsonl", ".yml", ".yaml"}


def test_retired_concepts_do_not_reappear_in_active_text():
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in {".git", ".venv", "swe_workspace", ".guardian_repo_cache"} for part in path.parts):
            continue
        if path.name == "test_no_retired_concepts.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in FORBIDDEN:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(root)} -> {pattern.pattern}")
                break
    assert not offenders, "retired concepts found:\n" + "\n".join(offenders)
