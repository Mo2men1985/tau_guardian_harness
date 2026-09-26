#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping


def normalize_patch_text(text: str) -> str:
    """Extract a unified diff without modifying diff-line prefixes or indentation."""
    raw = (text or "").strip("\n")
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        raw = "\n".join(lines)

    lines = raw.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.startswith("diff --git "):
            start = idx
            break
    if start is None:
        for idx, line in enumerate(lines):
            if line.startswith("--- ") and any(x.startswith("+++ ") for x in lines[idx + 1 :]):
                start = idx
                break
    if start is not None:
        lines = lines[start:]
        # Remove only a trailing markdown fence/prose boundary. Never lstrip diff lines.
        end = len(lines)
        for idx, line in enumerate(lines):
            if idx > 0 and line.strip() == "```":
                end = idx
                break
        raw = "\n".join(lines[:end])
    if not raw.endswith("\n"):
        raw += "\n"
    return raw


def validate_patch(repo_path: str | Path, patch_text: str) -> tuple[bool, str]:
    """Validate patch syntax/applicability without changing the repository."""
    patch_text = normalize_patch_text(patch_text)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".patch", delete=False) as fh:
        fh.write(patch_text)
        patch_path = fh.name
    try:
        proc = subprocess.run(
            ["git", "apply", "--check", patch_path],
            cwd=str(repo_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        return proc.returncode == 0, proc.stdout
    finally:
        Path(patch_path).unlink(missing_ok=True)


def _normalize_prediction_mapping(mapping: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for instance_id, payload in mapping.items():
        rec = dict(payload) if isinstance(payload, dict) else {"model_patch": payload}
        rec.setdefault("instance_id", instance_id)
        rows.append(rec)
    return rows


def load_predictions(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if p.suffix.lower() == ".jsonl":
        rows: List[Dict[str, Any]] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                obj = json.loads(line)
                if isinstance(obj, dict): rows.append(obj)
        return rows
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [dict(x) for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        return _normalize_prediction_mapping(data)
    raise ValueError("predictions must be JSON object/list or JSONL")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize mini-SWE/SWE-bench prediction artifacts without inventing benchmark scores."
    )
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = load_predictions(args.predictions)
    normalized = []
    for row in rows:
        item = dict(row)
        item["model_patch"] = normalize_patch_text(str(item.get("model_patch", "")))
        normalized.append(item)
    Path(args.output).write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    print(f"Wrote {len(normalized)} normalized predictions to {args.output}")


if __name__ == "__main__":
    main()
